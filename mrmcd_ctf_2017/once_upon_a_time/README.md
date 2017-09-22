## Once upon a time ##

All flags in this CTF started with the string "MRMCD{.." or "mrmcd{.." .

To look at the main function in radare2, I used the following commands:
```
> aaa           ; analyze all functions
> pdf@main      ; disassemble main function
```

Opening the binary and looking at the main function, it looks like the values which are compared to a local variable were ASCII.
![r2 command pdf@main](./radare1.png)

Filtering for the cmp instructions (~ works like a grep in radare2), the flag can directly be read.

```
[0x00000660]> pdf@main~cmp      ; disassemble main function, grep for cmp command
|     |`--> 0x000007ec      4883bde8fdff.  cmp qword [local_218h], 0
|       |   0x00000808      4883bde0fdff.  cmp qword [local_220h], 0x4d ; [0x4d:8]=0x40000000 ; 'M'
|     |`--> 0x00000848      4883bdf8fdff.  cmp qword [local_208h], 0
|       |   0x00000864      4883bdf0fdff.  cmp qword [local_210h], 0x52 ; [0x52:8]=0x40000000000000 ; 'R'
|     |`--> 0x000008a4      4883bd08feff.  cmp qword [local_1f8h], 0
|       |   0x000008c0      4883bd00feff.  cmp qword [local_200h], 0x4d ; [0x4d:8]=0x40000000 ; 'M'
|     |`--> 0x00000900      4883bd18feff.  cmp qword [local_1e8h], 0
|       |   0x0000091c      4883bd10feff.  cmp qword [local_1f0h], 0x43 ; [0x43:8]=0x400000000500 ; 'C'
|     |`--> 0x0000095c      4883bd28feff.  cmp qword [local_1d8h], 0
|       |   0x00000978      4883bd20feff.  cmp qword [local_1e0h], 0x44 ; [0x44:8]=0x4000000005 ; 'D'
|     |`--> 0x000009b8      4883bd38feff.  cmp qword [local_1c8h], 0
|       |   0x000009d4      4883bd30feff.  cmp qword [local_1d0h], 0x7b ; [0x7b:8]=0x2380000000400 ; '{'
|     |`--> 0x00000a14      4883bd48feff.  cmp qword [local_1b8h], 0
|       |   0x00000a30      4883bd40feff.  cmp qword [local_1c0h], 0x73 ; [0x73:8]=0x30000000000 ; 's'
|     |`--> 0x00000a70      4883bd58feff.  cmp qword [local_1a8h], 0
|       |   0x00000a8c      4883bd50feff.  cmp qword [local_1b0h], 0x6f ; [0x6f:8]=0x800 ; 'o'
|     |`--> 0x00000acc      4883bd68feff.  cmp qword [local_198h], 0
|       |   0x00000ae8      4883bd60feff.  cmp qword [local_1a0h], 0x5f ; [0x5f:8]=0x1f800 ; '_'
|     |`--> 0x00000b28      4883bd78feff.  cmp qword [local_188h], 0
|       |   0x00000b44      4883bd70feff.  cmp qword [local_190h], 0x73 ; [0x73:8]=0x30000000000 ; 's'
|     |`--> 0x00000b84      4883bd88feff.  cmp qword [local_178h], 0
|       |   0x00000ba0      4883bd80feff.  cmp qword [local_180h], 0x6f ; [0x6f:8]=0x800 ; 'o'
|     |`--> 0x00000be0      4883bd98feff.  cmp qword [local_168h], 0
|       |   0x00000bfc      4883bd90feff.  cmp qword [local_170h], 0x72 ; [0x72:8]=0x3000000000000 ; 'r'
|     |`--> 0x00000c3c      4883bda8feff.  cmp qword [local_158h], 0
|       |   0x00000c58      4883bda0feff.  cmp qword [local_160h], 0x72 ; [0x72:8]=0x3000000000000 ; 'r'
|     |`--> 0x00000c98      4883bdb8feff.  cmp qword [local_148h], 0
|       |   0x00000cb4      4883bdb0feff.  cmp qword [local_150h], 0x79 ; [0x79:8]=0x3800000004000000 ; 'y'
|     |`--> 0x00000cf4      4883bdc8feff.  cmp qword [local_138h], 0
|       |   0x00000d10      4883bdc0feff.  cmp qword [local_140h], 0x5f ; [0x5f:8]=0x1f800 ; '_'
|     |`--> 0x00000d50      4883bdd8feff.  cmp qword [local_128h], 0
|       |   0x00000d6c      4883bdd0feff.  cmp qword [local_130h], 0x66 ; [0x66:8]=0x1f80000 ; 'f'
|     |`--> 0x00000dac      4883bde8feff.  cmp qword [local_118h], 0
|       |   0x00000dc8      4883bde0feff.  cmp qword [local_120h], 0x6f ; [0x6f:8]=0x800 ; 'o'
|     |`--> 0x00000e08      4883bdf8feff.  cmp qword [local_108h], 0
|       |   0x00000e24      4883bdf0feff.  cmp qword [local_110h], 0x72 ; [0x72:8]=0x3000000000000 ; 'r'
|     |`--> 0x00000e64      4883bd08ffff.  cmp qword [local_f8h], 0
|       |   0x00000e80      4883bd00ffff.  cmp qword [local_100h], 0x5f ; [0x5f:8]=0x1f800 ; '_'
|     |`--> 0x00000ec0      4883bd18ffff.  cmp qword [local_e8h], 0
|       |   0x00000edc      4883bd10ffff.  cmp qword [local_f0h], 0x74 ; [0x74:8]=0x300000000 ; 't'
|     |`--> 0x00000f1c      4883bd28ffff.  cmp qword [local_d8h], 0
|       |   0x00000f38      4883bd20ffff.  cmp qword [local_e0h], 0x68 ; [0x68:8]=504 ; 'h'
|     |`--> 0x00000f78      4883bd38ffff.  cmp qword [local_c8h], 0
|       |   0x00000f94      4883bd30ffff.  cmp qword [local_d0h], 0x65 ; [0x65:8]=0x1f8000000 ; 'e'
|     |`--> 0x00000fd4      4883bd48ffff.  cmp qword [local_b8h], 0
|       |   0x00000ff0      4883bd40ffff.  cmp qword [local_c0h], 0x5f ; [0x5f:8]=0x1f800 ; '_'
|     |`--> 0x00001030      4883bd58ffff.  cmp qword [local_a8h], 0
|       |   0x0000104c      4883bd50ffff.  cmp qword [local_b0h], 0x64 ; [0x64:8]=0x1f800000000 ; 'd'
|     |`--> 0x0000108c      4883bd68ffff.  cmp qword [local_98h], 0
|       |   0x000010a8      4883bd60ffff.  cmp qword [local_a0h], 0x65 ; [0x65:8]=0x1f8000000 ; 'e'
|     |`--> 0x000010e8      4883bd78ffff.  cmp qword [local_88h], 0
|       |   0x00001104      4883bd70ffff.  cmp qword [local_90h], 0x6c ; [0x6c:8]=0x800000000 ; 'l'
|     |`--> 0x0000113b      48837d8800     cmp qword [local_78h], 0
|       |   0x0000114e      48837d8061     cmp qword [local_80h], 0x61 ; [0x61:8]=0xf800000000000001 ; 'a'
|     |`--> 0x00001182      48837d9800     cmp qword [local_68h], 0
|       |   0x00001195      48837d9079     cmp qword [local_70h], 0x79 ; [0x79:8]=0x3800000004000000 ; 'y'
|     |`--> 0x000011c9      48837da800     cmp qword [local_58h], 0
|       |   0x000011dc      48837da07d     cmp qword [local_60h], 0x7d ; [0x7d:8]=0x238000000 ; '}'
```
The flag is: `MRMCD{so_sorry_for_the_delay}`.
