---
title: "Adventures in Heap: Malloc, Free, and Fastbin Dup"
date: 2021-05-25T18:20:00+02:00
description: "Explanations of some memory allocation internals in GLIBC"
---

Heap is like the wild west of binary exploitation in my opinion, or perhaps more like an alien, no one knows what is happening (atleast I don't). A lot of CTF pwn challenges these days are heap exploitations, even the simpler ones, so let's learn some heap. Let's get started. 


# Malloc

Malloc is a function in C, which can handle the allocation of memory. Which is why it's called m alloc [memory alloc]. It's quite interesting how malloc works, but let's not delve too deep into that.  

When the malloc function is called a "chunk" of data is allocated on the heap, which is essentially a datastructure that holds dynamically allocated data. Consider the following C demo program:

```c
#include <stdio.h>

int main(){
    void *a = malloc(1);
    void *b = malloc(1);
    void *c = malloc(1);

}
```

When this program is called, one would think: "Well that should allocate memory of 1 byte in a, b, and c." This however is incorrect, as malloc always allocates atleast 24 bytes. Run the script in pwngdb, and take one command at a time with the "n" pwngdb command, then use "vis" to look at the heap. 

Graphically depicted below:
```
          Heap
┌──────────────────────────┐   malloc(1);
│  previnuse = 0x21        │
│                          │
│  0x0000 0000 0000 0021   │
│                          │
│  0x0000 0000 0000 0000   │
│                          │
│  0x0000 0000 0000 0000   │
│                          │
│  0x0000 0000 0000 0000   │
└──────────────────────────┘
```

"Hmm this isn't 24 bytes" one might think. Exactly right, this is actually (8*4) or 32 bytes. But 8 of these serve a certain purpose, they are what's called a "previnuse flag", and tells the heap the size of the allocated chunk. In this case the value is 0x21. This is also called the size field. In this case the flag tells us the size is 0x20 + 0x1 (this 0x1 i assume is the previnuse flag size) 

Now if we keep allocating memory, at a point we'll hit a barrier where the heap isn't large enough to serve our requests anymore, at that point the heap expands. The way the expansion work is, that the heap has a "top chunk" which if reached will create more heap space. 

Furthermore there's a libc symbol called "__malloc_hook" which is very useful in exploit development, if we can overwrite this with an address, this address will be called the next time malloc is called. 

# Free, and fastbins

Free is the opposite of malloc, it's the counterpart that allows the memory to be freed again [quite obvious]. 
Now to understand free, we need to understand fastbins. Fastbins are bins or "cups", that hold data based on a freed chunk, this would be the address of the previous allocated space. Consider the following pseudo-code:

```
a = malloc(1) #at addr_a
free(a) 
```

Now the fastbin will point to the addr_a. There are a variety of fastbins, the exact amount is not important right now, however it's important to note that they differ in sizes, so that there's a fastbin for 0x20 sized chunks, one for 0x30 sized chunks, and so on. 

Consider the following fictional scenario:

We allocate 24 A's with malloc, and then free said A's:

```
                ┌──────────────────────────┐   a = malloc(0x18, "A"*0x18)
                │  previnuse = 0x21        │
                │                          │
                │  0x0000 0000 0000 0021   │
                │                          │
                │  0x4141 4141 4141 4141   │
                │                          │
                │  0x4141 4141 4141 4141   │
                │                          │
                │  0x4141 4141 4141 4141   │
                └──────────────────────────┘

                ┌────────────┐
                │            │
                │ fastbins   │           free(a)
                │            │
   ┌─┬─────────┬┴────────────┴───────────┐
   │ ├─────────┤                         │
   │ │ 0x20    ├─► someaddr  ◄─────  0x0 │
   │ ├─────────┤                         │
   └─┴─────────┴─────────────────────────┘
```

As can be seen, the heap at the beginning holds our 24 bytes or 0x18 A's, in form of it's ASCII representative 0x41. Furthermore we can see the fastbin 0x20, pointing to some address, which has the value 0. This is because we just freed the A's, so in their place is now 0x0. Inspecting with pwndbg's "vis" afterwards will show the heap as follows:

```
              ┌────────────────┐
              │  Heap          │
          ┌───┴────────────────┴─────┐
          │  previnuse = 0x21        │
          │                          │
          │  0x0000 0000 0000 0021   │
          │                          │
          │  0x0000 0000 0000 0000   │
          │                          │
          │  0x4141 4141 4141 4141   │
          │                          │
          │  0x4141 4141 4141 4141   │
          └──────────────────────────┘
```

Now as one could perhaps expect, a program is not so happy trying to free NULL, this means that if we try to free the same "a", twice we'll get a bug known as a doublefree. 

But what would happen if one tried to free multiple buffers of the same size? A so-called "linked list" would be created. See the graphic depiction below:
```
             ┌──────────────┐
             │              │
             │  Fastbins    │
             │              │
             │              │
             ├──────────────┤
┌────────────┴──────────────┴──────────────┐
│                                          │
│                                          │
│  0x20 ────►second freed───►first ◄──  0x0│
│                                          │
│                                          │
└──────────────────────────────────────────┘

GDB Example:
pwndbg> vis
0x20: 0x602020 —▸ 0x602000 ◂— 0x0
```

What this means is, that the newly freed nullbytes is now pointing to the previous freed chunk, creating this list. See:
```
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][1]
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][0]
0x602030        0x0000000000602000      0x0000000000000000      . `.............
0x602040        0x0000000000000000      
```

Where the numbers indicates the most recent freed chunk, starting at 0. One can imagine it as a LIFO just like the stack. Let's assume the libc doesn't have tcache for now, as this added further security for double free vulnerabilities. 

Now let's consider the folowing program:
```c
#include <stdlib.h>

int main(){
    void *a = malloc(1);
    void *b = malloc(1);
    
    free(a);
    free(b);
    free(a);

}
```
This wouldn't cause an error then, because the old libc security measure just checked if the last freed chunk is being freed again, which isn't the case here. 

This creates the following linked list:

```
0x20: 0x602020 —▸ 0x602000 ◂— 0x602020
```

Since the fastbins should be considered a LIFO, when malloc is called again, the last freed chunk will be allocated. If we look above we have a circular list, as it keeps going around, and around, not stopping anytime soon. If we look at the chunks:
```
0x603000        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][0], fastbins[0x20][0]
0x603010        0x0000000000603020      0x0000000000000000       0`.............
0x603020        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][1]
0x603030        0x0000000000603000      0x6262626262626262      .0`.....bbbbbbbb
0x603040        0x6262626262626262      0x0000000000020fc1      bbbbbbbb........         <-- Top chunk
```

We can see at the 0x603020 address that the first QWORD is pointing to 0x603000 and the first QWORD at 0x603000 after the previnuse flag is pointing to 0x603020, which again is pointing back. This is bad, because we can now use malloc and extend the list as follows:

```
free(a)
free(b)
free(a)

a -> b -> a 
at this point the link is essentially two long,
since there's two different entities


malloc(24, c)

b -> a -> c
suddenly we allocate one of the a's with c, and now
we have a list that is three long

now we just put garbage at the next two

malloc(24, garb)

a -> c

malloc(24, garb)

-> c
```

Hopefully the above example made sense. Essentially what happens is the address is a pointer to a new element in the list, when we get our double free vulnerability, we have the opportunity of changing one of these pointers. So what we do is change the pointer of a to point to a new element, then we change the pointer of b to point to garbage and then lastly we change the pointer of a to point to some garbage. What happened is then, that a now had a new element, so the program **thinks** that there's still a fastbin left, and then goes to that element - the next malloc will then overwrite was is at this address (considering the sizefield is correct). This can be used to make semi-arbitrary writes, which can definitely be useful.

In pwndbg there's a "pwndbg> find_fake_fast &segment" function which can find these sizefields quickly, so that it's easier to exploit. One could use this technique to exploit a binary, by overwriting the __malloc_hook with system, so that the next time malloc is called system will be called, and you'll get a shell


# Main Arena

Malloc manages a programs heaps with a struct known as malloc_state. These structs are often called arenas. These arenas consist of the fastbins from before, but also smallbins, largebins etc. [Out of scope for now]. The main arena stores a pointer to the head of the fastbin.

