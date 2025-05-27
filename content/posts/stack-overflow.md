---
title: "What is a stack, and how does it overflow?"
date: 2021-05-23T18:03:05+02:00
description: "Simple explanation of basic memory corruption vulnerabilities"
---

# Stack
Memory is divided into three regions:
**Data**, **Text**, and **Stack**

In the data segment, one usually finds strings or other statically created variables. In a C program, these are variables that reside outside of functions and are therefore static. 

In the text segment, one will find compiled C code turned into machine code. Machine code is not assembly, but directly consists of binaries which can be executed by the computer, while assembly is a low-level programming language that first requires assembling to be converted into machine code.

The stack is a data structure used to hold variables initialized during runtime. This includes data in local functions or function arguments. 

While dynamically allocated memory, such as allocating memory during runtime and freeing said memory, would be stored on the "heap".

```
┌────────┐  Lower memory addresses
│        │
│  Text  │
│        │
├────────┤
│Init*   │
│  Data  │
│Uninit* │
├────────┤
│        │
│  Stack │
│        │
└────────┘  Higher memory addresses
```

So at the lower memory addresses we have our code. In the data segment we have two parts: the initialized data and the uninitialized data, where the initialized data is at the lower memory address.
The stack is at the higher memory addresses. 

# Overflow 
An overflow is essentially when this stack isn't given some boundary check condition, and therefore allows users with malicious intent to put in too much data. In the same way as if one is to pour water into a glass and just continues pouring after the glass is full. 

An example of a vulnerable program could be the following:
```c
#include <stdio.h>
int main(){
    char vulnerable_buffer[20];
    gets(vulnerable_buffer);
}
```

The "gets" function reads user input (from stdin file descriptor) but doesn't check the size of the user input. As indicated by the square brackets of the vulnerable buffer, the buffer is able to hold 20 bytes. Now if the user were to put in more than 20 bytes of data, the user would have overflowed the buffer.
