---
title: "pwn2win 2021: \"Oldschool Adventures - Apple II\""
date: 2021-06-01T17:17:45+02:00
description: "QR code magic in an old Apple II emulator"
---

# Oldschool Adventures - Description

Dockerfiles: [Oldschool_Adventure](https://cavetownie.github.io/chall_files/oldschool_adventures/old_adventure.tar.gz)


Challenge description:

We found this Rhiza's Government Server, and we need to access it! It runs an Apple II emulator and accepts codes in Applesoft BASIC. If the result of your code generates a valid QR Code standard (not micro QR), it will be read and the content will be executed as a shell command on the Linux system. A very interesting way to interact with a server, don't you think?


Follow the directives below:


Maximum size of the payload: 268 chars (it will be truncated at this point)

Send the entire payload in one line (only printable chars), replacing line-break with the symbol § (only 1 allowed)

Only QR Codes are accepted (not micro QR)

Your code can take up to 50 seconds to be drawn, before the QR Code verification occurs

If you have any questions, take a look at the source code of the server inside the container

---

# Local setup pt. 1

To build the dockerfile install docker.io, and docker-compose and run:
```
$ sudo docker-compose up
$ nc localhost 1337
```

When netcatting into the localhost, one'll see a line like the following:
```
Send the solution for "hashcash -mb 25 gupwkotuhi":
```
The correct solution for that would be: 
```
hashcash token: 1:25:210601:gupwkotuhi::yX58UMHvX6PCwSdU:0000001VRsL
```
Where only the data after "hashcash token: " should be sent.

# Osint gang

Now we're ready to research. 

We're told that we need to generate a QR code which the server will read. Whatever content is in this QR code will then be executed. On the following link, one can make QR codes with specific text.

https://qrcode.tec-it.com/en

Now that we've got a general idea of how a QR code may look, we need to generate one, or rather draw one, only using Applesoft Basic. So we need an interpreter, where we can check what commands are going to do, the following website provides one:

https://www.calormen.com/jsbasic/

A teammate found the following twitter post:
https://twitter.com/AppleIIBot/status/1319004260139294721

Where a QR-code for a rickroll is being generated with Applesoft BASIC, now the length is:
```python3
>> len("""1REM________!L%P__??M]]__7T>1___%U6T__?17%]__W74?___!4%P____7____'$JJ___5?=W___")(^__7_Q1___7(1^____E#]__'0PF___]]XU__?11R\__74WY___%UP___??=+___'0!M_______________2FORY=0TO159:Z=PEEK(2054+Y)-32:FORI=0TO5:Q%=Z/2:POKE50,(Q%*2-Z)*192+255:Z=Q%:IFY+I-164THEN?" ";4NEXT I,Y:GETA""")
275
```

Which is just short of the desired length. Running this in the calormen jsbasic website renders following:
```
Unsupported PEEK location: 2054 in line 2
```

However, we know this is supported Applesoft BASIC, as it renders correctly on the post. Problem is, that the calormen site, doesn't have access to memory, which is what peek does. 

We then found the following site, which uses uploaded local files:
https://www.scullinsteel.com/apple2/

# Local setup pt. 2
However it's not so straightforward to compile files to use for this site. We ended op using python3, JDK and a tokenizing script. The instructions for compiling are as follows:

Compiling file: [compiling.zip](https://cavetownie.github.io/chall_files/oldschool_adventures/compiling.zip)

1. Download & Extract "compiling.zip"
2. Install Python3 & JDK
3. Edit your Applesoft BASIC source code in src.basic
4. Change working directory to compiling/tools/
4. Run 
```
python3 tokenize.py ../src.basic ../src.bin; cp ../template.dsk .; java -jar ac.jar -p template.dsk HELLO BAS 0x801 < ../src.bin
``` 
5. Go to https://www.scullinsteel.com/apple2/
6. Load template.dsk from compiling/tools/

---

Now we can use the source code from before, and we'll see a qr-code that when scanned rickrolls us. 

Great, so far so good. Now we can begin reversing how the string works.

So let's look at it:
```
1REM________!L%P__??M]]__7T>1___%U6T__?17%]__W74?___!4%P____7____'$JJ___5?=W___")(^__7_Q1___7(1^____E#]__'0PF___]]XU__?11R\__74WY___%UP___??=+___'0!M_______________
2FORY=0TO159:Z=PEEK(2054+Y)-32:FORI=0TO5:Q%=Z/2:POKE50,(Q%*2-Z)*192+255:Z=Q%:IFY+I-164THEN?" ";
4NEXT I,Y:GETA
```

We know from the documentation that "REM" is comment, but why do we have a comment? A teammate noticed the "peek" command, seemed to refer to some memory, probably the comment. So it's using the comment as a form of data, but how does this data work? Now through trial and error we figured a few things out, it's using some form of data based on these ascii characters. So let's look at underscore, which is probably pure white, as there's a lot of these, and the picture is mostly white.  

The hex value of "_" is 0x5f. The byte can be turnt into a lower and upper nibble, which binary data looks like this:

```
5: 0101
f: 1111
```

Together: ```0101 1111```

Now through the trial and error, we noted that whatever character we replaced, when we only replaced one, 6 dots where drawed. Meaning that we need to sort this into only 6 bits. We use the 6 LSBs, as 1 = white on the qr-code. 

Now we're left with:

```011111```

This would then draw one black dot, by our logic - problematic, because we thought "_" is pure white. We concluded that the math doing by the function, switches the most significant bit with the next one, so that:

```0100 0010```

Would become:

```0010 0010```

That means that 

```0101 1111```

Would become:

```0011 1111```

And as it's only groups of six, it would be:

```111 111```

Also known as, pure white.

Let's look at another character, "!"
which has the hex value 0x21, this becomes 0010 0001

This will be become:

```0100 0001```

Which in groups of six will be:

```000 001```

Which should just be one dot. 

An illustration of this could be the following program, which doesn't create a QR-code but just tried to show what "!" and "_" really does:

This is the code compiled and uploaded
```
1REM_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!_!!L!P_!?!C!]_!74>1___%M4T__?1W%]__WW;?___!4%P____9____'!(W___W6$R__?!0&\__W[@<___/Y_V____)P\__'0T%___]U9V__?1A[^__7T0H___%59U__??-B^__'0]/______?
2FORY=0TO159:Z=PEEK(2054+Y)-32:FORI=0TO5:Q%=Z/2:POKE50,(Q%*2-Z)*192+255:Z=Q%:IFY+I-164THEN?" ";
4NEXT I,Y:GETA
```

This yields the following:

![QRCodePNG](/pictures/qrcode.png)


And this should illustrate that we are indeed right in our hypothesis. There is however one detail worth noting, the endianness is swapped. If we look at the white spaces and actually count the pixels, we'll be able to count 7 white pixels. This is because the "!" gets turnt into: `100 000`

Now from the Dockerfile we know the flag is somewhere in:
```
1337/1338/1339/1337/1338
```

So the command we want to encode is "cat \*/\*/\*/\*/\*/\*/", now we had a solution script for this, but one can also do this manually by counting and hardcoding. 

# Final script
```python
from PIL import Image

def imagetomatrix(image):
    img = Image.open(image)
    matrix_out = []
    for i in range(39):
        matrix_out.append(1)
    for y in range(img.size[1]):
        for i in range(10):
            matrix_out.append(1)
        for x in range(img.size[0]):
            matrix_out.append(1 if img.getpixel((x,y)) in [1,255] else 0)
        for i in range(9):
            matrix_out.append(1)
    for i in range(32):
        matrix_out.append(1)

    return matrix_out


if __name__ == '__main__':
    #cat */*/*/*/*/*
    m = imagetomatrix("miniqr.png")
    ascii = ''
    for i in range(0, len(m), 6):
        ascii += chr(int("".join([str(x) for x in m[i: i+6]])[::-1], 2) + 32)
    print(ascii)
```

