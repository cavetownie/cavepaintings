# Challenge 1 
Extract firmware, see if you can find which users exist on the system 

Hint: passwd 

# Challenge 2 
Install Ghidra or another decompile, and see if you can find out which 
address the vulnerable function is at in which binary 

Hint 1: it's on the slides, but try to figure it out without
Hint 2: create a bash script to find ELFs and run strings to find "0 %s NULL %d" 

# Challenge 3
Can you find other vulnerabilities

# Final boss - Not expected, but fun if you want to do this for a living
Get Firmadyne [https://github.com/firmadyne/firmadyne] to work with the firmware
Emulate the router
Exploit it first by the command injection
Add gdbserver for the correct architecture for remote debugging
Exploit one of the stack overflow (Look for strcpy)
