import base64
import binascii
import json

from pwn import *

r = remote("based.challs.olicyber.it", 10600)
r.recvuntil(b"risposta\n\n")

while True:
    task = r.recvline().decode().strip()
    line = r.recvline().decode()
    try:
        message = json.loads(line)["message"]
    except:
        print(task)
        print(line)
        break

    print(f"{task} -> {message}")
    
    answer = ""
    
    if "da binario" in task:
        if len(message) % 2 != 0:
            message = "0" + message
            
        for i in range(0, len(message), 8):
            answer += chr(int(message[i: i + 8], 2))
        
    elif "a binario" in task:
        answer = "".join(format(ord(char), '08b') for char in message).replace("0b", "")[1:]
        
    elif "da base64" in task:
        answer = base64.b64decode(message.encode()).decode()
        
    elif "a base64" in task:
        answer = base64.b64encode(message.encode()).decode()

    elif "da esadecimale" in task:
        answer = bytes.fromhex(message).decode()

    elif "a esadecimale" in task:
        answer = hex(int.from_bytes(message.encode()))[2:]
        
    payload = json.dumps({
        "answer": answer
    })
    
    r.sendlineafter(b"risposta", payload.encode())      
    try:
        r.recvuntil(b"Ottimo!\n\n")
    except:
        r.interactive()
        
r.interactive()
