from pwn import *

exe = ELF("./brainfuck_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe

HOST = ""
PORT = 9002

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def main():
    r = conn()

    # good luck pwning :D

    r.interactive()

if __name__ == "__main__":
    main()
