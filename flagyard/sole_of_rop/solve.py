from pwn import *

exe = ELF("./sole_of_ROP_patched")

context.binary = exe

HOST = "addr"
PORT = 1337

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

POP_RAX = pack(0x0400177)
SYSCALL = pack(0x04000fd)

def main():
    r = conn()

    # good luck pwning :D

    r.interactive()

if __name__ == "__main__":
    main()
