from pwn import *

exe = ELF("./easy_badges_patched")

context.binary = exe

HOST = "addr"
PORT = 1337

gdbscript = """
"""

args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
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
