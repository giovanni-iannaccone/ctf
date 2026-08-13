from pwn import *

exe  = ELF("{binary}", checksec=True)
libc = ELF("{libc}", checksec=False)

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
        r = process(exe.path)
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
