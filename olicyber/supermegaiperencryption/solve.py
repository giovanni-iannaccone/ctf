from pwn import *

exe = ELF("./supermegaiperencryption")

context.binary = exe

HOST = "supermegaiperencryption.challs.olicyber.it"
PORT = 10803

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

def take_enc_string():
    """
    r = conn()
    r.recvuntil(b"supercriptazione:\n")
    return r.recvline().strip()
    """
    return "3202320827732033223320432092573209275275275321023123132002252643211275277320032002753209228321432012252563201321832013208322232253246"

def reverse_lvl1(chars):
    for i in chars:
        if i > 199:
            print(chr(i - 100), end="")
        else:
            print(chr(i + 20), end="")

def reverse_lvl2(enc):
    chars = []
    i = 0
    
    while i < len(enc):
        chars.append(int(enc[i + 1 : i + 1 + int(enc[i])]))
        i += int(enc[i]) + 1
        
    return chars

def reverse_level3(enc):
    return enc

def main():
    enc = take_enc_string()

    enc = reverse_level3(enc)
    chars = reverse_lvl2(enc)
    reverse_lvl1(chars)

    print()
    
if __name__ == "__main__":
    main()
