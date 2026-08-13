from pwn import *

exe = ELF("./ghost")

context.binary = exe

gdbscript = """
set breakpoint pending on
b printf
c
p (char *)0x00404200
"""

def conn():
    return gdb.debug([exe.path], gdbscript=gdbscript)

def main():
    r = conn()
    log.success("THE FLAG IS NOW WRITTEN IN GDB LOGS")
    r.interactive()

if __name__ == "__main__":
    main()
