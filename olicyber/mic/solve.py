from angr import *
from pwn import *

exe = ELF("./MIC")

context.binary = exe

p = Project(exe.path, load_options={"auto_load_libs":False}, main_opts={"base_addr":0})

def conn():
    return process([exe.path])

def getpass():
    init = p.factory.entry_state()
    sim = p.factory.simulation_manager(init)
    s = sim.explore(find=0x15de, avoid=0x156c)
    return s.found[0].posix.dumps(0).decode()

def main():
    passwd = getpass()

    r = conn()
    r.sendline(passwd)
    r.interactive()
    
if __name__ == "__main__":
    main()
