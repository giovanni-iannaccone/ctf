import angr
from pwn import *

p = angr.Project("./controllo_ricorsivo_circa", load_options={"auto_load_libs":False}, main_opts={"base_addr":0})

init = p.factory.entry_state()
sim = p.factory.simulation_manager(init)
s = sim.explore(find=0x13b7, avoid=0x13c5)

payload = s.found[0].posix.dumps(0)

r = remote("crc.challs.olicyber.it", 12201)
r.sendlineafter(b"password: ", payload)
r.interactive()
