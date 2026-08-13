import angr
from pwn import *

p = angr.Project("BINARY_NAME", load_options={"auto_load_libs":False}, main_opts={"base_addr":0})

def failure(state):
    return b"Sorry" in state.posix.dumps(sys.stdout.fileno())
    
def success(state):
    return b"successfully" in state.posix.dumps(sys.stdout.fileno())    

def print_founds(s):
    if len(s.found) == 0:
        log.failure("No combination found")
        return
    
    for found in s.found:
        print("-" * 30)
        log.success(f"OUTPUT: {found.posix.dumps(sys.stdout.fileno())}")
        log.success(f"INPUT: {found.posix.dumps(sys.stdin.fileno())}")

def main():
    init = p.factory.entry_state()
    sim = p.factory.simulation_manager(init)
    s = sim.explore(find=success, avoid=failure)

    print_founds(s)
    
if __name__ == "__main__":
    main()
