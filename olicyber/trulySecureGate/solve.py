import struct

from pwn import *

HOST = "tsg.challs.olicyber.it"
PORT = 14000

MASK = 0xffffffff

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK

def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & MASK
    x[d] = rotl32(x[a] ^ x[d], 16)

    x[c] = (x[c] + x[d]) & MASK
    x[b] = rotl32(x[c] ^ x[b], 12)

    x[a] = (x[a] + x[b]) & MASK
    x[d] = rotl32(x[a] ^ x[d], 8)

    x[c] = (x[c] + x[d]) & MASK
    x[b] = rotl32(x[c] ^ x[b], 7)

def block_next(state):
    x = state.copy()

    for _ in range(10):
        quarter_round(x, 0, 4, 8, 12)
        quarter_round(x, 1, 5, 9, 13)
        quarter_round(x, 2, 6, 10, 14)
        quarter_round(x, 3, 7, 11, 15)

        quarter_round(x, 0, 5, 10, 15)
        quarter_round(x, 1, 6, 11, 12)
        quarter_round(x, 2, 7, 8, 13)
        quarter_round(x, 3, 4, 9, 14)

    return [
        (x[i] + state[i]) & MASK
        for i in range(16)
    ]

def get_password():
    constants = b"this is not magi"

    key = b"notthepasswordlo" + b"noncelapassword\x00"
    nonce = b"noncelapassword\x00"
    
    state = []
    
    state += struct.unpack("<4I", constants)
    state += struct.unpack("<8I", key)
    state.append(0)
    state += struct.unpack("<3I", nonce[:12])

    ciphertext = bytes.fromhex(
        "130db8c68482077d"
        "57439a98dc2b60f5"
        "92ba9887b135bce0"
        "a372df"
    )
    
    block = block_next(state)
    keystream = struct.pack("<16I", *block)

    return bytes(c ^ k for c, k in zip(ciphertext, keystream))
    
def send_password(password):
    r = remote(HOST, PORT)
    
    r.sendlineafter(b"$", b"cat flag.txt")
    r.sendlineafter(b"Password: ", password)

    r.interactive()

def main():
    password = get_password()
    send_password(password)
    
if __name__ == "__main__":
    main()
