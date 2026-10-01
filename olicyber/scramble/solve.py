from pwn import *

HOST = "scramble.challs.olicyber.it"
PORT = 11304

def conn():
    return remote(HOST, PORT)

def get_flag(r):
    r.sendlineafter(b"> ", b"2")
    return r.recvline().decode().strip()

def get_chars(enc):
    freq = {}
    
    for c in enc:
        freq[c] = freq.get(c, 0) + 1

    chars = list(freq.keys())
    chars.sort(key=lambda c: freq[c], reverse=True)
    return chars

def decrypt(enc, chars):
    for shift in range(1, len(chars)):
        charsn = chars[shift:] + chars[:shift]
        decrypt_map = dict(zip(charsn, chars))

        candidate = "".join(
            decrypt_map[c] for c in enc
        )

        if candidate.startswith("ptm{") and candidate.endswith("}"):
            return candidate

    return None

def main():
    r = conn()

    enc = get_flag(r)
    chars = get_chars(enc)

    print(decrypt(enc, chars))

if __name__ == "__main__":
    main()
