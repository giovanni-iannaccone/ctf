with open("output.txt", "r") as f:
    flag = f.read().split()[1]

flag = bytes.fromhex(flag)
target = "flag{1"

key = ""
for i in range(6):
    key += chr(flag[i] ^ ord(target[i]))

key *= len(flag) // len(key) +  1
for f, k in zip(flag, key):
    print(chr(f ^ ord(k)), end="")

print()
