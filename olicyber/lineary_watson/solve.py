output = ""

with open("output.txt", "r") as f:
    output = f.read()

output = bytes.fromhex(output)
dword = (0x4a + 0x1aacf60 * 0x4b) % 0x10001

for i in output:
    print(chr(i ^ (dword % 256)), end="")
    dword = (0x4a + dword * 0x4b) % 0x10001
