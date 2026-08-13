with open("ct.txt", "r") as f:
    flag = f.read()

idx = 0
for i in flag:
    if i in ("{", "_", "}"):
        print(i, end="")
        continue
    elif idx % 2:
        char = (ord(i) - 14) % ord('a') + ord('a')
        if char < ord('a') or char > ord('z'):
            char = (ord(i) + 12) % ord('a') + ord('a')

        print(chr(char), end="")
    else:
        print(i, end="")

    idx += 1
print()
