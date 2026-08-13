import string

from hashlib import sha256

with open("ct.txt", "r") as f:
    for letter in f:
        for i in string.printable:
            m = sha256()
            m.update(i.encode())
            if m.hexdigest() == letter.strip():
                print(i, end="")
                break

        else:
            print("ERROR")
print()
