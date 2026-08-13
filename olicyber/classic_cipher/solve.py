enc = "xcqv{gvyavn_zvztv_etvtddlnxcgy}"
alphabet = "abcdefghijklmnopqrstuvwxyz"

start = alphabet.index(enc[0]) - ord('f') + ord('a')
key = alphabet[start:] + alphabet[0:start]

for i in range(len(enc)):
    if enc[i] in alphabet:
        print(alphabet[key.index(enc[i])], end="")
        key = "".join([key[len(key)-1:],key[0:len(key)-1]])

    else:
        print(enc[i], end="")

print()
