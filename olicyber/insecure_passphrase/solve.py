words = [
    "casa", "albero", "notte", "sole", "montagna", "fiume", "mare", "vento", "nuvola", 
    "pioggia", "strada", "amico", "sorriso", "viaggio", "tempo", "cuore", "stella", 
    "sogno", "giorno", "libro", "porta", "luce", "ombra", "silenzio", "fiore", "luna"
]

phrase = []
with open("passphrase.txt", "r") as f:
    phrase = f.read().split("-")

flag = ""
for word in phrase:
    if word in words:
        flag = flag + chr(words.index(word) + ord('a'))
    else:
        flag = flag + word
        
print(flag)
