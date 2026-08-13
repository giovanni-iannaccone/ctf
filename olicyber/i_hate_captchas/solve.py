from pwn import *

flag = ""
r = remote("ihc.challs.olicyber.it", 34008)

r.sendafter(b"invio", b"\n")

while "}" not in flag:
    line = r.recvuntil(b"Risposta: ").decode().replace("Risposta: ", "").replace('?', '').split()
    result = ""
    
    if "posizioni" in line:
        string = line[-1]
        for i in line[6:]:
            try:
                result += string[int(i.replace('[', '').replace(']', '').replace(',', '')) - 1]
                if "]" in i:
                    break
            except:
                break

    elif "risultato" in line:
        if line[5] == "(troncato)":
            num1 = line[6]
            op = "//"
            num2 = line[8]
        else:
            num1 = line[5]
            op = line[6]
            num2 = line[7]

        num1.replace('[', '')
        num2.replace(']', '')

        expr = f"{num1} {op} {num2}"
        result = str(eval(expr))

    elif "compare" in line:
        result = str(line[-1].count(line[5]))

    elif "contrario:" in line:
        result = line[-1][::-1]
        
    r.sendline(result.encode())    
    r.recvuntil(b"premio:")
    flag += r.recvline().decode().strip()

    print(flag + "\r", end="")

print()
