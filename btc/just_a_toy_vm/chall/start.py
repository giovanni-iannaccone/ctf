import base64
import os

def main() -> None:
    b64 = input("Send the code (base64): ")
    with open("/tmp/code.l", "w") as f:
        f.write(base64.decode(b64))

    os.system("./lil /tmp/code.l")

if __name__ == "__main__":
    main()
