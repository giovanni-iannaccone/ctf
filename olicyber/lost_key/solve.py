import string
import subprocess

FLAG = [" "] * 15

def check_outputs():    
    with open("ciphertext.txt", "r") as f:
        ciphertext = f.read()

    with open("saved.txt", "r") as f:
        saved = f.read()

    return ciphertext == saved

def write_to_file(s):
    with open("flag.txt", "w") as f:
        f.write("".join(s))

def run_command():
    subprocess.check_output(["./challenge"])
    
def main():
    for i in range(15):
        for j in string.printable:
            FLAG[i] = j
            write_to_file(FLAG)
            run_command()
            if check_outputs():
                break

    print("".join(FLAG))
    
if __name__ == "__main__":
    main()
