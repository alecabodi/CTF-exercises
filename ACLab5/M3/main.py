import hashlib
import hmac
import multiprocessing
from itertools import product
from string import ascii_lowercase

SALT = bytes.fromhex("b49d3002f2a089b371c3")
HASH = "d262db83f67a37ff672cf5e1d0dfabc696e805bc"

def brute(firstletterascii: int):
    global HASH
    letters = bytearray(6)
    letters[0] = firstletterascii
    for letters[1] in range(97, 97 + 26):
        print(letters[1])
        for letters[2] in range(97, 97 + 26):
            for letters[3] in range(97, 97 + 26):
                for letters[4] in range(97, 97 + 26):
                    for letters[5] in range(97, 97 + 26):
                        h = hmac.new(letters, SALT, 'sha1').hexdigest()
                        if h == HASH:
                            password = "".join(chr(x) for x in letters)
                            print(password + " => " + h)
    return 0



def main():
    with multiprocessing.Pool() as p:
        p.map(brute, range(97, 97+26))

if __name__ == "__main__":
    main()
