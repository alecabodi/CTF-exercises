# M4
#
# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/
import math
import telnetlib
import json
from itertools import cycle

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50404

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])


prev = b''
index = -1
char = 0

# stop when char '}' is reached
while True:

    char += 1

    print(char)

    if char % 16 == 1:
        index += 1

    # similar to M3, but we must generalise the approach
    # also, the message must be crafted differently with respect to what I did in M3

    for guess in range(0, 2 ** 8):

        guess = guess.to_bytes(1, 'big')

        # garbage is just for convenience
        garbage = b'C' * 16

        offset = b'B' * ((16 - char) % 16)
        data = garbage + offset + prev + guess + offset

        # extract the block preceding block containing to be used later in XOR
        # index is updated every 16 discovered characters of the flag
        data_blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        iv_prime = data_blocks[index]

        # craft the message blocks to obtain something like:
        # filename=AAAAAAA
        # AAAAAAAAAA&data=
        # CCCCCCCCCCCCCCCC
        #
        # flag{longerflag}
        # BBBBBBBBBBBBBBB&
        # flag{longerflag}
        #
        # where X is the current guess

        request = {
            "command": "encrypt",
            "file_name": (b'A' * 17).decode(),
            "data": data.hex()
        }

        json_send(request)
        response = json_recv()
        ciphertext = bytes.fromhex(response.get('ctxt'))
        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

        # XOR "ciphertext" block with previously extracted plaintext block
        Dk_guessblock = xor(iv_prime, blocks[index + 3])

        if char < 17:
            # due to garbage inserted at the beginning
            # after first block is recovered, iv_prime is the same for Dk_guessblock and Dk_flagblock
            iv_prime = offset + prev + guess

        distance = math.ceil(char / 16)
        Dk_flagblock = xor(iv_prime, blocks[index + 3 + distance])

        # exploit determinism to see if we have the right guess
        if Dk_guessblock == Dk_flagblock:
            prev += guess
            print(prev)
            break

    # if last recovered char is '}' we have reached the end of the flag
    if guess == b'}':
        break
