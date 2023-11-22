# M3
#
# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import time
from itertools import cycle

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50403

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


for i in range(0, 10):

    # since server is using CBC decrypt, by XOR "ciphertext" block with previous plaintext block CBC mode reverts to ECB
    # if craft the message so to have a block with guess + 0f_padding and a block with secret + 0f_padding,
    # we can check when those two blocks are the same (exploiting determinism) and send to the server the guess value
    for guess in range(0, 2 ** 8):

        # craft the message blocks to obtain something like:
        # filename=AAAAAAA
        # AAAAAAAAAA&data=
        # {guess} + 0f * 15
        # BBB&secret_byte=
        # {secret} + 0f * 15
        padded_guess = pad(guess.to_bytes(1, 'big'), 16)
        offset = b'B' * 3
        hex_string = (padded_guess + offset).hex()
        request = {
            "command": "encrypt",
            "file_name": (b'A' * 17).decode(),
            "data": hex_string
        }

        json_send(request)
        response = json_recv()
        ciphertext = bytes.fromhex(response.get('ctxt'))
        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

        # XOR "ciphertext" block with previous plaintext block
        Dk_guessblock = xor(b'AAAAAAAAAA&data=', blocks[2])
        Dk_secretblock = xor(b'BBB&secret_byte=', blocks[4])

        # exploit determinism to see if we have the right guess
        if Dk_guessblock == Dk_secretblock:
            request = {
                "command": "solve",
                "solve": format(guess, '02x')
            }

            json_send(request)
            response = json_recv()
            print(response)
            break

request = {
        "command": "flag",
}
json_send(request)
response = json_recv()
print(response)
