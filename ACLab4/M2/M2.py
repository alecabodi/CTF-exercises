# M2
#
# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from itertools import cycle

REMOTE = True

host = "aclabs.ethz.ch"
if not REMOTE:
    host = 'localhost'

tn = telnetlib.Telnet(host, 50402)


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


request = {
    "command": "flag",
}

json_send(request)
response = json_recv()
print(response)
m_prev = bytes.fromhex(response.get('m0'))
c_prev = bytes.fromhex(response.get('c0'))
challenge = bytes.fromhex(response.get('ctxt'))
blocks = [challenge[i:i + 16] for i in range(0, len(challenge), 16)]

final = b''
string = b''
i = 0

# similar to padding oracle attack from previous week

# iterate through all the blocks
for i in range(0, len(blocks)):
    prev_n = b''
    final += string
    string = b''

    print("i : " + str(i))

    # ciphertext block under examination (XOR with mi-1 is already done by decrypt function in server)
    unknown_block = blocks[i]

    # iterate through all the characters in the ciphertext block under examination
    for c in range(0, 16):
        found = False

        # try for every possible delta to see if we get a valid padding
        for n in range(1, 2 ** 8):

            # modify the previous ciphertext block which is XORed to the result of the decipher block to induce
            # controlled modifications on the next plaintext block
            controlled_block = xor(c_prev, n.to_bytes(16 - len(prev_n), 'big') + prev_n)
            request = {
                "command": "decrypt",
                "ctxt": unknown_block.hex(),
                "m0": m_prev.hex(),
                "c0": controlled_block.hex()
            }

            json_send(request)
            response = json_recv()

            # if padding is correct we get res, otherwise we get error
            if response.get('res') is not None:
                found = True
                print(n.to_bytes(1, 'big').hex())

                # XOR to obtain the value of the original plaintext
                curr = xor((c + 1).to_bytes(1, 'big'), n.to_bytes(1, 'big'))
                string = curr + string
                print(b"STRING: " + string)
                prev_n = b''

                # prepare n_prev for next round
                for char in string:
                    prev_n += xor((c + 2).to_bytes(1, 'big'), char.to_bytes(1, 'big'))

                break

        # to address last block which is already correctly padded
        if not found:
            string = (c + 1).to_bytes(1, 'big') * (c + 1)
            print(b"TEST" + string)

            prev_n = b''

            for char in string:
                prev_n += xor((c + 2).to_bytes(1, 'big'), char.to_bytes(1, 'big'))

    # update for next block
    m_prev = string
    c_prev = blocks[i]

final += string
print(final)
