# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from itertools import cycle

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50604

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

request = {
    "command": "flag"
}

json_send(request)
response = json_recv()
print(response)
enc_flag = bytes.fromhex(response.get("ctxt"))
nonce = response.get('nonce')

flag = b''
old_delta = b''
for i in range(0, len(enc_flag)):
    guess = 'a'*(i+1)
    request = {
        "command": "encrypt",
        "ptxt": guess
    }

    json_send(request)
    response = json_recv()
    print(response)
    mac_tag = response.get('mac_tag')

    for delta in range(0, 2**8):
        ctxt_tmp = xor(enc_flag[:i+1], old_delta + int.to_bytes(delta, 1, 'big'))

        request = {
            "command": "decrypt",
            "ctxt": ctxt_tmp.hex(),
            "mac_tag": mac_tag,
            'nonce': nonce
        }

        json_send(request)
        response = json_recv()

        if response.get("success"):
            print("EUREKA")
            old_delta += delta.to_bytes(1, 'big')
            flag += xor(b'a', delta.to_bytes(1, 'big'))
            print(flag)
            break
