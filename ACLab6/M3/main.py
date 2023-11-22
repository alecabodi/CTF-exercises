# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Hash import HMAC, SHA256
from string import ascii_letters, digits
from itertools import product

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50603

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


request = {
    "command": "corrupt"
}

json_send(request)
response = json_recv()
k_auth = bytes.fromhex(response.get('res').replace("We are very generous, here is the authentication key: ", ""))

ALPHABET = ascii_letters + digits
keywords = [''.join(i) for i in product(ALPHABET, repeat=4)]

table = dict()
for ptxt in keywords:
    print(ptxt)
    tag = HMAC.new(k_auth, ptxt.encode(), SHA256).hexdigest()
    table[tag] = ptxt

for i in range(0, 128):
    request = {
        "command": "challenge"
    }

    json_send(request)
    response = json_recv()
    c = response.get('res')

    msg = table.get(c[-64:])
    request = {
        "command": "guess",
        "guess": msg
    }

    json_send(request)
    response = json_recv()
    print(response)

request = {
        "command": "flag"
    }

json_send(request)
response = json_recv()
print(response)
