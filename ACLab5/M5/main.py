# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from itertools import cycle

from Crypto.Hash import MD5

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50505

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
    "command": "token"
}

json_send(request)
response = json_recv()
print(response)
token = response.get("token_enc")
nonce = response.get("nonce")

coll1 = bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2')
print(coll1)
coll2 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'
m2 = coll2

string1 = b'Pepper and lemon spaghetti with basil and pine nuts&fav_food_rec'
delta1 = xor(string1, coll1)

string2 = b'ipe:Heat the oil '
string3 = b'&fav_food_recipe:'
delta2 = xor(string2, string3)

tmp = b'\x00'*len(b"username:admin&m1:") + delta1 + delta2 + b'\x00'*len(b"in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]")
token2 = xor(bytes.fromhex(token), tmp)

request = {
    "command": "login",
    "token_enc": token2.hex(),
    "nonce": nonce,
    "m2": m2
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



