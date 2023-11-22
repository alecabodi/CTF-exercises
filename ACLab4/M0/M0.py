# M0
#
# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

tn = telnetlib.Telnet("aclabs.ethz.ch", 50400)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


# goal is to implement attack similar to that on 2-DES

m1 = b'A' * 16

table = dict()
lkey = None
rkey = None

# create table with entries {Enc(k, m1) : k} where k is the first 2 bytes of the actual key
# since the table does not change (m1 is the same throughout the execution) table can be created just once, at the start
for k1 in range(0, 2 ** 16):
    lkey = SHA256.new(k1.to_bytes(2, 'big')).digest()
    lcipher = AES.new(lkey, AES.MODE_ECB)
    tmp = lcipher.encrypt(m1).hex()
    table.update({tmp: lkey})

for i in range(0, 64):

    request = {
        "command": "query",
        "m": m1.hex()
    }
    json_send(request)

    response = json_recv()
    c1 = response.get('res')

    found = False

    # same as above: try to find collision with previous table
    # if collision is found very likely b=0, else b=1
    for k2 in range(0, 2 ** 16):
        rkey = SHA256.new(k2.to_bytes(2, 'big')).digest()
        rcipher = AES.new(rkey, AES.MODE_ECB)
        tmp = rcipher.decrypt(bytes.fromhex(c1)).hex()
        if tmp in table.keys():
            print("FOUND!")
            found = True
            lkey = table.get(tmp)
            rkey = rkey
            break

    # NO COLLISION
    if not found:
        print("NOT FOUND!")
        request = {
            "command": "guess",
            "b": 1
        }
        json_send(request)
        response = json_recv()
        print(response)
        continue

    # COLLISION (new query to tackle corner case of (unlikely) collision even if random permutation)
    m2 = b'B' * 16

    request = {
        "command": "query",
        "m": m2.hex()
    }
    json_send(request)

    response = json_recv()
    c2 = bytes.fromhex(response.get('res'))

    lcipher = AES.new(lkey, AES.MODE_ECB)
    rcipher = AES.new(rkey, AES.MODE_ECB)
    m2_prime = lcipher.decrypt(rcipher.decrypt(c2))

    b = 1

    # if indeed m2 and m2_prime correspond, we are sure to be in case b=0
    if m2 == m2_prime:
        b = 0

    request = {
        "command": "guess",
        "b": b
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
