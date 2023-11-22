# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50806

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
    "command": "generate"
}

json_send(request)
response = json_recv()
print(response)
N = response.get("N")

while True:
    request = {
        "command": "generate"
    }

    json_send(request)
    response = json_recv()
    print(response)
    N_tmp = response.get("N")

    if number.GCD(N, N_tmp) != 1:
        print("EUREKA")
        p = number.GCD(N, N_tmp)
        break

q = N // p
print(p*q == N)

e = 65537
phi = (p - 1) * (q - 1)
d = number.inverse(e, phi)
print(d)

request = {
    "command": "encrypt",
    "index": 0
}

json_send(request)
response = json_recv()
print(response)
c = bytes.fromhex(response.get("encrypted_flag"))

key = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(key)
m = cipher.decrypt(c)
print(m)
print(m.decode())
