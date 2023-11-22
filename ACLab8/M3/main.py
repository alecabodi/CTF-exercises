# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/
import math
import telnetlib
import json

import decimal
from decimal import Decimal
import numpy

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50803

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
    "command": "encrypted_flag"
}

json_send(request)
response = json_recv()
print(response)
N = int(response.get("N"))


def find_pq(n):
    i = Decimal(0)
    while True:
        decimal.getcontext().prec = 100000
        t = Decimal(n).sqrt() + i
        i = i + Decimal(1)
        print(t)
        s2 = t.__pow__(2) - Decimal(n)
        print(s2)
        s2 = s2.to_integral()
        print(s2)
        if s2 < 0:
            continue
        if math.sqrt(s2).is_integer():
            print("EUREKA")
            s = s2.sqrt()
            p = t + s
            break

    p = int(p)
    for j in range(0, 100000):
        if number.GCD(n, p - j) != 1:
            q = n // (p - j)
            return p - j, q

    for j in range(0, 100000):
        if number.GCD(n, p + j) != 1:
            q = n // (p + j)
            return p + j, q


p, q = find_pq(N)
print("P")
print(p)
print("Q")
print(q)
print(p * q)
print(N)

ctxt = bytes.fromhex(response.get("ctxt"))

e = 65537
phiN = (p - 1) * (q - 1)
d = number.inverse(e, phiN)

key = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(key)
m = cipher.decrypt(ctxt)
print(m)
