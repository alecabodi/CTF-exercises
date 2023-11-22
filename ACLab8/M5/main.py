# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util import number

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50805

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
    "command": "pub_key",
}

json_send(request)
response = json_recv()
N = int(response.get("N"), 16)

e1 = number.getPrime(1024)
request = {
    "command": "encrypt",
    "e": e1
}

json_send(request)
response = json_recv()
c1 = int(response.get("ciphertext"), 16)

e2 = number.getPrime(1024)
request = {
    "command": "encrypt",
    "e": e2
}

json_send(request)
response = json_recv()
c2 = int(response.get("ciphertext"), 16)


# function for extended Euclidean Algorithm
def gcdExtended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b % a, a)

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


# Driver code
a, b = e1, e2
g, x, y = gcdExtended(a, b)

m1 = (pow(c1, x, N) * pow(c2, y, N))%N
m2 = (pow(c1, y, N) * pow(c2, x, N))%N

print(int.to_bytes(m1, 512, 'big'))
print(int.to_bytes(m2, 512, 'big'))
