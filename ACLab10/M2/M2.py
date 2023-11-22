# M2
# !/usr/bin/env python3

import telnetlib
import json

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import isPrime
from Crypto.Hash import SHA256

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51002

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


# the idea is to implement a small subgroup attack

# select arbitrarily small prime integer t to be the order of the subgroup and find suitable p:
# p = k*(group_order) + 1 by construction (p = k*q + 1 with large prime q ideally)
# -> we just need to set p = k*t + 1 (with our small t) until we find a p which is prime
t = 7
k = 2 ** 1023 // t
p = 4
while not isPrime(p):
    p = k * t + 1
    k += 1

# find h generator of the subgroup from random element g (1 < g < p) such that:
# res = h^t % p => res == 1
g = 2
h = pow(g, ((p - 1) // t), p)

# set server parameters inducing use of small subgroup
request = {
    "command": "set_params",
    "p": p,
    "g": h
}
json_send(request)
response = json_recv()
print(response)
X = response.get("bob_pubkey")

# get encrypted flag
request = {
    "command": "encrypt"
}
json_send(request)
response = json_recv()
print(response)
pk = response.get("pk")
nonce = bytes.fromhex(response.get("nonce"))
ciphertext = bytes.fromhex(response.get("ciphertext"))

# small subgroup means we can iterate through all possible values of Y and Z and eventually derive the secret key
# we can use public value pk to see when guessed Y is right, then it is sufficient to reimplement the key derivation function
# given the key, we can simply decrypt the ciphertext containing the flag
for r in range(0, t):
    Y = pow(h, r, p)
    if Y == pk:
        Z = pow(X, r, p)
        K: bytes = HKDF(int.to_bytes(Z, 512, 'big') + int.to_bytes(Y, 512, 'big') + int.to_bytes(X, 512, 'big'), 32,
                        salt=b"", num_keys=1, context=b"dhies-enc", hashmod=SHA256)  # type: ignore
        cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print(plaintext)
