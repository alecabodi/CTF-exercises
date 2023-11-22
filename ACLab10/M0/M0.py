# M0
# !/usr/bin/env python3

import telnetlib
import json
from Crypto.Hash import SHA256, HMAC, MD5
import math
from typing import Tuple

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51000

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


# Idea is to apply attack against security of DSA under randomness failure

# get parameters g, p, q
request = {
    "command": "get_params"
}

json_send(request)
response = json_recv()
print(response)
g = response.get("g")
p = response.get("p")
q = response.get("q")

# the nonce, created deterministically, depends on the MD5 hash of the message
# the result is that if 2 MD5-colliding messages are input to the signing oracle,
# for signatures sigma1 = (r1, s1) and sigma2 = (r2, s2) -> r1 == r2
m1 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'
request = {
    "command": "sign",
    "message": m1
}

json_send(request)
response = json_recv()
print(response)
r1 = response.get("r")
s1 = response.get("s")

m2 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'
request = {
    "command": "sign",
    "message": m2
}

json_send(request)
response = json_recv()
print(response)
r2 = response.get("r")
s2 = response.get("s")

# given s = k^-1 * (H(m) + x*r) mod q
# when evaluating s1 - s2, since r1 == r2, the term x*r disappears,
# thus given the equation s1 - s2 = k^-1 * (H(m1) - H(m2)) mod q
# we can solve it for k and eventually find x
H1 = int.from_bytes(SHA256.new(bytes.fromhex(m1)).digest(), "big")
H2 = int.from_bytes(SHA256.new(bytes.fromhex(m2)).digest(), "big")
k = pow(s1 - s2, -1, q) * (H1 - H2) % q
x = (k * s1 - H1) * pow(r1, -1, q) % q


# below the signing algorithm implementation is copied from the server code
def get_nonce(msg: bytes, sign_key: int, g: int, p: int, q: int) -> Tuple[int, int]:
    # Because we don't trust our server, we will be hedging against randomness failures by derandomising

    h = MD5.new(msg).digest()

    # We begin by deterministically deriving a nonce
    # as specified in https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
    l = 8 * MD5.digest_size
    rlen = math.ceil(q.bit_length() / 8)
    V = bytes([1] * l)
    K = bytes([0] * l)

    K = HMAC.new(K, V + b'\x00' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()
    K = HMAC.new(K, V + b'\x01' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()

    while True:
        T = b''
        tlen = 0

        while tlen < q.bit_length():
            V = HMAC.new(K, V).digest()
            T += V
            tlen += len(V) * 8

        # Apply bits2int and bring down k to the length of q
        k = int.from_bytes(T, "big")
        k >>= k.bit_length() - q.bit_length()

        r = pow(g, k, p) % q

        if 1 <= k <= q - 1 and r != 0:
            break

        K = HMAC.new(K, V + b'\x00').digest()
        V = HMAC.new(K, V).digest()

    return k, r


def DSA_sign(msg: bytes, sign_key: int, g: int, p: int, q: int):
    # Get k and r = (g^k mod p) mod q
    k, r = get_nonce(msg, sign_key, g, p, q)

    print(f"k is {k}")
    print(f"r is {r}")

    # Compute the signature
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    s = (pow(k, -1, q) * (h + sign_key * r)) % q
    print(f"xr is {sign_key * r}")

    return r, s


# we are now able to forge a signature for arbitrary message, so we can get the flag
message = b"Give me a flag!"
r, s = DSA_sign(message, x, g, p, q)
request = {
    "command": "flag",
    "r": r,
    "s": s
}

json_send(request)
response = json_recv()
print(response)
