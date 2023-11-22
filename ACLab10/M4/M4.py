# M4
# !/usr/bin/env python3

import telnetlib
import json
import math
from typing import Tuple
from decimal import *

from Crypto.PublicKey import RSA
from Crypto.Hash import SHAKE256

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51004

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


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"{len(a)}, {len(b)}"
    return bytes(x ^ y for x, y in zip(a, b))


# the following builds upon M3
request = {
    "command": "get_params"
}

json_send(request)
response = json_recv()
print(response)
N = int(response.get("N"))
e = int(response.get("e"))

RSA_KEYLEN = 1024  # 1024-bit modulus
RAND_LEN = 256  # 256-bit of randomness for masking
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8

k = RSA_KEYLEN // 8
B = 2 ** (8 * (k - 1))


# the oracle is the same as in M3
def askOracle(c_prime):
    request = {
        "command": "decrypt",
        "ctxt": c_prime.to_bytes(c_prime.bit_length(), "big").hex()
    }

    json_send(request)
    response = json_recv()
    # print(response)
    error = response.get('error')
    if error == "Invalid parameters: ValueError Error: Decryption failed":
        # Dec(c_prime) > B
        return True
    else:
        # Dec(c_prime) <= B
        return False


# implement get_multiplier from handout (use Decimal for better precision: necessary in this implementation to get correct results)
def ceil(a: int, b: int) -> int:
    return a // b + (1 if a % b != 0 else 0)


def get_multiplier(m_max: int, m_min: int, N: int, B: int) -> Tuple[int, int]:
    tmp = (Decimal(2 * B) / Decimal(m_max - m_min)).to_integral_value(rounding=ROUND_UP)
    # print(f"tmp: {tmp}")
    r = (Decimal(tmp * m_min) / Decimal(N)).to_integral_value(rounding=ROUND_DOWN)
    # print(f"i: {r}")
    alpha = (Decimal(r * N) / Decimal(m_min)).to_integral_value(rounding=ROUND_UP)

    r = int(r)
    alpha = int(alpha)
    # print(f"alpha: {alpha}")
    return alpha, r


# get encrypted flag
# our objective is to iteratively narrow down the bounds a and b on m (where a < m < b)
# eventually a = b, hence m = a = b
request = {
    "command": "flag"
}
json_send(request)
response = json_recv()
print(response)
c = int.from_bytes(bytes.fromhex(response.get("flag")), "big")

# start by finding preliminary a and b as in M3
f1 = 2
c_prime = pow(f1, e, N) * c % N

while not askOracle(c_prime):
    f1 *= 2
    c_prime = pow(f1, e, N) * c % N

# we can improve the previous bounds by finding f2 such that f2*m is just less than N + B for max m
# that is, since B/2 < f1/2 * m < B -> find C such that C * f1/2 * m = N + B where m = B (i.e. max f1/2 * m)
# hence, C = (N+B) / B and we can take f2 = C * f1/2 as starting point
getcontext().prec = 50000
f2 = int((Decimal(N + B) / Decimal(B)).to_integral_value(rounding=ROUND_DOWN)) * (f1 // 2)
c_prime = pow(f2, e, N) * c % N

# if f2 * m > B (by oracle), it follows that N/2 < f2 * m < N (assuming 2B < N)
# we can then calculate that (f2 + f1/2) * m < N + B
# if instead f2 * m < B, a reduction has taken place, and we can deduce that N < f2 * m < N + B which is exactly our objective
# we can repeatedly increase f2 by f1/2 until we find suitable f2 and fall in case f2 * m < B (s.t we are sure a reduction has taken place)
while askOracle(c_prime):
    f2 += (f1 // 2)
    c_prime = pow(f2, e, N) * c % N

# we can now narrow down the interval
a = int((Decimal(N) / Decimal(f2)).to_integral_value(rounding=ROUND_UP))
b = int((Decimal(N + B) / Decimal(f2)).to_integral_value(rounding=ROUND_DOWN))

# we are now ready for the last step
# use get_multiplier function from handout to get coefficient f3, that will be used similarly to above
# we are now able to mimic binary search by posing a or b equal to (B + rN)/f3, according to oracle result
# eventually, we will obtain a = b, at which point we will have recovered the (padded) plaintext
while a < b:
    f3, r = get_multiplier(b, a, N, B)

    c_prime = pow(f3, e, N) * c % N
    if askOracle(c_prime):
        a = int((Decimal(B + r * N) / Decimal(f3)).to_integral_value(rounding=ROUND_UP))
    else:
        b = int((Decimal(B + r * N) / Decimal(f3)).to_integral_value(rounding=ROUND_DOWN))

    print(f"a: {a}")
    print(f"b: {b}")

# implement unpad function from server code
def RSA_unpad(m: int) -> bytes:
    m = m.to_bytes(RSA_KEYLEN // 8, 'big')

    if m[0] != 0:
        raise ValueError("Error: Decryption failed")

    rand = m[1:1 + RAND_LEN // 8]
    ptxt_masked = m[1 + RAND_LEN // 8:]

    rand_hashed = SHAKE256.new(rand).read(P_LEN)
    ptxt_padded = xor(ptxt_masked, rand_hashed)

    for i, b in enumerate(ptxt_padded):
        if b == 1 and all(ch == 0 for ch in ptxt_padded[:i]):
            return ptxt_padded[i + 1:]
    else:
        raise ValueError("Eror: Decryption failed")

# unpad m = a and obtain the flag plaintext
plaintext = RSA_unpad(a)
print(plaintext)
