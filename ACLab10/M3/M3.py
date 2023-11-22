# M3
# !/usr/bin/env python3

import telnetlib
import json
import math

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51003

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


# get public parameters
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

# given that m (that is, the padded message) is k bytes long, since m[0] = b'\x00'
# 0 < m < B where B = 2^(8 * (k-1))
B = 2 ** (8 * (k - 1))


# we can use check on m[0] during unpadding by the server to distinguish two error messages
# based on the error message we know whether the injected message got decrypted to something smaller or bigger than B
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
        # Dec(c_prime) < B
        # (notice this includes the unlikely case in which injected c_prime gets decrypted to a valid plaintext)
        return False


for t in range(0, 256):

    request = {
        "command": "get_challenge"
    }
    json_send(request)
    response = json_recv()
    print(response)
    c = int.from_bytes(bytes.fromhex(response["challenge"]), "big")

    # in the following, the idea is to exploit the malleability of ciphertexts to inject modified plaintexts
    # the consequence is that we are able to get more meaningful bounds on the original message

    # by malleability it is possible to inject coeff^e * c, which will get decrypted to coeff * m
    # hence we can find f1 such that f1*m ∈ [B,2B[
    f1 = 2
    c_prime = pow(f1, e, N) * c % N

    while not askOracle(c_prime):  # as long as Dec(c_prime) < B
        f1 *= 2
        c_prime = pow(f1, e, N) * c % N

    # result is that B <= f1 * m < 2B --> B/f1 <= m < 2B/f1
    a = math.ceil(B / f1)
    b = math.floor(2*B / f1)

    # according to the bound above, m >= a and m < b = 2a < 2^(i+1)
    # we can then use a.bitlength as guess
    request = {
        "command": "solve",
        "i": a.bit_length()
    }

    json_send(request)
    response = json_recv()
    print(response)

# get the flag
request = {
    "command": "flag"
}

json_send(request)
response = json_recv()
print(response)
