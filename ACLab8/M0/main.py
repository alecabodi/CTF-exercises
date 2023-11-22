from Crypto.Util import number
from Crypto.Random import random

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50800

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


def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)
    """

    e = 65537

    while True:
        while True:
            p = number.getPrime(nbits//2)
            if number.GCD(p, e) == 1:
                break

        while True:
            q = number.getPrime(nbits//2)
            if number.GCD(q, e) == 1:
                break

        N = p*q
        if number.size(N) == nbits:
            break

    phi = (p-1)*(q-1)
    d = number.inverse(e, phi)

    return (N, e), (N, d), (p, q)

def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """

    c = pow(m, pk[1], pk[0])
    return c


def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """
    m = pow(c, sk[1], sk[0])
    return m


# pk, sk, t = rsa_key_gen()
# c = rsa_enc(pk, 42)
# m = rsa_dec(sk, c)
# print(m)

pk, sk, t = rsa_key_gen()
N = pk[0]
e = pk[1]
d = sk[1]
p = t[0]
q = t[1]

request = {
    "command": "set_parameters",
    "N": N,
    "e": e,
    "d": d,
    "p": p,
    "q": q
}

json_send(request)
response = json_recv()
print(response)

request = {
    "command": "encrypted_flag",
}

json_send(request)
response = json_recv()
c = response.get("res").replace("Here is your flag... oh no, it is RSA encrypted: ", "")

c = int(c)
m = rsa_dec(sk, c)
print(m.to_bytes(2048//8, 'big'))

