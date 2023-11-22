from random import Random
from typing import Tuple

from Crypto.PublicKey import ElGamal
from Crypto import Random
import secrets


class ElGamalImpl:
    @classmethod
    def decrypt(cls, key: ElGamal.ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """

        x = int(key.x)
        p = int(key.p)

        c1 = int.from_bytes(c1, 'big')
        c2 = int.from_bytes(c2, 'big')
        K = pow(c1, x, p)
        m = c2 * pow(K, -1, p) % p

        return int.to_bytes(m, 512, 'big')

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """

        y = int(key.y)
        g = int(key.g)
        p = int(key.p)

        k = secrets.randbelow(p)
        K = pow(y, k, p)
        m = int.from_bytes(msg, 'big')

        c1 = pow(g, k, p)
        c2 = K*m % p

        return int.to_bytes(c1, 512, 'big'), int.to_bytes(c2, 512, 'big')


# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50902

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
    "command": "get_public_parameters"
}

json_send(request)
response = json_recv()
print(response)
p = int(response.get("p"))
g = int(response.get("g"))

my_key = ElGamal.generate(256, Random.new().read)
request = {
    "command": "set_response_key",
    "p": str(int(my_key.p)),
    "g": str(int(my_key.g)),
    "y": str(int(my_key.y))
}
json_send(request)
response = json_recv()
print(response)

command = 'backdoor'.encode()
command = int.from_bytes(b'backdoor', 'big') % p

# c1, c2 = ElGamalImpl.encrypt(server_key, command)
request = {
    "command": "encrypted_command",
    "encrypted_command": {"c1": (1).to_bytes(1, 'big').hex(), "c2": b'backdoor'.hex()}
}
json_send(request)
response = json_recv()
print(response)
enc_resp = response.get("encrypted_res")
c1 = bytes.fromhex(enc_resp.get("c1"))
c2 = bytes.fromhex(enc_resp.get("c2"))

m = ElGamalImpl.decrypt(my_key, c1, c2)
print(m)