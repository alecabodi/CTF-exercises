# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50900

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
    "command": "alice_initialisation"
}

json_send(request)
response = json_recv()
print(response)
response["alice_key"] = 1
print(response)

request = {
    "command": "bob_initialisation",
    "alice_hello": response
}

json_send(request)
response = json_recv()
print(response)
response["bob_key"] = 1
print(response)

request = {
    "command": "alice_finished",
    "bob_hello": response
}

json_send(request)
response = json_recv()
print(response)
enc_flag = bytes.fromhex(response.get("encrypted_flag"))
nonce = bytes.fromhex(response.get("nonce"))

shared = 1
shared_bytes = (1).to_bytes((1).bit_length(), 'big')
secure_key = HKDF(master=shared_bytes, key_len=32, salt=b'Secure alice and bob protocol', hashmod=SHA512, num_keys=1)
print(secure_key)
cipher = AES.new(secure_key, AES.MODE_CTR, nonce=nonce)
print(cipher.nonce.hex())
flag = cipher.decrypt(enc_flag)
print(flag)
