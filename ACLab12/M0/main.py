# !/usr/bin/env python3
import telnetlib
import json

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Util.number import long_to_bytes

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51200

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
q = (p - 1) // 2
g = 3


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


request = {
    "command": "client_hello"
}

json_send(request)
response = json_recv()
print(response)
client_nonce = response.get("client_nonce")

request = {
    "command": "boss_hello",
    "client_nonce": client_nonce
}

json_send(request)
response = json_recv()
print(response)
boss_nonce = response.get("boss_nonce")
boss_pubkey = int(response.get("pubkey"))

request = {
    "command": "client_finished",
    "boss_nonce": boss_nonce,
    "pubkey": boss_pubkey
}

json_send(request)
response = json_recv()
print(response)

c_1 = response["encrypted_shared_key"]["c1"]
c_2 = response["encrypted_shared_key"]["c2"]
nonce = response.get("nonce")
ciphertext = response.get("ciphertext")

request = {
    "command": "compromise"
}

json_send(request)
response = json_recv()
print(response)
boss_private = response.get("secret")

K = pow(c_1, boss_private, p)
shared_secret = (c_2 * pow(K, -1, p)) % p

secure_key = HKDF(
    master=long_to_bytes(shared_secret),
    key_len=32,
    salt=bytes.fromhex(client_nonce) + bytes.fromhex(boss_nonce),
    hashmod=SHA512,
    num_keys=1,
)
cipher = AES.new(
    secure_key, AES.MODE_CTR, nonce=bytes.fromhex(nonce)
)

message = cipher.decrypt(bytes.fromhex(ciphertext))
print(message)
