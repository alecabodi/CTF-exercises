# M1
# !/usr/bin/env python3

import telnetlib
import json
import secrets

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51001

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


# given that in tag algorithm, everything but the term K^2 * c remains constant under 2 different ciphertexts of the same length
# we can exploit this to get the value of K^2

# notice that the nonce must be the same throughout the exploit
nonce = secrets.token_hex(8)

m1 = 'A' * 15
request = {
    "command": "encrypt",
    "message": m1,
    "nonce": nonce
}

json_send(request)
response = json_recv()
c1 = int(response.get("ciphertext"), 16)
tag1 = int(response.get("tag"), 16)


m2 = b'B' * 15
request = {
    "command": "encrypt",
    "message": m2.decode(),
    "nonce": nonce
}

json_send(request)
response = json_recv()
c2 = int(response.get("ciphertext"), 16)
tag2 = int(response.get("tag"), 16)

# tag1 - tag2 = K^2 * (c1 - c2)
# => K^2 = (tag1 - tag2) * mod_inverse(c1 - c2)
p = 2**127 - 1
K2 = (tag1 - tag2) * pow(c1 - c2, -1, p) % p

# while we cannot simply get K by sqrt (special algorithm is needed), we can replicate the equation above to get tag_flag, since now we know K^2
# we cannot encrypt "Give me a flag!" directly, but we can encrypt "Give me a flag " and xor the last byte given that "!" = " " XOR 1
request = {
    "command": "encrypt",
    "message": "Give me a flag ",
    "nonce": nonce
}
json_send(request)
response = json_recv()
print(response)
ctxt = bytes.fromhex(response.get("ciphertext"))

# now can get the ciphertext of the actual "Give me a flag!" plaintext by xoring the last byte of ctxt with 1
xor_byte = ctxt[-1] ^ 1
flag_ctxt = ctxt[:-1] + xor_byte.to_bytes(1, 'big')
flag_ctxt_int = int.from_bytes(flag_ctxt, 'big')

# as mentioned above, now we can find tag_flag by using tag_flag - tag1 = K2 * (c_flag - c1)
flag_tag = (K2 * (flag_ctxt_int - c1) + tag1) % p

# we can now get the flag from the decryption oracle
request = {
    "command": "decrypt",
    "ciphertext": flag_ctxt.hex(),
    "tag": hex(flag_tag)[2:],
    "nonce": nonce
}
json_send(request)
response = json_recv()
print(response)
