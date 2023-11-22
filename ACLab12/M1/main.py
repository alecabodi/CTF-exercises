import telnetlib
import json
from eccrypto import *

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import ECC

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = False

# Remember to change the port if you are re-using this client for other challenges
PORT = 51201

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


CURVE_NAME = "secp256r1"
CURVE_P_LEN = 32


def point_to_bytes(point: ECC.EccPoint):
    y = int(point.y).to_bytes(CURVE_P_LEN, "big")
    x = int(point.x).to_bytes(CURVE_P_LEN, "big")
    return x + y


request = {
    "command": "get_public_key"
}

json_send(request)
response = json_recv()
print(response)
x = response.get("x")
y = response.get("y")

ecdsa = ECDSA()
ecdsa.keygen()
point = ECC.EccPoint(x, y, curve=CURVE_NAME)
point_at_inf = point.point_at_infinity()

request = {
    "command": "client_hello",
    "id": 'not_server',
    "eph_x": 0,
    "eph_y": 0

}

json_send(request)
response = json_recv()
print(response)

key_raw = point_to_bytes(point_at_inf)
shared_key = HKDF(
                    master=key_raw,
                    salt=None,
                    key_len=32,
                    hashmod=SHA256,
                    context=b"aead encryption",
                )

nonce = secrets.token_bytes(8)
cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
enc_res, tag = cipher.encrypt_and_digest(b'{"secure_command":"server"}')
cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
enc_res, tag = cipher.encrypt_and_digest(b'{"secure_command":"server"}')

print(f"enc {enc_res.hex()}, tag {tag}")

request = {
    "command": "secure_command",
    "enc_payload": enc_res.hex(),
    "tag": tag.hex(),
    "nonce": int.from_bytes(nonce, 'big')
}
json_send(request)
response = json_recv()
print(response)
signature = response.get("signature")

request = {
    "command": "client_hello",
    "id": 'server',
    "eph_x": 0,
    "eph_y": 0,
    "signature": signature

}

json_send(request)
response = json_recv()
print(response)


#
# cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=(int.from_bytes(nonce, 'big') + 1).to_bytes(8, "big"))
# payload = json.loads(cipher.decrypt_and_verify(enc_payload, tag).decode())
#
# if payload == 'server':
