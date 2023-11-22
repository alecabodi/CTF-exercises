# # # ex 1
import string

import cryptography.hazmat.primitives.padding

flag = "flag, please!".encode()
print(flag)
padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
padded_data = padder.update(flag) + padder.finalize()
print(padded_data.hex())


# ex 2

# !/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50200

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
    "command": "flag",
    "token": "534554454320415354524f4e4f4d59",
}
json_send(request)

response = json_recv()

print(response)


# ex 3

file = open("/Users/alecabodi/Downloads/aes.data", "r")
lines = file.readlines()
print(lines)


def check_repeated(blocks):
    seen = set()
    uniq = [block for block in blocks if block not in seen and not seen.add(block)]
    if len(uniq) == len(blocks):
        # print("UNIQ SET")
        # print(uniq)
        return False

    return True


for line in lines:
    blocks = [line[i:i + 32] for i in range(0, len(line), 32)]
    if check_repeated(blocks):
        print(line)


# ex 4

# !/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50220

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


print("HEY")
flag = (b'flag, please!' + b'\x03' * 3).hex()
print(flag)
print(len(flag))

request = {
    "command": "encrypt",
    "prepend_pad": flag
}
json_send(request)

response = json_recv()

print(response)


request = {
    "command": "solve",
    "ciphertext": response.get('res')[0:32]
}
json_send(request)

response = json_recv()

print(response)


# ex 5

# !/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""
import string
import time

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50221

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

found = False
for succ in range(0, 5):
    print("SUCCESS: " + str(succ))

    for i in range(0, 16):
        print(i)
        for b in string.ascii_letters:
            b = b.encode()
            request = {
                "command": "encrypt",
                "prepend_pad": (b + b'\x0f' * 15 + b'A' * i).hex()
            }
            json_send(request)

            response = json_recv()
            print(b)

            if response.get('res')[:32] == response.get('res')[-32:]:
                print("VICTORY")
                print(response.get('res')[:32])
                print(response.get('res')[-32:])
                guess = b.decode()

                request = {
                    "command": "solve",
                    "solve": guess
                }
                json_send(request)
                response = json_recv()
                found = True
                break

        if found:
            found = False
            time.sleep(2)
            break

response = json_recv()
print(response)

# ex 6

# !/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""
import string
import time

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50222

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


found = False
prev = b''
first = True
stop = 16
ALPHABET = "abcdefghijklmnopqrstuvwxyz{}_"


x = 0
for char in range(1, 128):
    print("char: " + str(char))
    ok = True

    for i in range(0, stop):
        print(i)
        if char == 1:
            size = i
        for b in range(0, 2**8):
            b = b.to_bytes(1, 'big')
            string = b + prev + ((16 - char) % 16).to_bytes(1, 'big') * ((16 - char) % 16) + b'A' * (size % 16)
            if first:
                print(size)
                print(string)
                first = False
            request = {
                "command": "encrypt",
                "prepend_pad": string.hex()
            }
            json_send(request)

            response = json_recv()

            if char % 16 == 0 and ok:
                ok = False
                x += 1

            response_length = len(response.get('res')) - 32 * x
            offset = 32 * (x + 1)

            if response.get('res')[:32] == response.get('res')[-offset:response_length]:
                print("VICTORY")
                print(response.get('res'))
                print(response.get('res')[:32])
                print(response.get('res')[-offset:response_length])
                guess = b.decode()

                found = True
                stop = 1
                size += 1
                break

        if found:
            found = False
            b += prev
            prev = b
            print(prev)
            first = True
            time.sleep(1)
            break

print(prev)


# ex 7

from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key

def aes_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def aes_cbc_decryption(ciphertext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")
CIPHERTEXT = bytes.fromhex("79b04593c08cb44da3ed9393e3cbb094ad1ea5b7af8a40457ce87f2c3095e29980a28da9b2180061e56f61cd3ee023ebb08e8607bc44ae37682b1a4a39ca7eaf285b32f575a8bfb630ccd1548c6a7c6d78ceec8e1f45866a0f17bf5216c29ca3")

for seed in range(0, 2**16):
    key = generate_aes_key(seed, 16)
    p_i = aes_cbc_decryption(CIPHERTEXT, key, iv)

    # only one attempt is necessary since block size is equal to key size (only one valid key is possible)
    if p_i.__contains__(b'the'):
        print("HERE")
        print(p_i)
