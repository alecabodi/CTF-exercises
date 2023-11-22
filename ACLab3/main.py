# # # # ex 1
# # #
# # #!/usr/bin/env python3
# # # from https://cryptohack.org/challenges/introduction/
# #
# import telnetlib
# import json
#
# tn = telnetlib.Telnet("aclabs.ethz.ch", 50303)
#
#
# def readline():
#     return tn.read_until(b"\n")
#
#
# def json_recv():
#     line = readline()
#     return json.loads(line.decode())
#
#
# def json_send(req):
#     request = json.dumps(req).encode()
#     tn.write(request + b"\n")


#
#
# request = {
#     "command": "hex_command",
#     "hex_command": b'\xff'.hex()
# }
# json_send(request)
#
# response = json_recv()
#
# print(response)

# # ex 2
from itertools import cycle
import cryptography.hazmat.primitives.padding
# #
# # from Crypto.Cipher import AES
# # from Crypto.Random import get_random_bytes
# # from Crypto.Hash import SHA1
# #
# #
# # def xor(a, b):
# #     if len(a) < len(b):
# #         a, b = b, a
# #     return bytes([i ^ j for i, j in zip(a, cycle(b))])
# #
# #
# # class StrangeCBC():
# #     def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
# #         """Initialize the CBC cipher.
# #         """
# #
# #         if iv is None:
# #             iv = b'0'
# #
# #         self.iv = iv
# #         self.key = key
# #         self.block_length = block_length
# #
# #     def encrypt(self, plaintext: bytes):
# #         """Encrypt the input plaintext using AES-128 in strange-CBC mode:
# #
# #         C_i = E_k(P_i xor C_(i-1) xor 1336)
# #         C_0 = IV
# #
# #         Uses IV and key set from the constructor.
# #
# #         Args:
# #             plaintext (bytes): input plaintext.
# #
# #         Returns:
# #             bytes: ciphertext, starting from block 1 (do not include the IV)
# #         """
# #
# #         cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
# #         padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
# #         padded_data = padder.update(plaintext) + padder.finalize()
# #         ciphertext = cipher.encrypt(xor(padded_data, (1336).to_bytes(16, 'big')))
# #         return ciphertext
# #
# #     def decrypt(self, ciphertext: bytes):
# #         """Decrypt the input ciphertext using AES-128 in strange-CBC mode.
# #
# #         Uses IV and key set from the constructor.
# #
# #         Args:
# #             ciphertext (bytes): input ciphertext.
# #
# #         Returns:
# #             bytes: plaintext.
# #         """
# #
# #         cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
# #         print(ciphertext)
# #         plaintext = cipher.decrypt(ciphertext)
# #         print(plaintext)
# #         plaintext = xor(plaintext, (1336).to_bytes(16, 'big'))
# #         print(plaintext)
# #         unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
# #         unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
# #
# #         return unpadded_data
# #
# #
# # def main():
# #     cipher = StrangeCBC(get_random_bytes(16), get_random_bytes(16))
# #
# #     # Block-aligned pts
# #     for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
# #         assert cipher.decrypt(cipher.encrypt(pt)) == pt
# #
# #     # Non-block-aligned pts
# #     for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
# #         assert cipher.decrypt(cipher.encrypt(pt)) == pt
# #
# #     key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
# #     iv = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
# #     ct = bytes.fromhex(
# #         "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
# #         "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
# #         "3fd46234ff7b62ad365d1db13bb249721b")
# #
# #     pt = StrangeCBC(key=key, iv=iv).decrypt(ct)
# #     print(pt.decode())
# #     print("flag{" + SHA1.new(pt).digest().hex() + "}")
# #
# #
# # if __name__ == "__main__":
# #     main()
#
# # ex 3
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA1
#
# def xor(a, b):
#     if len(a) < len(b):
#         a, b = b, a
#     return bytes([i ^ j for i, j in zip(a, cycle(b))])
#
#
# class StrangeCTR():
#     def __init__(self, key: bytes, nonce : bytes = None, initial_value : int = 0, block_length: int = 16):
#         """Initialize the CTR cipher.
#         """
#
#         if nonce is None:
#             # Pick a random nonce
#             nonce = get_random_bytes(block_length//2)
#
#         self.nonce = nonce
#         print(nonce)
#         self.initial_value = initial_value
#         print(initial_value)
#         self.key = key
#         self.block_length = block_length
#         self.i = 0
#         self.j = 0
#
#     def encrypt(self, plaintext: bytes):
#         """Encrypt the input plaintext using AES-128 in strange-CTR mode:
#
#         C_i = E_k(N || c(i)) xor P_i xor 1337
#
#         Uses nonce, counter initial value and key set from the constructor.
#
#         Args:
#             plaintext (bytes): input plaintext.
#
#         Returns:
#             bytes: ciphertext
#         """
#         cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, initial_value=self.initial_value)
#         padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#         padded_data = padder.update(plaintext) + padder.finalize()
#         ciphertext = cipher.encrypt(xor(plaintext, (1337).to_bytes(16, 'big')))
#         print(b'ciphertext: ' + ciphertext)
#
#         return ciphertext
#
#     def decrypt(self, ciphertext: bytes):
#         """Decrypt the input ciphertext using AES-128 in strange-CTR mode.
#
#         Uses nonce, counter initial value and key set from the constructor.
#
#         Args:
#             ciphertext (bytes): input ciphertext.
#
#         Returns:
#             bytes: plaintext.
#         """
#
#         cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, initial_value=self.initial_value)
#         plaintext = cipher.decrypt(ciphertext)
#         plaintext = xor((1337).to_bytes(16, 'big'), plaintext)
#         print(b'plaintext: ' + plaintext)
#         unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
#         unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
#
#         return unpadded_data
#
# def main():
#     cipher = StrangeCTR(get_random_bytes(16))
#
#     # # Block-aligned pts
#     # for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
#     #     print(pt)
#     #     assert cipher.decrypt(cipher.encrypt(pt)) == pt
#     #
#     # # Non-block-aligned pts
#     # for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
#     #     assert cipher.decrypt(cipher.encrypt(pt)) == pt
#
#     request = {
#         "command": "howto"
#     }
#     json_send(request)
#
#     response = json_recv()
#     print(response)
#
# c = bytes.fromhex('01f0ceb3dad5f9cd23293937c893e0ec')
# p = b'intro'
# padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
# padded_p = padder.update(p) + padder.finalize()
# keystream = xor(c, padded_p)
#
# padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
# padded_flag = padder.update(b'flag') + padder.finalize()
# encrypted_flag = xor(padded_flag, keystream)
#
#
# request = {
#     "command": "encrypted_command",
#     "encrypted_command": encrypted_flag.hex()
# }
# json_send(request)
#
# response = json_recv()
# print(response)
#
#
# if __name__ == "__main__":
#     main()


# #  ex 4
#
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA1
#
#
# def xor(a, b):
#     if len(a) < len(b):
#         a, b = b, a
#     return bytes([i ^ j for i, j in zip(a, cycle(b))])
#
#
# class StrangeCTR():
#     def __init__(self, key: bytes, nonce: bytes = None, initial_value: int = 0, block_length: int = 16):
#         """Initialize the CTR cipher.
#         """
#
#         if nonce is None:
#             # Pick a random nonce
#             nonce = get_random_bytes(block_length // 2)
#
#         self.nonce = nonce
#         print(nonce)
#         self.initial_value = initial_value
#         print(initial_value)
#         self.key = key
#         self.block_length = block_length
#         self.i = 0
#         self.j = 0
#
#     def encrypt(self, plaintext: bytes):
#         """Encrypt the input plaintext using AES-128 in strange-CTR mode:
#
#         C_i = E_k(N || c(i)) xor P_i xor 1337
#
#         Uses nonce, counter initial value and key set from the constructor.
#
#         Args:
#             plaintext (bytes): input plaintext.
#
#         Returns:
#             bytes: ciphertext
#         """
#         cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, initial_value=self.initial_value)
#         padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#         padded_data = padder.update(plaintext) + padder.finalize()
#         ciphertext = cipher.encrypt(xor(padded_data, (1337).to_bytes(16, 'big')))
#         print(b'ciphertext: ' + ciphertext)
#
#         return ciphertext
#
#     def decrypt(self, ciphertext: bytes):
#         """Decrypt the input ciphertext using AES-128 in strange-CTR mode.
#
#         Uses nonce, counter initial value and key set from the constructor.
#
#         Args:
#             ciphertext (bytes): input ciphertext.
#
#         Returns:
#             bytes: plaintext.
#         """
#
#         cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, initial_value=self.initial_value)
#         plaintext = cipher.decrypt(ciphertext)
#         plaintext = xor((1337).to_bytes(16, 'big'), plaintext)
#         print(b'plaintext: ' + plaintext)
#         unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
#         unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
#
#         return unpadded_data
#
#
# def main():
#     cipher = StrangeCTR(get_random_bytes(16))
#
#     # # Block-aligned pts
#     # for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
#     #     print(pt)
#     #     assert cipher.decrypt(cipher.encrypt(pt)) == pt
#     #
#     # # Non-block-aligned pts
#     # for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
#     #     assert cipher.decrypt(cipher.encrypt(pt)) == pt
#
#     tmp = 0
#     for n in range(0, 2 ** 8):
#         request = {
#             "command": "encrypted_command",
#             "encrypted_command": (b'A' * 15 + n.to_bytes(1, 'big')).hex()
#         }
#         json_send(request)
#
#         response = json_recv()
#
#         if response.get('res') != 'Failed to execute command: Decryption failed':
#             print(response)
#             p = response.get('res').replace("No such command: ", "")
#             tmp = n
#             break
#
#     c = b'A' * 15 + tmp.to_bytes(1, 'big')
#     p = bytes.fromhex(p)
#
#     padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#     padded_p = padder.update(p) + padder.finalize()
#     keystream = xor(c, padded_p)
#
#     padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#     padded_flag = padder.update(b'flag') + padder.finalize()
#     encrypted_flag = xor(padded_flag, keystream)
#
#     request = {
#         "command": "encrypted_command",
#         "encrypted_command": encrypted_flag.hex()
#     }
#     json_send(request)
#
#     response = json_recv()
#     print(response)
#
#
# if __name__ == "__main__":
#     main()

# # ex 4
#
# # !/usr/bin/env python3
# # from https://cryptohack.org/challenges/introduction/
#
# import telnetlib
# import json
#
# tn = telnetlib.Telnet("aclabs.ethz.ch", 50340)
#
#
# def readline():
#     return tn.read_until(b"\n")
#
#
# def json_recv():
#     line = readline()
#     return json.loads(line.decode())
#
#
# def json_send(req):
#     request = json.dumps(req).encode()
#     tn.write(request + b"\n")
#
#
# request = {
#     "command": "decrypt",
#     "ciphertext": 'c0e70a1a2d9ad0bc0536c8b5f993fd3a9bd5020eabfb2bb093eea4b64bed4707'
# }
# json_send(request)
# response = json_recv()
# print(response)
# prev_msg = response.get('res')
#
# for i in range(0, 300):
#     flag = False
#     if len(prev_msg) > 64:
#         flag = True
#
#     request = {
#         "command": "guess",
#         "guess": flag
#     }
#     json_send(request)
#     response = json_recv()
#     print(response)
#
#     request = {
#         "command": "decrypt",
#         "ciphertext": prev_msg
#     }
#     json_send(request)
#     response = json_recv()
#     prev_msg = response.get('res')
#
#
# request = {
#         "command": "flag"
# }
# json_send(request)
# response = json_recv()
# print(response)

# ex 5
# from itertools import cycle
# import cryptography.hazmat.primitives.padding
# import time
#
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA1
#
#
# def xor(a, b):
#     if len(a) < len(b):
#         a, b = b, a
#     return bytes([i ^ j for i, j in zip(a, cycle(b))])
#
#
# class StrangeCBC():
#     def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
#         """Initialize the CBC cipher.
#         """
#
#         if iv is None:
#             iv = b'0'
#
#         self.iv = iv
#         self.key = key
#         self.block_length = block_length
#
#     def encrypt(self, plaintext: bytes):
#         """Encrypt the input plaintext using AES-128 in strange-CBC mode:
#
#         C_i = E_k(P_i xor C_(i-1) xor 1336)
#         C_0 = IV
#
#         Uses IV and key set from the constructor.
#
#         Args:
#             plaintext (bytes): input plaintext.
#
#         Returns:
#             bytes: ciphertext, starting from block 1 (do not include the IV)
#         """
#
#         cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
#         padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#         padded_data = padder.update(plaintext) + padder.finalize()
#         ciphertext = cipher.encrypt(xor(padded_data, (1336).to_bytes(16, 'big')))
#         return ciphertext
#
#     def decrypt(self, ciphertext: bytes):
#         """Decrypt the input ciphertext using AES-128 in strange-CBC mode.
#
#         Uses IV and key set from the constructor.
#
#         Args:
#             ciphertext (bytes): input ciphertext.
#
#         Returns:
#             bytes: plaintext.
#         """
#
#         cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
#         # print(ciphertext)
#         plaintext = cipher.decrypt(ciphertext)
#         # print(plaintext)
#         plaintext = xor(plaintext, (1336).to_bytes(16, 'big'))
#         # print(plaintext)
#         unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
#         unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
#
#         return unpadded_data
#
#
# def main():
#     cipher = StrangeCBC(get_random_bytes(16), get_random_bytes(16))
#     flag_command = b"flag"
#     ciphertext = bytes.fromhex("e66e363fa235172573ee42c018efac35f2cb7f12981734597b929db2e12c2057")
#     iv = ciphertext[:16]
#     c = ciphertext[16:]
#
#     # tmp = iv + b'intro' + 1336
#     # ciphertext = E_k(tmp) = iv || c
#     # iv_prime = tmp + b'flag' + 1336
#     # ciphertext_prime = iv_prime || c
#
#     padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#     padded_data = padder.update(b'intro') + padder.finalize()
#     tmp = xor(iv, xor(padded_data, (1336).to_bytes(16, 'big')))
#
#     padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
#     padded_data = padder.update(b'flag') + padder.finalize()
#     iv_prime = xor(tmp, xor(padded_data, (1336).to_bytes(16, 'big')))
#
#     ciphertext = iv_prime + c
#
#     print(ciphertext.hex())
#     request = {
#         "command": "encrypted_command",
#         "encrypted_command": ciphertext.hex()
#     }
#
#     json_send(request)
#     response = json_recv()
#     print(response)
#
#     # pt = StrangeCBC(key=key, iv=iv).decrypt(ct)
#     # print(pt.decode())
#     # print("flag{" + SHA1.new(pt).digest().hex() + "}")

#
# if __name__ == "__main__":
#     main()

# # ex 5
#
# # !/usr/bin/env python3
# # from https://cryptohack.org/challenges/introduction/
#
# import telnetlib
# import json
#
# # Change this to REMOTE = False if you are running against a local instance of the server
# REMOTE = True
#
# # Remember to change the port if you are re-using this client for other challenges
# PORT = 50341
#
# if REMOTE:
#     host = "aclabs.ethz.ch"
# else:
#     host = "localhost"
#
# tn = telnetlib.Telnet(host, PORT)
#
#
# def readline():
#     return tn.read_until(b"\n")
#
#
# def json_recv():
#     line = readline()
#     return json.loads(line.decode())
#
#
# def json_send(req):
#     request = json.dumps(req).encode()
#     tn.write(request + b"\n")
#
#
# def xor(a, b):
#     if len(a) < len(b):
#         a, b = b, a
#     return bytes([i ^ j for i, j in zip(a, cycle(b))])
#
#
# for i in range(0, 100):
#     request = {
#         "command": "challenge",
#     }
#     json_send(request)
#     response = json_recv()
#     challenge = response.get('res')
#
#     c1 = bytes.fromhex(challenge[:32])
#     c2 = bytes.fromhex(challenge[32:])
#
#     for n in range(0, 2 ** 8):
#         ciphertext = (xor(c1, n.to_bytes(16, 'big')) + c2)
#         request = {
#             "command": "decrypt",
#             "ciphertext": ciphertext.hex()
#         }
#
#         json_send(request)
#         response = json_recv()
#         prev_msg = response.get('res')
#
#         if len(prev_msg) == 64:
#             guess = xor(b'\x01', n.to_bytes(1, 'big'))
#             break
#
#     request = {
#         "command": "guess",
#         "guess": guess.decode()
#     }
#
#     json_send(request)
#     response = json_recv()
#     print(response)
#
# request = {
#     "command": "flag"
# }
# json_send(request)
# response = json_recv()
# print(response)

# ex 6

# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

# import telnetlib
# import json
#
# # Change this to REMOTE = False if you are running against a local instance of the server
# REMOTE = True
#
# # Remember to change the port if you are re-using this client for other challenges
# PORT = 50342
#
# if REMOTE:
#     host = "aclabs.ethz.ch"
# else:
#     host = "localhost"
#
# tn = telnetlib.Telnet(host, PORT)
#
#
# def readline():
#     return tn.read_until(b"\n")
#
#
# def json_recv():
#     line = readline()
#     return json.loads(line.decode())
#
#
# def json_send(req):
#     request = json.dumps(req).encode()
#     tn.write(request + b"\n")
#
#
# def xor(a, b):
#     if len(a) < len(b):
#         a, b = b, a
#     return bytes([i ^ j for i, j in zip(a, cycle(b))])
#
#
# for i in range(0, 10):
#     request = {
#         "command": "challenge",
#     }
#     json_send(request)
#     response = json_recv()
#     challenge = response.get('res')
#
#     c1 = bytes.fromhex(challenge[:32])
#     c2 = bytes.fromhex(challenge[32:])
#
#     prev_n = b''
#     string = b''
#
#     for c in range(1, 17):
#
#         for n in range(0, 2 ** 8):
#             ciphertext = xor(c1, n.to_bytes(16 - len(prev_n), 'big') + prev_n) + c2
#             request = {
#                 "command": "decrypt",
#                 "ciphertext": ciphertext.hex()
#             }
#
#             json_send(request)
#             response = json_recv()
#             prev_msg = response.get('res')
#
#             if len(prev_msg) == 64:
#                 curr = xor(c.to_bytes(1, 'big'), n.to_bytes(1, 'big'))
#                 string = curr + string
#                 print(string)
#                 prev_n = b''
#
#                 for char in string:
#                     prev_n += xor((c + 1).to_bytes(1, 'big'), char.to_bytes(1, 'big'))
#
#                 break
#
#     request = {
#         "command": "guess",
#         "guess": string.decode()
#     }
#
#     json_send(request)
#     response = json_recv()
#     print(response)
#
# request = {
#     "command": "flag"
# }
# json_send(request)
# response = json_recv()
# print(response)


# ex 7

# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50343

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


def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])


c = b'A' * 31 + b'B'
request = {
    "command": "encrypted_command",
    "encrypted_command": c.hex()
}

json_send(request)
response = json_recv()
prev_msg = response.get('res')
challenge = prev_msg

blocks = [challenge[i:i + 32] for i in range(0, len(challenge), 32)]
print(blocks)

c = blocks[0] + blocks[1]
request = {
    "command": "encrypted_command",
    "encrypted_command": c
}

json_send(request)
response = json_recv()
prev_msg = response.get('res')
c = prev_msg

for n in range(0, 2 ** 8):
    ciphertext = xor(bytes.fromhex(c), n.to_bytes(16, 'big'))
    request = {
        "command": "encrypted_command",
        "encrypted_command": ciphertext.hex()
    }

    json_send(request)
    response = json_recv()
    prev_msg = response.get('res')
    print(prev_msg)

    if len(prev_msg) != 128:
        challenge = prev_msg
        break

print(challenge)
blocks = [challenge[i:i + 32] for i in range(0, len(challenge), 32)]
print(blocks)

final = b''
string = b''
for i in range(0, len(blocks) - 1):
    prev_n = b''
    final += string
    string = b''

    print("i : " + str(i))
    for c in range(0, 16):
        found = False

        for n in range(1, 2 ** 8):
            ciphertext = xor(bytes.fromhex(blocks[i]),
                             n.to_bytes(16 - len(prev_n), 'big') + prev_n) + bytes.fromhex(blocks[i + 1])
            request = {
                "command": "encrypted_command",
                "encrypted_command": ciphertext.hex()
            }

            json_send(request)
            response = json_recv()
            prev_msg = response.get('res')

            if len(prev_msg) != 128:
                found = True
                print(c)
                curr = xor((c + 1).to_bytes(1, 'big'), n.to_bytes(1, 'big'))
                string = curr + string
                print(b"STRING: " + string)
                prev_n = b''

                for char in string:
                    prev_n += xor((c + 2).to_bytes(1, 'big'), char.to_bytes(1, 'big'))

                break

        if not found:
            string = (c + 1).to_bytes(1, 'big') * (c + 1)
            print(b"TEST" + string)

            prev_n = b''

            for char in string:
                prev_n += xor((c + 2).to_bytes(1, 'big'), char.to_bytes(1, 'big'))

final += string
print(final)
