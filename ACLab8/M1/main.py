# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50801

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
    "command": "encrypted_flag"
}

json_send(request)
response = json_recv()
print(response)
c = int(response.get("encypted_flag"), 16)
N = int(response.get("N"), 16)
e = int(response.get("e"), 16)

s = pow(2, e, N)
c_prime = s*c % N

request = {
    "command": "decrypt",
    "ciphertext": hex(c_prime)[2:]
}

json_send(request)
response = json_recv()
print(response)
m_prime = response.get('res')

m = int.to_bytes(int(m_prime, 16)//2, 100, 'big')
print(m)

