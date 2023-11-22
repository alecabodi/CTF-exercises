from Crypto.Hash import HMAC, SHA256
from itertools import product
from string import ascii_lowercase
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50504

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
    "command": "salt",
}

json_send(request)
response = json_recv()
SALT = bytes.fromhex(response.get('salt'))

hashtable = dict()


ALPHABET = ascii_lowercase
keywords = [''.join(i) for i in product(ALPHABET, repeat=5)]

table = dict()
for pw in keywords:
    print(pw)
    h = HMAC.new(key=SALT, msg=pw.encode(), digestmod=SHA256).hexdigest()
    table[h] = pw

for i in range(5):
    request = {
        "command": "password",
    }

    json_send(request)
    response = json_recv()
    pw_hash = response.get('pw_hash')
    print(pw_hash)

    request = {
        "command": "guess",
        "password": table.get(pw_hash)
    }

    json_send(request)
    response = json_recv()
    print(response)

request = {
        "command": "flag",
}

json_send(request)
response = json_recv()
print(response)