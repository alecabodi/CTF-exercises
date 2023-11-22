# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Hash import HMAC, SHA256
from string import ascii_letters, digits
from itertools import product

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50600

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)


def readline(conn):
    return conn.read_until(b"\n")


def json_recv(conn):
    line = readline(conn)
    return json.loads(line.decode())


def json_send(req, conn):
    request = json.dumps(req).encode()
    conn.write(request + b"\n")


request = {
    "command": "token"
}

json_send(request, tn)
response = json_recv(tn)
token = response.get("token")
print(token)

data = token.get("command_string")
mac = token.get("mac")

tn2 = telnetlib.Telnet("aclabs.ethz.ch", 50690)

json_send({
    "command": "hashpump",
    "mac": mac,
    "data": "command=hello&arg=world",
    "append": "&command=flag"
}, tn2)

response = json_recv(tn2)
print(response)
new_mac = response.get("new_hash")
new_data = response.get("new_data")


token["command_string"] = new_data
token["mac"] = new_mac
print(token)

request = {
    "command": "token_command",
    "token": token
}

json_send(request, tn)
response = json_recv(tn)
print(response)

