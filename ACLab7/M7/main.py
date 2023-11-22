# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50707

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
    "command": "get_token"
}

json_send(request)
response = json_recv()
print(response)
# guest token = iv + ct + tag where tag_len = 24
guest_token = response.get("guest token")

for i in range(1, 2**8):
    request = {
        "command": "rekey",
        "key": int.to_bytes(i, 56, 'big').hex()
    }

    json_send(request)
    response = json_recv()
    print(response)

    request = {
        "command": "authenticate",
        "token": guest_token
    }

    json_send(request)
    response = json_recv()
    print(response)
    if response.get('error') == None:
        print("EUREKA")
        print(i)
        break

    request = {
        "command": "rekey",
        "key": int.to_bytes(i, 56, 'big').hex()
    }

    json_send(request)
    response = json_recv()
    print(response)

request = {
    "command": "show_state",
    "prefix": "ciao".encode().hex()
}

json_send(request)
response = json_recv()
print(response)
