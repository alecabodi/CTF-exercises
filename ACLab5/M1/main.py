from passlib.hash import argon2
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50501

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
    "command": "password"
}

json_send(request)
response = json_recv()
password = response.get("res")

h = argon2.hash(bytes.fromhex(password))

request = {
    "command": "guess",
    "guess": h
}

json_send(request)
response = json_recv()
print(response.get("res"))
