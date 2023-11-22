# M1
#
# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json


tn = telnetlib.Telnet("aclabs.ethz.ch", 50401)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

# exploit bug for which duplicate entries are not recognised
request = {
        "command": "register",
        "username": "username&role=admin",
        "favourite_coffee": "cappuccino"
}
json_send(request)
response = json_recv()
print(response)
token = response.get('token')

# login with admin token
request = {
        "command": "login",
        "token": token
}
json_send(request)
response = json_recv()
print(response)

# change settings of the coffee machine
request = {
        "command": "change_settings",
        "good_coffee": "true"
}
json_send(request)
response = json_recv()
print(response)

# get the flag
request = {
        "command": "get_coffee",
}
json_send(request)
response = json_recv()
print(response)



