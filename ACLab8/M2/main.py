# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import numpy
import math
from decimal import *

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50802

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
c = int(response.get("ctxt"))

getcontext().prec = 256
exp = Decimal(1) / Decimal(3)
m = int(numpy.power(c, exp))
print(int.to_bytes(m+1, 100, 'big'))