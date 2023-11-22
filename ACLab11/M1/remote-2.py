import json

from telnetlib import Telnet
from typing import List

import eccrypto
from eccrypto import ECDSA

REMOTE = True

ECDSAinstance = ECDSA()
ECDSAinstance.keygen()


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def signed_json_send(tn: Telnet, req: dict):
    req_str = json.dumps(req)

    public_point_compressed_bytes = ECDSAinstance.public_point.to_bytes(
        compression=True
    )
    signature = ECDSAinstance.sign(req_str.encode())
    # ver = ECDSAinstance.verify(req_str.encode(), signature[0], signature[1], ECDSAinstance.public_point.to_bytes())

    obj = {
        "command": "signed_command",
        "signed_command": req,
        "public_point": public_point_compressed_bytes.hex(),
        "r": signature[0].hex(),
        "s": signature[1].hex(),
    }
    json_send(tn, obj)


# Use the following 3 functions to send commands to the server
def get_status(tn: Telnet):
    obj = {"command": "get_status"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_challenge(tn: Telnet):
    obj = {"command": "get_challenge"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def reply_challenge(tn: Telnet, solution: List[bool]):
    obj = {"command": "backdoor", "solution": solution}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)
    res = get_challenge(tn)
    print(res)
    P = bytes.fromhex(res.get('public_point'))
    challenge = res.get('challenge')

    ver_list = []
    for c in challenge:
        msg = c.get('msg').encode()
        r = bytes.fromhex(c.get('r'))
        s = bytes.fromhex(c.get('s'))
        ver = ECDSAinstance.verify(msg, r, s, P)
        ver_list.append(ver)

    print(ver_list)

    res = reply_challenge(tn, ver_list)
    print(res)


if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51101
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
