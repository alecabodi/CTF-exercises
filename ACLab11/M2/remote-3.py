import json

from telnetlib import Telnet
from typing import List

from Crypto.Hash import SHA256

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
    # ver = ECDSAinstance.verify(req_str.encode(), signature[0], signature[1], public_point_compressed_bytes)

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


def get_debug_info(tn: Telnet):
    obj = {"command": "get_debug_info"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_control(tn: Telnet, d: int):
    obj = {"command": "get_control", "d": d}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)

    res = get_debug_info(tn)
    print(res)
    msg = res.get('msg')
    r = int(res.get('r'), 16)
    s = int(res.get('s'), 16)
    timings = res.get('timings')
    print(timings)

    k_bin = ''
    sum = 0
    for t in timings:
        sum += t

    avg = sum / len(timings)

    for t in timings:
        if t > avg:
            k_bin += '1'
        else:
            k_bin += '0'

    i = 0
    print(k_bin)
    while k_bin[i] == '0':
        tmp = (k_bin[:i] + '1' + k_bin[i+1:])[::-1]
        print(tmp)
        k = int(tmp, 2)
        kP = ECDSAinstance.ec.G.scalar_mult(k)
        r_test = kP.x % ECDSAinstance.ec.n
        if r_test == r:
            break

        i+=1

    h = int.from_bytes(SHA256.new(msg.encode()).digest(), 'big') % ECDSAinstance.ec.n
    x = pow(r, -1, ECDSAinstance.ec.n) * (k * s - h) % ECDSAinstance.ec.n
    print(x)

    res = get_control(tn, x)
    print(res)


if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51102
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
