# M6
#
# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/
from datetime import datetime, timezone
import re
import telnetlib
import json
from itertools import cycle
from string import ascii_letters, digits

REMOTE = True

host = "aclabs.ethz.ch"
if not REMOTE:
    host = 'localhost'

tn = telnetlib.Telnet(host, 50406)


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


def parse_repr(metadata):
    """Parses a string representation of a Message, returning the metadata fields"""

    majv, minv, src, rcv, ts = re.match(
        r"Montone Protocol \(v(\d+)\.(\d+)\) message from (\d+) to (\d+), sent on (.+)\.",
        metadata,
    ).groups()

    majv = int(majv).to_bytes(2, "little")
    minv = int(minv).to_bytes(1, "little")
    src = int(src).to_bytes(4, "little")
    rcv = int(rcv).to_bytes(4, "little")
    ts = int(datetime.fromisoformat(ts).timestamp()).to_bytes(4, "little")
    return src + rcv + ts + majv + minv


# same as M5 but we need to decrypt the whole flag here
# hence we need to extend previous attack to multiple blocks (but it is very straightforward)
request = {
    "command": "flag"
}
flag = b''
json_send(request)
response = json_recv()
print(response)
m0 = bytes.fromhex(response.get('m0'))
c0 = response.get('c0')
ctxt = bytes.fromhex(response.get('ctxt'))

m1 = b'MONTONE-PROTOCOL'

# the blocks before the flag are fixed
m_prev = b' be able to obta'
c = [ctxt[j:j + 16] for j in range(0, len(ctxt), 16)]
i = 0

# decrypt until } is found
while True:
    ctxt_prime = c[10 + i] + xor(xor(c[11 + i], m1), m_prev)
    m0_prime = xor(xor(m0, c[0]), c[10 + i])

    # extend previous attack to any target c_t
    # c_prime = c1_prime + c2_prime
    # where c1_prime = c_(t-1),
    # c2_prime = c_t XOR m1 XOR m_(t-1)
    # with m0_prime = m0 XOR c1 XOR c_t(-1)
    # such that by Dec(c_prime) we eventually get the target plaintext m_t

    # also here we need to add garbage to have enough parsing blocks
    garbage = b'A' * 100000
    request = {
        "command": "metadata_leak",
        "ctxt": (ctxt_prime + garbage).hex(),
        "m0": m0_prime.hex(),
        "c0": c0
    }

    json_send(request)
    response = json_recv()

    tmp = parse_repr(response.get('metadata'))
    flag += tmp

    low = 0

    # differently from M5 we cannot assume ALPHABET to be only ascii
    high = 256
    while low < high:
        mid = (low + high) // 2

        garbage = b'A' * (mid * 16)

        request = {
            "command": "metadata_leak",
            "ctxt": (ctxt_prime + garbage).hex(),
            "m0": m0_prime.hex(),
            "c0": c0
        }

        json_send(request)
        response = json_recv()

        if response.get("metadata") is not None:
            high = mid - 1

        else:
            low = mid + 1

    garbage = b'A' * (low * 16)

    request = {
        "command": "metadata_leak",
        "ctxt": (ctxt_prime + garbage).hex(),
        "m0": m0_prime.hex(),
        "c0": c0
    }
    json_send(request)
    response = json_recv()

    if response.get("metadata") is not None:
        # print(f"low {low}")
        last_byte = chr(low)
    else:
        # print(f"low+1 {low}")
        last_byte = chr(low + 1)

    flag += last_byte.encode()
    m_prev = tmp + last_byte.encode()
    i += 1
    if m_prev.__contains__(b"}"):
        break

print(flag)
