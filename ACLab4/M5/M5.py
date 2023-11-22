# M5
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

tn = telnetlib.Telnet(host, 50405)


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

# use parse function from the server (just concatenate the output)
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

# get challenge
request = {
    "command": "init"
}

json_send(request)
response = json_recv()
print(response)
m0 = bytes.fromhex(response.get('m0'))
c0 = response.get('c0')
ctxt = bytes.fromhex(response.get('ctxt'))


# to recover the additional metadata field, we can use metadata_leak command exploiting the self-synchronising feature
# of IGE mode, that allows us to cleverly craft the ciphertext to induce the partial decryption oracle to decrypt
# the additional metadata block in the challenge
request = {
    "command": "metadata_leak",
    "ctxt": ctxt.hex(),
    "m0": m0.hex(),
    "c0": c0
}

json_send(request)
response = json_recv()
print(response)

# m1 is necessary to pass check by server
m1 = b'MONTONE-PROTOCOL'

# goal now is to craft the packet in a clever way
# the idea is to skip block c2 and decrypt c3 instead by doing XOR operations beforehand, where m3 is the secret
#
# c0, m0 are IVs for IGE
# if c_prime = c1 || (c3 XOR m2 XOR m1)
# then m_prime = Dec(c_prime) = m1 || D_k(c3 XOR m2) XOR c1 (by IGE decryption)
# such that m3 = m_prime[1] XOR c1 XOR c2
#
# we can do all in one step by taking:
# c_prime = c1_prime || c2_prime
# where c1_prime = c2,
# c2_prime = c3 XOR m2 XOR m1
# with m0_prime = m0 XOR c1 XOR c2
# such that m_prime = Dec(c_prime) = D_k(c1 XOR m0) XOR c0 || D_k(c3 XOR m2) XOR c2 = m1 || m3


m2 = parse_repr(response.get('metadata'))
m2 += (2).to_bytes(1, 'big')

c = [ctxt[i:i + 16] for i in range(0, len(ctxt), 16)]

# include garbage to have enough parsing blocks
garbage = b'A' * 100000
ctxt_prime = c[1] + xor(xor(c[2], m1), m2)

m0_prime = xor(xor(m0, c[0]), c[1])

request = {
    "command": "metadata_leak",
    "ctxt": (ctxt_prime + garbage).hex(),
    "m0": m0_prime.hex(),
    "c0": c0
}

json_send(request)
response = json_recv()
metadata = parse_repr(response.get('metadata'))

# binary search for last byte (from metadata_leak we only get 15 bytes of last block)
# we need to bruteforce the add_metadata_len field (we can exploit error message when garbage is not long enough)
low = 0
high = 128
while low < high:
    mid = (low + high) // 2
    print(mid)

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
print(response)

if response.get("metadata") is not None:
    print(f"low {low}")
    last_byte = chr(low)
else:
    print(f"low+1 {low}")
    last_byte = chr(low+1)

print(last_byte)
metadata += last_byte.encode()
print(metadata)

request = {
    "command": "flag",
    "solve": metadata.decode()
}

json_send(request)
response = json_recv()
print(response)

