# !/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

import numpy as numpy
from Crypto.Util import number

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50804

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


def inv(a, m):
    m0 = m
    x0 = 0
    x1 = 1

    if (m == 1):
        return 0

    # Apply extended Euclid Algorithm
    while (a > 1):
        # q is quotient
        q = a // m

        t = m

        # m is remainder now, process
        # same as euclid's algo
        m = a % m
        a = t

        t = x0

        x0 = x1 - q * x0

        x1 = t

        # Make x1 positive
    if (x1 < 0):
        x1 = x1 + m0

    return x1


# k is size of num[] and rem[].
# Returns the smallest
# number x such that:
# x % num[0] = rem[0],
# x % num[1] = rem[1],
# ..................
# x % num[k-2] = rem[k-1]
# Assumption: Numbers in num[]
# are pairwise coprime
# (gcd for every pair is 1)
def findMinX(num, rem, k):
    # Compute product of all numbers
    prod = 1
    for i in range(0, k):
        prod = prod * num[i]

        # Initialize result
    result = 0

    # Apply above formula
    for i in range(0, k):
        pp = prod // num[i]
        result = result + rem[i] * inv(pp, num[i]) * pp

    return result % prod

names = ["Matteo", "Giacomo", "Kenny", "Mia", "Matilda", "Lukas"]
mods_tmp = [
    '0xe330a555ace82210c484d89e8f75161d469662ab2957becc52135108797cfb6b0300f1da3bff1354ecd289c13d720afc958a1d6ff025a016eb12d6806cb2509ea6b8b9ccc51a17c6189718eea10e90bb5bc28611841f3a4e54ac6ab1b107f621a58218dfc7f6c4f7d66e668d484034d1224868f583cd9a48c96ecbaa7e5104c3e9116f35148e9d995e377238eaa62aa96ba50905faf1827991e10c41a11fcc78a943ccfef733134274f75fe83ed30285a41e9e2411987515d058e1e056237235a3603af8ab4c74d4202f84130105561be2df9d1498b2b85d35c12e2ee9fc5621ded5fffde701b8d0ad0a520c4838023d451bdf7fd70ac9c39647c771e545120f',
    '0xe44a141f75b959508c017c62fcf64ee49fbbc003cbf244264fbe35d905d9e5201ad6b5e1ecb4fb3446aa94eb8b0b7e4f8e609bb58161ece8204d3d2366e4956748ad3e145cb0c82b38c7ad5ebe9e4035d74cbd1992ea9a2f7431730742cbe9381335afbd9d2ed411839e332c3fcfd1addeaaf7dedc448944abe94fb3f5dd3a1aab4edb111dbe2ff091da06d371514ffad6219606de85fd9f7bbdaca0e645a2005a59b7df8b8dd84eb2904df0265a69a5a081738469a3e5e19ab731ec44f57ff54597148e4df6c0d6f64b433d0b36c8899914bd7b282ea5f70fb5921ba5724cded01a43c309729ea77a9498b60f5a12a111e6c126ef244290d1f2291f23f211bf',
    '0x98988bea4f5b50b5c92b55114506c251209001e1e648c4e66d072fba4b95a591b4336dc8d23f3bed89c79d2e77e567ebd739aeae6e3693550ac1d89caa07bb2cd82de228243520f6239991746a84c67d083036190fa88746c4c0c32a81f179cfe3f89fa70c849c5eb9df3f3353409b063b6f5213554d98831436f9455551d3e1e5a474f41415736bf08fb00628ee9f014fa25301404b7f7ba4c68dfdcf90f9a8bca9d656eb8e52a41a0ee26f5222ee2194619126ed2b89d3f565481cdeb952d65561134adb35c61e6a2d7694b40843dd84c797f96b83fd80833ba63388958e1a068aabbad9eaba20180fd79e2a993a0618e4646af5e357055806740e6308411d',
    '0xadffa686d4191329f4ba9fe70d616e33b3fdc3b359d19d370e419bd744e0bff4da4865cdf7d5d05c1da0f40cf7a081afe5c6efaa20eaade3d1089b1a3f3d380636b44f93b3ea664187b01b78675892bf1482af2b9f83f8097f5b320f29fa2dad9c9a3208da43a95b4fdb4af56214a43050df94adfddf505a0bbb51d4e006d9605bf40f1b7c27fb2be645d2d06d6c939d5d1ad775338f0b8e7aeba2d72411a8a9892d9e58636fb7429baa11698ac51c7ac488eff887e110a7e78bfe27eaf1d49c9da9fb1094e1d8ce4e4458fc9cd16a7cc60e1b1489cb8c107dfe61a34a24ec80a565713568425e9cd637bff9eb93dccb8eea8593008f29e74699dd9b57e6311d',
    '0xb613dae93593b94885d5db78cd161c50fbb262aa0f1e47b609e4e68f1c37d30adb57af5bd99985f9f873c237f927f3a09c00b4f5cbb350be2044e84fd4565ab692a75900d2d3682790c2667002f93f17a35fbcde6afaeee084fcd3c7e905829524f1fd5792d2cfa7f765b54f263c32f545a0ec66a7edf89c7a2cf8bbfa0652461e57d64e7e5ed16b6a7ba7d1c542e437accf83f87f21227c4c20397f26eb866d63ae1b94b0679958fbdf96ca3207611f8b270fcb51a083d75f64635a3c52e23ebc89d875572fb30b5af548b5afbdd5e8f168cd294a60f3f4da8721ebfd9a61c4915de9f715ad683b4d8c5addd4a645ac9120cbbbba1eb43bdad3d6db84087b99',
    '0xd5d331b8da622cf139bf9919a543c20f7106a2ae23eaac184a6282e210cd8d5079170a9956b14789ec9156c937ff5d6d003771418be01e3d83a713ad2c65398ba1027b34994730119fbed6a62e2a11e614723879c245382c5bddba4db5fc9e9d46b61e77046726564a8c9449a4428cf91b44349635c2c0ca244aae524a267d34553b985c66b1bfc70601905718e7eb4ee42c5b7ade715f18bcfdb345fbef7b95acd97ec7e1f70c7f237ead73fdba5f2f6762c77fb7c8cc033cbf1fac8ade8794f512e33bda451d0d1bf336fd77c4c2c78ea05dd2f54793a44e3c29eb461c769bc824576b35236e4425c20481a64b3801030a5e8b413cbfbcc8086d6862e86cc3'
]

mods = []
for mod in mods_tmp:
    mods.append(int(mod, 16))

# for N1 in mods:
#     for N2 in mods:
#         if N1 != N2:
#             gcd = number.GCD(N1, N2)
#             if gcd != 1:
#                 print("EUREKA")

ciphertexts = []
for invitee in names:
    request = {
        "command": "invite",
        "invitee": invitee
    }

    json_send(request)
    response = json_recv()
    print(response)
    ciphertexts.append(int(response.get("ciphertext"), 16))

num = mods
rem = ciphertexts
print(rem)
k = len(num)
c = findMinX(num, rem, k)

import decimal
decimal.getcontext().prec = 512
exp = decimal.Decimal(1) / decimal.Decimal(3)
m = int(numpy.power(c, exp))
print(int.to_bytes(m, 512, 'big'))