from __future__ import annotations

import hashlib
import math
import secrets

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from typing import Tuple

import modsqrt

DEFAULT_CURVE_NAME = "secp256r1"


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

# Function to map a message to a bit string
def hash_message_to_bits(msg):
    h = hashlib.sha256()
    h.update(msg)
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits

# Function to map a truncated bit string to an integer modulo q
def bits_to_int(h_as_bits, q):
    val = 0
    len = int(math.log(q, 2))
    for i in range(len):
        val = val * 2
        if h_as_bits[i] == '1':
            val = val + 1
    return val % q


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return self.x == other.x and self.y == other.y
        return False


class EllipticCurve:
    CurveList = {
        "secp256k1": {
            "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            "a": 0x0000000000000000000000000000000000000000000000000000000000000000,
            "b": 0x0000000000000000000000000000000000000000000000000000000000000007,
            "G": (
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            ),
            "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "h": 0x1,
        },
        "secp256r1": {
            "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
            "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
            "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
            "G": (
                0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
            ),
            "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "h": 0x1,
        },
    }

    def __init__(self, curve_name):
        self.curve_name = curve_name
        assert curve_name in self.CurveList
        curve = self.CurveList[curve_name]
        self.G = EllipticCurvePoint(self, curve["G"][0], curve["G"][1])
        self.p = curve["p"]
        self.n = curve["n"]
        self.a = curve["a"]
        self.b = curve["b"]
        self.zero = EllipticCurvePoint(self, 0, 0)

    def point(self, x, y) -> EllipticCurvePoint:
        return EllipticCurvePoint(self, x, y)


class EllipticCurvePoint(Point):
    def __init__(self, curve: EllipticCurve, x, y):
        self.curve = curve
        super().__init__(x, y)

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return super(EllipticCurvePoint, self).__eq__(other)
        return False

    def __repr__(self):
        return f"Point({self.x}, {self.y})"

    def double(self) -> EllipticCurvePoint:
        m = (3 * pow(self.x, 2, self.curve.p) + self.curve.a) * pow(2 * self.y, -1, self.curve.p) % self.curve.p
        x_prime = (pow(m, 2, self.curve.p) - 2 * self.x) % self.curve.p
        y_prime = (m * (self.x - x_prime) - self.y) % self.curve.p
        return EllipticCurvePoint(self.curve, x_prime, y_prime)

    def add(self, Q: EllipticCurvePoint) -> EllipticCurvePoint:
        m = (Q.y - self.y) * pow(Q.x - self.x, -1, self.curve.p) % self.curve.p
        x_prime = (pow(m, 2, self.curve.p) - self.x - Q.x) % self.curve.p
        y_prime = (m * (self.x - x_prime) - self.y) % self.curve.p
        return EllipticCurvePoint(self.curve, x_prime, y_prime)

    def scalar_mult(self, n: int) -> EllipticCurvePoint:
        n_bin = "{0:b}".format(n)
        P = self
        for bit in n_bin[1:]:
            if bit == '0':
                P = P.double()
            if bit == '1':
                P = P.double().add(self)

        return P

    def to_bytes(self, compression: bool = False) -> bytes:
        if compression:
            if self.y % 2 == 0:
                b = b'\x02'
            else:
                b = b'\x03'

            return b + long_to_bytes(self.x)

        else:
            b = b'\x04'
            return b + long_to_bytes(self.x) + long_to_bytes(self.y)

    @staticmethod
    def from_bytes(curve: EllipticCurve, bs: bytes) -> EllipticCurvePoint:
        b = bs[0].to_bytes(1, 'big')
        P = bs[1:]
        if b == b'\x04':
            x = int.from_bytes(P[:len(P) // 2], 'big')
            y = int.from_bytes(P[len(P) // 2:], 'big')

        else:
            x = int.from_bytes(P, 'big')
            if b == b'\x02':
                y = modsqrt.modular_sqrt((pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p, curve.p)
            elif b == b'\x03':
                y = curve.p - modsqrt.modular_sqrt((pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p, curve.p)

        return EllipticCurvePoint(curve, x, y)


class ECDSA:
    def __init__(self, curve_name: str = DEFAULT_CURVE_NAME):
        self.ec = EllipticCurve(curve_name)
        self.d = None
        self.public_point = None

    def keygen(self):
        self.d = 1 + secrets.randbelow(self.ec.n - 1)
        self.public_point = self.ec.G.scalar_mult(self.d)
        print(self.public_point)

    # please use SHA256 as the hash function
    def sign(self, msg_bytes: bytes) -> Tuple[bytes, bytes]:
        h = int.from_bytes(SHA256.new(msg_bytes).digest(), 'big') % self.ec.n
        k = secrets.randbelow(self.ec.n)
        r = self.ec.G.scalar_mult(k).x % self.ec.n
        s = pow(k, -1, self.ec.n) * (h + self.d * r) % self.ec.n

        return r.to_bytes(r.bit_length() // 8 + 1, 'big'), s.to_bytes(s.bit_length() // 8 + 1, 'big')

    # public_point_bytes can be in both compressed and de-compressed form, need to check
    def verify(
            self,
            msg_bytes: bytes,
            r_bytes: bytes,
            s_bytes: bytes,
            public_point_bytes: bytes,
    ) -> bool:

        # r = bytes_to_long(r_bytes) % self.ec.n
        # s = bytes_to_long(s_bytes) % self.ec.n
        r = int.from_bytes(r_bytes, 'big')
        s = int.from_bytes(s_bytes, 'big')
        if not ((1 <= r <= self.ec.n) and (1 <= r <= self.ec.n)):
            r = r % self.ec.n
            s = s % self.ec.n

        w = pow(s, -1, self.ec.n)
        h = int.from_bytes(SHA256.new(msg_bytes).digest(), 'big') % self.ec.n
        u1 = (w * h) % self.ec.n
        u2 = (w * r) % self.ec.n

        public_point = EllipticCurvePoint.from_bytes(self.ec, public_point_bytes)
        print(public_point)
        Z = self.ec.G.scalar_mult(u1).add(public_point.scalar_mult(u2))
        # print(f"Z.x: {Z.x % self.ec.n}")
        # print(f"r: {r}")

        # print(Z == self.ec.G.scalar_mult(w*(h+self.d*r)))

        if (Z.x % self.ec.n) == r:
            print("VERY GOOD")
            return True
        else:
            print("bad Z")
            return False
