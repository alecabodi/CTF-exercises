from __future__ import annotations
from Crypto.Util.number import long_to_bytes

import modsqrt


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
            x = int.from_bytes(P[:len(P)//2], 'big')
            y = int.from_bytes(P[len(P)//2:], 'big')

        else:
            x = int.from_bytes(P, 'big')
            if b == b'\x02':
                y = modsqrt.modular_sqrt((pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p, curve.p)
            elif b == b'\x03':
                y = curve.p - modsqrt.modular_sqrt((pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p, curve.p)

        return EllipticCurvePoint(curve, x, y)


