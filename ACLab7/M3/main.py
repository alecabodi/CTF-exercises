#!/usr/bin/env python

from Crypto.Hash import SHA256

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        ...
    def _add_pt_padding(self, pt: bytes):
        p = int.to_bytes(16 - (len(pt) % 16), 1, 'big') * (16 - (len(pt) % 16))
        return pt + p

    def _remove_pt_padding(self, pt: bytes):
        pad_len = int.from_bytes(pt[-1:], 'big')
        if not 1 < pad_len < 16 and len(pt) < pad_len:
            raise ValueError("Bad decryption")
        return pt[:-pad_len]


def main():
    aead = CBC_HMAC(16, 16, b''.join(bytes([i]) for i in range(32)))
    pt = b"Just plaintext\x02\x00"
    assert aead._remove_pt_padding(aead._add_pt_padding(pt)) == pt
    print(SHA256.new(data=aead._add_pt_padding(pt)).hexdigest())

if __name__ == "__main__":
    main()
