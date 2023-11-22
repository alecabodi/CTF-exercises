#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes


class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        """Initialize the AEAD cipher.

                Keyword arguments:
                enc_key_len  -- byte length of the encryption key
                mac_key_len  -- byte length of the mac key
                key          -- key bytes
                """

        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = 24

        # a correctly sized key must always be provided by the caller
        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")

        self.mac_key = key[0:mac_key_len]
        self.enc_key = key[-enc_key_len:]

        self.block_len = 16

    def _add_pt_padding(self, pt: bytes):
        p = int.to_bytes(16 - (len(pt) % 16), 1, 'big') * (16 - (len(pt) % 16))
        return pt + p

    def _remove_pt_padding(self, pt: bytes):
        pad_len = int.from_bytes(pt[-1:], 'big')
        if not 1 < pad_len < 16 and len(pt) < pad_len:
            raise ValueError("Bad decryption")
        return pt[:-pad_len]

    def decrypt(self, ct: bytes, add_data: bytes = b''):
        """Compute ciphertext and MAC tag.

        Keyword arguments:
        ct       -- plaintext
        add_data -- additional data
        iv       -- initialization vector
        """

        al = int.to_bytes(len(add_data) * 8, 8, 'big', signed=False)
        tag = ct[-self.tag_len:]
        ct = ct[:-self.tag_len]
        print(ct.hex())

        h = HMAC.new(self.mac_key, digestmod=SHA256)
        h.update(add_data)
        h.update(ct)
        h.update(al)
        tag_prime = h.digest()[:self.tag_len]
        print(tag_prime.hex())
        print(tag.hex())

        # if tag != tag_prime:
        #     raise ValueError

        print(ct.hex())
        iv = ct[:16]
        ct = ct[16:]
        cipher = AES.new(key=self.enc_key, iv=iv, mode=AES.MODE_CBC)
        padded_pt = cipher.decrypt(ct)

        pt = self._remove_pt_padding(padded_pt)

        return pt


def main():
    test_key = bytes.fromhex("""
        41206c6f6e6720726561642061626f75742073797374656d6420697320776861
        7420796f75206e65656420616674657220746865206c6162
        """)

    test_ct = bytes.fromhex("""
        bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78
        aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1
        b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab
        7df30af4ad0db52e
        """)

    test_ad = bytes.fromhex("")

    print(CBC_HMAC(32, 24, test_key).decrypt(test_ct, test_ad))


if __name__ == "__main__":
    main()