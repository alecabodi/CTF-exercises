#!/usr/bin/env python3
import struct

import bitstring

def blockify(data: bytes, blocksize: int):
    assert(len(data) % blocksize == 0)
    return [int.from_bytes(data[i:i+blocksize], 'big') for i in range(0, len(data), blocksize)]

def left_shift_circular(word: int, shift_amount:int = 1) -> int:
    return ((word << shift_amount) | (word >> (32 - shift_amount))) & 0xffffffff

BLOCK_SIZE_BYTES = 64
WORD_SIZE_BYTES = 4
LONG_SIZE_BYTES = 8

class SHAzam:
    def __init__(self):
        self.hash = [
            0x49276d20,
            0x62756c6c,
            0x65747072,
            0x6f6f6620,
            0x3f213f21
        ]
        self.buffer = b''
        self.length = 0

    def _compress(self, data):
        W = blockify(data, 4)
        W += [0] * (80 - len(W))
        assert(len(W) == 80)
        for t in range(16, 80):
            W[t] = left_shift_circular(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])

        A, B, C, D, E = self.hash[0], self.hash[1], self.hash[2], self.hash[3], self.hash[4]
        for t in range(0, 80):
            temp = left_shift_circular(A, 5) + self._f(t, B, C, D) + E + W[t] + self._K(t)
            temp &= 0xffffffff
            A, B, C, D, E = temp, A, left_shift_circular(B, 30), C, D

        self.hash[0] = (self.hash[0] + A) & 0xffffffff
        self.hash[1] = (self.hash[1] + B) & 0xffffffff
        self.hash[2] = (self.hash[2] + C) & 0xffffffff
        self.hash[3] = (self.hash[3] + D) & 0xffffffff
        self.hash[4] = (self.hash[4] + E) & 0xffffffff


    def _K(self, t):
        if 0 <= t < 20:
            return 0x5a827999
        elif 20 <= t < 40:
            return 0x6ed9eba1
        elif 40 <= t < 60:
            return 0x8f1bbcdc
        elif 60 <= t < 80:
            return 0xca62c1d6
        else:
            raise ValueError(f"Invalid value for t={t} (Must be 0 <= t < 80)")


    def _f(self, t, B, C, D) -> int:
        if 0 <= t < 20:
            return (B & C) | ((~B) & D)
        elif 20 <= t < 40:
            return B ^ C ^ D
        elif 40 <= t < 60:
            return (B & C) | (B & D) | (C & D)
        elif 60 <= t < 80:
            return B ^ C ^ D
        else:
            raise ValueError(f"Invalid value for t={t} (Must be 0 <= t < 80)")


    def update(self, data: bytes) -> None:
        """Takes `data` and updates the hash state

        This function take bytes as input and appends them to `buffer`. If the length of `buffer` is now greater
        than or equal to BLOCK_SIZE_BYTES, the buffer is split into blocks of size BLOCK_SIZE_BYTES and each full block is processed
        by using the `_compress` function. The last incomplete block (if any) becomes the new value of the buffer.
        If there is no such block, the buffer becomes empty.

        The instance member `self.length` helps you to keep track of the number of bytes being processed by the `_compress` function.

        """
        self.buffer += data
        if len(self.buffer) >= BLOCK_SIZE_BYTES:
            data_blocks = [self.buffer[i:i+BLOCK_SIZE_BYTES] for i in range(0, len(data), BLOCK_SIZE_BYTES)]
            for block in data_blocks[:-1]:
                if len(block) == BLOCK_SIZE_BYTES:
                    self._compress(block)
                    self.length += BLOCK_SIZE_BYTES

            if len(data_blocks[-1]) == BLOCK_SIZE_BYTES:
                self.buffer = b''
                self.length = 0
            else:
                self.buffer = data_blocks[-1]
                self.length += len(self.buffer)

    def pad(self, m):
        bits = bitstring.BitArray(hex=m).bin
        l = int.to_bytes(len(bits), 8, 'big').hex()
        bits += '1'
        bits += '0'*(448-len(bits))
        bits += bitstring.BitArray(hex=l).bin
        print(len(bits))
        res = bitstring.BitArray(bin=bits).hex

        return res

    def digest(self):
        """Returns the digest of the data

        This function applies the final padding to the data and extracts the resulting hash.
        For the padding, use the scheme shown here: https://datatracker.ietf.org/doc/html/rfc3174#section-4.
        The length of the message mentioned in the rfc is in bits (not bytes).
        Then, use the update function with the computed padding.
        To extract the hash, take `self.hash` and convert each integer into a 4-byte word. Then, concatenate them to obtain a single
        20-byte string.
        """
        # padded_data = bytes.fromhex(self.pad(self.buffer.hex()))
        padded_data = self.buffer
        m_len = self.length + len(self.buffer)

        padded_data += b'\x80'
        padded_data += b'\x00' * ((56 - (m_len + 1) % 64) % 64)
        m_bit_len = m_len * 8
        padded_data += struct.pack(b'>Q', m_bit_len)
        self._compress(padded_data[:BLOCK_SIZE_BYTES])

        if len(padded_data) == BLOCK_SIZE_BYTES:
            return b''.join(struct.pack(b'>I', h) for h in self.hash)

        self._compress(padded_data[BLOCK_SIZE_BYTES:])
        return b''.join(struct.pack(b'>I', h) for h in self.hash)

if __name__ == "__main__":
    sha = SHAzam()

    # sha.pad('')

    # Add assert for compression function
    # sha.update(b'DC is better than Marvel anyway!')
    # assert(sha.digest().hex() == '3cd46b5888ee08dc695cd77003e1ebe4cd4d552f')

    sha.update(b"I'm sorry Stan Lee, I actually love you please don't hurt me")
    print(f'Your flag is: {sha.digest().hex()}')
