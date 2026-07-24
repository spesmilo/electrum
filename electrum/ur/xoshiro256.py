#
# xoshiro256.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

import sys
try:
    import uhashlib as hashlib
except:
    try:
        import hashlib
    except:
        sys.exit("ERROR: No hashlib or uhashlib implementation found (required for sha256)")

from .utils import string_to_bytes, int_to_bytes
from .constants import MAX_UINT64

# Original Info:
# Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

# To the extent possible under law, the author has dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.

# See <http://creativecommons.org/publicdomain/zero/1.0/>.

# This is xoshiro256** 1.0, one of our all-purpose, rock-solid
# generators. It has excellent (sub-ns) speed, a state (256 bits) that is
# large enough for any parallel application, and it passes all tests we
# are aware of.

# For generating just floating-point numbers, xoshiro256+ is even faster.

# The state must be seeded so that it is not everywhere zero. If you have
# a 64-bit seed, we suggest to seed a splitmix64 generator and use its
# output to fill s.

def rotl(x, k):
	return ((x << k) | (x >> (64 - k))) & MAX_UINT64

JUMP = [ 0x180ec6d33cfd0aba, 0xd5a61266f0c9392c, 0xa9582618e03fc9aa, 0x39abdc4529b1661c ]
LONG_JUMP = [ 0x76e15d3efefdcbbf, 0xc5004e441c522fb3, 0x77710069854ee241, 0x39109bb02acbe635 ]

class Xoshiro256:
    def __init__(self, arr = None):
        self.s = [0] * 4
        if arr != None:
            self.s[0] = arr[0]
            self.s[1] = arr[1]
            self.s[2] = arr[2]
            self.s[3] = arr[3]


    def _set_s(self, arr):
        for i in range(4):
            o = i * 8
            v = 0
            for n in range(8):
                v <<= 8
                v |= (arr[o + n])
            self.s[i] = v

    def _hash_then_set_s(self, buf):
        m = hashlib.sha256()
        m.update(buf)
        digest = m.digest()
        self._set_s(digest)

    @classmethod
    def from_int8_array(cls, arr):
        x = Xoshiro256()
        x._set_s(arr)
        return x

    @classmethod
    def from_bytes(cls, buf):
        x = Xoshiro256()
        x._hash_then_set_s(buf)
        return x

    @classmethod
    def from_crc32(cls, crc32):
        x = Xoshiro256()
        buf = int_to_bytes(crc32)
        x._hash_then_set_s(buf)
        return x

    @classmethod
    def from_string(cls, s):
        x = Xoshiro256()
        buf = string_to_bytes(s)
        x._hash_then_set_s(buf)
        return x

    def next(self):
        result = (rotl((self.s[1] * 5) & MAX_UINT64, 7) * 9) & MAX_UINT64
        t = (self.s[1] << 17) & MAX_UINT64

        self.s[2] ^= self.s[0]
        self.s[3] ^= self.s[1]
        self.s[1] ^= self.s[2]
        self.s[0] ^= self.s[3]

        self.s[2] ^= t

        self.s[3] = rotl(self.s[3], 45) & MAX_UINT64

        return result

    def next_double(self):
        m = float(MAX_UINT64) + 1
        nxt = self.next()
        return nxt / m

    def next_int(self, low, high):
        return int(self.next_double() * (high - low + 1) + low) & MAX_UINT64

    def next_byte(self):
        return self.next_int(0, 255)

    def next_data(self, count):
        result = bytearray()
        for i in range(count):
            result.append(self.next_byte())
        return result

    def jump(self):
        global JUMP

        s0 = 0
        s1 = 0
        s2 = 0
        s3 = 0
        for i in range(len(JUMP)):
            for b in range(64):
                if JUMP[i] & (1 << b):
                    s0 ^= self.s[0]
                    s1 ^= self.s[1]
                    s2 ^= self.s[2]
                    s3 ^= self.s[3]
                self.next()

        self.s[0] = s0
        self.s[1] = s1
        self.s[2] = s2
        self.s[3] = s3

    def long_jump(self):
        global LONG_JUMP

        s0 = 0
        s1 = 0
        s2 = 0
        s3 = 0
        for i in range(len(LONG_JUMP)):
            for b in range(64):
                if LONG_JUMP[i] & (1 << b):
                    s0 ^= self.s[0]
                    s1 ^= self.s[1]
                    s2 ^= self.s[2]
                    s3 ^= self.s[3]
                self.next()

        self.s[0] = s0
        self.s[1] = s1
        self.s[2] = s2
        self.s[3] = s3
