#!/usr/bin/env python3
#
# scrypt.py - basic implementation of Litecoin's proof-of-work algorithm
# Copyright (C) 2014, 2017 pooler@litecoinpool.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import hashlib
import hmac

def scrypt_1024_1_1_80(header):
    if not isinstance(header, bytes) or len(header) != 80:
        raise ValueError('header must be 80 bytes')

    mac = hmac.new(header, digestmod=hashlib.sha256)

    V = [0]*32*1024
    X = [0]*32

    B = list(header[:]) + [0]*4
    for i in range(4):
        B[83] = i + 1
        m = mac.copy()
        m.update(bytes(B))
        H = m.digest()
        for j in range(8):
            X[i*8 + j] = (H[j*4 + 0] << 0 | H[j*4 + 1] << 8 |
                          H[j*4 + 2] << 16 | H[j*4 + 3] << 24)

    for i in range(1024):
        V[i*32:i*32+32] = X
        _xor_salsa8_2(X)

    for i in range(1024):
        k = (X[16] & 1023) * 32
        for j in range(32):
            X[j] ^= V[k+j]
        _xor_salsa8_2(X)

    B = [0]*(128+3) + [1]
    for i in range(32):
        B[i*4 + 0] = X[i] >> 0 & 0xff
        B[i*4 + 1] = X[i] >> 8 & 0xff
        B[i*4 + 2] = X[i] >> 16 & 0xff
        B[i*4 + 3] = X[i] >> 24 & 0xff

    mac.update(bytes(B))
    return mac.digest()

def _xor_salsa8_2(X):
    [
        x00, x01, x02, x03, x04, x05, x06, x07,
        x08, x09, x10, x11, x12, x13, x14, x15,
        x16, x17, x18, x19, x20, x21, x22, x23,
        x24, x25, x26, x27, x28, x29, x30, x31
    ] = X
    
    x00 ^= x16
    x01 ^= x17
    x02 ^= x18
    x03 ^= x19
    x04 ^= x20
    x05 ^= x21
    x06 ^= x22
    x07 ^= x23
    x08 ^= x24
    x09 ^= x25
    x10 ^= x26
    x11 ^= x27
    x12 ^= x28
    x13 ^= x29
    x14 ^= x30
    x15 ^= x31

    t00 = x00
    t01 = x01
    t02 = x02
    t03 = x03
    t04 = x04
    t05 = x05
    t06 = x06
    t07 = x07
    t08 = x08
    t09 = x09
    t10 = x10
    t11 = x11
    t12 = x12
    t13 = x13
    t14 = x14
    t15 = x15

    for j in range(4):
        t = t00+t12 & 0xffffffff; t04 ^= (t >> 25) | (t << 7)
        t = t04+t00 & 0xffffffff; t08 ^= (t >> 23) | (t << 9)
        t = t08+t04 & 0xffffffff; t12 ^= (t >> 19) | (t << 13)
        t = t12+t08 & 0xffffffff; t00 ^= (t >> 14) | (t << 18)
        t = t05+t01 & 0xffffffff; t09 ^= (t >> 25) | (t << 7)
        t = t09+t05 & 0xffffffff; t13 ^= (t >> 23) | (t << 9)
        t = t13+t09 & 0xffffffff; t01 ^= (t >> 19) | (t << 13)
        t = t01+t13 & 0xffffffff; t05 ^= (t >> 14) | (t << 18)
        t = t10+t06 & 0xffffffff; t14 ^= (t >> 25) | (t << 7)
        t = t14+t10 & 0xffffffff; t02 ^= (t >> 23) | (t << 9)
        t = t02+t14 & 0xffffffff; t06 ^= (t >> 19) | (t << 13)
        t = t06+t02 & 0xffffffff; t10 ^= (t >> 14) | (t << 18)
        t = t15+t11 & 0xffffffff; t03 ^= (t >> 25) | (t << 7)
        t = t03+t15 & 0xffffffff; t07 ^= (t >> 23) | (t << 9)
        t = t07+t03 & 0xffffffff; t11 ^= (t >> 19) | (t << 13)
        t = t11+t07 & 0xffffffff; t15 ^= (t >> 14) | (t << 18)
        t = t00+t03 & 0xffffffff; t01 ^= (t >> 25) | (t << 7)
        t = t01+t00 & 0xffffffff; t02 ^= (t >> 23) | (t << 9)
        t = t02+t01 & 0xffffffff; t03 ^= (t >> 19) | (t << 13)
        t = t03+t02 & 0xffffffff; t00 ^= (t >> 14) | (t << 18)
        t = t05+t04 & 0xffffffff; t06 ^= (t >> 25) | (t << 7)
        t = t06+t05 & 0xffffffff; t07 ^= (t >> 23) | (t << 9)
        t = t07+t06 & 0xffffffff; t04 ^= (t >> 19) | (t << 13)
        t = t04+t07 & 0xffffffff; t05 ^= (t >> 14) | (t << 18)
        t = t10+t09 & 0xffffffff; t11 ^= (t >> 25) | (t << 7)
        t = t11+t10 & 0xffffffff; t08 ^= (t >> 23) | (t << 9)
        t = t08+t11 & 0xffffffff; t09 ^= (t >> 19) | (t << 13)
        t = t09+t08 & 0xffffffff; t10 ^= (t >> 14) | (t << 18)
        t = t15+t14 & 0xffffffff; t12 ^= (t >> 25) | (t << 7)
        t = t12+t15 & 0xffffffff; t13 ^= (t >> 23) | (t << 9)
        t = t13+t12 & 0xffffffff; t14 ^= (t >> 19) | (t << 13)
        t = t14+t13 & 0xffffffff; t15 ^= (t >> 14) | (t << 18)

    x00 = x00+t00 & 0xffffffff
    x01 = x01+t01 & 0xffffffff
    x02 = x02+t02 & 0xffffffff
    x03 = x03+t03 & 0xffffffff
    x04 = x04+t04 & 0xffffffff
    x05 = x05+t05 & 0xffffffff
    x06 = x06+t06 & 0xffffffff
    x07 = x07+t07 & 0xffffffff
    x08 = x08+t08 & 0xffffffff
    x09 = x09+t09 & 0xffffffff
    x10 = x10+t10 & 0xffffffff
    x11 = x11+t11 & 0xffffffff
    x12 = x12+t12 & 0xffffffff
    x13 = x13+t13 & 0xffffffff
    x14 = x14+t14 & 0xffffffff
    x15 = x15+t15 & 0xffffffff

    x16 ^= x00
    x17 ^= x01
    x18 ^= x02
    x19 ^= x03
    x20 ^= x04
    x21 ^= x05
    x22 ^= x06
    x23 ^= x07
    x24 ^= x08
    x25 ^= x09
    x26 ^= x10
    x27 ^= x11
    x28 ^= x12
    x29 ^= x13
    x30 ^= x14
    x31 ^= x15

    t00 = x16
    t01 = x17
    t02 = x18
    t03 = x19
    t04 = x20
    t05 = x21
    t06 = x22
    t07 = x23
    t08 = x24
    t09 = x25
    t10 = x26
    t11 = x27
    t12 = x28
    t13 = x29
    t14 = x30
    t15 = x31

    for j in range(4):
        t = t00+t12 & 0xffffffff; t04 ^= (t >> 25) | (t << 7)
        t = t04+t00 & 0xffffffff; t08 ^= (t >> 23) | (t << 9)
        t = t08+t04 & 0xffffffff; t12 ^= (t >> 19) | (t << 13)
        t = t12+t08 & 0xffffffff; t00 ^= (t >> 14) | (t << 18)
        t = t05+t01 & 0xffffffff; t09 ^= (t >> 25) | (t << 7)
        t = t09+t05 & 0xffffffff; t13 ^= (t >> 23) | (t << 9)
        t = t13+t09 & 0xffffffff; t01 ^= (t >> 19) | (t << 13)
        t = t01+t13 & 0xffffffff; t05 ^= (t >> 14) | (t << 18)
        t = t10+t06 & 0xffffffff; t14 ^= (t >> 25) | (t << 7)
        t = t14+t10 & 0xffffffff; t02 ^= (t >> 23) | (t << 9)
        t = t02+t14 & 0xffffffff; t06 ^= (t >> 19) | (t << 13)
        t = t06+t02 & 0xffffffff; t10 ^= (t >> 14) | (t << 18)
        t = t15+t11 & 0xffffffff; t03 ^= (t >> 25) | (t << 7)
        t = t03+t15 & 0xffffffff; t07 ^= (t >> 23) | (t << 9)
        t = t07+t03 & 0xffffffff; t11 ^= (t >> 19) | (t << 13)
        t = t11+t07 & 0xffffffff; t15 ^= (t >> 14) | (t << 18)
        t = t00+t03 & 0xffffffff; t01 ^= (t >> 25) | (t << 7)
        t = t01+t00 & 0xffffffff; t02 ^= (t >> 23) | (t << 9)
        t = t02+t01 & 0xffffffff; t03 ^= (t >> 19) | (t << 13)
        t = t03+t02 & 0xffffffff; t00 ^= (t >> 14) | (t << 18)
        t = t05+t04 & 0xffffffff; t06 ^= (t >> 25) | (t << 7)
        t = t06+t05 & 0xffffffff; t07 ^= (t >> 23) | (t << 9)
        t = t07+t06 & 0xffffffff; t04 ^= (t >> 19) | (t << 13)
        t = t04+t07 & 0xffffffff; t05 ^= (t >> 14) | (t << 18)
        t = t10+t09 & 0xffffffff; t11 ^= (t >> 25) | (t << 7)
        t = t11+t10 & 0xffffffff; t08 ^= (t >> 23) | (t << 9)
        t = t08+t11 & 0xffffffff; t09 ^= (t >> 19) | (t << 13)
        t = t09+t08 & 0xffffffff; t10 ^= (t >> 14) | (t << 18)
        t = t15+t14 & 0xffffffff; t12 ^= (t >> 25) | (t << 7)
        t = t12+t15 & 0xffffffff; t13 ^= (t >> 23) | (t << 9)
        t = t13+t12 & 0xffffffff; t14 ^= (t >> 19) | (t << 13)
        t = t14+t13 & 0xffffffff; t15 ^= (t >> 14) | (t << 18)

    x16 = x16+t00 & 0xffffffff
    x17 = x17+t01 & 0xffffffff
    x18 = x18+t02 & 0xffffffff
    x19 = x19+t03 & 0xffffffff
    x20 = x20+t04 & 0xffffffff
    x21 = x21+t05 & 0xffffffff
    x22 = x22+t06 & 0xffffffff
    x23 = x23+t07 & 0xffffffff
    x24 = x24+t08 & 0xffffffff
    x25 = x25+t09 & 0xffffffff
    x26 = x26+t10 & 0xffffffff
    x27 = x27+t11 & 0xffffffff
    x28 = x28+t12 & 0xffffffff
    x29 = x29+t13 & 0xffffffff
    x30 = x30+t14 & 0xffffffff
    x31 = x31+t15 & 0xffffffff

    X[:] = [
        x00, x01, x02, x03, x04, x05, x06, x07,
        x08, x09, x10, x11, x12, x13, x14, x15,
        x16, x17, x18, x19, x20, x21, x22, x23,
        x24, x25, x26, x27, x28, x29, x30, x31
    ]



if __name__ == '__main__':
    from binascii import unhexlify

    vectors = [
        ("00"*80, "161d0876f3b93b1048cda1bdeaa7332ee210f7131b42013cb43913a6553a4b69"),
        ("ff"*80, "5253069c14ecedf978745486375ee37415e977f55cdbedac31ebee8bf33dd127"),
        ("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa8e4ef0ff0f1ecd513f7c", "001e67b013726fd7382e9acb69165b4b6316227fb3156b5b414ba6340c050000"),
        ("01000000ae178934851bfa0e83ccb6a3fc4bfddff3641e104b6c4680c31509074e699be2bd672d8d2199ef37a59678f92443083e3b85edef8b45c71759371f823bab59a97126614f44d5001d45920180", "01796dae1f78a72dfb09356db6f027cd884ba0201e6365b72aa54b3b00000000"),
        ("020000008f49e5fd7ef50db9a2a1bff5d3e93717a096329a8ac802a248463ef366ceea1099b1fd0db4ce8f4728251711f759081d0b5b4da015fb78421d8ffbfda1105a2abda1db521b64101b00e60cd0", "461ae94540dc88c9bffbf42bb47e46a2416280adbeeb1d883c18090000000000"),
    ]

    from timeit import default_timer
    t0 = default_timer()

    for header, hash in vectors:
        assert scrypt_1024_1_1_80(unhexlify(header)) == unhexlify(hash)

    dt = (default_timer() - t0) / len(vectors)
    print("%.1f ms/hash" % (dt*1000))
    print("%.2f hash/s" % (1.0 / dt))
