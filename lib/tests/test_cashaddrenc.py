#!/usr/bin/python3

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


"""Reference tests for cashaddr adresses"""

import binascii
import unittest
import random
from lib import cashaddr

VALID_PUBKEY_ADDRESSES = [
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
    "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"
]

VALID_SCRIPT_ADDRESSES = [
    "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
    "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"
]

VALID_HASHES = [
    [ 118, 160, 64,  83, 189, 160, 168, 139, 218, 81,
     119, 184, 106, 21, 195, 178, 159, 85,  152, 115 ],
    [ 203, 72, 18, 50, 41,  156, 213, 116, 49,  81,
     172, 75, 45, 99, 174, 25,  142, 123, 176, 169 ] ,
    [ 1,   31, 40,  228, 115, 201, 95, 64,  19,  215,
     213, 62, 197, 251, 195, 180, 45, 248, 237, 16 ]
]


class TestCashAddrAddress(unittest.TestCase):

    # Valid address sizes from the cashaddr spec
    valid_sizes = [160, 192, 224, 256, 320, 384, 448, 512]

    """Unit test class for cashaddr addressess."""
    def test_encode_decode(self):
        """Test whether valid addresses encode and decode properly, for all valid hash sizes."""
        for bits_size in self.valid_sizes:
            size = bits_size // 8
            # Convert to a valid number of bytes for a hash
            hashbytes = [random.randint(0,255) for i in range(size)]
            addr = cashaddr.encode(cashaddr.BCH_HRP, cashaddr.PUBKEY_TYPE,
                                   hashbytes)
            addrtype, addrhash = cashaddr.decode(cashaddr.BCH_HRP, addr)
            self.assertIsNotNone(addrtype)
            self.assertEqual(addrtype, cashaddr.PUBKEY_TYPE)
            self.assertEqual(addrhash, hashbytes)

    def test_bad_encode_size(self):
        """Test that bad sized hashes fail to encode."""
        for bits_size in self.valid_sizes:
            size = bits_size // 8
            # Make size invalid
            size += 1
            # Convert to a valid number of bytes for a hash
            hashbytes = [random.randint(0,255) for i in range(size)]
            addr = cashaddr.encode(cashaddr.BCH_HRP, cashaddr.PUBKEY_TYPE,
                                   hashbytes)
            self.assertIsNone(addr)


    def test_bad_decode_size(self):
        """Test that addresses with invalid sizes fail to decode."""
        for bits_size in self.valid_sizes:
            size = bits_size // 8
            # Convert to a valid number of bytes for a hash
            hashbytes = [random.randint(0,255) for i in range(size)]
            packed = cashaddr.pack_addr_data(cashaddr.PUBKEY_TYPE, hashbytes)
            # Add some more 5-bit data after size has been encoded
            packed.extend([random.randint(0,15) for i in range(3)])
            # Add checksum
            addr = cashaddr.cashaddr_encode(cashaddr.BCH_HRP, packed)
            # Check decode fails
            addrtype, addrhash = cashaddr.decode(cashaddr.BCH_HRP, addr)
            self.assertIsNone(addrtype)
            self.assertIsNone(addrhash)

    def test_bad_decode_checksum(self):
        """Test whether addresses with invalid checksums fail to decode."""
        for bits_size in self.valid_sizes:
            size = bits_size // 8
            # Convert to a valid number of bytes for a hash
            hashbytes = [random.randint(0,255) for i in range(size)]
            addr = cashaddr.encode(cashaddr.BCH_HRP, cashaddr.PUBKEY_TYPE,
                                   hashbytes)
            addrlist = list(addr)
            # Inject between 1 and 10 errors
            for errors in range(0, random.randint(1,10)):
                addrlist[random.randint(0, len(addr)-1)] = random.choice(cashaddr.CHARSET)

            mangled_addr = ''.join(addrlist)
            addrtype, addrhash = cashaddr.decode(cashaddr.BCH_HRP, mangled_addr)
            self.assertIsNone(addrtype)
            self.assertIsNone(addrhash)


    def test_valid_pubkeyhash(self):
        """Test whether valid P2PK addresses decode to the correct output."""
        for (address, hashbytes) in zip(VALID_SCRIPT_ADDRESSES, VALID_HASHES):
            addrtype, addrhash = cashaddr.decode(cashaddr.BCH_HRP, address)
            self.assertIsNotNone(addrtype)
            self.assertEqual(addrtype, cashaddr.SCRIPT_TYPE)
            self.assertEqual(addrhash, hashbytes)

    def test_valid_scripthash(self):
        """Test whether valid P2SH addresses decode to the correct output."""
        for (address, hashbytes) in zip(VALID_PUBKEY_ADDRESSES, VALID_HASHES):
            addrtype, addrhash = cashaddr.decode(cashaddr.BCH_HRP, address)
            self.assertIsNotNone(addrtype)
            self.assertEqual(addrtype, 0)
            self.assertEqual(addrhash, hashbytes)

if __name__ == '__main__':
    unittest.main()
