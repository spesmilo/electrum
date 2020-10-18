##!/usr/bin/env python3
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
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

'''
Cash Accounts tests.
'''
import unittest
import random

from .. import cashacct
from ..address import Address

class TestCashAccounts(unittest.TestCase):

    def test_class_ScriptOutput(self):
        '''Test for the cashacct.ScriptOutput class'''

        valid_registration_scripts = [
            ( 1, 'bv1', Address.from_string('bitcoincash:qzgvpjawln2l8wfmsg2qwnnytcua02hy45vpdvrqu5'),
              bytes.fromhex('6a040101010103627631150190c0cbaefcd5f3b93b8214074e645e39d7aae4ad')),
            ( 1, 'im_uname', Address.from_string('qqevtgm50kulte70smem643qs07fjkj47y5jv2d2v7'),
              bytes.fromhex('6a040101010108696d5f756e616d65150132c5a3747db9f5e7cf86f3bd562083fc995a55f1')),
            ( 1, 'Mark', Address.from_string('qqy9myvyt7qffgye5a2mn2vn8ry95qm6asy40ptgx2'),
              bytes.fromhex('6a0401010101044d61726b1501085d91845f8094a099a755b9a99338c85a037aec')),
            ( 1, 'Markk', Address.from_string('pqy9myvyt7qffgye5a2mn2vn8ry95qm6asnsjwvtah'),
              '6a0401010101054d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec'),  # also tests auto-un-hexlify of str arg
            # an entry with more than 1 payment data in it
            ( 3, "Mark", Address.from_string('qqy9myvyt7qffgye5a2mn2vn8ry95qm6asy40ptgx2'),
              '6a0401010101044d61726b1501085d91845f8094a099a755b9a99338c85a037aec1501085d91845f8094a099a755b9a99338c85a037aec1501085d91845f8094a099a755b9a99338c85a037aec'),
        ]
        for num, name, address, b in valid_registration_scripts:
            so = cashacct.ScriptOutput(b)
            self.assertEqual(name, so.name)
            self.assertEqual(address, so.address)
            self.assertEqual(num, len(so.addresses))
            self.assertTrue(address in so.addresses)
            if num == 1:
                so2 = cashacct.ScriptOutput.create_registration(name, address)
            else:
                so2 = cashacct.ScriptOutput(so)
                self.assertTrue(all(isinstance(a, Address) for a in so2.addresses))
            self.assertEqual(so2, so)
            self.assertEqual(so2.name, name)
            self.assertEqual(so2.address, address)
            self.assertFalse(so.is_complete())
            so3 = cashacct.ScriptOutput(so2, number=101, collision_hash='1234567890')
            self.assertNotEqual(so2, so3)
            so4 = cashacct.ScriptOutput(so2, number=101, collision_hash='1234567890')
            self.assertEqual(so3, so4)
            self.assertTrue(so4.is_complete())
            self.assertTrue(so3.make_complete2(103, '0123456789'))
            self.assertRaises(Exception, so2.make_complete2, 1, '12334567890')
            self.assertRaises(Exception, so2.make_complete2, 'adasd', '12334567890')
            self.assertRaises(Exception, so2.make_complete2, -1, '0123asdb2')
            self.assertRaises(Exception, so2.make_complete2, 99, '0123456789')

        # test the alternate from_script factory method
        nilac = '6a04010101010c4e696c61635468654772696d15017ee7b62fa98a985c5553ff66120a91b8189f6581'
        txid = '731cdf537f6f10c142d4fc3a3d787986a783123c34727f53deaa5aa67be61911'
        bhash = '000000000000000002e5216ece231134437e29a837937a90f374807b76fdbb1b'
        bheight = 565806
        expected_name = 'NilacTheGrim'
        expected_address = Address.from_string('qplw0d304x9fshz420lkvys2jxup38m9symky6k028')
        expected_collision_hash = '1887135381'
        expected_number = 2186
        expected_emoji = chr(128273)
        so = cashacct.ScriptOutput.from_script(nilac, block_hash=bhash, txid=txid, block_height=bheight)
        self.assertEqual(so.collision_hash, expected_collision_hash)
        self.assertEqual(so.name, expected_name)
        self.assertEqual(so.number, expected_number)
        self.assertEqual(so.address, expected_address)
        self.assertEqual(so.emoji, expected_emoji)
        # test incomplete / conflicting args
        self.assertRaises(ValueError, lambda: cashacct.ScriptOutput.from_script(nilac, block_hash=bhash))  # incomplete
        self.assertRaises(ValueError, lambda: cashacct.ScriptOutput.from_script(nilac, block_hash=bhash, txid=txid, collision_hash=expected_collision_hash))  # conflicting args
        self.assertRaises(ValueError, lambda: cashacct.ScriptOutput.from_script(nilac, number=expected_number, block_height=bheight))  # conflicting args
        # test operator __eq__ and also make_complete
        so2 = cashacct.ScriptOutput.from_script(nilac)
        self.assertNotEqual(so, so2)
        self.assertFalse(so2.is_complete())
        self.assertTrue(so2.make_complete(bheight, bhash, txid))
        self.assertTrue(so2.is_complete())
        self.assertEqual(so, so2)
        self.assertEqual(so.number, so2.number)
        self.assertEqual(so.collision_hash, so2.collision_hash)
        self.assertEqual(so.emoji, so2.emoji)
        # test copy
        so_copy = so.copy()
        self.assertEqual(so_copy, so)
        # test info <-> script
        info = cashacct.Info.from_script(so_copy, txid)
        so_copy_2, txid_2 = info.to_script()
        self.assertEqual(so_copy_2, so_copy)
        self.assertEqual(txid_2, txid)


        invalid_registration_scripts = [
            b'garbage',
            'wrongtype',  ['more wrong type'],
            # bad protocol header
            bytes.fromhex('6a040102010103627631150190c0cbaefcd5f3b93b8214074e645e39d7aae4ad'),
            bytes.fromhex('6a070101010108696d5f756e616d65150132c5a3747db9f5e7cf86f3bd562083fc995a55f1'),
            # not op_return
            bytes.fromhex('6b0401010101044d61726b1501085d91845f8094a099a755b9a99338c85a037aec'),
            # bad pushdata
            bytes.fromhex('6a0301010101054d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec'),
            # out of spec char in name
            bytes.fromhex('6a0401010101057d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec'),
            # empty name
            bytes.fromhex('6a0401010101001502085d91845f8094a099a755b9a99338c85a037aec'),
            # too long a name
            bytes.fromhex('6a04010101016561616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161611502085d91845f8094a099a755b9a99338c85a037aec'),
            # bad address type
            bytes.fromhex('6a040101010103627631150990c0cbaefcd5f3b93b8214074e645e39d7aae4ad'),
            # bad length of pushdata
            bytes.fromhex('6a040101010103627631140190c0cbaefcd5f3b93b8214074e645e39d7aae4ad'),
            # extra garbage at the end
            bytes.fromhex('6a0401010101054d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec6a6a6a6a6a6a'),
            # extra garbage at the end II
            bytes.fromhex('6a0401010101054d61726b6b15020102010201020102010201020102010201020102ffffffffffff'),
            # extra garbage at the end III
            bytes.fromhex('6a0401010101054d61726b6b150201020102010201020102010201020102010201025f4f3f2f1f8f'),
        ]
        for b in invalid_registration_scripts:
            self.assertRaises(cashacct.ArgumentError, cashacct.ScriptOutput, b)
            self.assertRaises(cashacct.ArgumentError, cashacct.ScriptOutput.from_script, b)
            self.assertRaises(cashacct.ArgumentError, cashacct.ScriptOutput.parse_script, b)

    def test_collision_hash_and_emoji_and_number(self):
        ''' Tests collision_hash code and other stuff. '''
        bh = '000000000000000002abbeff5f6fb22a0b3b5c2685c6ef4ed2d2257ed54e9dcb'
        th = '590d1fdf7e04af0ee08f9194bb9e8d1971bdcbf55d29303d5bf32d4eae5e7136'
        # ensure accepts both hex encoded and bytes args
        self.assertEqual(cashacct.collision_hash(bh, th), cashacct.collision_hash(bytes.fromhex(bh), bytes.fromhex(th)))
        # ensure it works as expected
        self.assertEqual(cashacct.collision_hash(bh, th), '5876958390')
        # ensure raises on invalid args
        self.assertRaises(ValueError, cashacct.collision_hash, bh[1:10], th)
        self.assertRaises(ValueError, cashacct.collision_hash, bh, th[:-1])
        self.assertRaises(ValueError, cashacct.collision_hash, 'blab'*8, 'he'*16)
        # ensure collision_hash always length 10 for random inputs
        for i in range(10):
            bas = [bytearray(32), bytearray(32)]
            for j in range(32):
                bas[0][j] = random.randint(0, 255)
                bas[1][j] = random.randint(0, 255)
            self.assertEqual(len(cashacct.collision_hash(bas[0], bas[1])), 10)

        # emoji
        self.assertEqual(cashacct.emoji(bh, th), chr(9775))  # == '☯'
        # block height modification -> number
        self.assertEqual(cashacct.number_from_block_height(563720), 100)

    def test_minimal_collision_hash(self):
        ''' Tests the minimal collision hash calculaction algorithm '''
        my_collision_hash = '0321123151'
        other_collision_hashes = [
            '2501905124',
            '0736985563',
            '3806873923',
            '3401870692',
            '0627868303',
            '8419948552',
            '5363727682',
            '1939867611',
            '4677311172',
        ]
        all_chs = [my_collision_hash] + other_collision_hashes
        myname = 'calin'
        l = []
        for ch in all_chs:
            l.append((myname, ch))
        for i in range(10000):
            n = 'jimmy' + chr(ord('a') + random.randrange(26))
            for j in range(6):
                l.append((n, all_chs[random.randrange(len(all_chs))]))
        d = cashacct.CashAcct._calc_minimal_chashes_for_sorted_lcased_tups(sorted(l))
        self.assertEqual(sum(len(v) for k,v in d.items()), len(set(l)))
        self.assertEqual(d[myname][my_collision_hash], '03')
