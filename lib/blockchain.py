#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.



import os
import util
import bitcoin
from bitcoin import *

try:
    from ltc_scrypt import getPoWHash
except ImportError:
    util.print_msg("Warning: ltc_scrypt not available, using fallback")
    from scrypt import scrypt_1024_1_1_80 as getPoWHash

MAX_TARGET = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

def deserialize_header(s, height):
    hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    h['block_height'] = height
    return h

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(serialize_header(header).decode('hex')))

def pow_hash_header(header):
    return rev_hex(getPoWHash(serialize_header(header).decode('hex')).encode('hex'))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(config.path))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent = blockchains[int(filename.split('_')[1])]
        b = Blockchain(config, checkpoint, parent)
        blockchains[b.checkpoint] = b
    return blockchains

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):

    '''Manages blockchain headers and their verification'''

    def __init__(self, config, checkpoint, parent):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.parent = parent

    def get_max_child(self):
        children = filter(lambda y: y.parent==self, blockchains.values())
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, checkpoint):
        self = Blockchain(parent.config, checkpoint, parent)
        # create file
        open(self.path(), 'w+').close()
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        p = self.path()
        return os.path.getsize(p)/80 if os.path.exists(p) else 0

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = hash_header(prev_header)
        _hash = hash_header(header)
        _powhash = pow_hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if bitcoin.TESTNET:
            return
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if int('0x' + _powhash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _powhash, 16), target))

    def verify_chain(self, chain):
        first_header = chain[0]
        prev_header = self.read_header(first_header.get('block_height') - 1)
        for header in chain:
            height = header.get('block_height')
            bits, target = self.get_target(height / 2016, chain)
            self.verify_header(header, prev_header, bits, target)
            prev_header = header

    def verify_chunk(self, index, data):
        num = len(data) / 80
        prev_header = None
        if index != 0:
            prev_header = self.read_header(index*2016 - 1)
        bits, target = self.get_target(index)
        for i in range(num):
            raw_header = data[i*80:(i+1) * 80]
            header = deserialize_header(raw_header, index*2016 + i)
            self.verify_header(header, prev_header, bits, target)
            prev_header = header

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent is None else 'fork_%d_%d'%(self.parent.checkpoint, self.checkpoint)
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * 2016 - self.checkpoint) * 80
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        with open(filename, 'rb+') as f:
            f.seek(d)
            f.write(chunk)

    def swap_with_parent(self):
        self.print_error("swap", self.checkpoint, self.parent.checkpoint)
        assert self.size() == self.get_branch_size()
        parent = self.parent
        checkpoint = self.checkpoint
        size = parent.get_branch_size()
        with open(parent.path(), 'rb+') as f:
            f.seek((checkpoint - parent.checkpoint)*80)
            parent_data = f.read(size*80)
            f.seek((checkpoint - parent.checkpoint)*80)
            f.truncate()
        with open(self.path(), 'rb+') as f:
            my_data = f.read()
            f.seek(0)
            f.truncate()
            f.write(parent_data)
        with open(parent.path(), 'rb+') as f:
            f.seek((checkpoint - parent.checkpoint)*80)
            f.write(my_data)
        # swap parameters
        self.parent = parent.parent; parent.parent = self
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def save_header(self, header):
        filename = self.path()
        delta = header.get('block_height') - self.checkpoint
        data = serialize_header(header).decode('hex')
        assert delta == self.size()
        assert len(data) == 80
        with open(filename, 'rb+') as f:
            f.seek(delta * 80)
            f.write(data)
        # order files
        if self.parent and self.parent.get_branch_size() < self.get_branch_size():
            self.swap_with_parent()

    def read_header(self, height):
        assert self.parent != self
        if height < self.checkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        if os.path.exists(name):
            f = open(name, 'rb')
            f.seek(delta * 80)
            h = f.read(80)
            f.close()
        return deserialize_header(h, height)

    def get_hash(self, height):
        return bitcoin.GENESIS if height == 0 else hash_header(self.read_header(height))

    def BIP9(self, height, flag):
        v = self.read_header(height)['version']
        return ((v & 0xE0000000) == 0x20000000) and ((v & flag) == flag)

    def segwit_support(self, N=576):
        h = self.local_height
        return sum([self.BIP9(h-i, 2) for i in range(N)])*10000/N/100.

    def get_target(self, index, chain=None):
        if bitcoin.TESTNET:
            return 0, 0
        if index == 0:
            return 0x1e0ffff0, 0x00000FFFF0000000000000000000000000000000000000000000000000000000
        # Litecoin: go back the full period unless it's the first retarget
        first = self.read_header((index-1) * 2016 - 1 if index > 1 else 0)
        last = self.read_header(index*2016 - 1)
        if last is None:
            for h in chain:
                if h.get('block_height') == index*2016 - 1:
                    last = h
        assert last is not None
        # bits to target
        bits = last.get('bits')
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1e):
            raise BaseException("First part of bits should be in [0x03, 0x1e]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        target = bitsBase << (8 * (bitsN-3))
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 84 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan / 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target*nActualTimespan) / nTargetTimespan)
        # convert new target to bits
        c = ("%064x" % new_target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) / 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits, bitsBase << (8 * (bitsN-3))

    def can_connect(self, header):
        height = header['block_height']
        if self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == bitcoin.GENESIS
        previous_header = self.read_header(height -1)
        if not previous_header:
            return False
        prev_hash = hash_header(previous_header)
        if prev_hash != header.get('prev_block_hash'):
            return False
        bits, target = self.get_target(height / 2016)
        try:
            self.verify_header(header, previous_header, bits, target)
        except:
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = hexdata.decode('hex')
            self.verify_chunk(idx, data)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk failed', str(e))
            return False
