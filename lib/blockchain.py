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

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

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


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 'blockchain_headers')
    l = filter(lambda x: x.startswith('fork_'), os.listdir(config.path))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for x in l:
        b = Blockchain(config, x)
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

    def __init__(self, config, filename):
        self.config = config
        self.filename = filename
        self.catch_up = None # interface catching up
        self.is_saved = True
        self.headers = []
        if filename == 'blockchain_headers':
            self.parent = None
            self.checkpoint = 0
        elif filename.startswith('fork_'):
            self.parent = blockchains[int(filename.split('_')[1])]
            self.checkpoint = int(filename.split('_')[2])
        else:
            raise BaseException('')

    def get_max_child(self):
        children = filter(lambda y: y.parent==self, blockchains.values())
        return max([x.checkpoint for x in children]) if children else None

    def get_branch_size(self):
        mc = self.get_max_child()
        checkpoint = mc if mc is not None else self.checkpoint
        return self.height() - checkpoint

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, checkpoint):
        filename = 'fork_%d_%d'%(parent.checkpoint, checkpoint)
        self = Blockchain(parent.config, filename)
        self.is_saved = False
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        if self.is_saved:
            p = self.path()
            return os.path.getsize(p)/80 if os.path.exists(p) else 0
        else:
            return len(self.headers)

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = hash_header(prev_header)
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if bitcoin.TESTNET:
            return
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if int('0x' + _hash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

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
        return os.path.join(d, self.filename)

    def save_chunk(self, index, chunk):
        if not self.is_saved:
            self.save()
        filename = self.path()
        d = (index * 2016 - self.checkpoint) * 80
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        with open(filename, 'rb+') as f:
            f.seek(d)
            f.write(chunk)

    def save(self):
        # recursively save parents if they have not been saved
        if self.parent and not self.parent.is_saved:
            self.parent.save()
        open(self.path(), 'w+').close()
        for h in self.headers:
            self.write_header(h)
        self.headers = []
        self.is_saved = True
        self.print_error("saved", self.filename)

    def swap_with_parent(self):
        self.print_error("swap")
        parent = self.parent
        checkpoint = self.checkpoint
        # copy headers
        parent.headers = [parent.read_header(h) for h in range(checkpoint, checkpoint + parent.get_branch_size())]
        # truncate parent file
        with open(parent.path(), 'rb+') as f:
            f.seek(checkpoint*80)
            f.truncate()
        parent.is_saved = False
        # swap chains
        fn = self.filename; self.filename = parent.filename; parent.filename = fn
        self.parent = parent.parent; parent.parent = parent
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        # write my headers
        for h in self.headers:
            self.write_header(h)
        self.headers = []
        self.is_saved = True

    def save_header(self, header):
        N = 10
        height = header.get('block_height')
        if not self.is_saved:
            assert height == self.checkpoint + len(self.headers)
            self.headers.append(header)
            if len(self.headers) > N:
                if self.parent.get_branch_size() <= N:
                    self.swap_with_parent()
                else:
                    self.save()
            return
        self.write_header(header)

    def write_header(self, header):
        filename = self.path()
        delta = header.get('block_height') - self.checkpoint
        data = serialize_header(header).decode('hex')
        assert delta * 80 == os.path.getsize(filename)
        assert len(data) == 80
        with open(filename, 'rb+') as f:
            f.seek(delta * 80)
            f.write(data)

    def read_header(self, height):
        if height < self.checkpoint:
            return self.parent.read_header(height)
        delta = height - self.checkpoint
        if not self.is_saved:
            if delta >= len(self.headers):
                return None
            header = self.headers[delta]
            assert header.get('block_height') == height
            return header
        name = self.path()
        if os.path.exists(name):
            f = open(name, 'rb')
            f.seek(delta * 80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = deserialize_header(h, height)
                return h

    def get_hash(self, height):
        return bitcoin.GENESIS if height == 0 else hash_header(self.read_header(height))

    def BIP9(self, height, flag):
        v = self.read_header(height)['version']
        return ((v & 0xE0000000) == 0x20000000) and ((v & flag) == flag)

    def segwit_support(self, N=144):
        h = self.local_height
        return sum([self.BIP9(h-i, 2) for i in range(N)])*10000/N/100.

    def truncate_headers(self, height):
        self.print_error('Truncating headers file at height %d'%height)
        name = self.path()
        f = open(name, 'rb+')
        f.seek(height * 80)
        f.truncate()
        f.close()

    def get_target(self, index, chain=None):
        if bitcoin.TESTNET:
            return 0, 0
        if index == 0:
            return 0x1d00ffff, MAX_TARGET
        first = self.read_header((index-1) * 2016)
        last = self.read_header(index*2016 - 1)
        if last is None:
            for h in chain:
                if h.get('block_height') == index*2016 - 1:
                    last = h
        assert last is not None
        # bits to target
        bits = last.get('bits')
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1d):
            raise BaseException("First part of bits should be in [0x03, 0x1d]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        target = bitsBase << (8 * (bitsN-3))
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14 * 24 * 60 * 60
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
        previous_height = header['block_height'] - 1
        previous_header = self.read_header(previous_height)
        if not previous_header:
            return False
        prev_hash = hash_header(previous_header)
        if prev_hash != header.get('prev_block_hash'):
            return False
        height = header.get('block_height')
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
