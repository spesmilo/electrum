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
import threading

from . import util
from . import bitcoin
from .bitcoin import *

MAX_TARGET = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
SEVEN_DAYS = 7 * 24 * 60 * 60
HEIGHT_FORK_ONE = 33000
HEIGHT_FORK_TWO = 87948


def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

def deserialize_header(s, height):
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    h['block_height'] = height
    return h

def pow_hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(PoWHash(bfh(serialize_header(header))))

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
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
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.parent_id = parent_id
        self.lock = threading.Lock()
        with self.lock:
            self.update_size()

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
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

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//80 if os.path.exists(p) else 0

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = hash_header(prev_header)
        _hash = pow_hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if bitcoin.NetworkConstants.TESTNET:
            return
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if int('0x' + _hash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

    def verify_chunk(self, index, data):
        num = len(data) // 80
        headers = [self.read_header(index * 2016 - 1)] if index != 0 else [None]
        for i in range(num):
            raw_header = data[i*80:(i+1) * 80]
            headers.append(deserialize_header(raw_header, index*2016 + i))
        for i in range(num):
            bits, target = self.get_target(index*2016 + i, headers)
            self.verify_header(headers[i+1], headers[i], bits, target)

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * 2016 - self.checkpoint) * 80
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        self.write(chunk, d)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        with open(parent.path(), 'rb') as f:
            f.seek((checkpoint - parent.checkpoint)*80)
            parent_data = f.read(parent_branch_size*80)
        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*80)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def write(self, data, offset):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if offset != self._size*80:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.checkpoint
        data = bfh(serialize_header(header))
        assert delta == self.size()
        assert len(data) == 80
        self.write(data, delta*80)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        if os.path.exists(name):
            with open(name, 'rb') as f:
                f.seek(delta * 80)
                h = f.read(80)
        return deserialize_header(h, height)

    def get_hash(self, height):
        return hash_header(self.read_header(height))

    def BIP9(self, height, flag):
        v = self.read_header(height)['version']
        return ((v & 0xE0000000) == 0x20000000) and ((v & flag) == flag)

    def segwit_support(self, N=144):
        h = self.local_height
        return sum([self.BIP9(h-i, 2) for i in range(N)])*10000/N/100.

    def get_target(self, height, headers):
        if bitcoin.NetworkConstants.TESTNET:
            return 0, 0
        if height == 0:
            return 0x1e0ffff0, MAX_TARGET
        elif height >= HEIGHT_FORK_TWO:
            return self.__fork_two_target(height, headers)
        elif height >= HEIGHT_FORK_ONE:
            return self.__fork_one_target(height, headers)
        else:
            return self.__vanilla_target(height, headers)

    @staticmethod
    def __damp(nActualTimespan, nTargetTimespan):
        return (nActualTimespan + 3 * nTargetTimespan) // 4

    def __fork_two_target(self, height, headers):
        interval = 126
        last_height = height - 1
        last = self.get_header(last_height, height, headers)
        bits = last.get('bits')
        target = Blockchain.bits2target(bits)
        if height % interval != 0 and height != HEIGHT_FORK_TWO:
            return bits, target
        first = self.get_header(last_height - interval, height, headers)
        nActualTimespanShort = last.get('timestamp') - first.get('timestamp')
        first = self.get_header(last_height - interval * 4, height, headers)
        nActualTimespanLong = (last.get('timestamp') - first.get('timestamp')) // 4
        nActualTimespan = (nActualTimespanShort + nActualTimespanLong) // 2
        nTargetTimespan = SEVEN_DAYS // 32
        nActualTimespan = Blockchain.__damp(nActualTimespan, nTargetTimespan)
        return Blockchain.__get_target(target, nActualTimespan, nTargetTimespan, 453, 494)

    def __fork_one_target(self, height, headers):
        interval = 504
        last_height = height - 1
        last = self.get_header(last_height, height, headers)
        bits = last.get('bits')
        target = Blockchain.bits2target(bits)
        if height % interval != 0 and height != HEIGHT_FORK_ONE:
            return bits, target
        first = self.get_header(last_height - interval, height, headers)
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        return Blockchain.__get_target(target, nActualTimespan, SEVEN_DAYS // 8, 70, 99)

    def __vanilla_target(self, height, headers):
        interval = 2016
        last_height = height - 1
        last = self.get_header(last_height, height, headers)
        bits = last.get('bits')
        target = Blockchain.bits2target(bits)
        if height % interval != 0:
            return bits, target
        first = self.get_header(max(0, last_height - interval), height, headers)
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        return Blockchain.__get_target(target, nActualTimespan, SEVEN_DAYS // 2, 1, 4)

    @staticmethod
    def __get_target(target, nActualTimespan, nTargetTimespan, numerator, denominator):
        nActualTimespan = max(nActualTimespan, nTargetTimespan * numerator // denominator)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * denominator // numerator)
        new_target = min(MAX_TARGET, (target * nActualTimespan) // nTargetTimespan)
        return Blockchain.target2bits(new_target)

    def get_header(self, height, ref_height, headers):
        delta = ref_height % 2016
        if height < ref_height - delta or headers is None:
            return self.read_header(height)
        return headers[delta - (ref_height - height) + 1]

    @staticmethod
    def target2bits(target):
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits, bitsBase << (8 * (bitsN - 3))

    @staticmethod
    def bits2target(bits):
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1e):
            raise BaseException("First part of bits should be in [0x03, 0x1e]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    def can_connect(self, header, check_height=True):
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == bitcoin.NetworkConstants.GENESIS
        previous_header = self.read_header(height -1)
        if not previous_header:
            return False
        prev_hash = hash_header(previous_header)
        if prev_hash != header.get('prev_block_hash'):
            return False
        bits, target = self.get_target(height, None)
        try:
            self.verify_header(header, previous_header, bits, target)
        except:
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx, data)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk failed', str(e))
            return False
