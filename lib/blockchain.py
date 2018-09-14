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
import struct
from io import BytesIO

from . import util
from . import bitcoin
from . import constants
from .bitcoin import *
import base64

from .equihash import is_gbp_valid
import logging
logging.basicConfig(level=logging.INFO)

# https://en.bitcoin.it/wiki/Target
MAX_TARGET = 0x0007FFFFFFFF0000000000000000000000000000000000000000000000000000

def serialize_header(res):
    r = b''
    r += struct.pack("<i", res.get('version'))
    r += str_to_hash(res.get('prev_block_hash'))
    r += str_to_hash(res.get('merkle_root'))
    r += str_to_hash(res.get('hash_reserved'))
    r += struct.pack("<I", res.get('timestamp'))
    r += struct.pack("<I", res.get('bits'))
    r += str_to_hash(res.get('nonce'))
    r += ser_char_vector(base64.b64decode(res.get('n_solution').encode('utf8')))
    return r

def deserialize_header(f, height):
    f = BytesIO(f)
    h = {}
    h['version'] = struct.unpack("<I", f.read(4))[0]
    h['prev_block_hash'] = hash_to_str(f.read(32))
    h['merkle_root'] = hash_to_str(f.read(32))
    h['hash_reserved'] = hash_to_str(f.read(32))
    h['timestamp'] = struct.unpack("<I", f.read(4))[0]
    h['bits'] = struct.unpack("<I", f.read(4))[0]
    h['nonce'] = hash_to_str(f.read(32))
    h['n_solution'] = base64.b64encode(bytes(deser_char_vector(f))).decode('utf8')
    h['block_height'] = height
    return h

# def deserialize_header(f, height):
#     h = {}
#     h['version'] = struct.unpack("<I", f.read(4))[0]
#     h['prev_block_hash'] = hash_to_str(f.read(32))
#     h['merkle_root'] = hash_to_str(f.read(32))
#     h['hash_reserved'] = hash_to_str(f.read(32))
#     h['timestamp'] = struct.unpack("<I", f.read(4))[0]
#     h['bits'] = struct.unpack("<I", f.read(4))[0]
#     h['nonce'] = hash_to_str(f.read(32))
#     h['n_solution'] = base64.b64encode(bytes(deser_char_vector(f))).decode('utf8')
#     h['block_height'] = height
#     return h

def sha256_header(header):
    return uint256_from_bytes(Hash(serialize_header(header)))

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*64
        '''
        TODO 32?
        '''
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
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)
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
        self.checkpoints = constants.net.CHECKPOINTS
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

    def verify_header(self, header, prev_hash, target):
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return
        bits = self.target_to_bits(target)
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if int('0x' + _hash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))
        nonce = uint256_from_bytes(str_to_hash(header.get('nonce')))
        n_solution = vector_from_bytes(base64.b64decode(header.get('n_solution').encode('utf8')))
        if not is_gbp_valid(serialize_header(header), nonce, n_solution,
            constants.net.EQUIHASH_N, constants.net.EQUIHASH_K):
            raise BaseException("Equihash invalid")

    def verify_chunk(self, index, data):
        num = len(data) // bitcoin.HEADER_SIZE
        prev_hash = self.get_hash(index * constants.net.CHUNK_SIZE - 1)
        target = self.get_target(index-1)
        for i in range(num):
            raw_header = data[i*bitcoin.HEADER_SIZE:(i+1) * bitcoin.HEADER_SIZE]
            header = deserialize_header(raw_header, index*constants.net.CHUNK_SIZE + i)
            self.verify_header(header, prev_hash, target)
            prev_hash = hash_header(header)

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * constants.net.CHUNK_SIZE - self.checkpoint) * bitcoin.HEADER_SIZE
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        truncate = index >= len(self.checkpoints)
        self.write(chunk, d, truncate)
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
            f.seek((checkpoint - parent.checkpoint)*bitcoin.HEADER_SIZE)
            parent_data = f.read(parent_branch_size*bitcoin.HEADER_SIZE)

        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*bitcoin.HEADER_SIZE)
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

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*bitcoin.HEADER_SIZE:
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
        assert len(data) == bitcoin.HEADER_SIZE
        self.write(data, delta*bitcoin.HEADER_SIZE)
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
                f.seek(delta * bitcoin.HEADER_SIZE)
                h = f.read(bitcoin.HEADER_SIZE)
        if h == bytes([0])*bitcoin.HEADER_SIZE:
            return None
        return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif height < len(self.checkpoints) * constants.net.CHUNK_SIZE:
            assert (height+1) % constants.net.CHUNK_SIZE == 0, height
            index = height // constants.net.CHUNK_SIZE
            h, t = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height))

    def get_target(self, index):
        # compute target from chunk x, used in chunk x+1
        if constants.net.TESTNET:
            return 0
        if index == -1:
            return MAX_TARGET
        if index < len(self.checkpoints):
            h, t = self.checkpoints[index]
            return t
        # new target
        first = self.read_header(index * constants.net.CHUNK_SIZE)
        last = self.read_header(index * constants.net.CHUNK_SIZE + (constants.net.CHUNK_SIZE - 1))
        bits = last.get('bits')
        target = self.bits_to_target(bits)
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14 * 24 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target * nActualTimespan) // nTargetTimespan)
        return new_target

    def bits_to_target(self, bits):
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1d):
            raise BaseException("First part of bits should be in [0x03, 0x1d]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    def target_to_bits(self, target):
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def can_connect(self, header, check_height=True):
        height = header['block_height']
        if check_height and self.height() != height - 1:
            self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        target = self.get_target(height // constants.net.CHUNK_SIZE - 1)
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException as e:
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
            self.print_error('verify_chunk %d failed'%idx, str(e))
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // 2016
        for index in range(n):
            h = self.get_hash((index+1) * 2016 -1)
            target = self.get_target(index)
            cp.append((h, target))
        return cp
