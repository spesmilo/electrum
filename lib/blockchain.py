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

def bits_to_work(bits):
    return (1 << 256) // (bits_to_target(bits) + 1)

def bits_to_target(bits):
    if bits == 0:
        return 0
    size = bits >> 24
    assert size <= 0x1d

    word = bits & 0x00ffffff
    assert 0x8000 <= word <= 0x7fffff

    if size <= 3:
        return word >> (8 * (3 - size))
    else:
        return word << (8 * (size - 3))

def target_to_bits(target):
    if target == 0:
        return 0
    target = min(target, MAX_TARGET)
    size = (target.bit_length() + 7) / 8
    mask64 = 0xffffffffffffffff
    if size <= 3:
        compact = (target & mask64) << (8 * (3 - size))
    else:
        compact = (target >> (8 * (size - 3))) & mask64

    if compact & 0x00800000:
        compact >>= 8
        size += 1
    assert compact == (compact & 0x007fffff)
    assert size < 256
    return compact | size << 24

MAX_BITS = 0x1d00ffff
MAX_TARGET = bits_to_target(MAX_BITS)

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
        self.cur_chunk = None
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

    def verify_header(self, header, prev_header, bits):
        prev_hash = hash_header(prev_header)
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        # checkpoint BitcoinCash fork block
        if ( header.get('block_height') == bitcoin.BITCOIN_CASH_FORK_BLOCK_HEIGHT and hash_header(header) != bitcoin.BITCOIN_CASH_FORK_BLOCK_HASH ):
            err_str = "block at height %i is not cash chain fork block. hash %s" % (header.get('block_height'), hash_header(header))
            self.print_error(err_str)
            raise BaseException(err_str)
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        target = bits_to_target(bits)
        if int('0x' + _hash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

    def verify_chunk(self, index, data):
        self.cur_chunk = data
        self.cur_chunk_index = index
        num = len(data) / 80
        prev_header = None
        if index != 0:
            prev_header = self.read_header(index*2016 - 1)
        for i in range(num):
            raw_header = data[i*80:(i+1) * 80]
            header = deserialize_header(raw_header, index*2016 + i)
            bits = self.get_bits(header)
            self.verify_header(header, prev_header, bits)
            prev_header = header
        self.cur_chunk = None

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
        if self.cur_chunk and (height // 2016) == self.cur_chunk_index:
            n = height % 2016
            h = self.cur_chunk[n * 80: (n + 1) * 80]
            return deserialize_header(h, height)
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

    def get_median_time_past(self, height):
        if height < 0:
            return 0
        times = [self.read_header(h)['timestamp']
                 for h in range(max(0, height - 10), height + 1)]
        return sorted(times)[len(times) // 2]

    def get_suitable_block_height(self, suitableheight):

	#In order to avoid a block in a very skewed timestamp to have too much
	#influence, we select the median of the 3 top most block as a start point
	#Reference: github.com/Bitcoin-ABC/bitcoin-abc/master/src/pow.cpp#L201
	blocks2 = self.read_header(suitableheight)
	blocks1 = self.read_header(suitableheight-1)
	blocks = self.read_header(suitableheight-2)

	if (blocks['timestamp'] > blocks2['timestamp'] ):
		blocks,blocks2 = blocks2,blocks
	if (blocks['timestamp'] > blocks1['timestamp'] ):
		blocks,blocks1 = blocks1,blocks
	if (blocks1['timestamp'] > blocks2['timestamp'] ):
		blocks1,blocks2 = blocks2,blocks1

	return blocks1['block_height']

    def get_bits(self, header):
        '''Return bits for the given height.'''
        # Difficulty adjustment interval?
        height = header['block_height']
        # Genesis
        if height == 0:
            return MAX_BITS

        prior = self.read_header(height - 1)
        bits = prior['bits']

        # testnet 20 minute rule
        if bitcoin.TESTNET and height % 2016 != 0:
            if header['timestamp'] - prior['timestamp'] > 20*60:
                return MAX_BITS

        #NOV 13 HF DAA

	prevheight = height -1
        daa_mtp=self.get_median_time_past(prevheight)

        #if (daa_mtp >= 1509559291):  #leave this here for testing
        if (daa_mtp >= 1510600000):

            # determine block range
            daa_starting_height=self.get_suitable_block_height(prevheight-144)
            daa_ending_height=self.get_suitable_block_height(prevheight)

            # calculate cumulative work (EXcluding work from block daa_starting_height, INcluding work from block daa_ending_height)
            daa_cumulative_work=0
            for daa_i in range (daa_starting_height+1,daa_ending_height+1):
                daa_prior = self.read_header(daa_i)
                daa_bits_for_a_block=daa_prior['bits']
                daa_work_for_a_block=bits_to_work(daa_bits_for_a_block)
                daa_cumulative_work += daa_work_for_a_block

            # calculate and sanitize elapsed time
            daa_starting_timestamp = self.read_header(daa_starting_height)['timestamp']
            daa_ending_timestamp = self.read_header(daa_ending_height)['timestamp']
            daa_elapsed_time=daa_ending_timestamp-daa_starting_timestamp
            if (daa_elapsed_time>172800):
                daa_elapsed_time=172800
            if (daa_elapsed_time<43200):
                daa_elapsed_time=43200

            # calculate and return new target
            daa_Wn= (daa_cumulative_work*600)//daa_elapsed_time
            daa_target= (1 << 256) // daa_Wn -1
            daa_retval = target_to_bits(daa_target)
            daa_retval = int(daa_retval)
            return daa_retval

        #END OF NOV-2017 DAA

        if height % 2016 == 0:
            return self.get_new_bits(height)

        if bitcoin.TESTNET:
            return self.read_header(int(height / 2016) * 2016)['bits']

        # bitcoin cash EDA
        # Can't go below minimum, so early bail
        if bits == MAX_BITS:
            return bits
        mtp_6blocks = (self.get_median_time_past(height - 1)
                       - self.get_median_time_past(height - 7))
        if mtp_6blocks < 12 * 3600:
            return bits
        # If it took over 12hrs to produce the last 6 blocks, increase the
        # target by 25% (reducing difficulty by 20%).
        target = bits_to_target(bits)
        target += target >> 2

        return target_to_bits(target)

    def get_new_bits(self, height):
        assert height % 2016 == 0
        # Genesis
        if height == 0:
            return MAX_BITS
        first = self.read_header(height - 2016)
        prior = self.read_header(height - 1)
        prior_target = bits_to_target(prior['bits'])

        target_span = 14 * 24 * 60 * 60
        span = prior['timestamp'] - first['timestamp']
        span = min(max(span, target_span / 4), target_span * 4)
        new_target = (prior_target * span) / target_span
        return target_to_bits(new_target)

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
        bits = self.get_bits(header)
        try:
            self.verify_header(header, previous_header, bits)
        except:
            #self.print_error('can_connect: verify_header failed');
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
