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
import sys
import threading

from typing import Optional

from . import asert_daa
from . import networks
from . import util

from .bitcoin import *

class VerifyError(Exception):
    '''Exception used for blockchain verification errors.'''

CHUNK_FORKS = -3
CHUNK_BAD = -2
CHUNK_LACKED_PROOF = -1
CHUNK_ACCEPTED = 0

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
    size = (target.bit_length() + 7) // 8
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

HEADER_SIZE = 80 # bytes
MAX_BITS = 0x1d00ffff
MAX_TARGET = bits_to_target(MAX_BITS)
# indicates no header in data file
NULL_HEADER = bytes([0]) * HEADER_SIZE
NULL_HASH_BYTES = bytes([0]) * 32
NULL_HASH_HEX = NULL_HASH_BYTES.hex()

def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

def deserialize_header(s, height):
    h = {}
    h['version'] = int.from_bytes(s[0:4], 'little')
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = int.from_bytes(s[68:72], 'little')
    h['bits'] = int.from_bytes(s[72:76], 'little')
    h['nonce'] = int.from_bytes(s[76:80], 'little')
    h['block_height'] = height
    return h

def hash_header_hex(header_hex):
    return hash_encode(Hash(bfh(header_hex)))

def hash_header(header):
    if header is None:
        return NULL_HASH_HEX
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_header_hex(serialize_header(header))

blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        parent_base_height = int(filename.split('_')[1])
        base_height = int(filename.split('_')[2])
        b = Blockchain(config, base_height, parent_base_height)
        blockchains[b.base_height] = b
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

def verify_proven_chunk(chunk_base_height, chunk_data):
    chunk = HeaderChunk(chunk_base_height, chunk_data)

    header_count = len(chunk_data) // HEADER_SIZE
    prev_header = None
    prev_header_hash = None
    for i in range(header_count):
        header = chunk.get_header_at_index(i)
        # Check the chain of hashes for all headers preceding the proven one.
        this_header_hash = hash_header(header)
        if i > 0:
            if prev_header_hash != header.get('prev_block_hash'):
                raise VerifyError("prev hash mismatch: %s vs %s" % (prev_header_hash, header.get('prev_block_hash')))
        prev_header_hash = this_header_hash

# Copied from electrumx
def root_from_proof(hash, branch, index):
    hash_func = Hash
    for elt in branch:
        if index & 1:
            hash = hash_func(elt + hash)
        else:
            hash = hash_func(hash + elt)
        index >>= 1
    if index:
        raise ValueError('index out of range for branch')
    return hash

class HeaderChunk:
    def __init__(self, base_height, data):
        self.base_height = base_height
        self.header_count = len(data) // HEADER_SIZE
        self.headers = [deserialize_header(data[i * HEADER_SIZE : (i + 1) * HEADER_SIZE],
                                           base_height + i)
                        for i in range(self.header_count)]

    def __repr__(self):
        return "HeaderChunk(base_height={}, header_count={})".format(self.base_height, self.header_count)

    def get_count(self):
        return self.header_count

    def contains_height(self, height):
        return height >= self.base_height and height < self.base_height + self.header_count

    def get_header_at_height(self, height):
        assert self.contains_height(height)
        return self.get_header_at_index(height - self.base_height)

    def get_header_at_index(self, index):
        return self.headers[index]

class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, base_height, parent_base_height):
        self.config = config
        self.catch_up = None # interface catching up
        self.base_height = base_height
        self.parent_base_height = parent_base_height

        self.lock = threading.Lock()
        with self.lock:
            self.update_size()

    def __repr__(self):
        return "<{}.{} {}>".format(__name__, type(self).__name__, self.format_base())

    def format_base(self):
        return "{}@{}".format(self.get_name(), self.get_base_height())

    def parent(self):
        return blockchains[self.parent_base_height]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_base_height==self.base_height, blockchains.values()))
        return max([x.base_height for x in children]) if children else None

    def get_base_height(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.base_height

    def get_branch_size(self):
        return self.height() - self.get_base_height() + 1

    def get_name(self):
        return self.get_hash(self.get_base_height()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        base_height = header.get('block_height')
        self = Blockchain(parent.config, base_height, parent.base_height)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.base_height + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//HEADER_SIZE if os.path.exists(p) else 0

    def verify_header(self, header, prev_header, bits=None):
        prev_header_hash = hash_header(prev_header)
        this_header_hash = hash_header(header)
        if prev_header_hash != header.get('prev_block_hash'):
            raise VerifyError("prev hash mismatch: %s vs %s" % (prev_header_hash, header.get('prev_block_hash')))

        # We do not need to check the block difficulty if the chain of linked header hashes was proven correct against our checkpoint.
        if bits is not None:
            # checkpoint BitcoinCash fork block
            if (header.get('block_height') == networks.net.BITCOIN_CASH_FORK_BLOCK_HEIGHT and hash_header(header) != networks.net.BITCOIN_CASH_FORK_BLOCK_HASH):
                err_str = "block at height %i is not cash chain fork block. hash %s" % (header.get('block_height'), hash_header(header))
                raise VerifyError(err_str)
            if bits != header.get('bits'):
                raise VerifyError("bits mismatch: %s vs %s" % (bits, header.get('bits')))
            target = bits_to_target(bits)
            if int('0x' + this_header_hash, 16) > target:
                raise VerifyError("insufficient proof of work: %s vs target %s" % (int('0x' + this_header_hash, 16), target))

    def verify_chunk(self, chunk_base_height, chunk_data):
        chunk = HeaderChunk(chunk_base_height, chunk_data)

        prev_header = None
        if chunk_base_height != 0:
            prev_header = self.read_header(chunk_base_height - 1)

        header_count = len(chunk_data) // HEADER_SIZE
        for i in range(header_count):
            header = chunk.get_header_at_index(i)
            # Check the chain of hashes and the difficulty.
            bits = self.get_bits(header, chunk)
            self.verify_header(header, prev_header, bits)
            prev_header = header

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_base_height is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_base_height, self.base_height))
        return os.path.join(d, filename)

    def save_chunk(self, base_height, chunk_data):
        chunk_offset = (base_height - self.base_height) * HEADER_SIZE
        if chunk_offset < 0:
            chunk_data = chunk_data[-chunk_offset:]
            chunk_offset = 0
        # Headers at and before the verification checkpoint are sparsely filled.
        # Those should be overwritten and should not truncate the chain.
        top_height = base_height + (len(chunk_data) // HEADER_SIZE) - 1
        truncate = top_height > networks.net.VERIFICATION_BLOCK_HEIGHT
        self.write(chunk_data, chunk_offset, truncate)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_base_height is None:
            return
        parent_branch_size = self.parent().height() - self.base_height + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.base_height, self.parent_base_height)
        parent_base_height = self.parent_base_height
        base_height = self.base_height
        parent = self.parent()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        with open(parent.path(), 'rb') as f:
            f.seek((base_height - parent.base_height)*HEADER_SIZE)
            parent_data = f.read(parent_branch_size*HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (base_height - parent.base_height)*HEADER_SIZE)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_base_height = parent.parent_base_height; parent.parent_base_height = parent_base_height
        self.base_height = parent.base_height; parent.base_height = base_height
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.base_height] = self
        blockchains[parent.base_height] = parent

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*HEADER_SIZE:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.base_height
        data = bfh(serialize_header(header))
        assert delta == self.size()
        assert len(data) == HEADER_SIZE
        self.write(data, delta*HEADER_SIZE)
        self.swap_with_parent()

    def read_header(self, height, chunk=None):
        # If the read is done within an outer call with local unstored header data, we first look in the chunk data currently being processed.
        if chunk is not None and chunk.contains_height(height):
            return chunk.get_header_at_height(height)

        assert self.parent_base_height != self.base_height
        if height < 0:
            return
        if height < self.base_height:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.base_height
        name = self.path()
        if os.path.exists(name):
            with open(name, 'rb') as f:
                f.seek(delta * HEADER_SIZE)
                h = f.read(HEADER_SIZE)
            # Is it a pre-checkpoint header that has never been requested?
            if h == NULL_HEADER:
                return None
            return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return NULL_HASH_HEX
        elif height == 0:
            return networks.net.GENESIS
        return hash_header(self.read_header(height))

    # Not used.
    def BIP9(self, height, flag):
        v = self.read_header(height)['version']
        return ((v & 0xE0000000) == 0x20000000) and ((v & flag) == flag)

    def get_median_time_past(self, height, chunk=None):
        if height < 0:
            return 0
        times = [
            self.read_header(h, chunk)['timestamp']
            for h in range(max(0, height - 10), height + 1)
        ]
        return sorted(times)[len(times) // 2]

    def get_suitable_block_height(self, suitableheight, chunk=None):
        #In order to avoid a block in a very skewed timestamp to have too much
        #influence, we select the median of the 3 top most block as a start point
        #Reference: github.com/Bitcoin-ABC/bitcoin-abc/master/src/pow.cpp#L201
        blocks2 = self.read_header(suitableheight, chunk)
        blocks1 = self.read_header(suitableheight-1, chunk)
        blocks = self.read_header(suitableheight-2, chunk)

        if (blocks['timestamp'] > blocks2['timestamp'] ):
            blocks,blocks2 = blocks2,blocks
        if (blocks['timestamp'] > blocks1['timestamp'] ):
            blocks,blocks1 = blocks1,blocks
        if (blocks1['timestamp'] > blocks2['timestamp'] ):
            blocks1,blocks2 = blocks2,blocks1

        return blocks1['block_height']

    # cached Anchor, per-Blockchain instance, only used if the checkpoint for this network is *behind* the anchor block
    _cached_asert_anchor: Optional[asert_daa.Anchor] = None

    def get_asert_anchor(self, prevheader, mtp, chunk=None):
        """Returns the asert_anchor either from Networks.net if hardcoded or
        calculated in realtime if not."""
        if networks.net.asert_daa.anchor is not None:
            # Checkpointed (hard-coded) value exists, just use that
            return networks.net.asert_daa.anchor
        # Bug note: The below does not work if we don't have all the intervening
        # headers -- therefore this execution path should only be taken for networks
        # where the checkpoint block is before the anchor block.  This means that
        # adding a checkpoint after the anchor block without setting the anchor
        # block in networks.net.asert_daa.anchor will result in bugs.
        if (self._cached_asert_anchor is not None
                and self._cached_asert_anchor.height <= prevheader['block_height']):
            return self._cached_asert_anchor

        anchor = prevheader
        activation_mtp = networks.net.asert_daa.MTP_ACTIVATION_TIME
        while mtp >= activation_mtp:
            ht = anchor['block_height']
            prev = self.read_header(ht - 1, chunk)
            if prev is None:
                self.print_error("get_asert_anchor missing header {}".format(ht - 1))
                return None
            prev_mtp = self.get_median_time_past(ht - 1, chunk)
            if prev_mtp < activation_mtp:
                # Ok, use this as anchor -- since it is the first in the chain
                # after activation.
                bits = anchor['bits']
                self._cached_asert_anchor = asert_daa.Anchor(ht, bits, prev['timestamp'])
                return self._cached_asert_anchor
            mtp = prev_mtp
            anchor = prev

    def get_bits(self, header, chunk=None):
        '''Return bits for the given height.'''
        # Difficulty adjustment interval?
        height = header['block_height']
        # Genesis
        if height == 0:
            return MAX_BITS

        prior = self.read_header(height - 1, chunk)
        if prior is None:
            raise Exception("get_bits missing header {} with chunk {!r}".format(height - 1, chunk))
        bits = prior['bits']

        # NOV 13 HF DAA and/or ASERT DAA

        prevheight = height - 1
        daa_mtp = self.get_median_time_past(prevheight, chunk)


        # ASERTi3-2d DAA activated on Nov. 15th 2020 HF
        if daa_mtp >= networks.net.asert_daa.MTP_ACTIVATION_TIME:
            header_ts = header['timestamp']
            prev_ts = prior['timestamp']
            if networks.net.TESTNET:
                # testnet 20 minute rule
                if header_ts - prev_ts > 20*60:
                    return MAX_BITS

            anchor = self.get_asert_anchor(prior, daa_mtp, chunk)
            assert anchor is not None, "Failed to find ASERT anchor block for chain {!r}".format(self)

            return networks.net.asert_daa.next_bits_aserti3_2d(anchor.bits,
                                                               prev_ts - anchor.prev_time,
                                                               prevheight - anchor.height)


        # Mon Nov 13 19:06:40 2017 DAA HF
        if prevheight >= networks.net.CW144_HEIGHT:

            if networks.net.TESTNET:
                # testnet 20 minute rule
                if header['timestamp'] - prior['timestamp'] > 20*60:
                    return MAX_BITS

            # determine block range
            daa_starting_height = self.get_suitable_block_height(prevheight-144, chunk)
            daa_ending_height = self.get_suitable_block_height(prevheight, chunk)

            # calculate cumulative work (EXcluding work from block daa_starting_height, INcluding work from block daa_ending_height)
            daa_cumulative_work = 0
            for daa_i in range (daa_starting_height+1, daa_ending_height+1):
                daa_prior = self.read_header(daa_i, chunk)
                daa_bits_for_a_block = daa_prior['bits']
                daa_work_for_a_block = bits_to_work(daa_bits_for_a_block)
                daa_cumulative_work += daa_work_for_a_block

            # calculate and sanitize elapsed time
            daa_starting_timestamp = self.read_header(daa_starting_height, chunk)['timestamp']
            daa_ending_timestamp = self.read_header(daa_ending_height, chunk)['timestamp']
            daa_elapsed_time = daa_ending_timestamp - daa_starting_timestamp
            if (daa_elapsed_time>172800):
                daa_elapsed_time=172800
            if (daa_elapsed_time<43200):
                daa_elapsed_time=43200

            # calculate and return new target
            daa_Wn = (daa_cumulative_work*600) // daa_elapsed_time
            daa_target = (1 << 256) // daa_Wn - 1
            daa_retval = target_to_bits(daa_target)
            daa_retval = int(daa_retval)
            return daa_retval

        #END OF NOV-2017 DAA
        N_BLOCKS = networks.net.LEGACY_POW_RETARGET_BLOCKS  # Normally 2016
        if height % N_BLOCKS == 0:
            return self.get_new_bits(height, chunk)

        if networks.net.TESTNET:
            # testnet 20 minute rule
            if header['timestamp'] - prior['timestamp'] > 20*60:
                return MAX_BITS
            # special case for a newly started testnet (such as testnet4)
            if height < N_BLOCKS:
                return MAX_BITS
            return self.read_header(height // N_BLOCKS * N_BLOCKS, chunk)['bits']

        # bitcoin cash EDA
        # Can't go below minimum, so early bail
        if bits == MAX_BITS:
            return bits
        mtp_6blocks = self.get_median_time_past(height - 1, chunk) - self.get_median_time_past(height - 7, chunk)
        if mtp_6blocks < 12 * 3600:
            return bits

        # If it took over 12hrs to produce the last 6 blocks, increase the
        # target by 25% (reducing difficulty by 20%).
        target = bits_to_target(bits)
        target += target >> 2

        return target_to_bits(target)

    def get_new_bits(self, height, chunk=None):
        N_BLOCKS = networks.net.LEGACY_POW_RETARGET_BLOCKS
        assert height % N_BLOCKS == 0
        # Genesis
        if height == 0:
            return MAX_BITS
        first = self.read_header(height - N_BLOCKS, chunk)
        prior = self.read_header(height - 1, chunk)
        prior_target = bits_to_target(prior['bits'])

        target_span = networks.net.LEGACY_POW_TARGET_TIMESPAN # usually: 14 * 24 * 60 * 60 = 2 weeks
        span = prior['timestamp'] - first['timestamp']
        span = min(max(span, target_span // 4), target_span * 4)
        new_target = (prior_target * span) // target_span
        return target_to_bits(new_target)

    def can_connect(self, header, check_height=True):
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == networks.net.GENESIS
        previous_header = self.read_header(height -1)
        if not previous_header:
            return False
        prev_hash = hash_header(previous_header)
        if prev_hash != header.get('prev_block_hash'):
            return False
        bits = self.get_bits(header)
        try:
            self.verify_header(header, previous_header, bits)
        except VerifyError as e:
            self.print_error('verify header {} failed at height {:d}: {}'
                             .format(hash_header(header), height, e))
            return False
        return True

    def connect_chunk(self, base_height, hexdata, proof_was_provided=False):
        chunk = HeaderChunk(base_height, hexdata)

        header_count = len(hexdata) // HEADER_SIZE
        top_height = base_height + header_count - 1
        # We know that chunks before the checkpoint height, end at the checkpoint height, and
        # will be guaranteed to be covered by the checkpointing. If no proof is provided then
        # this is wrong.
        if top_height <= networks.net.VERIFICATION_BLOCK_HEIGHT:
            if not proof_was_provided:
                return CHUNK_LACKED_PROOF
            # We do not truncate when writing chunks before the checkpoint, and there's no
            # way at this time to know if we have this chunk, or even a consecutive subset.
            # So just overwrite it.
        elif base_height < networks.net.VERIFICATION_BLOCK_HEIGHT and proof_was_provided:
            # This was the initial verification request which gets us enough leading headers
            # that we can calculate difficulty and verify the headers that we add to this
            # chain above the verification block height.
            if top_height <= self.height():
                return CHUNK_ACCEPTED
        elif base_height != self.height() + 1:
            # This chunk covers a segment of this blockchain which we already have headers
            # for. We need to verify that there isn't a split within the chunk, and if
            # there is, indicate the need for the server to fork.
            intersection_height = min(top_height, self.height())
            chunk_header = chunk.get_header_at_height(intersection_height)
            our_header = self.read_header(intersection_height)
            if hash_header(chunk_header) != hash_header(our_header):
                return CHUNK_FORKS
            if intersection_height <= self.height():
                return CHUNK_ACCEPTED
        else:
            # This base of this chunk joins to the top of the blockchain in theory.
            # We need to rule out the case where the chunk is actually a fork at the
            # connecting height.
            our_header = self.read_header(self.height())
            chunk_header = chunk.get_header_at_height(base_height)
            if hash_header(our_header) != chunk_header['prev_block_hash']:
                return CHUNK_FORKS

        try:
            if not proof_was_provided:
                self.verify_chunk(base_height, hexdata)
            self.save_chunk(base_height, hexdata)
            return CHUNK_ACCEPTED
        except VerifyError as e:
            self.print_error('verify_chunk failed: {}'.format(e))
            return CHUNK_BAD
