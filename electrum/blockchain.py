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

from . import util
from .bitcoin import Hash, hash_encode, int_to_hex, rev_hex, op_push
from .transaction import parse_redeemScript_multisig, script_GetOp
from . import constants
from .util import bfh, bh2u
from . import ecc 
from pprint import pprint

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


class MissingHeader(Exception):
    pass

class InvalidHeader(Exception):
    "Header downloaded from network is invalid."

class InvalidFile(Exception):
    "Data stored locally are invalid."
    
    def __init__(self, filename, *messages):
        super().__init__(*messages)
        self.filename = filename

def serialize_header(res, get_hash = False):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + rev_hex(res.get('contract_hash'))

    s += rev_hex(res.get('attestation_hash'))
    s += rev_hex(res.get('mapping_hash'))

    s += int_to_hex(int(res.get('timestamp')), 4) +\
         int_to_hex(int(res.get('block_height')), 4)

    challenge = res.get('challenge')
    s += int_to_hex(int(len(challenge)/2), 1) + rev_hex(challenge)

    if not get_hash:
        proof = res.get('proof')
        s += int_to_hex(int(len(proof)/2), 1) + rev_hex(proof)

    return s

def deserialize_headers(s, height):
    headers = []
    # s is bytes format
    # use deserialize_header to pick up the next header
    # use serialize_header to find the header length
    while s:
        next_header = deserialize_header(s, height)
        headers.append(next_header)
        s = s[int(len(serialize_header(next_header))/2):]
        height += 1

    return headers

def verify_header_proof(h):
    rproof = h['proof']
    rchallenge = h['challenge']
    proof = "".join(reversed([rproof[i:i+2] for i in range(0, len(rproof), 2)]))
    challenge = "".join(reversed([rchallenge[i:i+2] for i in range(0, len(rchallenge), 2)]))
    if challenge != constants.net.CHALLENGE: 
        return False

    try:
        m, n, x_pubkeys, pubkeys, redeem_script = parse_redeemScript_multisig(bytearray.fromhex(challenge))
    except:
        return False

    signatures = []
    try:
        decoded = [ x for x in script_GetOp(bytearray.fromhex(proof)) ]
    except struct.error:
        return False

    for element in decoded[1:]:
        signatures.append(element[1])

    rhhash = hash_header(h)
    hhash = "".join(reversed([rhhash[i:i+2] for i in range(0, len(rhhash), 2)]))

    keyfound = []
    nverified = 0
    #loop over each signature and then check each pubkey in turn
    for sig in signatures:
        sig_string = ecc.sig_string_from_der_sig(sig)
        for pubkey in pubkeys:
            if pubkey in keyfound: continue
            pubpoint = ecc.ser_to_point(bytes.fromhex(pubkey))
            public_key = ecc.ECPubkey.from_point(pubpoint)
            try:
                public_key.verify_message_hash(sig_string, bytes.fromhex(hhash))
                keyfound.append(pubkey)
                nverified += 1
            except:
                pass
        if nverified >= m: 
            return True

    return False

def deserialize_header(s, height):
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    if len(s) < constants.net.MIN_HEADER_SIZE:
        raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['contract_hash'] = hash_encode(s[68:100])

    h['attestation_hash'] = hash_encode(s[100:132])
    h['mapping_hash'] = hash_encode(s[132:164])

    h['timestamp'] = hex_to_int(s[constants.net.BASIC_HEADER_SIZE-8:constants.net.BASIC_HEADER_SIZE-4])
    h['block_height'] = height

    challenge = ''
    proof = ''
    challenge_size = s[constants.net.BASIC_HEADER_SIZE]
    if challenge_size > 0:
        challenge = hash_encode(s[constants.net.BASIC_HEADER_SIZE+1:
                        constants.net.BASIC_HEADER_SIZE+1+challenge_size])
        proof_size = s[constants.net.BASIC_HEADER_SIZE+1+challenge_size]
        if proof_size > 0:
            proof = hash_encode(s[constants.net.BASIC_HEADER_SIZE+1+challenge_size+1:
                                        constants.net.BASIC_HEADER_SIZE+1+challenge_size+1+proof_size])
    h['challenge'] = challenge
    h['proof'] = proof

    return h

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header, True))))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    util.make_dir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        forkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, forkpoint, parent_id)
        util.print_error("forkpoint:{0}\nparent_id:{1}".format(forkpoint, parent_id))
        h = b.read_header(b.forkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.forkpoint] = b
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

    def __init__(self, config, forkpoint, parent_id):
        self.config = config
        self.catch_up = None  # interface catching up
        self.forkpoint = forkpoint
        self.checkpoints = constants.net.CHECKPOINTS
        self.parent_id = parent_id
        assert parent_id != forkpoint
        self.lock = threading.RLock()
        with self.lock:
            self.update_size()

    def with_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.forkpoint, blockchains.values()))
        return max([x.forkpoint for x in children]) if children else None

    def get_forkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_branch_size(self):
        return self.height() - self.get_forkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_forkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        forkpoint = header.get('block_height')
        self = Blockchain(parent.config, forkpoint, parent.forkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.forkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.offset_path()
        self._size = (os.path.getsize(p)//8) - 1 if os.path.exists(p) else 0

    def verify_header(self, header, prev_hash):
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))

    def verify_chunk(self, index, headers):
        num = len(headers)
        prev_hash = self.get_hash(index * 2016 - 1)
        for i in range(num):
            header = headers[i]
            self.verify_header(header, prev_hash)
            prev_hash = hash_header(header)

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.forkpoint))
        return os.path.join(d, filename)

    def offset_path(self):
        d = util.get_headers_dir(self.config)
        filename = 'headers_offset'
        return os.path.join(d, filename)

    @with_lock
    def save_chunk(self, index, chunk):
        chunk_within_checkpoint_region = index < len(self.checkpoints)
        # chunks in checkpoint region are the responsibility of the 'main chain'
        if chunk_within_checkpoint_region and self.parent_id is not None:
            main_chain = blockchains[0]
            main_chain.save_chunk(index, chunk)
            return

        delta_height = (index * 2016 - self.forkpoint)
        delta_bytes = 0
        header_data = b''
        offset_data = b''
        initial_offset = self.dynamic_header_offset(delta_height)
        offset = initial_offset
        for idx, header in enumerate(chunk):
            header_bytes = bfh(serialize_header(header))
            if idx + delta_height < 0:
                delta_bytes += len(header_bytes)
            header_data += header_bytes
            offset += len(header_bytes)
            offset_data += bfh(int_to_hex(offset, 8))

        # if this chunk contains our forkpoint, only save the part after forkpoint
        # (the part before is the responsibility of the parent)
        if delta_bytes > 0:
            header_data = header_data[delta_bytes:]
            offset_data = offset_data[delta_height*8:]
            delta_bytes = 0
        truncate = not chunk_within_checkpoint_region

        self.write(header_data, initial_offset, truncate)
        self.write_offset(offset_data, (delta_height + 1)*8)
        self.swap_with_parent()

    @with_lock
    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.forkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.forkpoint, self.parent_id)
        parent_id = self.parent_id
        forkpoint = self.forkpoint
        parent = self.parent()
        self.assert_headers_file_available(self.path())

        # headers
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        with open(parent.path(), 'rb') as f:
            f.seek(self.dynamic_header_offset(forkpoint - parent.forkpoint))
            parent_data = f.read(self.dynamic_header_offset(parent_branch_size))

        # header offsets
        self.assert_headers_file_available(self.offset_path())
        with open(self.offset_path(), 'rb') as f:
            my_offset_data = f.read()
        self.assert_headers_file_available(parent.offset_path())
        with open(parent.offset_path(), 'rb') as f:
            f.seek((forkpoint - parent.forkpoint + 1) * 8)
            parent_offset_data = f.read(parent_branch_size * 8)

        self.write(parent_data, 0)
        self.write_offset(parent_offset_data, 0)
        parent.write(my_data, self.dynamic_header_offset(forkpoint - parent.forkpoint))
        parent.write_offset(my_offset_data, (forkpoint - parent.forkpoint + 1) * 8)

        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.forkpoint = parent.forkpoint; parent.forkpoint = forkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.forkpoint] = self
        blockchains[parent.forkpoint] = parent

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            self.assert_headers_file_available(filename)
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*80:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def write_offset(self, data, offset):
        filename = self.offset_path()
        with self.lock:
            self.assert_headers_file_available(filename)
            with open(filename, 'rb+') as f:
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    @with_lock
    def save_header(self, header):
        delta = header.get('block_height') - self.forkpoint
        data = bfh(serialize_header(header))
        assert delta == self.size()

        offset = self.dynamic_header_offset(delta)
        self.write(data, offset)

        offset += len(data)
        pos = (delta + 1) * 8
        self.write_offset(bfh(int_to_hex(offset, 8)), pos)
        self.swap_with_parent()

    def dynamic_header_offset(self, height):
        name = self.offset_path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(height * 8)
            h = f.read(8)

        hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16) if len(s)!=0 else 0
        offset = hex_to_int(h)
        #self.print_error("height{0}-offset{1}".format(height, offset))
        return offset

    def dynamic_header_len(self, height):
        return self.dynamic_header_offset(height + 1)\
               - self.dynamic_header_offset(height)

    def read_header(self, height):
        assert self.parent_id != self.forkpoint
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.forkpoint

        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(self.dynamic_header_offset(delta))
            h = f.read(self.dynamic_header_len(delta))
            if len(h) < constants.net.MIN_HEADER_SIZE:
                raise InvalidFile(name, 'Expected to read a full header. This was only {} bytes'.format(len(h)))
        if h == bytes([0])*(constants.net.MIN_HEADER_SIZE):
            return None

        return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif height < len(self.checkpoints) * 2016:
            assert (height+1) % 2016 == 0, height
            index = height // 2016
            h, t = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height))

    def can_connect(self, header, check_height=True):
        if header is None:
            self.print_error("header is None")
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            self.print_error(hash_header(header), "==", constants.net.GENESIS)
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except Exception as e:
            self.print_error("get_hash:", str(e))
            return False
        if prev_hash != header.get('prev_block_hash'):
            self.print_error(prev_hash, "!=", header.get('prev_block_hash'))
            return False
        try:
            self.verify_header(header, prev_hash)
        except BaseException as e:
            self.print_error("verify_header:", str(e))
            return False
        if not verify_header_proof(header):
            self.print_error("invalid block proof at height ", height)
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            headers = deserialize_headers(data, idx*2016)
            self.verify_chunk(idx, headers)
            self.save_chunk(idx, headers)
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
            cp.append(h)
        return cp
