#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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
"""
Some pieces of fusion that can be reused in the server.
"""

from electroncash.transaction import Transaction, TYPE_SCRIPT, TYPE_ADDRESS, get_address_from_output_script
from electroncash.address import Address, ScriptOutput, hash160, OpCodes

from . import fusion_pb2 as pb
from .protocol import Protocol

import hashlib
import ecdsa

# Internally used exceptions, shouldn't leak out of this plugin.
class FusionError(Exception):
    '''This represents an "expected" type of error, having to do with protocol
    errors and degraded conditions that cause a fusion round to fail. It should
    not be used to mask programming errors.'''


def sha256(x):
    return hashlib.sha256(x).digest()

def size_of_input(pubkey):
    # Sizes of inputs after signing:
    #   32+8+1+1+[length of sig]+1+[length of pubkey]
    #   == 141 for compressed pubkeys, 173 for uncompressed.
    # (we use schnorr signatures, always)
    assert 1 < len(pubkey) < 76  # need to assume regular push opcode
    return 108 + len(pubkey)

def size_of_output(scriptpubkey):
    # == 34 for P2PKH, 32 for P2SH
    assert len(scriptpubkey) < 253  # need to assume 1-byte varint
    return 9 + len(scriptpubkey)

def component_fee(size, feerate):
    # feerate in sat/kB
    # size and feerate should both be integer
    # fee is always rounded up
    return (size * feerate + 999) // 1000

def dust_limit(lenscriptpubkey):
    return 3*(lenscriptpubkey + 148)

def pubkeys_from_privkey(privkey):
    P = int.from_bytes(privkey, 'big') * ecdsa.SECP256k1.generator
    return (b'\x04' + P.x().to_bytes(32,'big') + P.y().to_bytes(32,'big'),
            bytes((2 + (P.y()&1),)) + P.x().to_bytes(32,'big'),
            )

def gen_keypair():
    # Returns privkey (32 bytes), pubkey (65 bytes, uncompressed), pubkey (33 bytes, compressed)
    privkey = ecdsa.util.randrange(ecdsa.SECP256k1.order)
    P = privkey * ecdsa.SECP256k1.generator
    return (privkey.to_bytes(32,'big'),
            b'\x04' + P.x().to_bytes(32,'big') + P.y().to_bytes(32,'big'),
            bytes((2 + (P.y()&1),)) + P.x().to_bytes(32,'big'),
            )

def listhash(iterable):
    """Hash a list of bytes arguments with well-defined boundaries."""
    h = hashlib.sha256()
    for x in iterable:
        h.update(len(x).to_bytes(4,'big'))
        h.update(x)
    return h.digest()

def calc_initial_hash(tier, covert_domain_b, covert_port, covert_ssl, begin_time):
    return listhash([b'Cash Fusion Session',
                     Protocol.VERSION,
                     tier.to_bytes(8,'big'),
                     covert_domain_b,
                     covert_port.to_bytes(4,'big'),
                     b'\x01' if covert_ssl else b'\0',
                     begin_time.to_bytes(8,'big'),
                     ])

def calc_round_hash(last_hash, round_pubkey, round_time, all_commitments, all_components):
    return listhash([b'Cash Fusion Round',
                     last_hash,
                     round_pubkey,
                     round_time.to_bytes(8,'big'),
                     listhash(all_commitments),
                     listhash(all_components),
                     ])


def tx_from_components(all_components, session_hash):
    """ Returns the tx and a list of indices matching inputs with components"""
    input_indices = []
    assert len(session_hash) == 32
    if Protocol.FUSE_ID is None:
        prefix = []
    else:
        assert len(Protocol.FUSE_ID) == 4
        prefix = [4, *Protocol.FUSE_ID]
    inputs = []
    outputs = [(TYPE_SCRIPT, ScriptOutput(bytes([OpCodes.OP_RETURN, *prefix, 32]) + session_hash), 0)]
    for i,compser in enumerate(all_components):
        comp = pb.Component()
        comp.ParseFromString(compser)
        ctype = comp.WhichOneof('component')
        if ctype == 'input':
            inp = comp.input
            if len(inp.prev_txid) != 32:
                raise FusionError("bad component prevout")
            inputs.append(dict(address = Address.from_P2PKH_hash(hash160(inp.pubkey)),
                               prevout_hash = inp.prev_txid[::-1].hex(),
                               prevout_n = inp.prev_index,
                               num_sig = 1,
                               signatures = [None],
                               type = 'p2pkh',
                               x_pubkeys = [inp.pubkey.hex()],
                               pubkeys = [inp.pubkey.hex()],
                               sequence = 0xffffffff,
                               value = inp.amount))
            input_indices.append(i)
        elif ctype == 'output':
            out = comp.output
            atype, addr = get_address_from_output_script(out.scriptpubkey)
            if atype != TYPE_ADDRESS:
                raise FusionError("bad component address")
            outputs.append((TYPE_ADDRESS, addr, out.amount))
        elif ctype != 'blank':
            raise FusionError("bad component")
    tx = Transaction.from_io(inputs, outputs, locktime=0, sign_schnorr=True)
    tx.version = 1
    return tx, input_indices


def rand_position(seed, num_positions, counter):
    """
    Generate a uniform number in the range [0 ... `num_positions` - 1] by hashing
    `seed` (bytes) and `counter` (int). Note that proper uniformity requires that
    num_positions should be much less than 2**64.

    (see https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/)
    """
    int64 = int.from_bytes(sha256(seed + counter.to_bytes(4, 'big'))[:8], 'big')
    return (int64 * num_positions) >> 64
