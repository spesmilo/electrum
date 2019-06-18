# -*- coding: utf-8 -*-
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2018 The Namecoin developers
#
# License for all components not part of Electrum-DOGE:
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
#
# Based on Electrum-DOGE - lightweight Dogecoin client
# Copyright (C) 2014 The Electrum-DOGE contributors
#
# License for the Electrum-DOGE components:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import binascii

# electrum.blockchain is an absolute import because cyclic imports must be
# absolute prior to Python 3.5.
import electrum.blockchain
from .bitcoin import hash_encode, hash_decode
from .crypto import sha256d
from . import transaction
from .transaction import BCDataStream, Transaction, TYPE_SCRIPT
from .util import bfh, bh2u
from . import constants

BLOCK_VERSION_AUXPOW_BIT = 0x100
MIN_AUXPOW_HEIGHT = 1

# TODO: move this to network constants
CHAIN_ID = 0x1000


def auxpow_active(base_header):
    height_allows_auxpow = base_header['block_height'] >= MIN_AUXPOW_HEIGHT
    version_allows_auxpow = base_header['version'] & BLOCK_VERSION_AUXPOW_BIT

    return height_allows_auxpow and version_allows_auxpow


def get_chain_id(base_header):
    return base_header['version'] >> 16


# If expect_trailing_data, returns start position of trailing data
def deserialize_auxpow_header(base_header, s, expect_trailing_data=False, start_position=0):
    if len(s) - start_position == 0 and not expect_trailing_data:
        return None

    auxpow_header = {}

    # Chain ID is the top 16 bits of the 32-bit version.
    auxpow_header['chain_id'] = get_chain_id(base_header)

    # The parent coinbase transaction is first.
    # Deserialize it and save the trailing data.
    parent_coinbase_tx = Transaction(None,
                                     expect_trailing_data=True,
                                     raw_bytes=s,
                                     expect_trailing_bytes=True,
                                     copy_input=False,
                                     start_position=start_position)
    parent_coinbase_tx_dict, start_position = fast_tx_deserialize(parent_coinbase_tx)
    auxpow_header['parent_coinbase_tx'] = parent_coinbase_tx

    # Next is the parent block hash.  According to the Bitcoin.it wiki,
    # this field is not actually consensus-critical.  So we don't save it.
    start_position = start_position + 32

    # The coinbase and chain merkle branches/indices are next.
    # Deserialize them and save the trailing data.
    auxpow_header['coinbase_merkle_branch'], \
        auxpow_header['coinbase_merkle_index'], \
        start_position = deserialize_merkle_branch(s, start_position=start_position)

    auxpow_header['chain_merkle_branch'], \
        auxpow_header['chain_merkle_index'], \
        start_position = deserialize_merkle_branch(s, start_position=start_position)

    # Finally there's the parent header.  Deserialize it, along with any
    # trailing data if requested.
    if expect_trailing_data:
        auxpow_header['parent_header'], \
            start_position = electrum.blockchain.deserialize_header(s, 1, expect_trailing_data=expect_trailing_data,
                                                                    start_position=start_position)
    else:
        auxpow_header['parent_header'] = electrum.blockchain.deserialize_header(s, 1,
                                                                                expect_trailing_data=expect_trailing_data,
                                                                                start_position=start_position)
    # The parent block header doesn't have any block height,
    # so delete that field.  (We used 1 as a dummy value above.)
    del auxpow_header['parent_header']['block_height']

    if expect_trailing_data:
        return auxpow_header, start_position

    return auxpow_header

# Copied from merkle_branch_from_string in https://github.com/electrumalt/electrum-doge/blob/f74312822a14f59aa8d50186baff74cade449ccd/lib/blockchain.py#L622
# Returns list of hashes, merkle index, and position of trailing data in s
# TODO: Audit this function carefully.
def deserialize_merkle_branch(s, start_position=0):
    vds = BCDataStream()
    vds.input = s
    vds.read_cursor = start_position
    hashes = []
    n_hashes = vds.read_compact_size()
    for i in range(n_hashes):
        _hash = vds.read_bytes(32)
        hashes.append(hash_encode(_hash))
    index = vds.read_int32()
    return hashes, index, vds.read_cursor


# TODO: This is dead code that will probably be removed.
def strip_auxpow_headers(index, chunk):
    result = bytearray()
    trailing_data = chunk

    i = 0
    while len(trailing_data) > 0:
        header, trailing_data = electrum.blockchain.deserialize_header(
            trailing_data,
            index * constants.net.POW_BLOCK_ADJUST + i,
            expect_trailing_data=True
        )
        result.extend(bfh(electrum.blockchain.serialize_header(header)))
        i = i + 1

    return bytes(result)


def hash_parent_header(header):
    if not auxpow_active(header):
        return electrum.blockchain.hash_header(header)

    verify_auxpow(header)

    return electrum.blockchain.hash_header(header['auxpow']['parent_header'])

# Reimplementation of btcutils.check_merkle_branch from Electrum-DOGE.
# btcutils seems to have an unclear license and no obvious Git repo, so it
# seemed wiser to re-implement.
# This re-implementation is roughly based on libdohj's calculateMerkleRoot.
def calculate_merkle_root(leaf, merkle_branch, index):
    target = hash_decode(leaf)
    mask = index

    for merkle_step in merkle_branch:
        if mask & 1 == 0: # 0 means it goes on the right
            data_to_hash = target + hash_decode(merkle_step)
        else:
            data_to_hash = hash_decode(merkle_step) + target
        target = sha256d(data_to_hash)
        mask = mask >> 1

    return hash_encode(target)

# Copied from Electrum-DOGE
# TODO: Audit this function carefully.
# https://github.com/kR105/i0coin/compare/bitcoin:master...master#diff-610df86e65fce009eb271c2a4f7394ccR262
def calc_merkle_index(chain_id, nonce, merkle_size):
    rand = nonce
    rand = (rand * 1103515245 + 12345) & 0xffffffff
    rand += chain_id
    rand = (rand * 1103515245 + 12345) & 0xffffffff
    return rand % merkle_size

# Copied from Electrum-DOGE
# TODO: Audit this function carefully.
def verify_auxpow(header):
    auxhash = electrum.blockchain.hash_header(header)
    auxpow = header['auxpow']

    parent_block = auxpow['parent_header']
    coinbase = auxpow['parent_coinbase_tx']
    coinbase_hash = fast_txid(coinbase)

    chain_merkle_branch = auxpow['chain_merkle_branch']
    chain_index = auxpow['chain_merkle_index']

    coinbase_merkle_branch = auxpow['coinbase_merkle_branch']
    coinbase_index = auxpow['coinbase_merkle_index']

    #if (get_chain_id(parent_block) == chain_id)
    #  return error("Aux POW parent has our chain ID");

    if (get_chain_id(parent_block) == CHAIN_ID):
        raise Exception('Aux POW parent has our chain ID')

    #// Check that the chain merkle root is in the coinbase
    #uint256 nRootHash = CBlock::CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    #vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    #std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

    # Check that the chain merkle root is in the coinbase
    root_hash = calculate_merkle_root(auxhash, chain_merkle_branch, chain_index)

    # Check that we are in the parent block merkle tree
    # if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != parentBlock.hashMerkleRoot)
    #    return error("Aux POW merkle root incorrect");
    if (calculate_merkle_root(coinbase_hash, coinbase_merkle_branch, coinbase_index) != parent_block['merkle_root']):
        raise Exception('Aux POW merkle root incorrect')

    #// Check that the same work is not submitted twice to our chain.
    #//

    #CScript::const_iterator pcHead =
    #std::search(script.begin(), script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));

    #CScript::const_iterator pc =
    #std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

    #if (pc == script.end())
    #return error("Aux POW missing chain merkle root in parent coinbase");

    script = coinbase.inputs()[0]['scriptSig']
    pos = script.find(root_hash)

    # todo: if pos == -1 ??
    if pos == -1:
        raise Exception('Aux POW missing chain merkle root in parent coinbase')

    #todo: make sure only submitted once
    #if (pcHead != script.end())
    #{
    #// Enforce only one chain merkle root by checking that a single instance of the merged
    #// mining header exists just before.
    #if (script.end() != std::search(pcHead + 1, script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader)))
    #return error("Multiple merged mining headers in coinbase");
    #if (pcHead + sizeof(pchMergedMiningHeader) != pc)
    #return error("Merged mining header is not just before chain merkle root");
    #}
    #else
    #{
    #// For backward compatibility.
    #// Enforce only one chain merkle root by checking that it starts early in the coinbase.
    #// 8-12 bytes are enough to encode extraNonce and nBits.
    #if (pc - script.begin() > 20)
    #return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
    #}


    #// Ensure we are at a deterministic point in the merkle leaves by hashing
    #// a nonce and our chain ID and comparing to the index.
    #pc += vchRootHash.size();
    #if (script.end() - pc < 8)
    #return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");

    pos = pos + len(root_hash)
    if (len(script) - pos < 8):
        raise Exception('Aux POW missing chain merkle tree size and nonce in parent coinbase')

    #int nSize;
    #memcpy(&nSize, &pc[0], 4);
    #if (nSize != (1 << vChainMerkleBranch.size()))
    #return error("Aux POW merkle branch size does not match parent coinbase");

    def hex_to_int(s):
        b = bytes.fromhex(s)
        b_reversed = b[::-1]
        h = binascii.hexlify(b_reversed).decode('ascii')
        return int(h, 16)

    size = hex_to_int(script[pos:pos+8])
    nonce = hex_to_int(script[pos+8:pos+16])

    #print 'size',size
    #print 'nonce',nonce
    #print '(1 << len(chain_merkle_branch)))', (1 << len(chain_merkle_branch))
    #size = hex_to_int(script[pos:pos+4])
    #nonce = hex_to_int(script[pos+4:pos+8])

    if (size != (1 << len(chain_merkle_branch))):
        raise Exception('Aux POW merkle branch size does not match parent coinbase')

    #int nNonce;
    #memcpy(&nNonce, &pc[4], 4);
    #// Choose a pseudo-random slot in the chain merkle tree
    #// but have it be fixed for a size/nonce/chain combination.
    #//
    #// This prevents the same work from being used twice for the
    #// same chain while reducing the chance that two chains clash
    #// for the same slot.
    #unsigned int rand = nNonce;
    #rand = rand * 1103515245 + 12345;
    #rand += nChainID;
    #rand = rand * 1103515245 + 12345;

    #if (nChainIndex != (rand % nSize))
    #return error("Aux POW wrong index");

    index = calc_merkle_index(CHAIN_ID, nonce, size)
    #print 'index', index

    if (chain_index != index):
        raise Exception('Aux POW wrong index')


# This is calculated the same as the Transaction.txid() method, but doesn't
# reserialize it.
def fast_txid(tx):
    return bh2u(sha256d(tx.raw_bytes)[::-1])


# Used by fast_tx_deserialize
def stub_parse_output(vds, i):
    vds.read_int64() # d['value']
    vds.read_bytes(vds.read_compact_size()) # scriptPubKey
    return {'type': TYPE_SCRIPT, 'address': None, 'value': 0}


# This is equivalent to tx.deserialize(), but doesn't parse outputs.
def fast_tx_deserialize(tx):
    # Monkeypatch output address parsing with a stub, since we only care about
    # inputs.
    real_parse_output, transaction.parse_output = transaction.parse_output, stub_parse_output

    try:
        result = tx.deserialize()
    finally:
        # Restore the real output address parser.
        transaction.parse_output = real_parse_output

    return result
