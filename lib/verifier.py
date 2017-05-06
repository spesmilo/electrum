#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2012 Thomas Voegtlin
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


from util import ThreadJob
from bitcoin import *


class SPV(ThreadJob):
    """ Simple Payment Verification """

    def __init__(self, network, wallet):
        self.wallet = wallet
        self.network = network
        # Keyed by tx hash.  Value is None if the merkle branch was
        # requested, and the merkle root once it has been verified
        self.merkle_roots = {}

    def run(self):
        lh = self.network.get_local_height()
        unverified = self.wallet.get_unverified_txs()
        for tx_hash, tx_height in unverified.items():
            # do not request merkle branch before headers are available
            if tx_height>0 and tx_hash not in self.merkle_roots and tx_height <= lh:
                request = ('blockchain.transaction.get_merkle',
                           [tx_hash, tx_height])
                self.network.send([request], self.verify_merkle)
                self.print_error('requested merkle', tx_hash)
                self.merkle_roots[tx_hash] = None

    def verify_merkle(self, r):
        if r.get('error'):
            self.print_error('received an error:', r)
            return

        params = r['params']
        merkle = r['result']

        # Verify the hash of the server-provided merkle branch to a
        # transaction matches the merkle root of its block
        tx_hash = params[0]
        tx_height = merkle.get('block_height')
        pos = merkle.get('pos')
        merkle_root = self.hash_merkle_root(merkle['merkle'], tx_hash, pos)
        header = self.network.get_header(tx_height)
        if not header or header.get('merkle_root') != merkle_root:
            # FIXME: we should make a fresh connection to a server to
            # recover from this, as this TX will now never verify
            self.print_error("merkle verification failed for", tx_hash)
            return

        # we passed all the tests
        self.merkle_roots[tx_hash] = merkle_root
        self.print_error("verified %s" % tx_hash)
        self.wallet.add_verified_tx(tx_hash, (tx_height, header.get('timestamp'), pos))


    def hash_merkle_root(self, merkle_s, target_hash, pos):
        h = hash_decode(target_hash)
        for i in range(len(merkle_s)):
            item = merkle_s[i]
            h = Hash( hash_decode(item) + h ) if ((pos >> i) & 1) else Hash( h + hash_decode(item) )
        return hash_encode(h)


    def undo_verifications(self, height):
        tx_hashes = self.wallet.undo_verifications(height)
        for tx_hash in tx_hashes:
            self.print_error("redoing", tx_hash)
            self.merkle_roots.pop(tx_hash, None)
