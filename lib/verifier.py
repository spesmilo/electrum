#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
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
            if tx_hash not in self.merkle_roots and tx_height <= lh:
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
