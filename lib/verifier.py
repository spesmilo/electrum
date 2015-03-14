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


import threading, time, Queue, os, sys, shutil

import util
from util import user_dir, print_error
from bitcoin import *




class TxVerifier(util.DaemonThread):
    """ Simple Payment Verification """

    def __init__(self, network, storage):
        util.DaemonThread.__init__(self)
        self.storage = storage
        self.network = network
        self.transactions    = {}                                 # requested verifications (with height sent by the requestor)
        self.verified_tx     = storage.get('verified_tx3',{})      # height, timestamp of verified transactions
        self.merkle_roots    = storage.get('merkle_roots',{})      # hashed by me
        self.lock = threading.Lock()
        self.queue = Queue.Queue()

    def get_confirmations(self, tx):
        """ return the number of confirmations of a monitored transaction. """
        with self.lock:
            if tx in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx]
                conf = (self.network.get_local_height() - height + 1)
                if conf <= 0: timestamp = None
            elif tx in self.transactions:
                conf = -1
                timestamp = None
            else:
                conf = 0
                timestamp = None

        return conf, timestamp


    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            x = self.verified_tx.get(tx_hash)
            y = self.transactions.get(tx_hash)
        if x:
            height, timestamp, pos = x
            return height, pos
        elif y:
            return y, 0
        else:
            return 1e12, 0


    def get_height(self, tx_hash):
        with self.lock:
            v = self.verified_tx.get(tx_hash)
        height = v[0] if v else None
        return height


    def add(self, tx_hash, tx_height):
        """ add a transaction to the list of monitored transactions. """
        assert tx_height > 0
        with self.lock:
            if tx_hash not in self.transactions.keys():
                self.transactions[tx_hash] = tx_height

    def run(self):
        requested_merkle = []
        while self.is_running():
            # request missing tx
            for tx_hash, tx_height in self.transactions.items():
                if tx_hash not in self.verified_tx:
                    # do not request merkle branch before headers are available
                    if tx_height > self.network.get_local_height():
                        continue
                    if self.merkle_roots.get(tx_hash) is None and tx_hash not in requested_merkle:
                        if self.network.send([ ('blockchain.transaction.get_merkle',[tx_hash, tx_height]) ], self.queue.put):
                            print_error('requesting merkle', tx_hash)
                            requested_merkle.append(tx_hash)
            try:
                r = self.queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            if not r:
                continue

            if r.get('error'):
                print_error('Verifier received an error:', r)
                continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r['result']

            if method == 'blockchain.transaction.get_merkle':
                tx_hash = params[0]
                self.verify_merkle(tx_hash, result)

        self.print_error("stopped")


    def verify_merkle(self, tx_hash, result):
        tx_height = result.get('block_height')
        pos = result.get('pos')
        merkle_root = self.hash_merkle_root(result['merkle'], tx_hash, pos)
        header = self.network.get_header(tx_height)
        if not header: return
        if header.get('merkle_root') != merkle_root:
            print_error("merkle verification failed for", tx_hash)
            return

        # we passed all the tests
        self.merkle_roots[tx_hash] = merkle_root
        timestamp = header.get('timestamp')
        with self.lock:
            self.verified_tx[tx_hash] = (tx_height, timestamp, pos)
        print_error("verified %s"%tx_hash)
        self.storage.put('verified_tx3', self.verified_tx, True)
        self.network.trigger_callback('updated')


    def hash_merkle_root(self, merkle_s, target_hash, pos):
        h = hash_decode(target_hash)
        for i in range(len(merkle_s)):
            item = merkle_s[i]
            h = Hash( hash_decode(item) + h ) if ((pos >> i) & 1) else Hash( h + hash_decode(item) )
        return hash_encode(h)



    def undo_verifications(self, height):
        with self.lock:
            items = self.verified_tx.items()[:]
        for tx_hash, item in items:
            tx_height, timestamp, pos = item
            if tx_height >= height:
                print_error("redoing", tx_hash)
                with self.lock:
                    self.verified_tx.pop(tx_hash)
                    if tx_hash in self.merkle_roots:
                        self.merkle_roots.pop(tx_hash)
