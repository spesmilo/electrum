#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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
from threading import Lock
import hashlib

# from .bitcoin import Hash, hash_encode
from .transaction import Transaction
from .util import ThreadJob, bh2u


class Synchronizer(ThreadJob):
    '''The synchronizer keeps the wallet up-to-date with its set of
    addresses and their transactions.  It subscribes over the network
    to wallet addresses, gets the wallet to generate new addresses
    when necessary, requests the transaction history of any addresses
    we don't have the full history of, and requests binary transaction
    data of any transactions the wallet doesn't have.

    External interface: __init__() and add() member functions.
    '''

    def __init__(self, wallet, network):
        self.wallet = wallet
        self.network = network
        self.new_addresses = set()
        # Entries are (tx_hash, tx_height) tuples
        self.requested_tx = {}
        self.requested_histories = {}
        self.requested_addrs = set()
        self.lock = Lock()

        self.initialized = False
        self.initialize()

    def parse_response(self, response):
        if response.get('error'):
            self.print_error("response error:", response)
            return None, None
        return response['params'], response['result']

    def is_up_to_date(self):
        return (not self.requested_tx and not self.requested_histories
                and not self.requested_addrs)

    def release(self):
        self.network.unsubscribe(self.on_address_status)

    def add(self, address):
        '''This can be called from the proxy or GUI threads.'''
        with self.lock:
            self.new_addresses.add(address)

    def subscribe_to_addresses(self, addresses):
        if addresses:
            self.requested_addrs |= addresses
            self.network.subscribe_to_addresses(addresses, self.on_address_status)

    def get_status(self, h):
        if not h:
            return None
        status = ''
        for tx_hash, height in h:
            status += tx_hash + ':%d:' % height
        return bh2u(hashlib.sha256(status.encode('ascii')).digest())

    def on_address_status(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, result = self.parse_response(response)
        if not params:
            return
        addr = params[0]
        history = self.wallet.history.get(addr, [])
        if self.get_status(history) != result:
            if self.requested_histories.get(addr) is None:
                self.requested_histories[addr] = result
                self.network.request_address_history(addr, self.on_address_history)
        # remove addr from list only after it is added to requested_histories
        if addr in self.requested_addrs:  # Notifications won't be in
            self.requested_addrs.remove(addr)

    def on_address_history(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, result = self.parse_response(response)
        if not params:
            return
        addr = params[0]
        server_status = self.requested_histories.get(addr)
        if server_status is None:
            self.print_error("receiving history (unsolicited)", addr, len(result))
            return
        self.print_error("receiving history", addr, len(result))
        hashes = set(map(lambda item: item['tx_hash'], result))
        hist = list(map(lambda item: (item['tx_hash'], item['height']), result))
        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result]
        tx_fees = dict(filter(lambda x:x[1] is not None, tx_fees))
        # Note if the server hasn't been patched to sort the items properly
        if hist != sorted(hist, key=lambda x:x[1]):
            self.network.interface.print_error("serving improperly sorted address histories")
        # Check that txids are unique
        if len(hashes) != len(result):
            self.print_error("error: server history has non-unique txids: %s"% addr)
        # Check that the status corresponds to what was announced
        elif self.get_status(hist) != server_status:
            self.print_error("error: status mismatch: %s" % addr)
        else:
            # Store received history
            self.wallet.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            self.request_missing_txs(hist)
        # Remove request; this allows up_to_date to be True
        self.requested_histories.pop(addr)

    def tx_response(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, result = self.parse_response(response)
        if not params:
            return
        tx_hash = params[0]
        #assert tx_hash == hash_encode(Hash(bytes.fromhex(result)))
        tx = Transaction(result)
        try:
            tx.deserialize()
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return
        tx_height = self.requested_tx.pop(tx_hash)
        self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
        self.print_error("received tx %s height: %d bytes: %d" %
                         (tx_hash, tx_height, len(tx.raw)))
        # callbacks
        self.network.trigger_callback('new_transaction', tx)
        if not self.requested_tx:
            self.network.trigger_callback('updated')


    def request_missing_txs(self, hist):
        # "hist" is a list of [tx_hash, tx_height] lists
        requests = []
        for tx_hash, tx_height in hist:
            if tx_hash in self.requested_tx:
                continue
            if tx_hash in self.wallet.transactions:
                continue
            requests.append(('blockchain.transaction.get', [tx_hash]))
            self.requested_tx[tx_hash] = tx_height
        self.network.send(requests, self.tx_response)


    def initialize(self):
        '''Check the initial state of the wallet.  Subscribe to all its
        addresses, and request any transactions in its address history
        we don't have.
        '''
        for history in self.wallet.history.values():
            # Old electrum servers returned ['*'] when all history for
            # the address was pruned.  This no longer happens but may
            # remain in old wallets.
            if history == ['*']:
                continue
            self.request_missing_txs(history)

        if self.requested_tx:
            self.print_error("missing tx", self.requested_tx)
        self.subscribe_to_addresses(set(self.wallet.get_addresses()))
        self.initialized = True

    def run(self):
        '''Called from the network proxy thread main loop.'''
        # 1. Create new addresses
        self.wallet.synchronize()

        # 2. Subscribe to new addresses
        with self.lock:
            addresses = self.new_addresses
            self.new_addresses = set()
        self.subscribe_to_addresses(addresses)

        # 3. Detect if situation has changed
        up_to_date = self.is_up_to_date()
        if up_to_date != self.wallet.is_up_to_date():
            self.wallet.set_up_to_date(up_to_date)
            self.network.trigger_callback('updated')
