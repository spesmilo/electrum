#!/usr/bin/env python3
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
import traceback

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
        self.requested_hashes = set()
        self.h2addr = {}
        self.lock = Lock()
        self.initialize()

    def parse_response(self, response):
        error = True
        try:
            if not response: return None, None, error
            error = response.get('error')
            return response['params'], response.get('result'), error
        finally:
            if error:
                self.print_error("response error:", response)

    def is_up_to_date(self):
        return (not self.requested_tx and not self.requested_histories
                and not self.requested_hashes)

    def release(self):
        self.network.unsubscribe(self.on_address_status)

    def add(self, address):
        '''This can be called from the proxy or GUI threads.'''
        with self.lock:
            self.new_addresses.add(address)

    def subscribe_to_addresses(self, addresses):
        hashes = [addr.to_scripthash_hex() for addr in addresses]
        # Keep a hash -> address mapping
        self.h2addr.update({h:addr for h, addr in zip(hashes, addresses)})
        self.network.subscribe_to_scripthashes(hashes, self.on_address_status)
        self.requested_hashes |= set(hashes)

    def get_status(self, h):
        if not h:
            return None
        status = ''
        for tx_hash, height in h:
            status += tx_hash + ':%d:' % height
        return bh2u(hashlib.sha256(status.encode('ascii')).digest())

    def on_address_status(self, response):
        params, result, error = self.parse_response(response)
        if error:
            return
        scripthash = params[0]
        addr = self.h2addr.get(scripthash, None)
        if not addr:
            return  # Bad server response?
        history = self.wallet.get_address_history(addr)
        if self.get_status(history) != result:
            if self.requested_histories.get(scripthash) is None:
                self.requested_histories[scripthash] = result
                self.network.request_scripthash_history(scripthash,
                                                        self.on_address_history)
        # remove addr from list only after it is added to requested_histories
        self.requested_hashes.discard(scripthash)  # Notifications won't be in

    def on_address_history(self, response):
        params, result, error = self.parse_response(response)
        if error:
            return
        scripthash = params[0]
        addr = self.h2addr.get(scripthash, None)
        if not addr or not scripthash in self.requested_histories:
            return  # Bad server response?
        self.print_error("receiving history {} {}".format(addr, len(result)))
        # Remove request; this allows up_to_date to be True
        server_status = self.requested_histories.pop(scripthash)
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
            self.print_error("error: server history has non-unique txids: {}"
                             .format(addr))
        # Check that the status corresponds to what was announced
        elif self.get_status(hist) != server_status:
            self.print_error("error: status mismatch: {}".format(addr))
        else:
            # Store received history
            self.wallet.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            self.request_missing_txs(hist)

    def tx_response(self, response):
        params, result, error = self.parse_response(response)
        tx_hash = params[0] or ''
        # unconditionally pop. so we don't end up in a "not up to date" state
        # on bad server reply or reorg.
        # see Electrum commit 7b8114f865f644c5611c3bb849c4f4fc6ce9e376 fix#5122
        tx_height = self.requested_tx.pop(tx_hash, 0)
        if error:
            # was some response error. note we popped the tx already
            # we assume a blockchain reorg happened and tx disappeared.
            self.print_error("error for tx_hash {}, skipping".format(tx_hash))
            return
        try:
            tx = Transaction(result)
            tx.deserialize()
        except Exception:
            traceback.print_exc()
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return
        # NB: this is slow, and I am not sure what bug it fixes. Commenting out.
        #if tx_hash != tx.txid():
        #    self.print_error("received tx does not match expected txid ({} != {}), skipping"
        #                     .format(tx_hash, tx.txid()))
        #    return
        self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
        self.print_error("received tx %s height: %d bytes: %d" %
                         (tx_hash, tx_height, len(tx.raw)))
        # callbacks
        self.network.trigger_callback('new_transaction', tx, self.wallet)
        if not self.requested_tx:
            # New in 3.3.6: 'updated' callbacks from synchronizer always specify which wallet, so GUI can ignore irrelevant 'updated' events
            self.network.trigger_callback('updated', self.wallet)


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
        # FIXME: encapsulation
        for history in self.wallet._history.values():
            self.request_missing_txs(history)

        if self.requested_tx:
            self.print_error("missing tx", self.requested_tx)
        self.subscribe_to_addresses(self.wallet.get_addresses())

    def run(self):
        '''Called from the network proxy thread main loop.'''
        # 1. Create new addresses
        self.wallet.synchronize()

        # 2. Subscribe to new addresses
        with self.lock:
            addresses = self.new_addresses
            self.new_addresses = set()
        if addresses:
            self.subscribe_to_addresses(addresses)

        # 3. Detect if situation has changed
        up_to_date = self.is_up_to_date()
        if up_to_date != self.wallet.is_up_to_date():
            self.wallet.set_up_to_date(up_to_date)
            # New in 3.3.6: 'updated' callbacks from synchronizer always specify which wallet, so GUI can ignore irrelevant 'updated' events
            self.network.trigger_callback('updated', self.wallet)
