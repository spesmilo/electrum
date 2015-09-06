#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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


from threading import Lock

from bitcoin import Hash, hash_encode
from transaction import Transaction
from util import print_error, print_msg, ThreadJob


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
        self.requested_tx = set()
        self.requested_histories = {}
        self.requested_addrs = set()
        self.lock = Lock()
        self.initialize()

    def parse_response(self, response):
        if response.get('error'):
            self.print_error("response error:", response)
            return None, None
        return response['params'], response['result']

    def is_up_to_date(self):
        return (not self.requested_tx and not self.requested_histories
                and not self.requested_addrs)

    def add(self, address):
        '''This can be called from the proxy or GUI threads.'''
        with self.lock:
            self.new_addresses.add(address)

    def subscribe_to_addresses(self, addresses):
        if addresses:
            self.requested_addrs |= addresses
            msgs = map(lambda addr: ('blockchain.address.subscribe', [addr]),
                       addresses)
            self.network.send(msgs, self.addr_subscription_response)

    def addr_subscription_response(self, response):
        params, result = self.parse_response(response)
        if not params:
            return
        addr = params[0]
        if addr in self.requested_addrs:  # Notifications won't be in
            self.requested_addrs.remove(addr)
        history = self.wallet.get_address_history(addr)
        if self.wallet.get_status(history) != result:
            if self.requested_histories.get(addr) is None:
                self.network.send([('blockchain.address.get_history', [addr])],
                                  self.addr_history_response)
                self.requested_histories[addr] = result

    def addr_history_response(self, response):
        params, result = self.parse_response(response)
        if not params:
            return
        addr = params[0]
        self.print_error("receiving history", addr, len(result))
        server_status = self.requested_histories.pop(addr)

        # Check that txids are unique
        hashes = set(map(lambda item: item['tx_hash'], result))
        if len(hashes) != len(result):
            self.print_error("error: server history has non-unique txids: %s"% addr)
            return

        # Check that the status corresponds to what was announced
        hist = map(lambda item: (item['tx_hash'], item['height']), result)
        # Note if the server hasn't been patched to sort the items properly
        if hist != sorted(hist, key=lambda x:x[1]):
            self.network.interface.print_error("serving improperly sorted "
                                               "address histories")
        if self.wallet.get_status(hist) != server_status:
            self.print_error("error: status mismatch: %s" % addr)
            return

        # Store received history
        self.wallet.receive_history_callback(addr, hist)

        # Request transactions we don't have
        self.request_missing_txs(hist)

    def tx_response(self, response):
        params, result = self.parse_response(response)
        if not params:
            return
        tx_hash, tx_height = params
        assert tx_hash == hash_encode(Hash(result.decode('hex')))
        tx = Transaction(result)
        try:
            tx.deserialize()
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return
        self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
        self.requested_tx.remove((tx_hash, tx_height))
        self.print_error("received tx %s height: %d bytes: %d" %
                         (tx_hash, tx_height, len(tx.raw)))
        # callbacks
        self.network.trigger_callback('new_transaction', (tx,))
        if not self.requested_tx:
            self.network.trigger_callback('updated')


    def request_missing_txs(self, hist):
        # "hist" is a list of [tx_hash, tx_height] lists
        missing = set()
        for tx_hash, tx_height in hist:
            if self.wallet.transactions.get(tx_hash) is None:
                missing.add((tx_hash, tx_height))
        missing -= self.requested_tx
        if missing:
            requests = [('blockchain.transaction.get', tx) for tx in missing]
            self.network.send(requests, self.tx_response)
            self.requested_tx |= missing

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
        self.subscribe_to_addresses(set(self.wallet.addresses(True)))

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
            if up_to_date:
                self.wallet.save_transactions()
            self.network.trigger_callback('updated')
