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


import threading
import time
import Queue

import bitcoin
import util
from util import print_error
from transaction import Transaction


class WalletSynchronizer(util.DaemonThread):

    def __init__(self, wallet, network):
        util.DaemonThread.__init__(self)
        self.wallet = wallet
        self.network = network
        self.was_updated = True
        self.lock = threading.Lock()
        self.queue = Queue.Queue()
        self.address_queue = Queue.Queue()

    def add(self, address):
        self.address_queue.put(address)

    def subscribe_to_addresses(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.network.send(messages, self.queue.put)

    def run(self):
        while self.is_running():
            if not self.network.is_connected():
                time.sleep(0.1)
                continue
            self.run_interface()
        self.print_error("stopped")

    def run_interface(self):
        #print_error("synchronizer: connected to", self.network.get_parameters())

        requested_tx = []
        missing_tx = []
        requested_histories = {}

        # request any missing transactions
        for history in self.wallet.history.values():
            if history == ['*']: continue
            for tx_hash, tx_height in history:
                if self.wallet.transactions.get(tx_hash) is None and (tx_hash, tx_height) not in missing_tx:
                    missing_tx.append( (tx_hash, tx_height) )

        if missing_tx:
            print_error("missing tx", missing_tx)

        # subscriptions
        self.subscribe_to_addresses(self.wallet.addresses(True))

        while self.is_running():

            # 1. create new addresses
            self.wallet.synchronize()

            # request missing addresses
            new_addresses = []
            while True:
                try:
                    addr = self.address_queue.get(block=False)
                except Queue.Empty:
                    break
                new_addresses.append(addr)
            if new_addresses:
                self.subscribe_to_addresses(new_addresses)

            # request missing transactions
            for tx_hash, tx_height in missing_tx:
                if (tx_hash, tx_height) not in requested_tx:
                    self.network.send([ ('blockchain.transaction.get',[tx_hash, tx_height]) ], self.queue.put)
                    requested_tx.append( (tx_hash, tx_height) )
            missing_tx = []

            # detect if situation has changed
            if self.network.is_up_to_date() and self.queue.empty():
                if not self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(True)
                    self.was_updated = True
            else:
                if self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(False)
                    self.was_updated = True

            if self.was_updated:
                self.network.trigger_callback('updated')
                self.was_updated = False

            # 2. get a response
            try:
                r = self.queue.get(timeout=0.1)
            except Queue.Empty:
                continue

            # 3. process response
            method = r['method']
            params = r['params']
            result = r.get('result')
            error = r.get('error')
            if error:
                print_error("error", r)
                continue

            if method == 'blockchain.address.subscribe':
                addr = params[0]
                if self.wallet.get_status(self.wallet.get_history(addr)) != result:
                    if requested_histories.get(addr) is None:
                        self.network.send([('blockchain.address.get_history', [addr])], self.queue.put)
                        requested_histories[addr] = result

            elif method == 'blockchain.address.get_history':
                addr = params[0]
                print_error("receiving history", addr, result)
                if result == ['*']:
                    assert requested_histories.pop(addr) == '*'
                    self.wallet.receive_history_callback(addr, result)
                else:
                    hist = []
                    # check that txids are unique
                    txids = []
                    for item in result:
                        tx_hash = item['tx_hash']
                        if tx_hash not in txids:
                            txids.append(tx_hash)
                            hist.append( (tx_hash, item['height']) )

                    if len(hist) != len(result):
                        raise Exception("error: server sent history with non-unique txid", result)

                    # check that the status corresponds to what was announced
                    rs = requested_histories.pop(addr)
                    if self.wallet.get_status(hist) != rs:
                        raise Exception("error: status mismatch: %s"%addr)

                    # store received history
                    self.wallet.receive_history_callback(addr, hist)

                    # request transactions that we don't have
                    for tx_hash, tx_height in hist:
                        if self.wallet.transactions.get(tx_hash) is None:
                            if (tx_hash, tx_height) not in requested_tx and (tx_hash, tx_height) not in missing_tx:
                                missing_tx.append( (tx_hash, tx_height) )

            elif method == 'blockchain.transaction.get':
                tx_hash = params[0]
                tx_height = params[1]
                assert tx_hash == bitcoin.hash_encode(bitcoin.Hash(result.decode('hex')))
                tx = Transaction.deserialize(result)
                self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
                self.was_updated = True
                requested_tx.remove( (tx_hash, tx_height) )
                print_error("received tx:", tx_hash, len(tx.raw))

            else:
                print_error("Error: Unknown message:" + method + ", " + repr(params) + ", " + repr(result) )

            if self.was_updated and not requested_tx:
                self.network.trigger_callback('updated')
                # Updated gets called too many times from other places as well; if we use that signal we get the notification three times
                self.network.trigger_callback("new_transaction")
                self.was_updated = False
