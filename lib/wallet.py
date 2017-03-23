#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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
Wallet classes:
  - Imported_Wallet: imported address, no keystore
  - Standard_Wallet: one keystore, P2PKH
  - Multisig_Wallet: several keystores, P2SH

"""

import os
import hashlib
import ast
import threading
import random
import time
import json
import copy
import re
import stat
from functools import partial
from collections import namedtuple, defaultdict

from i18n import _
from util import NotEnoughFunds, PrintError, UserCancelled, profiler

from bitcoin import *
from version import *
from keystore import load_keystore, Hardware_KeyStore
from storage import multisig_type

import transaction
from transaction import Transaction
from plugins import run_hook
import bitcoin
import coinchooser
from synchronizer import Synchronizer
from verifier import SPV
from mnemonic import Mnemonic

import paymentrequest
from paymentrequest import InvoiceStore
from contacts import Contacts


TX_STATUS = [
    _('Replaceable'),
    _('Unconfirmed parent'),
    _('Low fee'),
    _('Unconfirmed'),
    _('Not Verified'),
]



class Abstract_Wallet(PrintError):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    max_change_outputs = 3

    def __init__(self, storage):
        self.electrum_version = ELECTRUM_VERSION
        self.storage = storage
        self.network = None
        # verifier (SPV) and synchronizer are started in start_threads
        self.synchronizer = None
        self.verifier = None

        self.gap_limit_for_change = 6 # constant
        # saved fields
        self.use_change            = storage.get('use_change', True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = set(storage.get('frozen_addresses',[]))
        self.stored_height         = storage.get('stored_height', 0)       # last known height (for offline mode)
        self.history               = storage.get('addr_history',{})        # address -> list(txid, height)

        self.load_keystore()
        self.load_addresses()
        self.load_transactions()
        self.build_reverse_history()

        # load requests
        self.receive_requests = self.storage.get('payment_requests', {})

        # Transactions pending verification.  A map from tx hash to transaction
        # height.  Access is not contended so no lock is needed.
        self.unverified_tx = defaultdict(int)

        # Verified transactions.  Each value is a (height, timestamp, block_pos) tuple.  Access with self.lock.
        self.verified_tx = storage.get('verified_tx3', {})

        # there is a difference between wallet.up_to_date and interface.is_up_to_date()
        # interface.is_up_to_date() returns true when all requests have been answered and processed
        # wallet.up_to_date is true when the wallet is synchronized (stronger requirement)
        self.up_to_date = False
        self.lock = threading.Lock()
        self.transaction_lock = threading.Lock()

        self.check_history()

        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

        # invoices and contacts
        self.invoices = InvoiceStore(self.storage)
        self.contacts = Contacts(self.storage)


    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def get_master_public_key(self):
        return None

    @profiler
    def load_transactions(self):
        self.txi = self.storage.get('txi', {})
        self.txo = self.storage.get('txo', {})
        self.tx_fees = self.storage.get('tx_fees', {})
        self.pruned_txo = self.storage.get('pruned_txo', {})
        tx_list = self.storage.get('transactions', {})
        self.transactions = {}
        for tx_hash, raw in tx_list.items():
            tx = Transaction(raw)
            self.transactions[tx_hash] = tx
            if self.txi.get(tx_hash) is None and self.txo.get(tx_hash) is None and (tx_hash not in self.pruned_txo.values()):
                self.print_error("removing unreferenced tx", tx_hash)
                self.transactions.pop(tx_hash)

    @profiler
    def save_transactions(self, write=False):
        with self.transaction_lock:
            tx = {}
            for k,v in self.transactions.items():
                tx[k] = str(v)
            self.storage.put('transactions', tx)
            self.storage.put('txi', self.txi)
            self.storage.put('txo', self.txo)
            self.storage.put('tx_fees', self.tx_fees)
            self.storage.put('pruned_txo', self.pruned_txo)
            self.storage.put('addr_history', self.history)
            if write:
                self.storage.write()

    def clear_history(self):
        with self.transaction_lock:
            self.txi = {}
            self.txo = {}
            self.tx_fees = {}
            self.pruned_txo = {}
        self.save_transactions()
        with self.lock:
            self.history = {}
            self.tx_addr_hist = {}

    @profiler
    def build_reverse_history(self):
        self.tx_addr_hist = {}
        for addr, hist in self.history.items():
            for tx_hash, h in hist:
                s = self.tx_addr_hist.get(tx_hash, set())
                s.add(addr)
                self.tx_addr_hist[tx_hash] = s

    @profiler
    def check_history(self):
        save = False
        for addr, hist in self.history.items():
            if not self.is_mine(addr):
                self.history.pop(addr)
                save = True
                continue

            for tx_hash, tx_height in hist:
                if tx_hash in self.pruned_txo.values() or self.txi.get(tx_hash) or self.txo.get(tx_hash):
                    continue
                tx = self.transactions.get(tx_hash)
                if tx is not None:
                    self.add_transaction(tx_hash, tx)
                    save = True
        if save:
            self.save_transactions()

    def basename(self):
        return os.path.basename(self.storage.path)

    def save_addresses(self):
        self.storage.put('addresses', {'receiving':self.receiving_addresses, 'change':self.change_addresses})

    def load_addresses(self):
        d = self.storage.get('addresses', {})
        if type(d) != dict: d={}
        self.receiving_addresses = d.get('receiving', [])
        self.change_addresses = d.get('change', [])

    def synchronize(self):
        pass

    def set_up_to_date(self, up_to_date):
        with self.lock:
            self.up_to_date = up_to_date
        if up_to_date:
            self.save_transactions(write=True)

    def is_up_to_date(self):
        with self.lock: return self.up_to_date

    def set_label(self, name, text = None):
        changed = False
        old_text = self.labels.get(name)
        if text:
            text = text.replace("\n", " ")
            if old_text != text:
                self.labels[name] = text
                changed = True
        else:
            if old_text:
                self.labels.pop(name)
                changed = True

        if changed:
            run_hook('set_label', self, name, text)
            self.storage.put('labels', self.labels)

        return changed

    def is_mine(self, address):
        return address in self.get_addresses()

    def is_change(self, address):
        if not self.is_mine(address):
            return False
        return address in self.change_addresses

    def get_address_index(self, address):
        if self.keystore.can_import():
            for pubkey in self.keystore.keypairs.keys():
                if self.pubkeys_to_address(pubkey) == address:
                    return pubkey
        elif address in self.receiving_addresses:
            return False, self.receiving_addresses.index(address)
        if address in self.change_addresses:
            return True, self.change_addresses.index(address)
        raise Exception("Address not found", address)

    def get_private_key(self, address, password):
        if self.is_watching_only():
            return []
        index = self.get_address_index(address)
        pk = self.keystore.get_private_key(index, password)
        return [pk]

    def get_public_key(self, address):
        if self.keystore.can_import():
            pubkey = self.get_address_index(address)
        else:
            sequence = self.get_address_index(address)
            pubkey = self.get_pubkey(*sequence)
        return pubkey

    def get_public_keys(self, address):
        sequence = self.get_address_index(address)
        return self.get_pubkeys(*sequence)

    def add_unverified_tx(self, tx_hash, tx_height):
        # tx will be verified only if height > 0
        if tx_hash not in self.verified_tx:
            self.unverified_tx[tx_hash] = tx_height

    def add_verified_tx(self, tx_hash, info):
        # Remove from the unverified map and add to the verified map and
        self.unverified_tx.pop(tx_hash, None)
        with self.lock:
            self.verified_tx[tx_hash] = info  # (tx_height, timestamp, pos)
        height, conf, timestamp = self.get_tx_height(tx_hash)
        self.network.trigger_callback('verified', tx_hash, height, conf, timestamp)

    def get_unverified_txs(self):
        '''Returns a map from tx hash to transaction height'''
        return self.unverified_tx

    def undo_verifications(self, height):
        '''Used by the verifier when a reorg has happened'''
        txs = []
        with self.lock:
            for tx_hash, item in self.verified_tx:
                tx_height, timestamp, pos = item
                if tx_height >= height:
                    self.verified_tx.pop(tx_hash, None)
                    txs.append(tx_hash)
        return txs

    def get_local_height(self):
        """ return last known height if we are offline """
        return self.network.get_local_height() if self.network else self.stored_height

    def get_tx_height(self, tx_hash):
        """ return the height and timestamp of a verified transaction. """
        with self.lock:
            if tx_hash in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx_hash]
                conf = max(self.get_local_height() - height + 1, 0)
                return height, conf, timestamp
            else:
                height = self.unverified_tx[tx_hash]
                return height, 0, False

    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            x = self.verified_tx.get(tx_hash)
            y = self.unverified_tx.get(tx_hash)
            if x:
                height, timestamp, pos = x
                return height, pos
            elif y > 0:
                return y, 0
            else:
                return 1e12 - y, 0

    def is_found(self):
        return self.history.values() != [[]] * len(self.history)

    def get_num_tx(self, address):
        """ return number of transactions where address is involved """
        return len(self.history.get(address, []))

    def get_tx_delta(self, tx_hash, address):
        "effect of tx on address"
        # pruned
        if tx_hash in self.pruned_txo.values():
            return None
        delta = 0
        # substract the value of coins sent from address
        d = self.txi.get(tx_hash, {}).get(address, [])
        for n, v in d:
            delta -= v
        # add the value of the coins received at address
        d = self.txo.get(tx_hash, {}).get(address, [])
        for n, v, cb in d:
            delta += v
        return delta

    def get_wallet_delta(self, tx):
        """ effect of tx on wallet """
        addresses = self.get_addresses()
        is_relevant = False
        is_mine = False
        is_pruned = False
        is_partial = False
        v_in = v_out = v_out_mine = 0
        for item in tx.inputs():
            addr = item.get('address')
            if addr in addresses:
                is_mine = True
                is_relevant = True
                d = self.txo.get(item['prevout_hash'], {}).get(addr, [])
                for n, v, cb in d:
                    if n == item['prevout_n']:
                        value = v
                        break
                else:
                    value = None
                if value is None:
                    is_pruned = True
                else:
                    v_in += value
            else:
                is_partial = True
        if not is_mine:
            is_partial = False
        for addr, value in tx.get_outputs():
            v_out += value
            if addr in addresses:
                v_out_mine += value
                is_relevant = True
        if is_pruned:
            # some inputs are mine:
            fee = None
            if is_mine:
                v = v_out_mine - v_out
            else:
                # no input is mine
                v = v_out_mine
        else:
            v = v_out_mine - v_in
            if is_partial:
                # some inputs are mine, but not all
                fee = None
            else:
                # all inputs are mine
                fee = v_in - v_out
        if not is_mine:
            fee = None
        return is_relevant, is_mine, v, fee

    def get_tx_info(self, tx):
        is_relevant, is_mine, v, fee = self.get_wallet_delta(tx)
        exp_n = None
        can_broadcast = False
        can_bump = False
        label = ''
        height = conf = timestamp = None
        tx_hash = tx.txid()
        if tx.is_complete():
            if tx_hash in self.transactions.keys():
                label = self.get_label(tx_hash)
                height, conf, timestamp = self.get_tx_height(tx_hash)
                if height > 0:
                    if conf:
                        status = _("%d confirmations") % conf
                    else:
                        status = _('Not verified')
                else:
                    status = _('Unconfirmed')
                    if fee is None:
                        fee = self.tx_fees.get(tx_hash)
                    if fee:
                        size = tx.estimated_size()
                        fee_per_kb = fee * 1000 / size
                        exp_n = self.network.config.reverse_dynfee(fee_per_kb)
                    can_bump = is_mine and not tx.is_final()
            else:
                status = _("Signed")
                can_broadcast = self.network is not None
        else:
            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if is_relevant:
            if is_mine:
                if fee is not None:
                    amount = v + fee
                else:
                    amount = v
            else:
                amount = v
        else:
            amount = None

        return tx_hash, status, label, can_broadcast, can_bump, amount, fee, height, conf, timestamp, exp_n


    def get_addr_io(self, address):
        h = self.history.get(address, [])
        received = {}
        sent = {}
        for tx_hash, height in h:
            l = self.txo.get(tx_hash, {}).get(address, [])
            for n, v, is_cb in l:
                received[tx_hash + ':%d'%n] = (height, v, is_cb)
        for tx_hash, height in h:
            l = self.txi.get(tx_hash, {}).get(address, [])
            for txi, v in l:
                sent[txi] = height
        return received, sent

    def get_addr_utxo(self, address):
        coins, spent = self.get_addr_io(address)
        for txi in spent:
            coins.pop(txi)
        out = []
        for txo, v in coins.items():
            tx_height, value, is_cb = v
            prevout_hash, prevout_n = txo.split(':')
            x = {
                'address':address,
                'value':value,
                'prevout_n':int(prevout_n),
                'prevout_hash':prevout_hash,
                'height':tx_height,
                'coinbase':is_cb
            }
            out.append(x)
        return out

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received, sent = self.get_addr_io(address)
        return sum([v for height, v, is_cb in received.values()])

    # return the balance of a bitcoin address: confirmed and matured, unconfirmed, unmatured
    def get_addr_balance(self, address):
        received, sent = self.get_addr_io(address)
        c = u = x = 0
        for txo, (tx_height, v, is_cb) in received.items():
            if is_cb and tx_height + COINBASE_MATURITY > self.get_local_height():
                x += v
            elif tx_height > 0:
                c += v
            else:
                u += v
            if txo in sent:
                if sent[txo] > 0:
                    c -= v
                else:
                    u -= v
        return c, u, x

    def get_spendable_coins(self, domain = None):
        return self.get_utxos(domain, exclude_frozen=True, mature=True)

    def get_utxos(self, domain = None, exclude_frozen = False, mature = False):
        coins = []
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen:
            domain = set(domain) - self.frozen_addresses
        for addr in domain:
            utxos = self.get_addr_utxo(addr)
            for x in utxos:
                if mature and x['coinbase'] and x['height'] + COINBASE_MATURITY > self.get_local_height():
                    continue
                coins.append(x)
                continue
        return coins

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_addresses(self):
        out = []
        out += self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out

    def get_frozen_balance(self):
        return self.get_balance(self.frozen_addresses)

    def get_balance(self, domain=None):
        if domain is None:
            domain = self.get_addresses()
        cc = uu = xx = 0
        for addr in domain:
            c, u, x = self.get_addr_balance(addr)
            cc += c
            uu += u
            xx += x
        return cc, uu, xx

    def get_address_history(self, address):
        with self.lock:
            return self.history.get(address, [])

    def find_pay_to_pubkey_address(self, prevout_hash, prevout_n):
        dd = self.txo.get(prevout_hash, {})
        for addr, l in dd.items():
            for n, v, is_cb in l:
                if n == prevout_n:
                    self.print_error("found pay-to-pubkey address:", addr)
                    return addr

    def add_transaction(self, tx_hash, tx):
        is_coinbase = tx.inputs()[0]['type'] == 'coinbase'
        with self.transaction_lock:
            # add inputs
            self.txi[tx_hash] = d = {}
            for txi in tx.inputs():
                addr = txi.get('address')
                if txi['type'] != 'coinbase':
                    prevout_hash = txi['prevout_hash']
                    prevout_n = txi['prevout_n']
                    ser = prevout_hash + ':%d'%prevout_n
                if addr == "(pubkey)":
                    addr = self.find_pay_to_pubkey_address(prevout_hash, prevout_n)
                # find value from prev output
                if addr and self.is_mine(addr):
                    dd = self.txo.get(prevout_hash, {})
                    for n, v, is_cb in dd.get(addr, []):
                        if n == prevout_n:
                            if d.get(addr) is None:
                                d[addr] = []
                            d[addr].append((ser, v))
                            break
                    else:
                        self.pruned_txo[ser] = tx_hash

            # add outputs
            self.txo[tx_hash] = d = {}
            for n, txo in enumerate(tx.outputs()):
                ser = tx_hash + ':%d'%n
                _type, x, v = txo
                if _type == TYPE_ADDRESS:
                    addr = x
                elif _type == TYPE_PUBKEY:
                    addr = bitcoin.public_key_to_p2pkh(x.decode('hex'))
                else:
                    addr = None
                if addr and self.is_mine(addr):
                    if d.get(addr) is None:
                        d[addr] = []
                    d[addr].append((n, v, is_coinbase))
                # give v to txi that spends me
                next_tx = self.pruned_txo.get(ser)
                if next_tx is not None:
                    self.pruned_txo.pop(ser)
                    dd = self.txi.get(next_tx, {})
                    if dd.get(addr) is None:
                        dd[addr] = []
                    dd[addr].append((ser, v))
            # save
            self.transactions[tx_hash] = tx

    def remove_transaction(self, tx_hash):
        with self.transaction_lock:
            self.print_error("removing tx from history", tx_hash)
            #tx = self.transactions.pop(tx_hash)
            for ser, hh in self.pruned_txo.items():
                if hh == tx_hash:
                    self.pruned_txo.pop(ser)
            # add tx to pruned_txo, and undo the txi addition
            for next_tx, dd in self.txi.items():
                for addr, l in dd.items():
                    ll = l[:]
                    for item in ll:
                        ser, v = item
                        prev_hash, prev_n = ser.split(':')
                        if prev_hash == tx_hash:
                            l.remove(item)
                            self.pruned_txo[ser] = next_tx
                    if l == []:
                        dd.pop(addr)
                    else:
                        dd[addr] = l
            try:
                self.txi.pop(tx_hash)
                self.txo.pop(tx_hash)
            except KeyError:
                self.print_error("tx was not in history", tx_hash)

    def receive_tx_callback(self, tx_hash, tx, tx_height):
        self.add_transaction(tx_hash, tx)
        self.add_unverified_tx(tx_hash, tx_height)

    def receive_history_callback(self, addr, hist, tx_fees):
        with self.lock:
            old_hist = self.history.get(addr, [])
            for tx_hash, height in old_hist:
                if (tx_hash, height) not in hist:
                    # remove tx if it's not referenced in histories
                    self.tx_addr_hist[tx_hash].remove(addr)
                    if not self.tx_addr_hist[tx_hash]:
                        self.remove_transaction(tx_hash)
            self.history[addr] = hist

        for tx_hash, tx_height in hist:
            # add it in case it was previously unconfirmed
            self.add_unverified_tx(tx_hash, tx_height)
            # add reference in tx_addr_hist
            s = self.tx_addr_hist.get(tx_hash, set())
            s.add(addr)
            self.tx_addr_hist[tx_hash] = s
            # if addr is new, we have to recompute txi and txo
            tx = self.transactions.get(tx_hash)
            if tx is not None and self.txi.get(tx_hash, {}).get(addr) is None and self.txo.get(tx_hash, {}).get(addr) is None:
                self.add_transaction(tx_hash, tx)

        # Store fees
        self.tx_fees.update(tx_fees)

    def get_history(self, domain=None):
        # get domain
        if domain is None:
            domain = self.get_addresses()
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(int)
        for addr in domain:
            h = self.get_address_history(addr)
            for tx_hash, height in h:
                delta = self.get_tx_delta(tx_hash, addr)
                if delta is None or tx_deltas[tx_hash] is None:
                    tx_deltas[tx_hash] = None
                else:
                    tx_deltas[tx_hash] += delta

        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            delta = tx_deltas[tx_hash]
            height, conf, timestamp = self.get_tx_height(tx_hash)
            history.append((tx_hash, height, conf, timestamp, delta))
        history.sort(key = lambda x: self.get_txpos(x[0]))
        history.reverse()

        # 3. add balance
        c, u, x = self.get_balance(domain)
        balance = c + u + x
        h2 = []
        for tx_hash, height, conf, timestamp, delta in history:
            h2.append((tx_hash, height, conf, timestamp, delta, balance))
            if balance is None or delta is None:
                balance = None
            else:
                balance -= delta
        h2.reverse()

        # fixme: this may happen if history is incomplete
        if balance not in [None, 0]:
            self.print_error("Error: history not synchronized")
            return []

        return h2

    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash, '')
        if label is '':
            label = self.get_default_label(tx_hash)
        return label

    def get_default_label(self, tx_hash):
        if self.txi.get(tx_hash) == {}:
            d = self.txo.get(tx_hash, {})
            labels = []
            for addr in d.keys():
                label = self.labels.get(addr)
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_tx_status(self, tx_hash, height, conf, timestamp):
        from util import format_time
        if conf == 0:
            tx = self.transactions.get(tx_hash)
            if not tx:
                return 3, 'unknown'
            is_final = tx and tx.is_final()
            fee = self.tx_fees.get(tx_hash)
            if fee and self.network and self.network.config.has_fee_estimates():
                size = len(tx.raw)/2
                low_fee = int(self.network.config.dynfee(0)*size/1000)
                is_lowfee = fee < low_fee * 0.5
            else:
                is_lowfee = False
            if height==0 and not is_final:
                status = 0
            elif height < 0:
                status = 1
            elif height == 0 and is_lowfee:
                status = 2
            elif height == 0:
                status = 3
            else:
                status = 4
        else:
            status = 4 + min(conf, 6)
        time_str = format_time(timestamp) if timestamp else _("unknown")
        status_str = TX_STATUS[status] if status < 5 else time_str
        return status, status_str

    def relayfee(self):
        RELAY_FEE = bitcoin.MIN_RELAY_TX_FEE
        MAX_RELAY_FEE = 10 * RELAY_FEE
        f = self.network.relay_fee if self.network and self.network.relay_fee else RELAY_FEE
        return min(f, MAX_RELAY_FEE)

    def dust_threshold(self):
        # Change <= dust threshold is added to the tx fee
        return DUST_SOFT_LIMIT

    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None):
        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            _type, data, value = o
            if _type == TYPE_ADDRESS:
                if not is_address(data):
                    raise BaseException("Invalid litecoin address:" + data)
            if value == '!':
                if i_max is not None:
                    raise BaseException("More than one output set to spend max")
                i_max = i

        # Avoid index-out-of-range with inputs[0] below
        if not inputs:
            raise NotEnoughFunds()

        if fixed_fee is None and config.fee_per_kb() is None:
            raise BaseException('Dynamic fee estimates not available')

        for item in inputs:
            self.add_input_info(item)

        # change address
        if change_addr:
            change_addrs = [change_addr]
        else:
            addrs = self.get_change_addresses()[-self.gap_limit_for_change:]
            if self.use_change and addrs:
                # New change addresses are created only after a few
                # confirmations.  Select the unused addresses within the
                # gap limit; if none take one at random
                change_addrs = [addr for addr in addrs if
                                self.get_num_tx(addr) == 0]
                if not change_addrs:
                    change_addrs = [random.choice(addrs)]
            else:
                change_addrs = [inputs[0]['address']]

        # Fee estimator
        if fixed_fee is None:
            fee_estimator = partial(self.estimate_fee, config, outputs=outputs)
        else:
            fee_estimator = lambda size: fixed_fee

        if i_max is None:
            # Let the coin chooser select the coins to spend
            max_change = self.max_change_outputs if self.multiple_change else 1
            coin_chooser = coinchooser.get_coin_chooser(config)
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs[:max_change],
                                      fee_estimator, self.dust_threshold())
        else:
            sendable = sum(map(lambda x:x['value'], inputs))
            _type, data, value = outputs[i_max]
            outputs[i_max] = (_type, data, 0)
            tx = Transaction.from_io(inputs, outputs[:])
            fee = fee_estimator(tx.estimated_size())
            amount = max(0, sendable - tx.output_value() - fee)
            outputs[i_max] = (_type, data, amount)
            tx = Transaction.from_io(inputs, outputs[:])

        # Sort the inputs and outputs deterministically
        tx.BIP_LI01_sort()

        run_hook('make_unsigned_transaction', self, tx)
        return tx

    def estimate_fee(self, config, size, outputs=[]):
        fee = int(config.fee_per_kb() * (1 + size / 1000))
        for _, _, value in outputs:
            if value > 0 and value < DUST_SOFT_LIMIT:
                fee += DUST_SOFT_LIMIT
        return fee

    def mktx(self, outputs, password, config, fee=None, change_addr=None, domain=None):
        coins = self.get_spendable_coins(domain)
        tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr)
        self.sign_transaction(tx, password)
        return tx

    def sweep(self, privkeys, network, config, recipient, fee=None, imax=100):
        inputs = []
        keypairs = {}
        for privkey in privkeys:
            pubkey = public_key_from_private_key(privkey)
            address = address_from_private_key(privkey)
            u = network.synchronous_get(('blockchain.address.listunspent', [address]))
            pay_script = transaction.get_scriptPubKey(address)
            for item in u:
                if len(inputs) >= imax:
                    break
                item['type'] = 'p2pkh'
                item['scriptPubKey'] = pay_script
                item['redeemPubkey'] = pubkey
                item['address'] = address
                item['prevout_hash'] = item['tx_hash']
                item['prevout_n'] = item['tx_pos']
                item['pubkeys'] = [pubkey]
                item['x_pubkeys'] = [pubkey]
                item['signatures'] = [None]
                item['num_sig'] = 1
                inputs.append(item)
            keypairs[pubkey] = privkey

        if not inputs:
            return

        total = sum(i.get('value') for i in inputs)
        if fee is None:
            outputs = [(TYPE_ADDRESS, recipient, total)]
            tx = Transaction.from_io(inputs, outputs)
            fee = self.estimate_fee(config, tx.estimated_size())

        outputs = [(TYPE_ADDRESS, recipient, total - fee)]
        tx = Transaction.from_io(inputs, outputs)
        tx.sign(keypairs)
        return tx

    def is_frozen(self, addr):
        return addr in self.frozen_addresses

    def set_frozen_state(self, addrs, freeze):
        '''Set frozen state of the addresses to FREEZE, True or False'''
        if all(self.is_mine(addr) for addr in addrs):
            if freeze:
                self.frozen_addresses |= set(addrs)
            else:
                self.frozen_addresses -= set(addrs)
            self.storage.put('frozen_addresses', list(self.frozen_addresses))
            return True
        return False

    def prepare_for_verifier(self):
        # review transactions that are in the history
        for addr, hist in self.history.items():
            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_tx(tx_hash, tx_height)

        # if we are on a pruning server, remove unverified transactions
        with self.lock:
            vr = self.verified_tx.keys() + self.unverified_tx.keys()
        for tx_hash in self.transactions.keys():
            if tx_hash not in vr:
                self.print_error("removing transaction", tx_hash)
                self.transactions.pop(tx_hash)

    def start_threads(self, network):
        self.network = network
        if self.network is not None:
            self.prepare_for_verifier()
            self.verifier = SPV(self.network, self)
            self.synchronizer = Synchronizer(self, network)
            network.add_jobs([self.verifier, self.synchronizer])
        else:
            self.verifier = None
            self.synchronizer = None

    def stop_threads(self):
        if self.network:
            self.network.remove_jobs([self.synchronizer, self.verifier])
            self.synchronizer.release()
            self.synchronizer = None
            self.verifier = None
            # Now no references to the syncronizer or verifier
            # remain so they will be GC-ed
            self.storage.put('stored_height', self.get_local_height())
        self.save_transactions()
        self.storage.put('verified_tx3', self.verified_tx)
        self.storage.write()

    def wait_until_synchronized(self, callback=None):
        def wait_for_wallet():
            self.set_up_to_date(False)
            while not self.is_up_to_date():
                if callback:
                    msg = "%s\n%s %d"%(
                        _("Please wait..."),
                        _("Addresses generated:"),
                        len(self.addresses(True)))
                    callback(msg)
                time.sleep(0.1)
        def wait_for_network():
            while not self.network.is_connected():
                if callback:
                    msg = "%s \n" % (_("Connecting..."))
                    callback(msg)
                time.sleep(0.1)
        # wait until we are connected, because the user
        # might have selected another server
        if self.network:
            wait_for_network()
            wait_for_wallet()
        else:
            self.synchronize()

    def can_export(self):
        return not self.is_watching_only()

    def is_used(self, address):
        h = self.history.get(address,[])
        c, u, x = self.get_addr_balance(address)
        return len(h) > 0 and c + u + x == 0

    def is_empty(self, address):
        c, u, x = self.get_addr_balance(address)
        return c+u+x == 0

    def address_is_old(self, address, age_limit=2):
        age = -1
        h = self.history.get(address, [])
        for tx_hash, tx_height in h:
            if tx_height == 0:
                tx_age = 0
            else:
                tx_age = self.get_local_height() - tx_height + 1
            if tx_age > age:
                age = tx_age
        return age > age_limit

    def bump_fee(self, tx, delta):
        if tx.is_final():
            raise BaseException(_("Cannot bump fee: transaction is final"))
        inputs = copy.deepcopy(tx.inputs())
        outputs = copy.deepcopy(tx.outputs())
        for txin in inputs:
            txin['signatures'] = [None] * len(txin['signatures'])
            self.add_input_info(txin)
        # use own outputs
        s = filter(lambda x: self.is_mine(x[1]), outputs)
        # ... unless there is none
        if not s:
            s = outputs
        # prioritize low value outputs, to get rid of dust
        s = sorted(s, key=lambda x: x[2])
        for o in s:
            i = outputs.index(o)
            otype, address, value = o
            if value - delta >= self.dust_threshold():
                outputs[i] = otype, address, value - delta
                delta = 0
                break
            else:
                del outputs[i]
                delta -= value
                if delta > 0:
                    continue
        if delta > 0:
            raise BaseException(_('Cannot bump fee: cound not find suitable outputs'))
        return Transaction.from_io(inputs, outputs)

    def cpfp(self, tx, fee):
        txid = tx.txid()
        for i, o in enumerate(tx.outputs()):
            otype, address, value = o
            if otype == TYPE_ADDRESS and self.is_mine(address):
                break
        else:
            return
        coins = self.get_addr_utxo(address)
        for item in coins:
            if item['prevout_hash'] == txid and item['prevout_n'] == i:
                break
        else:
            return
        self.add_input_info(item)
        inputs = [item]
        outputs = [(TYPE_ADDRESS, address, value - fee)]
        return Transaction.from_io(inputs, outputs)

    def add_input_info(self, txin):
        txin['type'] = self.txin_type
        # Add address for utxo that are in wallet
        if txin.get('scriptSig') == '':
            coins = self.get_spendable_coins()
            for item in coins:
                if txin.get('prevout_hash') == item.get('prevout_hash') and txin.get('prevout_n') == item.get('prevout_n'):
                    txin['address'] = item.get('address')
        address = txin['address']
        if self.is_mine(address):
            self.add_input_sig_info(txin, address)

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            if k.can_sign(tx):
                return True
        return False

    def get_input_tx(self, tx_hash):
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.transactions.get(tx_hash)
        if not tx and self.network:
            request = ('blockchain.transaction.get', [tx_hash])
            tx = Transaction(self.network.synchronous_get(request))
        return tx

    def add_hw_info(self, tx):
        # add previous tx for hw wallets
        for txin in tx.inputs():
            tx_hash = txin['prevout_hash']
            txin['prev_tx'] = self.get_input_tx(tx_hash)
        # add output info for hw wallets
        info = {}
        xpubs = self.get_master_public_keys()
        for txout in tx.outputs():
            _type, addr, amount = txout
            if self.is_change(addr):
                index = self.get_address_index(addr)
                pubkeys = self.get_public_keys(addr)
                # sort xpubs using the order of pubkeys
                sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                info[addr] = index, sorted_xpubs, self.m if isinstance(self, Multisig_Wallet) else None
        tx.output_info = info

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # hardware wallets require extra info
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx)) for k in self.get_keystores()]):
            self.add_hw_info(tx)
        # sign
        for k in self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password)
            except UserCancelled:
                continue

    def get_unused_addresses(self):
        # fixme: use slots from expired requests
        domain = self.get_receiving_addresses()
        return [addr for addr in domain if not self.history.get(addr)
                and addr not in self.receive_requests.keys()]

    def get_unused_address(self):
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]

    def get_receiving_address(self):
        # always return an address
        domain = self.get_receiving_addresses()
        if not domain:
            return
        choice = domain[0]
        for addr in domain:
            if not self.history.get(addr):
                if addr not in self.receive_requests.keys():
                    return addr
                else:
                    choice = addr
        return choice

    def get_payment_status(self, address, amount):
        local_height = self.get_local_height()
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, is_cb = x
            txid, n = txo.split(':')
            info = self.verified_tx.get(txid)
            if info:
                tx_height, timestamp, pos = info
                conf = local_height - tx_height
            else:
                conf = 0
            l.append((conf, v))
        vsum = 0
        for conf, v in reversed(sorted(l)):
            vsum += v
            if vsum >= amount:
                return True, conf
        return False, None

    def get_payment_request(self, addr, config):
        import util
        r = self.receive_requests.get(addr)
        if not r:
            return
        out = copy.copy(r)
        out['URI'] = 'litecoin:' + addr + '?amount=' + util.format_satoshis(out.get('amount'))
        status, conf = self.get_request_status(addr)
        out['status'] = status
        if conf is not None:
            out['confirmations'] = conf
        # check if bip70 file exists
        rdir = config.get('requests_dir')
        if rdir:
            key = out.get('id', addr)
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if os.path.exists(path):
                baseurl = 'file://' + rdir
                rewrite = config.get('url_rewrite')
                if rewrite:
                    baseurl = baseurl.replace(*rewrite)
                out['request_url'] = os.path.join(baseurl, 'req', key[0], key[1], key, key)
                out['URI'] += '&r=' + out['request_url']
                out['index_url'] = os.path.join(baseurl, 'index.html') + '?id=' + key
                websocket_server_announce = config.get('websocket_server_announce')
                if websocket_server_announce:
                    out['websocket_server'] = websocket_server_announce
                else:
                    out['websocket_server'] = config.get('websocket_server', 'localhost')
                websocket_port_announce = config.get('websocket_port_announce')
                if websocket_port_announce:
                    out['websocket_port'] = websocket_port_announce
                else:
                    out['websocket_port'] = config.get('websocket_port', 9999)
        return out

    def get_request_status(self, key):
        from paymentrequest import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
        r = self.receive_requests.get(key)
        if r is None:
            return PR_UNKNOWN
        address = r['address']
        amount = r.get('amount')
        timestamp = r.get('time', 0)
        if timestamp and type(timestamp) != int:
            timestamp = 0
        expiration = r.get('exp')
        if expiration and type(expiration) != int:
            expiration = 0
        conf = None
        if amount:
            if self.up_to_date:
                paid, conf = self.get_payment_status(address, amount)
                status = PR_PAID if paid else PR_UNPAID
                if status == PR_UNPAID and expiration is not None and time.time() > timestamp + expiration:
                    status = PR_EXPIRED
            else:
                status = PR_UNKNOWN
        else:
            status = PR_UNKNOWN
        return status, conf

    def make_payment_request(self, addr, amount, message, expiration):
        timestamp = int(time.time())
        _id = Hash(addr + "%d"%timestamp).encode('hex')[0:10]
        r = {'time':timestamp, 'amount':amount, 'exp':expiration, 'address':addr, 'memo':message, 'id':_id}
        return r

    def sign_payment_request(self, key, alias, alias_addr, password):
        req = self.receive_requests.get(key)
        alias_privkey = self.get_private_key(alias_addr, password)[0]
        pr = paymentrequest.make_unsigned_request(req)
        paymentrequest.sign_request_with_alias(pr, alias, alias_privkey)
        req['name'] = pr.pki_data
        req['sig'] = pr.signature.encode('hex')
        self.receive_requests[key] = req
        self.storage.put('payment_requests', self.receive_requests)

    def add_payment_request(self, req, config):
        import os
        addr = req['address']
        amount = req.get('amount')
        message = req.get('memo')
        self.receive_requests[addr] = req
        self.storage.put('payment_requests', self.receive_requests)
        self.set_label(addr, message) # should be a default label

        rdir = config.get('requests_dir')
        if rdir and amount is not None:
            key = req.get('id', addr)
            pr = paymentrequest.make_request(config, req)
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            with open(os.path.join(path, key), 'w') as f:
                f.write(pr.SerializeToString())
            # reload
            req = self.get_payment_request(addr, config)
            with open(os.path.join(path, key + '.json'), 'w') as f:
                f.write(json.dumps(req))
        return req

    def remove_payment_request(self, addr, config):
        if addr not in self.receive_requests:
            return False
        r = self.receive_requests.pop(addr)
        rdir = config.get('requests_dir')
        if rdir:
            key = r.get('id', addr)
            for s in ['.json', '']:
                n = os.path.join(rdir, 'req', key[0], key[1], key, key + s)
                if os.path.exists(n):
                    os.unlink(n)
        self.storage.put('payment_requests', self.receive_requests)
        return True

    def get_sorted_requests(self, config):
        def f(x):
            try:
                addr = x.get('address')
                return self.get_address_index(addr)
            except:
                return -1, (0, 0)
        return sorted(map(lambda x: self.get_payment_request(x, config), self.receive_requests.keys()), key=f)

    def get_fingerprint(self):
        raise NotImplementedError()

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_address(self):
        return False

    def add_address(self, address):
        if address not in self.history:
            self.history[address] = []
        if self.synchronizer:
            self.synchronizer.add(address)

    def has_password(self):
        return self.storage.get('use_encryption', False)


class Imported_Wallet(Abstract_Wallet):
    # wallet made of imported addresses

    wallet_type = 'imported'
    txin_type = 'address'

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    def load_keystore(self):
        pass

    def load_addresses(self):
        self.addresses = self.storage.get('addresses', [])
        self.receiving_addresses = self.addresses
        self.change_addresses = []

    def get_keystores(self):
        return []

    def has_password(self):
        return False

    def can_change_password(self):
        return False

    def can_import_address(self):
        return True

    def is_watching_only(self):
        return True

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def is_used(self, address):
        return False

    def get_master_public_keys(self):
        return []

    def is_beyond_limit(self, address, is_change):
        return False

    def get_fingerprint(self):
        return ''

    def get_addresses(self, include_change=False):
        return self.addresses

    def import_address(self, address):
        if address in self.addresses:
            return
        self.addresses.append(address)
        self.storage.put('addresses', self.addresses)
        self.storage.write()
        self.add_address(address)
        return address

    def can_delete_address(self):
        return True

    def delete_address(self, address):
        if address not in self.addresses:
            return
        self.addresses.remove(address)
        self.storage.put('addresses', self.addresses)
        self.storage.write()

    def get_receiving_addresses(self):
        return self.addresses[:]

    def get_change_addresses(self):
        return []

    def add_input_sig_info(self, txin, address):
        addrtype, hash160 = bc_address_to_hash_160(address)
        x_pubkey = 'fd' + (chr(addrtype) + hash160).encode('hex')
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]




class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 20)

    def has_seed(self):
        return self.keystore.has_seed()

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.save_addresses()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for a in addresses[::-1]:
            if self.history.get(a):break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if self.history.get(a):
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def create_new_address(self, for_change):
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(addr_list)
        x = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(x)
        addr_list.append(address)
        self.save_addresses()
        self.add_address(address)
        return address

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            addresses = self.get_change_addresses() if for_change else self.get_receiving_addresses()
            if len(addresses) < limit:
                self.create_new_address(for_change)
                continue
            if map(lambda a: self.address_is_old(a), addresses[-limit:] ) == limit*[False]:
                break
            else:
                self.create_new_address(for_change)

    def synchronize(self):
        with self.lock:
            if self.is_deterministic():
                self.synchronize_sequence(False)
                self.synchronize_sequence(True)
            else:
                if len(self.receiving_addresses) != len(self.keystore.keypairs):
                    pubkeys = self.keystore.keypairs.keys()
                    self.receiving_addresses = map(self.pubkeys_to_address, pubkeys)
                    self.save_addresses()
                    for addr in self.receiving_addresses:
                        self.add_address(addr)

    def is_beyond_limit(self, address, is_change):
        addr_list = self.get_change_addresses() if is_change else self.get_receiving_addresses()
        i = addr_list.index(address)
        prev_addresses = addr_list[:max(0, i)]
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if len(prev_addresses) < limit:
            return False
        prev_addresses = prev_addresses[max(0, i - limit):]
        for addr in prev_addresses:
            if self.history.get(addr):
                return False
        return True

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()




class Simple_Wallet(Abstract_Wallet):

    """ Wallet with a single pubkey per address """

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        self.is_segwit = self.keystore.is_segwit()
        self.txin_type = 'p2wpkh-p2sh' if self.is_segwit else 'p2pkh'

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def add_input_sig_info(self, txin, address):
        if not self.keystore.can_import():
            derivation = self.get_address_index(address)
            x_pubkey = self.keystore.get_xpubkey(*derivation)
        else:
            x_pubkey = self.get_public_key(address)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)


class Simple_Deterministic_Wallet(Deterministic_Wallet, Simple_Wallet):

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)

    def get_keystore(self):
        return self.keystore

    def get_keystores(self):
        return [self.keystore]

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def check_password(self, password):
        self.keystore.check_password(password)

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        self.keystore.update_password(old_pw, new_pw)
        self.save_keystore()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def can_delete_address(self):
        return self.keystore.can_import()

    def delete_address(self, address):
        pubkey = self.get_public_key(address)
        self.keystore.delete_imported_key(pubkey)
        self.save_keystore()
        self.receiving_addresses.remove(address)
        self.save_addresses()
        self.storage.write()

    def can_import_privkey(self):
        return self.keystore.can_import()

    def import_key(self, pk, pw):
        pubkey = self.keystore.import_key(pk, pw)
        self.save_keystore()
        addr = self.pubkeys_to_address(pubkey)
        self.receiving_addresses.append(addr)
        self.save_addresses()
        self.storage.write()
        self.add_address(addr)
        return addr


class P2SH:

    def pubkeys_to_redeem_script(self, pubkeys):
        raise NotImplementedError()

    def pubkeys_to_address(self, pubkey):
        redeem_script = self.pubkeys_to_redeem_script(pubkey)
        return bitcoin.hash160_to_p2sh(hash_160(redeem_script.decode('hex')))


class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_redeem_script(self, pubkey):
        if self.is_segwit:
            return transaction.segwit_script(pubkey)

    def pubkeys_to_address(self, pubkey):
        if not self.is_segwit:
            return bitcoin.public_key_to_p2pkh(pubkey.decode('hex'))
        elif bitcoin.TESTNET:
            redeem_script = self.pubkeys_to_redeem_script(pubkey)
            return bitcoin.hash160_to_p2sh(hash_160(redeem_script.decode('hex')))
        else:
            raise NotImplementedError()





class Multisig_Wallet(Deterministic_Wallet, P2SH):
    # generic m of n
    gap_limit = 20
    txin_type = 'p2sh'

    def __init__(self, storage):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage)

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def redeem_script(self, c, i):
        pubkeys = self.get_pubkeys(c, i)
        return transaction.multisig_script(sorted(pubkeys), self.m)

    def pubkeys_to_redeem_script(self, pubkeys):
        return transaction.multisig_script(sorted(pubkeys), self.m)

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.storage.put(name, k.dump())

    def get_keystore(self):
        return self.keystores.get('x1/')

    def get_keystores(self):
        return [self.keystores[i] for i in sorted(self.keystores.keys())]

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        for name, keystore in self.keystores.items():
            if keystore.can_change_password():
                keystore.update_password(old_pw, new_pw)
                self.storage.put(name, keystore.dump())
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def check_password(self, password):
        self.keystore.check_password(password)

    def has_seed(self):
        return self.keystore.has_seed()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def is_watching_only(self):
        return not any([not k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        # extended pubkeys
        txin['x_pubkeys'] = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
        # we need n place holders
        txin['signatures'] = [None] * self.n
        txin['num_sig'] = self.m


wallet_types = ['standard', 'multisig', 'imported']

def register_wallet_type(category):
    wallet_types.append(category)

wallet_constructors = {
    'standard': Standard_Wallet,
    'old': Standard_Wallet,
    'xpub': Standard_Wallet,
    'imported': Imported_Wallet
}

def register_constructor(wallet_type, constructor):
    wallet_constructors[wallet_type] = constructor

# former WalletFactory
class Wallet(object):
    """The main wallet "entry point".
    This class is actually a factory that will return a wallet of the correct
    type when passed a WalletStorage instance."""

    def __new__(self, storage):
        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        wallet = WalletClass(storage)
        # Convert hardware wallets restored with older versions of
        # Electrum to BIP44 wallets.  A hardware wallet does not have
        # a seed and plugins do not need to handle having one.
        rwc = getattr(wallet, 'restore_wallet_class', None)
        if rwc and storage.get('seed', ''):
            storage.print_error("converting wallet type to " + rwc.wallet_type)
            storage.put('wallet_type', rwc.wallet_type)
            wallet = rwc(storage)
        return wallet

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise RuntimeError("Unknown wallet type: " + wallet_type)

