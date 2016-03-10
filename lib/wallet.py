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
from unicodedata import normalize
from collections import namedtuple

from i18n import _
from util import NotEnoughFunds, PrintError, profiler

from bitcoin import *
from account import *
from version import *

from transaction import Transaction
from plugins import run_hook
import bitcoin
import coinchooser
from synchronizer import Synchronizer
from verifier import SPV
from mnemonic import Mnemonic

import paymentrequest

# internal ID for imported account
IMPORTED_ACCOUNT = '/x'

class WalletStorage(PrintError):

    def __init__(self, path):
        self.lock = threading.RLock()
        self.data = {}
        self.path = path
        self.file_exists = False
        self.modified = False
        self.print_error("wallet path", self.path)
        if self.path:
            self.read(self.path)

    def read(self, path):
        """Read the contents of the wallet file."""
        try:
            with open(self.path, "r") as f:
                data = f.read()
        except IOError:
            return
        if not data:
            return
        try:
            self.data = json.loads(data)
        except:
            try:
                d = ast.literal_eval(data)  #parse raw data from reading wallet file
                labels = d.get('labels', {})
            except Exception as e:
                raise IOError("Cannot read wallet file '%s'" % self.path)
            self.data = {}
            # In old versions of Electrum labels were latin1 encoded, this fixes breakage.
            for i, label in labels.items():
                try:
                    unicode(label)
                except UnicodeDecodeError:
                    d['labels'][i] = unicode(label.decode('latin1'))
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    self.print_error('Failed to convert label to json format', key)
                    continue
                self.data[key] = value
        self.file_exists = True

    def get(self, key, default=None):
        with self.lock:
            v = self.data.get(key)
            if v is None:
                v = default
            else:
                v = copy.deepcopy(v)
        return v

    def put(self, key, value):
        try:
            json.dumps(key)
            json.dumps(value)
        except:
            self.print_error("json error: cannot save", key)
            return
        with self.lock:
            if value is not None:
                if self.data.get(key) != value:
                    self.modified = True
                    self.data[key] = copy.deepcopy(value)
            elif key in self.data:
                self.modified = True
                self.data.pop(key)

    def write(self):
        if threading.currentThread().isDaemon():
            self.print_error('warning: daemon thread cannot write wallet')
            return
        if not self.modified:
            return
        s = json.dumps(self.data, indent=4, sort_keys=True)
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w") as f:
            f.write(s)
            f.flush()
            os.fsync(f.fileno())

        mode = os.stat(self.path).st_mode if os.path.exists(self.path) else stat.S_IREAD | stat.S_IWRITE
        # perform atomic write on POSIX systems
        try:
            os.rename(temp_path, self.path)
        except:
            os.remove(self.path)
            os.rename(temp_path, self.path)
        os.chmod(self.path, mode)
        self.print_error("saved", self.path)
        self.modified = False


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
        self.seed_version          = storage.get('seed_version', NEW_SEED_VERSION)
        self.use_change            = storage.get('use_change',True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.use_encryption        = storage.get('use_encryption', False)
        self.seed                  = storage.get('seed', '')               # encrypted
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = set(storage.get('frozen_addresses',[]))
        self.stored_height         = storage.get('stored_height', 0)       # last known height (for offline mode)
        self.history               = storage.get('addr_history',{})        # address -> list(txid, height)

        # imported_keys is deprecated. The GUI should call convert_imported_keys
        self.imported_keys = self.storage.get('imported_keys',{})

        self.load_accounts()
        self.load_transactions()
        self.build_reverse_history()

        # load requests
        self.receive_requests = self.storage.get('payment_requests', {})

        # Transactions pending verification.  A map from tx hash to transaction
        # height.  Access is not contended so no lock is needed.
        self.unverified_tx = {}
        # Verified transactions.  Each value is a (height, timestamp, block_pos) tuple.  Access with self.lock.
        self.verified_tx   = storage.get('verified_tx3',{})

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

    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def set_use_encryption(self, use_encryption):
        self.use_encryption = use_encryption
        self.storage.put('use_encryption', use_encryption)

    @profiler
    def load_transactions(self):
        self.txi = self.storage.get('txi', {})
        self.txo = self.storage.get('txo', {})
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
            self.storage.put('pruned_txo', self.pruned_txo)
            self.storage.put('addr_history', self.history)
            if write:
                self.storage.write()

    def clear_history(self):
        with self.transaction_lock:
            self.txi = {}
            self.txo = {}
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

    # wizard action
    def get_action(self):
        pass

    def basename(self):
        return os.path.basename(self.storage.path)

    def convert_imported_keys(self, password):
        for k, v in self.imported_keys.items():
            sec = pw_decode(v, password)
            pubkey = public_key_from_private_key(sec)
            address = public_key_to_bc_address(pubkey.decode('hex'))
            if address != k:
                raise InvalidPassword()
            self.import_key(sec, password)
            self.imported_keys.pop(k)
        self.storage.put('imported_keys', self.imported_keys)

    def load_accounts(self):
        self.accounts = {}
        d = self.storage.get('accounts', {})
        removed = False
        for k, v in d.items():
            if self.wallet_type == 'old' and k in [0, '0']:
                v['mpk'] = self.storage.get('master_public_key')
                self.accounts['0'] = OldAccount(v)
            elif v.get('imported'):
                self.accounts[k] = ImportedAccount(v)
            elif v.get('xpub'):
                self.accounts[k] = BIP32_Account(v)
            elif v.get('pending'):
                removed = True
            else:
                self.print_error("cannot load account", v)
        if removed:
            self.save_accounts()

    def create_main_account(self):
        pass

    def synchronize(self):
        pass

    def can_create_accounts(self):
        return False

    def needs_next_account(self):
        return self.can_create_accounts() and self.accounts_all_used()

    def permit_account_naming(self):
        return self.can_create_accounts()

    def set_up_to_date(self, up_to_date):
        with self.lock:
            self.up_to_date = up_to_date
        if up_to_date:
            self.save_transactions(write=True)

    def is_up_to_date(self):
        with self.lock: return self.up_to_date

    def is_imported(self, addr):
        account = self.accounts.get(IMPORTED_ACCOUNT)
        if account:
            return addr in account.get_addresses(0)
        else:
            return False

    def has_imported_keys(self):
        account = self.accounts.get(IMPORTED_ACCOUNT)
        return account is not None

    def import_key(self, sec, password):
        if not self.can_import():
            raise BaseException('This wallet cannot import private keys')
        try:
            pubkey = public_key_from_private_key(sec)
            address = public_key_to_bc_address(pubkey.decode('hex'))
        except Exception:
            raise Exception('Invalid private key')

        if self.is_mine(address):
            raise Exception('Address already in wallet')

        if self.accounts.get(IMPORTED_ACCOUNT) is None:
            self.accounts[IMPORTED_ACCOUNT] = ImportedAccount({'imported':{}})
        self.accounts[IMPORTED_ACCOUNT].add(address, pubkey, sec, password)
        self.save_accounts()

        # force resynchronization, because we need to re-run add_transaction
        if address in self.history:
            self.history.pop(address)

        if self.synchronizer:
            self.synchronizer.add(address)
        return address

    def delete_imported_key(self, addr):
        account = self.accounts[IMPORTED_ACCOUNT]
        account.remove(addr)
        if not account.get_addresses(0):
            self.accounts.pop(IMPORTED_ACCOUNT)
        self.save_accounts()

    def set_label(self, name, text = None):
        changed = False
        old_text = self.labels.get(name)
        if text:
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

    def addresses(self, include_change = True):
        return list(addr for acc in self.accounts for addr in self.get_account_addresses(acc, include_change))

    def is_mine(self, address):
        return address in self.addresses(True)

    def is_change(self, address):
        if not self.is_mine(address): return False
        acct, s = self.get_address_index(address)
        if s is None: return False
        return s[0] == 1

    def get_address_index(self, address):
        for acc_id in self.accounts:
            for for_change in [0,1]:
                addresses = self.accounts[acc_id].get_addresses(for_change)
                if address in addresses:
                    return acc_id, (for_change, addresses.index(address))
        raise Exception("Address not found", address)

    def get_private_key(self, address, password):
        if self.is_watching_only():
            return []
        account_id, sequence = self.get_address_index(address)
        return self.accounts[account_id].get_private_key(sequence, self, password)

    def get_public_keys(self, address):
        account_id, sequence = self.get_address_index(address)
        return self.accounts[account_id].get_pubkeys(*sequence)

    def sign_message(self, address, message, password):
        keys = self.get_private_key(address, password)
        assert len(keys) == 1
        sec = keys[0]
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed, address)

    def decrypt_message(self, pubkey, message, password):
        address = public_key_to_bc_address(pubkey.decode('hex'))
        keys = self.get_private_key(address, password)
        secret = keys[0]
        ec = regenerate_key(secret)
        decrypted = ec.decrypt_message(message)
        return decrypted

    def add_unverified_tx(self, tx_hash, tx_height):
        # Only add if confirmed and not verified
        if tx_height > 0 and tx_hash not in self.verified_tx:
            self.unverified_tx[tx_hash] = tx_height

    def add_verified_tx(self, tx_hash, info):
        # Remove from the unverified map and add to the verified map and
        self.unverified_tx.pop(tx_hash, None)
        with self.lock:
            self.verified_tx[tx_hash] = info  # (tx_height, timestamp, pos)
        self.storage.put('verified_tx3', self.verified_tx)

        conf, timestamp = self.get_confirmations(tx_hash)
        self.network.trigger_callback('verified', tx_hash, conf, timestamp)

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

    def get_confirmations(self, tx):
        """ return the number of confirmations of a monitored transaction. """
        with self.lock:
            if tx in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx]
                conf = (self.get_local_height() - height + 1)
                if conf <= 0: timestamp = None
            elif tx in self.unverified_tx:
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
        y = self.unverified_tx.get(tx_hash)
        if x:
            height, timestamp, pos = x
            return height, pos
        elif y:
            return y, 0
        else:
            return 1e12, 0

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
        addresses = self.addresses(True)
        is_relevant = False
        is_send = False
        is_pruned = False
        is_partial = False
        v_in = v_out = v_out_mine = 0
        for item in tx.inputs():
            addr = item.get('address')
            if addr in addresses:
                is_send = True
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
        if not is_send:
            is_partial = False
        for addr, value in tx.get_outputs():
            v_out += value
            if addr in addresses:
                v_out_mine += value
                is_relevant = True
        if is_pruned:
            # some inputs are mine:
            fee = None
            if is_send:
                v = v_out_mine - v_out
            else:
                # no input is mine
                v = v_out_mine
        else:
            v = v_out_mine - v_in
            if is_partial:
                # some inputs are mine, but not all
                fee = None
                is_send = v < 0
            else:
                # all inputs are mine
                fee = v_out - v_in
        return is_relevant, is_send, v, fee

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
        return coins

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


    def get_spendable_coins(self, domain = None, exclude_frozen = True):
        coins = []
        if domain is None:
            domain = self.addresses(True)
        if exclude_frozen:
            domain = set(domain) - self.frozen_addresses
        for addr in domain:
            c = self.get_addr_utxo(addr)
            for txo, v in c.items():
                tx_height, value, is_cb = v
                if is_cb and tx_height + COINBASE_MATURITY > self.get_local_height():
                    continue
                prevout_hash, prevout_n = txo.split(':')
                output = {
                    'address':addr,
                    'value':value,
                    'prevout_n':int(prevout_n),
                    'prevout_hash':prevout_hash,
                    'height':tx_height,
                    'coinbase':is_cb
                }
                coins.append(output)
                continue
        return coins

    def dummy_address(self):
        return self.addresses(False)[0]

    def get_max_amount(self, config, inputs, recipient, fee):
        sendable = sum(map(lambda x:x['value'], inputs))
        if fee is None:
            for i in inputs:
                self.add_input_info(i)
            outputs = [(TYPE_ADDRESS, recipient, sendable)]
            dummy_tx = Transaction.from_io(inputs, outputs)
            fee = self.estimate_fee(config, dummy_tx.estimated_size())
        amount = max(0, sendable - fee)
        return amount, fee

    def get_account_addresses(self, acc_id, include_change=True):
        '''acc_id of None means all user-visible accounts'''
        addr_list = []
        acc_ids = self.accounts_to_show() if acc_id is None else [acc_id]
        for acc_id in acc_ids:
            if acc_id in self.accounts:
                acc = self.accounts[acc_id]
                addr_list += acc.get_addresses(0)
                if include_change:
                    addr_list += acc.get_addresses(1)
        return addr_list

    def get_account_from_address(self, addr):
        "Returns the account that contains this address, or None"
        for acc_id in self.accounts:    # similar to get_address_index but simpler
            if addr in self.get_account_addresses(acc_id):
                return acc_id
        return None

    def get_account_balance(self, account):
        return self.get_balance(self.get_account_addresses(account))

    def get_frozen_balance(self):
        return self.get_balance(self.frozen_addresses)

    def get_balance(self, domain=None):
        if domain is None:
            domain = self.addresses(True)
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

    def get_status(self, h):
        if not h:
            return None
        status = ''
        for tx_hash, height in h:
            status += tx_hash + ':%d:' % height
        return hashlib.sha256( status ).digest().encode('hex')

    def find_pay_to_pubkey_address(self, prevout_hash, prevout_n):
        dd = self.txo.get(prevout_hash, {})
        for addr, l in dd.items():
            for n, v, is_cb in l:
                if n == prevout_n:
                    self.print_error("found pay-to-pubkey address:", addr)
                    return addr

    def add_transaction(self, tx_hash, tx):
        is_coinbase = tx.inputs()[0].get('is_coinbase') == True
        with self.transaction_lock:
            # add inputs
            self.txi[tx_hash] = d = {}
            for txi in tx.inputs():
                addr = txi.get('address')
                if not txi.get('is_coinbase'):
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
                    addr = public_key_to_bc_address(x.decode('hex'))
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
        self.save_transactions()
        self.add_unverified_tx(tx_hash, tx_height)


    def receive_history_callback(self, addr, hist):
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

        # Write updated TXI, TXO etc.
        self.save_transactions()

    def get_history(self, domain=None):
        from collections import defaultdict
        # get domain
        if domain is None:
            domain = self.get_account_addresses(None)

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
        for tx_hash, delta in tx_deltas.items():
            conf, timestamp = self.get_confirmations(tx_hash)
            history.append((tx_hash, conf, delta, timestamp))
        history.sort(key = lambda x: self.get_txpos(x[0]))
        history.reverse()

        # 3. add balance
        c, u, x = self.get_balance(domain)
        balance = c + u + x
        h2 = []
        for item in history:
            tx_hash, conf, delta, timestamp = item
            h2.append((tx_hash, conf, delta, timestamp, balance))
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

    def fee_per_kb(self, config):
        b = config.get('dynamic_fees')
        f = config.get('fee_factor', 50)
        F = config.get('fee_per_kb', bitcoin.RECOMMENDED_FEE)
        return min(bitcoin.RECOMMENDED_FEE, self.network.fee*(50 + f)/100) if b and self.network and self.network.fee else F

    def relayfee(self):
        RELAY_FEE = 5000
        MAX_RELAY_FEE = 50000
        f = self.network.relay_fee if self.network and self.network.relay_fee else RELAY_FEE
        return min(f, MAX_RELAY_FEE)

    def get_tx_fee(self, tx):
        # this method can be overloaded
        return tx.get_fee()

    def make_unsigned_transaction(self, coins, outputs, config, fixed_fee=None, change_addr=None):
        # check outputs
        for type, data, value in outputs:
            if type == TYPE_ADDRESS:
                if not is_address(data):
                    raise BaseException("Invalid bitcoin address:" + data)

        # Avoid index-out-of-range with coins[0] below
        if not coins:
            raise NotEnoughFunds()

        for item in coins:
            self.add_input_info(item)

        # change address
        if change_addr:
            change_addrs = [change_addr]
        else:
            # send change to one of the accounts involved in the tx
            address = coins[0].get('address')
            account, _ = self.get_address_index(address)
            if self.use_change and self.accounts[account].has_change():
                # New change addresses are created only after a few
                # confirmations.  Select the unused addresses within the
                # gap limit; if none take one at random
                addrs = self.accounts[account].get_addresses(1)[-self.gap_limit_for_change:]
                change_addrs = [addr for addr in addrs if
                                self.get_num_tx(addr) == 0]
                if not change_addrs:
                    change_addrs = [random.choice(addrs)]
            else:
                change_addrs = [address]

        # Fee estimator
        if fixed_fee is None:
            fee_estimator = partial(self.estimate_fee, config)
        else:
            fee_estimator = lambda size: fixed_fee

        # Change <= dust threshold is added to the tx fee
        dust_threshold = 182 * 3 * self.relayfee() / 1000

        # Let the coin chooser select the coins to spend
        max_change = self.max_change_outputs if self.multiple_change else 1
        coin_chooser = coinchooser.get_coin_chooser(config)
        tx = coin_chooser.make_tx(coins, outputs, change_addrs[:max_change],
                                  fee_estimator, dust_threshold)

        # Sort the inputs and outputs deterministically
        tx.BIP_LI01_sort()

        run_hook('make_unsigned_transaction', self, tx)
        return tx

    def estimate_fee(self, config, size):
        fee = int(self.fee_per_kb(config) * size / 1000.)
        fee = max(fee, self.relayfee())
        return fee

    def mktx(self, outputs, password, config, fee=None, change_addr=None, domain=None):
        coins = self.get_spendable_coins(domain)
        tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr)
        self.sign_transaction(tx, password)
        return tx

    def add_input_info(self, txin):
        address = txin['address']
        account_id, sequence = self.get_address_index(address)
        account = self.accounts[account_id]
        redeemScript = account.redeem_script(*sequence)
        pubkeys = account.get_pubkeys(*sequence)
        x_pubkeys = account.get_xpubkeys(*sequence)
        # sort pubkeys and x_pubkeys, using the order of pubkeys
        pubkeys, x_pubkeys = zip( *sorted(zip(pubkeys, x_pubkeys)))
        txin['pubkeys'] = list(pubkeys)
        txin['x_pubkeys'] = list(x_pubkeys)
        txin['signatures'] = [None] * len(pubkeys)

        if redeemScript:
            txin['redeemScript'] = redeemScript
            txin['num_sig'] = account.m
        else:
            txin['redeemPubkey'] = account.get_pubkey(*sequence)
            txin['num_sig'] = 1

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add derivation for utxo in wallets
        for i, addr in self.utxo_can_sign(tx):
            txin = tx.inputs()[i]
            txin['address'] = addr
            self.add_input_info(txin)
        # Add private keys
        keypairs = {}
        for x in self.xkeys_can_sign(tx):
            sec = self.get_private_key_from_xpubkey(x, password)
            if sec:
                keypairs[x] = sec
        # Sign
        if keypairs:
            tx.sign(keypairs)

    def update_password(self, old_password, new_password):
        if new_password == '':
            new_password = None

        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode( decoded, new_password)
            self.storage.put('seed', self.seed)

        imported_account = self.accounts.get(IMPORTED_ACCOUNT)
        if imported_account:
            imported_account.update_password(old_password, new_password)
            self.save_accounts()

        if hasattr(self, 'master_private_keys'):
            for k, v in self.master_private_keys.items():
                b = pw_decode(v, old_password)
                c = pw_encode(b, new_password)
                self.master_private_keys[k] = c
            self.storage.put('master_private_keys', self.master_private_keys)

        self.set_use_encryption(new_password is not None)

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
                self.add_unverified_tx (tx_hash, tx_height)

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

    def accounts_to_show(self):
        return self.accounts.keys()

    def get_accounts(self):
        return {a_id: a for a_id, a in self.accounts.items()
                if a_id in self.accounts_to_show()}

    def get_account_name(self, k):
        return self.labels.get(k, self.accounts[k].get_name(k))

    def get_account_names(self):
        ids = self.accounts_to_show()
        return dict(zip(ids, map(self.get_account_name, ids)))

    def add_account(self, account_id, account):
        self.accounts[account_id] = account
        self.save_accounts()

    def save_accounts(self):
        d = {}
        for k, v in self.accounts.items():
            d[k] = v.dump()
        self.storage.put('accounts', d)

    def can_import(self):
        return not self.is_watching_only()

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

    def can_sign(self, tx):
        if self.is_watching_only():
            return False
        if tx.is_complete():
            return False
        if self.xkeys_can_sign(tx):
            return True
        if self.utxo_can_sign(tx):
            return True
        return False

    def utxo_can_sign(self, tx):
        out = set()
        coins = self.get_spendable_coins()
        for i in tx.inputs_without_script():
            txin = tx.inputs[i]
            for item in coins:
                if txin.get('prevout_hash') == item.get('prevout_hash') and txin.get('prevout_n') == item.get('prevout_n'):
                    out.add((i, item.get('address')))
        return out

    def xkeys_can_sign(self, tx):
        out = set()
        for x in tx.inputs_to_sign():
            if self.can_sign_xpubkey(x):
                out.add(x)
        return out

    def get_private_key_from_xpubkey(self, x_pubkey, password):
        if x_pubkey[0:2] in ['02','03','04']:
            addr = bitcoin.public_key_to_bc_address(x_pubkey.decode('hex'))
            if self.is_mine(addr):
                return self.get_private_key(addr, password)[0]
        elif x_pubkey[0:2] == 'ff':
            xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
            for k, v in self.master_public_keys.items():
                if v == xpub:
                    xprv = self.get_master_private_key(k, password)
                    if xprv:
                        _, _, _, c, k = deserialize_xkey(xprv)
                        return bip32_private_key(sequence, k, c)
        elif x_pubkey[0:2] == 'fe':
            xpub, sequence = OldAccount.parse_xpubkey(x_pubkey)
            for k, account in self.accounts.items():
                if xpub in account.get_master_pubkeys():
                    pk = account.get_private_key(sequence, self, password)
                    return pk[0]
        elif x_pubkey[0:2] == 'fd':
            addrtype = ord(x_pubkey[2:4].decode('hex'))
            addr = hash_160_to_bc_address(x_pubkey[4:].decode('hex'), addrtype)
            if self.is_mine(addr):
                return self.get_private_key(addr, password)[0]
        else:
            raise BaseException("z")


    def can_sign_xpubkey(self, x_pubkey):
        if x_pubkey[0:2] in ['02','03','04']:
            addr = bitcoin.public_key_to_bc_address(x_pubkey.decode('hex'))
            return self.is_mine(addr)
        elif x_pubkey[0:2] == 'ff':
            if not isinstance(self, BIP32_Wallet): return False
            xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
            return xpub in [ self.master_public_keys[k] for k in self.master_private_keys.keys() ]
        elif x_pubkey[0:2] == 'fe':
            if not isinstance(self, OldWallet): return False
            xpub, sequence = OldAccount.parse_xpubkey(x_pubkey)
            return xpub == self.get_master_public_key()
        elif x_pubkey[0:2] == 'fd':
            addrtype = ord(x_pubkey[2:4].decode('hex'))
            addr = hash_160_to_bc_address(x_pubkey[4:].decode('hex'), addrtype)
            return self.is_mine(addr)
        else:
            raise BaseException("z")


    def is_watching_only(self):
        False

    def can_change_password(self):
        return not self.is_watching_only()

    def get_unused_addresses(self, account):
        # fixme: use slots from expired requests
        domain = self.get_account_addresses(account, include_change=False)
        return [addr for addr in domain if not self.history.get(addr)
                and addr not in self.receive_requests.keys()]

    def get_unused_address(self, account):
        addrs = self.get_unused_addresses(account)
        if addrs:
            return addrs[0]

    def get_payment_request(self, addr, config):
        import util
        r = self.receive_requests.get(addr)
        if not r:
            return
        out = copy.copy(r)
        out['URI'] = 'bitcoin:' + addr + '?amount=' + util.format_satoshis(out.get('amount'))
        out['status'] = self.get_request_status(addr)
        # check if bip70 file exists
        rdir = config.get('requests_dir')
        if rdir:
            key = out.get('id', addr)
            path = os.path.join(rdir, key)
            if os.path.exists(path):
                baseurl = 'file://' + rdir
                rewrite = config.get('url_rewrite')
                if rewrite:
                    baseurl = baseurl.replace(*rewrite)
                out['request_url'] = os.path.join(baseurl, key)
                out['URI'] += '&r=' + out['request_url']
                out['index_url'] = os.path.join(baseurl, 'index.html') + '?id=' + key
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
        if amount:
            if self.up_to_date:
                paid = amount <= self.get_addr_received(address)
                status = PR_PAID if paid else PR_UNPAID
                if status == PR_UNPAID and expiration is not None and time.time() > timestamp + expiration:
                    status = PR_EXPIRED
            else:
                status = PR_UNKNOWN
        else:
            status = PR_UNKNOWN
        return status

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
            path = os.path.join(rdir, key)
            with open(path, 'w') as f:
                f.write(pr.SerializeToString())
            # reload
            req = self.get_payment_request(addr, config)
            with open(os.path.join(rdir, key + '.json'), 'w') as f:
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
                n = os.path.join(rdir, key + s)
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


class Imported_Wallet(Abstract_Wallet):
    wallet_type = 'imported'

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        a = self.accounts.get(IMPORTED_ACCOUNT)
        if not a:
            self.accounts[IMPORTED_ACCOUNT] = ImportedAccount({'imported':{}})

    def is_watching_only(self):
        acc = self.accounts[IMPORTED_ACCOUNT]
        n = acc.keypairs.values()
        return len(n) > 0 and n == [[None, None]] * len(n)

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def check_password(self, password):
        self.accounts[IMPORTED_ACCOUNT].get_private_key((0,0), self, password)

    def is_used(self, address):
        return False

    def get_master_public_keys(self):
        return {}

    def is_beyond_limit(self, address, account, is_change):
        return False

    def get_fingerprint(self):
        return ''

class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    def has_seed(self):
        return self.seed != ''

    def is_deterministic(self):
        return True

    def is_watching_only(self):
        return not self.has_seed()

    def add_seed(self, seed, password):
        if self.seed:
            raise Exception("a seed exists")

        self.seed_version, self.seed = self.format_seed(seed)
        if password:
            self.seed = pw_encode(self.seed, password)
        self.storage.put('seed', self.seed)
        self.storage.put('seed_version', self.seed_version)
        self.set_use_encryption(password is not None)

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_mnemonic(self, password):
        return self.get_seed(password)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True

        elif value >= self.min_acceptable_gap():
            for key, account in self.accounts.items():
                addresses = account.get_addresses(False)
                k = self.num_unused_trailing_addresses(addresses)
                n = len(addresses) - k + value
                account.receiving_pubkeys = account.receiving_pubkeys[0:n]
                account.receiving_addresses = account.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.save_accounts()
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

        for account in self.accounts.values():
            addresses = account.get_addresses(0)
            k = self.num_unused_trailing_addresses(addresses)
            for a in addresses[0:-k]:
                if self.history.get(a):
                    n = 0
                else:
                    n += 1
                    if n > nmax: nmax = n
        return nmax + 1

    def default_account(self):
        return self.accounts['0']

    def create_new_address(self, account=None, for_change=0):
        if account is None:
            account = self.default_account()
        address = account.create_new_address(for_change)
        self.add_address(address)
        return address

    def add_address(self, address):
        if address not in self.history:
            self.history[address] = []
        if self.synchronizer:
            self.synchronizer.add(address)
        self.save_accounts()

    def synchronize(self):
        with self.lock:
            for account in self.accounts.values():
                account.synchronize(self)

    def is_beyond_limit(self, address, account, is_change):
        if type(account) == ImportedAccount:
            return False
        addr_list = account.get_addresses(is_change)
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

    def get_action(self):
        if not self.get_master_public_key():
            return 'create_seed'
        if not self.accounts:
            return 'create_main_account'

    def get_master_public_keys(self):
        out = {}
        for k, account in self.accounts.items():
            if type(account) == ImportedAccount:
                continue
            name = self.get_account_name(k)
            mpk_text = '\n\n'.join(account.get_master_pubkeys())
            out[name] = mpk_text
        return out

    def get_fingerprint(self):
        return self.get_master_public_key()


class BIP32_Wallet(Deterministic_Wallet):
    # abstract class, bip32 logic
    root_name = 'x/'

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)
        self.master_public_keys  = storage.get('master_public_keys', {})
        self.master_private_keys = storage.get('master_private_keys', {})
        self.gap_limit = storage.get('gap_limit', 20)

    def is_watching_only(self):
        return not bool(self.master_private_keys)

    def can_import(self):
        return False

    def get_master_public_key(self):
        return self.master_public_keys.get(self.root_name)

    def get_master_private_key(self, account, password):
        k = self.master_private_keys.get(account)
        if not k: return
        xprv = pw_decode(k, password)
        try:
            deserialize_xkey(xprv)
        except:
            raise InvalidPassword()
        return xprv

    def check_password(self, password):
        xpriv = self.get_master_private_key(self.root_name, password)
        xpub = self.master_public_keys[self.root_name]
        if deserialize_xkey(xpriv)[3] != deserialize_xkey(xpub)[3]:
            raise InvalidPassword()

    def add_master_public_key(self, name, xpub):
        if xpub in self.master_public_keys.values():
            raise BaseException('Duplicate master public key')
        self.master_public_keys[name] = xpub
        self.storage.put('master_public_keys', self.master_public_keys)

    def add_master_private_key(self, name, xpriv, password):
        self.master_private_keys[name] = pw_encode(xpriv, password)
        self.storage.put('master_private_keys', self.master_private_keys)

    def derive_xkeys(self, root, derivation, password):
        x = self.master_private_keys[root]
        root_xprv = pw_decode(x, password)
        xprv, xpub = bip32_private_derivation(root_xprv, root, derivation)
        return xpub, xprv

    def mnemonic_to_seed(self, seed, password):
        return Mnemonic.mnemonic_to_seed(seed, password)

    @classmethod
    def make_seed(self, lang=None):
        return Mnemonic(lang).make_seed()

    def format_seed(self, seed):
        return NEW_SEED_VERSION, ' '.join(seed.split())


class BIP32_Simple_Wallet(BIP32_Wallet):
    # Wallet with a single BIP32 account, no seed
    # gap limit 20
    wallet_type = 'xpub'

    def create_xprv_wallet(self, xprv, password):
        xpub = bitcoin.xpub_from_xprv(xprv)
        account = BIP32_Account({'xpub':xpub})
        self.storage.put('seed_version', self.seed_version)
        self.add_master_private_key(self.root_name, xprv, password)
        self.add_master_public_key(self.root_name, xpub)
        self.add_account('0', account)
        self.set_use_encryption(password is not None)

    def create_xpub_wallet(self, xpub):
        account = BIP32_Account({'xpub':xpub})
        self.storage.put('seed_version', self.seed_version)
        self.add_master_public_key(self.root_name, xpub)
        self.add_account('0', account)

class BIP32_RD_Wallet(BIP32_Wallet):
    # Abstract base class for a BIP32 wallet with a self.root_derivation

    @classmethod
    def account_derivation(self, account_id):
        return self.root_derivation + account_id

    @classmethod
    def address_derivation(self, account_id, change, address_index):
        account_derivation = self.account_derivation(account_id)
        return "%s/%d/%d" % (account_derivation, change, address_index)

    def address_id(self, address):
        acc_id, (change, address_index) = self.get_address_index(address)
        return self.address_derivation(acc_id, change, address_index)

    def add_xprv_from_seed(self, seed, name, password, passphrase=''):
        # we don't store the seed, only the master xpriv
        xprv, xpub = bip32_root(self.mnemonic_to_seed(seed, passphrase))
        xprv, xpub = bip32_private_derivation(xprv, "m/", self.root_derivation)
        self.add_master_public_key(name, xpub)
        self.add_master_private_key(name, xprv, password)

    def add_xpub_from_seed(self, seed, name):
        # store only master xpub
        xprv, xpub = bip32_root(self.mnemonic_to_seed(seed,''))
        xprv, xpub = bip32_private_derivation(xprv, "m/", self.root_derivation)
        self.add_master_public_key(name, xpub)

    def create_master_keys(self, password):
        seed = self.get_seed(password)
        self.add_xprv_from_seed(seed, self.root_name, password)


class BIP32_HD_Wallet(BIP32_RD_Wallet):
    # Abstract base class for a BIP32 wallet that admits account creation

    def __init__(self, storage):
        BIP32_Wallet.__init__(self, storage)
        # Backwards-compatibility.  Remove legacy "next_account2" and
        # drop unused master public key to avoid duplicate errors
        acc2 = storage.get('next_account2', None)
        if acc2:
            self.master_public_keys.pop(self.root_name + acc2[0] + "'", None)
            storage.put('next_account2', None)
            storage.put('master_public_keys', self.master_public_keys)

    def next_account_number(self):
        assert (set(self.accounts.keys()) ==
                set(['%d' % n for n in range(len(self.accounts))]))
        return len(self.accounts)

    def show_account(self, account_id):
        return self.account_is_used(account_id) or account_id in self.labels

    def last_account_id(self):
        return '%d' % (self.next_account_number() - 1)

    def accounts_to_show(self):
        # The last account is shown only if named or used
        result = list(self.accounts.keys())
        last_id = self.last_account_id()
        if not self.show_account(last_id):
            result.remove(last_id)
        return result

    def can_create_accounts(self):
        return self.root_name in self.master_private_keys.keys()

    def permit_account_naming(self):
        return (self.can_create_accounts() and
                not self.show_account(self.last_account_id()))

    def create_hd_account(self, password):
        # First check the password is valid (this raises if it isn't).
        if self.can_change_password():
            self.check_password(password)
        assert self.next_account_number() == 0
        self.create_next_account(password, _('Main account'))
        self.create_next_account(password)

    def create_next_account(self, password, label=None):
        account_id = '%d' % self.next_account_number()
        derivation = self.account_derivation(account_id)
        root_name = self.root_derivation.split('/')[0]  # NOT self.root_name!
        xpub, xprv = self.derive_xkeys(root_name, derivation, password)
        wallet_key = self.root_name + account_id + "'"
        self.add_master_public_key(wallet_key, xpub)
        if xprv:
            self.add_master_private_key(wallet_key, xprv, password)
        account = BIP32_Account({'xpub':xpub})
        self.add_account(account_id, account)
        if label:
            self.set_label(account_id, label)
        self.save_accounts()

    def account_is_used(self, account_id):
        return self.accounts[account_id].is_used(self)

    def accounts_all_used(self):
        return all(self.account_is_used(acc_id) for acc_id in self.accounts)


class BIP44_Wallet(BIP32_HD_Wallet):
    root_derivation = "m/44'/0'/"
    wallet_type = 'bip44'

    @classmethod
    def account_derivation(self, account_id):
        return self.root_derivation + account_id + "'"

    def can_sign_xpubkey(self, x_pubkey):
        xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub in self.master_public_keys.values()

    def can_create_accounts(self):
        return not self.is_watching_only()

    @staticmethod
    def normalize_passphrase(passphrase):
        return normalize('NFKD', unicode(passphrase or ''))

    @staticmethod
    def mnemonic_to_seed(mnemonic, passphrase):
        # See BIP39
        import pbkdf2, hashlib, hmac
        PBKDF2_ROUNDS = 2048
        mnemonic = normalize('NFKD', ' '.join(mnemonic.split()))
        passphrase = BIP44_Wallet.normalize_passphrase(passphrase)
        return pbkdf2.PBKDF2(mnemonic, 'mnemonic' + passphrase,
                             iterations = PBKDF2_ROUNDS, macmodule = hmac,
                             digestmodule = hashlib.sha512).read(64)

    def derive_xkeys(self, root, derivation, password):
        root = self.root_name
        derivation = derivation.replace(self.root_derivation, root)
        x = self.master_private_keys.get(root)
        if x:
            root_xprv = pw_decode(x, password)
            xprv, xpub = bip32_private_derivation(root_xprv, root, derivation)
            return xpub, xprv
        else:
            root_xpub = self.master_public_keys.get(root)
            xpub = bip32_public_derivation(root_xpub, root, derivation)
            return xpub, None


class NewWallet(BIP32_RD_Wallet, Mnemonic):
    # Standard wallet
    root_derivation = "m/"
    wallet_type = 'standard'

    def create_main_account(self):
        xpub = self.master_public_keys.get("x/")
        account = BIP32_Account({'xpub':xpub})
        self.add_account('0', account)


class Multisig_Wallet(BIP32_RD_Wallet, Mnemonic):
    # generic m of n
    root_name = "x1/"
    root_derivation = "m/"

    def __init__(self, storage):
        BIP32_Wallet.__init__(self, storage)
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = Wallet.multisig_type(self.wallet_type)

    def load_accounts(self):
        self.accounts = {}
        d = self.storage.get('accounts', {})
        v = d.get('0')
        if v:
            if v.get('xpub3'):
                v['xpubs'] = [v['xpub'], v['xpub2'], v['xpub3']]
            elif v.get('xpub2'):
                v['xpubs'] = [v['xpub'], v['xpub2']]
            self.accounts = {'0': Multisig_Account(v)}

    def create_main_account(self):
        account = Multisig_Account({'xpubs': self.master_public_keys.values(), 'm': self.m})
        self.add_account('0', account)

    def get_master_public_keys(self):
        return self.master_public_keys

    def get_action(self):
        for i in range(self.n):
            if self.master_public_keys.get("x%d/"%(i+1)) is None:
                return 'create_seed' if i == 0 else 'add_cosigners'
        if not self.accounts:
            return 'create_main_account'

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys().values()))


class OldWallet(Deterministic_Wallet):
    wallet_type = 'old'

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 5)

    def make_seed(self):
        import old_mnemonic
        seed = random_seed(128)
        return ' '.join(old_mnemonic.mn_encode(seed))

    def format_seed(self, seed):
        import old_mnemonic
        # see if seed was entered as hex
        seed = seed.strip()
        if seed:
            try:
                seed.decode('hex')
                return OLD_SEED_VERSION, str(seed)
            except Exception:
                pass
        words = seed.split()
        seed = old_mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
        return OLD_SEED_VERSION, seed

    def create_master_keys(self, password):
        seed = self.get_seed(password)
        mpk = OldAccount.mpk_from_seed(seed)
        self.storage.put('master_public_key', mpk)

    def get_master_public_key(self):
        return self.storage.get("master_public_key")

    def get_master_public_keys(self):
        return {'Main Account':self.get_master_public_key()}

    def create_main_account(self):
        mpk = self.storage.get("master_public_key")
        self.create_account(mpk)

    def create_account(self, mpk):
        self.accounts['0'] = OldAccount({'mpk':mpk, 0:[], 1:[]})
        self.save_accounts()

    def create_watching_only_wallet(self, mpk):
        self.seed_version = OLD_SEED_VERSION
        self.storage.put('seed_version', self.seed_version)
        self.storage.put('master_public_key', mpk)
        self.create_account(mpk)

    def get_seed(self, password):
        seed = pw_decode(self.seed, password).encode('utf8')
        return seed

    def check_password(self, password):
        seed = self.get_seed(password)
        self.accounts['0'].check_seed(seed)

    def get_mnemonic(self, password):
        import old_mnemonic
        s = self.get_seed(password)
        return ' '.join(old_mnemonic.mn_encode(s))


WalletType = namedtuple("WalletType", "category type constructor")

# former WalletFactory
class Wallet(object):
    """The main wallet "entry point".
    This class is actually a factory that will return a wallet of the correct
    type when passed a WalletStorage instance."""

    wallets = [   # category    type        constructor
        WalletType('standard', 'old',       OldWallet),
        WalletType('standard', 'xpub',      BIP32_Simple_Wallet),
        WalletType('standard', 'standard',  NewWallet),
        WalletType('standard', 'imported',  Imported_Wallet),
        WalletType('multisig', '2of2',      Multisig_Wallet),
        WalletType('multisig', '2of3',      Multisig_Wallet),
        WalletType('bip44',    'bip44',     BIP44_Wallet),
    ]

    def __new__(self, storage):
        seed_version = storage.get('seed_version')
        if not seed_version:
            seed_version = OLD_SEED_VERSION if len(storage.get('master_public_key','')) == 128 else NEW_SEED_VERSION

        if seed_version not in [OLD_SEED_VERSION, NEW_SEED_VERSION]:
            msg = "Your wallet has an unsupported seed version."
            msg += '\n\nWallet file: %s' % os.path.abspath(storage.path)
            if seed_version in [5, 7, 8, 9, 10]:
                msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
            if seed_version == 6:
                # version 1.9.8 created v6 wallets when an incorrect seed was entered in the restore dialog
                msg += '\n\nThis file was created because of a bug in version 1.9.8.'
                if storage.get('master_public_keys') is None and storage.get('master_private_keys') is None and storage.get('imported_keys') is None:
                    # pbkdf2 was not included with the binaries, and wallet creation aborted.
                    msg += "\nIt does not contain any keys, and can safely be removed."
                else:
                    # creation was complete if electrum was run from source
                    msg += "\nPlease open this file with Electrum 1.9.8, and move your coins to a new wallet."
            raise BaseException(msg)

        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type, seed_version)
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
    def categories():
        return [wallet.category for wallet in Wallet.wallets]

    @staticmethod
    def register_plugin_wallet(category, type, constructor):
        Wallet.wallets.append(WalletType(category, type, constructor))

    @staticmethod
    def wallet_class(wallet_type, seed_version):
        if wallet_type:
            if Wallet.multisig_type(wallet_type):
                return Multisig_Wallet

            for wallet in Wallet.wallets:
                if wallet.type == wallet_type:
                    return wallet.constructor

            raise RuntimeError("Unknown wallet type: " + wallet_type)

        return OldWallet if seed_version == OLD_SEED_VERSION else NewWallet

    @staticmethod
    def is_seed(seed):
        return is_old_seed(seed) or is_new_seed(seed)

    @staticmethod
    def is_mpk(text):
        return Wallet.is_old_mpk(text) or Wallet.is_xpub(text)

    @staticmethod
    def is_old_mpk(mpk):
        try:
            int(mpk, 16)
        except:
            return False
        return len(mpk) == 128

    @staticmethod
    def is_xpub(text):
        if text[0:4] != 'xpub':
            return False
        try:
            deserialize_xkey(text)
            return True
        except:
            return False

    @staticmethod
    def is_xprv(text):
        if text[0:4] != 'xprv':
            return False
        try:
            deserialize_xkey(text)
            return True
        except:
            return False

    @staticmethod
    def is_address(text):
        parts = text.split()
        return bool(parts) and all(bitcoin.is_address(x) for x in parts)

    @staticmethod
    def is_private_key(text):
        parts = text.split()
        return bool(parts) and all(bitcoin.is_private_key(x) for x in parts)

    @staticmethod
    def is_any(text):
        return (Wallet.is_seed(text) or Wallet.is_old_mpk(text)
                or Wallet.is_xprv(text) or Wallet.is_xpub(text)
                or Wallet.is_address(text) or Wallet.is_private_key(text))

    @staticmethod
    def should_encrypt(text):
        return (Wallet.is_seed(text) or Wallet.is_xprv(text)
                or Wallet.is_private_key(text))

    @staticmethod
    def multisig_type(wallet_type):
        '''If wallet_type is mofn multi-sig, return [m, n],
        otherwise return None.'''
        match = re.match('(\d+)of(\d+)', wallet_type)
        if match:
            match = [int(x) for x in match.group(1, 2)]
        return match

    @staticmethod
    def from_seed(seed, password, storage):
        if is_old_seed(seed):
            klass = OldWallet
        elif is_new_seed(seed):
            klass = NewWallet
        w = klass(storage)
        w.add_seed(seed, password)
        w.create_master_keys(password)
        return w

    @staticmethod
    def from_address(text, storage):
        w = Imported_Wallet(storage)
        for x in text.split():
            w.accounts[IMPORTED_ACCOUNT].add(x, None, None, None)
        w.save_accounts()
        return w

    @staticmethod
    def from_private_key(text, password, storage):
        w = Imported_Wallet(storage)
        w.update_password(None, password)
        for x in text.split():
            w.import_key(x, password)
        return w

    @staticmethod
    def from_old_mpk(mpk, storage):
        w = OldWallet(storage)
        w.seed = ''
        w.create_watching_only_wallet(mpk)
        return w

    @staticmethod
    def from_xpub(xpub, storage):
        w = BIP32_Simple_Wallet(storage)
        w.create_xpub_wallet(xpub)
        return w

    @staticmethod
    def from_xprv(xprv, password, storage):
        w = BIP32_Simple_Wallet(storage)
        w.create_xprv_wallet(xprv, password)
        return w

    @staticmethod
    def from_multisig(key_list, password, storage, wallet_type):
        storage.put('wallet_type', wallet_type)
        wallet = Multisig_Wallet(storage)
        key_list = sorted(key_list, key = Wallet.is_xpub)
        for i, text in enumerate(key_list):
            name = "x%d/" % (i+1)
            if Wallet.is_xprv(text):
                xpub = bitcoin.xpub_from_xprv(text)
                wallet.add_master_public_key(name, xpub)
                wallet.add_master_private_key(name, text, password)
            elif Wallet.is_xpub(text):
                wallet.add_master_public_key(name, text)
            elif Wallet.is_seed(text):
                if name == 'x1/':
                    wallet.add_seed(text, password)
                    wallet.create_master_keys(password)
                else:
                    wallet.add_xprv_from_seed(text, name, password)
            else:
                raise RunTimeError("Cannot handle text for multisig")
        wallet.set_use_encryption(password is not None)
        return wallet

    @staticmethod
    def from_text(text, password, storage):
        if Wallet.is_xprv(text):
            wallet = Wallet.from_xprv(text, password, storage)
        elif Wallet.is_old_mpk(text):
            wallet = Wallet.from_old_mpk(text, storage)
        elif Wallet.is_xpub(text):
            wallet = Wallet.from_xpub(text, storage)
        elif Wallet.is_address(text):
            wallet = Wallet.from_address(text, storage)
        elif Wallet.is_private_key(text):
            wallet = Wallet.from_private_key(text, password, storage)
        elif Wallet.is_seed(text):
            wallet = Wallet.from_seed(text, password, storage)
        else:
            raise BaseException('Invalid seedphrase or key')
        return wallet
