#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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

import sys
import base64
import os
import re
import hashlib
import copy
import operator
import ast
import threading
import random
import aes
import Queue
import time

from util import print_msg, print_error, user_dir, format_satoshis
from bitcoin import *


# AES encryption
EncodeAES = lambda secret, s: base64.b64encode(aes.encryptData(secret,s))
DecodeAES = lambda secret, e: aes.decryptData(secret, base64.b64decode(e))

def pw_encode(s, password):
    if password:
        secret = Hash(password)
        return EncodeAES(secret, s)
    else:
        return s

def pw_decode(s, password):
    if password is not None:
        secret = Hash(password)
        try:
            d = DecodeAES(secret, s)
        except:
            raise BaseException('Invalid password')
        return d
    else:
        return s





from version import ELECTRUM_VERSION, SEED_VERSION


class Wallet:
    def __init__(self, config={}):

        self.config = config
        self.electrum_version = ELECTRUM_VERSION
        self.gap_limit_for_change = 3 # constant

        # saved fields
        self.seed_version          = config.get('seed_version', SEED_VERSION)
        self.gap_limit             = config.get('gap_limit', 5)
        self.use_change            = config.get('use_change',True)
        self.fee                   = int(config.get('fee_per_kb',50000))
        self.num_zeros             = int(config.get('num_zeros',0))
        self.use_encryption        = config.get('use_encryption', False)
        self.seed                  = config.get('seed', '')               # encrypted
        self.labels                = config.get('labels', {})
        self.frozen_addresses      = config.get('frozen_addresses',[])
        self.prioritized_addresses = config.get('prioritized_addresses',[])
        self.addressbook           = config.get('contacts', [])

        self.imported_keys         = config.get('imported_keys',{})
        self.history               = config.get('addr_history',{})        # address -> list(txid, height)
        self.accounts              = config.get('accounts', {})   # this should not include public keys

        self.SequenceClass = ElectrumSequence
        self.sequences = {}
        self.sequences[0] = self.SequenceClass(self.config.get('master_public_key'))

        if self.accounts.get(0) is None:
            self.accounts[0] = { 0:[], 1:[], 'name':'Main account' }

        self.transactions = {}
        tx = config.get('transactions',{})
        try:
            for k,v in tx.items(): self.transactions[k] = Transaction(v)
        except:
            print_msg("Warning: Cannot deserialize transactions. skipping")
        
        # not saved
        self.prevout_values = {}     # my own transaction outputs
        self.spent_outputs = []

        # spv
        self.verifier = None

        # there is a difference between wallet.up_to_date and interface.is_up_to_date()
        # interface.is_up_to_date() returns true when all requests have been answered and processed
        # wallet.up_to_date is true when the wallet is synchronized (stronger requirement)
        
        self.up_to_date = False
        self.lock = threading.Lock()
        self.transaction_lock = threading.Lock()
        self.tx_event = threading.Event()

        if self.seed_version != SEED_VERSION:
            raise ValueError("This wallet seed is deprecated. Please run upgrade.py for a diagnostic.")

        for tx_hash, tx in self.transactions.items():
            if self.check_new_tx(tx_hash, tx):
                self.update_tx_outputs(tx_hash)
            else:
                print_error("unreferenced tx", tx_hash)
                self.transactions.pop(tx_hash)


    def set_up_to_date(self,b):
        with self.lock: self.up_to_date = b

    def is_up_to_date(self):
        with self.lock: return self.up_to_date

    def update(self):
        self.up_to_date = False
        self.interface.poke('synchronizer')
        while not self.is_up_to_date(): time.sleep(0.1)

    def import_key(self, sec, password):
        # check password
        seed = self.decode_seed(password)
        try:
            address = address_from_private_key(sec)
        except:
            raise BaseException('Invalid private key')

        if self.is_mine(address):
            raise BaseException('Address already in wallet')
        
        # store the originally requested keypair into the imported keys table
        self.imported_keys[address] = pw_encode(sec, password )
        self.config.set_key('imported_keys', self.imported_keys, True)
        return address
        
    def delete_imported_key(self, addr):
        if addr in self.imported_keys:
            self.imported_keys.pop(addr)
            self.config.set_key('imported_keys', self.imported_keys, True)


    def init_seed(self, seed):
        if self.seed: raise BaseException("a seed exists")
        if not seed: 
            seed = random_seed(128)
        self.seed = seed

    def save_seed(self):
        self.config.set_key('seed', self.seed, True)
        self.config.set_key('seed_version', self.seed_version, True)
        mpk = self.SequenceClass.mpk_from_seed(self.seed)
        self.init_sequence(mpk)


    def init_sequence(self, mpk):
        self.config.set_key('master_public_key', mpk, True)
        self.sequences[0] = self.SequenceClass(mpk)
        self.accounts[0] = { 0:[], 1:[], 'name':'Main account' }
        self.config.set_key('accounts', self.accounts, True)


    def addresses(self, include_change = True):
        o = self.get_account_addresses(-1, include_change)
        for a in self.accounts.keys():
            o += self.get_account_addresses(a, include_change)
        return o


    def is_mine(self, address):
        return address in self.addresses(True)

    def is_change(self, address):
        if not self.is_mine(address): return False
        if address in self.imported_keys.keys(): return False
        acct, s = self.get_address_index(address)
        return s[0] == 1

    def get_master_public_key(self):
        return self.config.get("master_public_key")

    def get_address_index(self, address):
        if address in self.imported_keys.keys():
            return -1, None
        for account in self.accounts.keys():
            for for_change in [0,1]:
                addresses = self.accounts[account][for_change]
                for addr in addresses:
                    if address == addr:
                        return account, (for_change, addresses.index(addr))
        raise BaseException("not found")
        

    def get_public_key(self, address):
        account, sequence = self.get_address_index(address)
        return self.sequences[account].get_pubkey( sequence )


    def decode_seed(self, password):
        seed = pw_decode(self.seed, password)
        self.sequences[0].check_seed(seed)
        return seed
        
    def get_private_key(self, address, password):
        return self.get_private_keys([address], password).get(address)

    def get_private_keys(self, addresses, password):
        if not self.seed: return {}
        # decode seed in any case, in order to test the password
        seed = self.decode_seed(password)
        out = {}
        l_sequences = []
        l_addresses = []
        for address in addresses:
            if address in self.imported_keys.keys():
                out[address] = pw_decode( self.imported_keys[address], password )
            else:
                account, sequence = self.get_address_index(address)
                if account == 0:
                    l_sequences.append(sequence)
                    l_addresses.append(address)

        pk = self.sequences[0].get_private_keys(l_sequences, seed)
        for i, address in enumerate(l_addresses): out[address] = pk[i]                     
        return out


    def signrawtransaction(self, tx, input_info, private_keys, password):
        unspent_coins = self.get_unspent_coins()
        seed = self.decode_seed(password)

        # convert private_keys to dict 
        pk = {}
        for sec in private_keys:
            address = address_from_private_key(sec)
            pk[address] = sec
        private_keys = pk

        for txin in tx.inputs:
            # convert to own format
            txin['tx_hash'] = txin['prevout_hash']
            txin['index'] = txin['prevout_n']

            for item in input_info:
                if item.get('txid') == txin['tx_hash'] and item.get('vout') == txin['index']:
                    txin['raw_output_script'] = item['scriptPubKey']
                    txin['redeemScript'] = item.get('redeemScript')
                    txin['KeyID'] = item.get('KeyID')
                    break
            else:
                for item in unspent_coins:
                    if txin['tx_hash'] == item['tx_hash'] and txin['index'] == item['index']:
                        txin['raw_output_script'] = item['raw_output_script']
                        break
                else:
                    # if neither, we might want to get it from the server..
                    raise

            # find the address:
            if txin.get('KeyID'):
                account, name, sequence = txin.get('KeyID')
                if name != 'Electrum': continue
                sec = self.sequences[account].get_private_key(sequence, seed)
                addr = self.sequences[account].get_address(sequence)
                txin['address'] = addr
                private_keys[addr] = sec

            elif txin.get("redeemScript"):
                txin['address'] = hash_160_to_bc_address(hash_160(txin.get("redeemScript").decode('hex')), 5)

            elif txin.get("raw_output_script"):
                import deserialize
                addr = deserialize.get_address_from_output_script(txin.get("raw_output_script").decode('hex'))
                sec = self.get_private_key(addr, password)
                if sec: 
                    private_keys[addr] = sec
                    txin['address'] = addr

        tx.sign( private_keys )

    def sign_message(self, address, message, password):
        sec = self.get_private_key(address, password)
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed, address)

    def verify_message(self, address, signature, message):
        try:
            EC_KEY.verify_message(address, signature, message)
            return True
        except BaseException as e:
            print_error("Verification error: {0}".format(e))
            return False

    def create_new_address(self, account, for_change):
        addresses = self.accounts[account][for_change]
        n = len(addresses)
        address = self.get_new_address( account, for_change, n)
        self.accounts[account][for_change].append(address)
        self.history[address] = []
        print_msg(address)
        return address
        

    def get_new_address(self, account, for_change, n):
        return self.sequences[account].get_address((for_change, n))
        print address
        return address

    def change_gap_limit(self, value):
        if value >= self.gap_limit:
            self.gap_limit = value
            self.config.set_key('gap_limit', self.gap_limit, True)
            self.interface.poke('synchronizer')
            return True

        elif value >= self.min_acceptable_gap():
            for key, account in self.accounts.items():
                addresses = account[0]
                k = self.num_unused_trailing_addresses(addresses)
                n = len(addresses) - k + value
                addresses = addresses[0:n]
                self.accounts[key][0] = addresses

            self.gap_limit = value
            self.config.set_key('gap_limit', self.gap_limit, True)
            self.config.set_key('accounts', self.accounts, True)
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
            addresses = account[0]
            k = self.num_unused_trailing_addresses(addresses)
            for a in addresses[0:-k]:
                if self.history.get(a):
                    n = 0
                else:
                    n += 1
                    if n > nmax: nmax = n
        return nmax + 1


    def address_is_old(self, address):
        age = -1
        h = self.history.get(address, [])
        if h == ['*']:
            return True
        for tx_hash, tx_height in h:
            if tx_height == 0:
                tx_age = 0
            else: 
                tx_age = self.verifier.height - tx_height + 1
            if tx_age > age:
                age = tx_age
        return age > 2


    def synchronize_sequence(self, account, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        addresses = self.accounts[account][for_change]
        new_addresses = []
        while True:
            if len(addresses) < limit:
                new_addresses.append( self.create_new_address(account, for_change) )
                continue
            if map( lambda a: self.address_is_old(a), addresses[-limit:] ) == limit*[False]:
                break
            else:
                new_addresses.append( self.create_new_address(account, for_change) )
        return new_addresses
        

    def synchronize_account(self, account):
        new = []
        new += self.synchronize_sequence(account, 0)
        new += self.synchronize_sequence(account, 1)
        return new

    def synchronize(self):
        new = []
        for account in self.accounts.keys():
            new += self.synchronize_account(account)
        if new:
            self.config.set_key('accounts', self.accounts, True)
            self.config.set_key('addr_history', self.history, True)
        return new


    def is_found(self):
        return self.history.values() != [[]] * len(self.history) 


    def add_contact(self, address, label=None):
        self.addressbook.append(address)
        self.config.set_key('contacts', self.addressbook, True)
        if label:  
            self.labels[address] = label
            self.config.set_key('labels', self.labels)

    def delete_contact(self, addr):
        if addr in self.addressbook:
            self.addressbook.remove(addr)
            self.config.set_key('addressbook', self.addressbook, True)


    def fill_addressbook(self):
        for tx_hash, tx in self.transactions.items():
            is_relevant, is_send, _, _ = self.get_tx_value(tx)
            if is_send:
                for addr, v in tx.outputs:
                    if not self.is_mine(addr) and addr not in self.addressbook:
                        self.addressbook.append(addr)
        # redo labels
        # self.update_tx_labels()

    def get_num_tx(self, address):
        n = 0 
        for tx in self.transactions.values():
            if address in map(lambda x:x[0], tx.outputs): n += 1
        return n


    def get_address_flags(self, addr):
        flags = "C" if self.is_change(addr) else "I" if addr in self.imported_keys.keys() else "-" 
        flags += "F" if addr in self.frozen_addresses else "P" if addr in self.prioritized_addresses else "-"
        return flags
        

    def get_tx_value(self, tx, account=None):
        domain = self.get_account_addresses(account)
        return tx.get_value(domain, self.prevout_values)

    
    def update_tx_outputs(self, tx_hash):
        tx = self.transactions.get(tx_hash)

        for i, (addr, value) in enumerate(tx.outputs):
            key = tx_hash+ ':%d'%i
            self.prevout_values[key] = value

        for item in tx.inputs:
            if self.is_mine(item.get('address')):
                key = item['prevout_hash'] + ':%d'%item['prevout_n']
                self.spent_outputs.append(key)


    def get_addr_balance(self, address):
        assert self.is_mine(address)
        h = self.history.get(address,[])
        if h == ['*']: return 0,0
        c = u = 0
        received_coins = []   # list of coins received at address

        for tx_hash, tx_height in h:
            tx = self.transactions.get(tx_hash)
            if not tx: continue

            for i, (addr, value) in enumerate(tx.outputs):
                if addr == address:
                    key = tx_hash + ':%d'%i
                    received_coins.append(key)

        for tx_hash, tx_height in h:
            tx = self.transactions.get(tx_hash)
            if not tx: continue
            v = 0

            for item in tx.inputs:
                addr = item.get('address')
                if addr == address:
                    key = item['prevout_hash']  + ':%d'%item['prevout_n']
                    value = self.prevout_values.get( key )
                    if key in received_coins: 
                        v -= value

            for i, (addr, value) in enumerate(tx.outputs):
                key = tx_hash + ':%d'%i
                if addr == address:
                    v += value

            if tx_height:
                c += v
            else:
                u += v
        return c, u


    def get_accounts(self):
        accounts = {}
        for k, account in self.accounts.items():
            accounts[k] = account.get('name')
        if self.imported_keys:
            accounts[-1] = 'Imported keys'
        return accounts

    def get_account_addresses(self, a, include_change=True):
        if a is None:
            o = self.addresses(True)
        elif a == -1:
            o = self.imported_keys.keys()
        else:
            ac = self.accounts[a]
            o = ac[0][:]
            if include_change: o += ac[1]
        return o

    def get_imported_balance(self):
        cc = uu = 0
        for addr in self.imported_keys.keys():
            c, u = self.get_addr_balance(addr)
            cc += c
            uu += u
        return cc, uu

    def get_account_balance(self, account):
        if account is None:
            return self.get_balance()
        elif account == -1:
            return self.get_imported_balance()
        
        conf = unconf = 0
        for addr in self.get_account_addresses(account): 
            c, u = self.get_addr_balance(addr)
            conf += c
            unconf += u
        return conf, unconf

    def get_frozen_balance(self):
        conf = unconf = 0
        for addr in self.frozen_addresses:
            c, u = self.get_addr_balance(addr)
            conf += c
            unconf += u
        return conf, unconf

        
    def get_balance(self):
        cc = uu = 0
        for a in self.accounts.keys():
            c, u = self.get_account_balance(a)
            cc += c
            uu += u
        c, u = self.get_imported_balance()
        cc += c
        uu += u
        return cc, uu


    def get_unspent_coins(self, domain=None):
        coins = []
        if domain is None: domain = self.addresses(True)
        for addr in domain:
            h = self.history.get(addr, [])
            if h == ['*']: continue
            for tx_hash, tx_height in h:
                tx = self.transactions.get(tx_hash)
                if tx is None: raise BaseException("Wallet not synchronized")
                for output in tx.d.get('outputs'):
                    if output.get('address') != addr: continue
                    key = tx_hash + ":%d" % output.get('index')
                    if key in self.spent_outputs: continue
                    output['tx_hash'] = tx_hash
                    coins.append(output)
        return coins



    def choose_tx_inputs( self, amount, fixed_fee, account = None ):
        """ todo: minimize tx size """
        total = 0
        fee = self.fee if fixed_fee is None else fixed_fee
        domain = self.get_account_addresses(account)
        coins = []
        prioritized_coins = []
        for i in self.frozen_addresses:
            if i in domain: domain.remove(i)

        for i in self.prioritized_addresses:
            if i in domain: domain.remove(i)

        coins = self.get_unspent_coins(domain)
        prioritized_coins = self.get_unspent_coins(self.prioritized_addresses)

        inputs = []
        coins = prioritized_coins + coins

        for item in coins: 
            addr = item.get('address')
            v = item.get('value')
            total += v
            inputs.append( item )
            fee = self.estimated_fee(inputs) if fixed_fee is None else fixed_fee
            if total >= amount + fee: break
        else:
            inputs = []

        return inputs, total, fee


    def estimated_fee(self, inputs):
        estimated_size =  len(inputs) * 180 + 80     # this assumes non-compressed keys
        fee = self.fee * int(round(estimated_size/1024.))
        if fee == 0: fee = self.fee
        return fee


    def add_tx_change( self, inputs, outputs, amount, fee, total, change_addr=None, account=0 ):
        "add change to a transaction"
        change_amount = total - ( amount + fee )
        if change_amount != 0:
            if not change_addr:
                if account is None: 
                    # send change to one of the accounts involved in the tx
                    address = inputs[0].get('address')
                    account, _ = self.get_address_index(address)

                if not self.use_change or account == -1:
                    change_addr = inputs[-1]['address']
                else:
                    change_addr = self.accounts[account][1][-self.gap_limit_for_change]

            # Insert the change output at a random position in the outputs
            posn = random.randint(0, len(outputs))
            outputs[posn:posn] = [( change_addr,  change_amount)]
        return outputs


    def get_history(self, address):
        with self.lock:
            return self.history.get(address)


    def get_status(self, h):
        if not h: return None
        if h == ['*']: return '*'
        status = ''
        for tx_hash, height in h:
            status += tx_hash + ':%d:' % height
        return hashlib.sha256( status ).digest().encode('hex')


    def receive_tx_callback(self, tx_hash, tx, tx_height):
        if not self.check_new_tx(tx_hash, tx):
            # may happen due to pruning
            print_error("received transaction that is no longer referenced in history", tx_hash)
            return

        with self.transaction_lock:
            self.transactions[tx_hash] = tx

            self.interface.pending_transactions_for_notifications.append(tx)

            self.save_transactions()
            if self.verifier and tx_height>0: 
                self.verifier.add(tx_hash, tx_height)
            self.update_tx_outputs(tx_hash)


    def save_transactions(self):
        tx = {}
        for k,v in self.transactions.items():
            tx[k] = str(v)
        self.config.set_key('transactions', tx, True)

    def receive_history_callback(self, addr, hist):

        if not self.check_new_history(addr, hist):
            raise BaseException("error: received history for %s is not consistent with known transactions"%addr)
            
        with self.lock:
            self.history[addr] = hist
            self.config.set_key('addr_history', self.history, True)

        if hist != ['*']:
            for tx_hash, tx_height in hist:
                if tx_height>0:
                    # add it in case it was previously unconfirmed
                    if self.verifier: self.verifier.add(tx_hash, tx_height)


    def get_tx_history(self, account=None):
        with self.transaction_lock:
            history = self.transactions.items()
            history.sort(key = lambda x: self.verifier.get_txpos(x[0]))
            result = []
    
            balance = 0
            for tx_hash, tx in history:
                is_relevant, is_mine, v, fee = self.get_tx_value(tx, account)
                if v is not None: balance += v

            c, u = self.get_account_balance(account)

            if balance != c+u:
                result.append( ('', 1000, 0, c+u-balance, None, c+u-balance, None ) )

            balance = c + u - balance
            for tx_hash, tx in history:
                is_relevant, is_mine, value, fee = self.get_tx_value(tx, account)
                if not is_relevant:
                    continue
                if value is not None:
                    balance += value

                conf, timestamp = self.verifier.get_confirmations(tx_hash) if self.verifier else (None, None)
                result.append( (tx_hash, conf, is_mine, value, fee, balance, timestamp) )

        return result


    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash)
        is_default = (label == '') or (label is None)
        if is_default: label = self.get_default_label(tx_hash)
        return label, is_default


    def get_default_label(self, tx_hash):
        tx = self.transactions.get(tx_hash)
        default_label = ''
        if tx:
            is_relevant, is_mine, _, _ = self.get_tx_value(tx)
            if is_mine:
                for o in tx.outputs:
                    o_addr, _ = o
                    if not self.is_mine(o_addr):
                        try:
                            default_label = self.labels[o_addr]
                        except KeyError:
                            default_label = o_addr
                        break
                else:
                    default_label = '(internal)'
            else:
                for o in tx.outputs:
                    o_addr, _ = o
                    if self.is_mine(o_addr) and not self.is_change(o_addr):
                        break
                else:
                    for o in tx.outputs:
                        o_addr, _ = o
                        if self.is_mine(o_addr):
                            break
                    else:
                        o_addr = None

                if o_addr:
                    dest_label = self.labels.get(o_addr)
                    try:
                        default_label = self.labels[o_addr]
                    except KeyError:
                        default_label = o_addr

        return default_label


    def mktx(self, outputs, password, fee=None, change_addr=None, account=None ):
        """
        create a transaction
        account parameter:
           None means use all accounts
           -1 means imported keys
           0, 1, etc are seed accounts
        """
        
        for address, x in outputs:
            assert is_valid(address)

        amount = sum( map(lambda x:x[1], outputs) )

        inputs, total, fee = self.choose_tx_inputs( amount, fee, account )
        if not inputs:
            raise ValueError("Not enough funds")

        outputs = self.add_tx_change(inputs, outputs, amount, fee, total, change_addr, account)

        tx = Transaction.from_io(inputs, outputs)

        pk_addresses = []
        for i in range(len(tx.inputs)):
            txin = tx.inputs[i]
            address = txin['address']
            if address in self.imported_keys.keys():
                pk_addresses.append(address)
                continue
            account, sequence = self.get_address_index(address)
            txin['KeyID'] = (account, 'Electrum', sequence) # used by the server to find the key
            pk_addr, redeemScript = self.sequences[account].get_input_info(sequence)
            if redeemScript: txin['redeemScript'] = redeemScript
            pk_addresses.append(pk_addr)

        # get all private keys at once.
        if self.seed:
            private_keys = self.get_private_keys(pk_addresses, password)
            tx.sign(private_keys)

        for address, x in outputs:
            if address not in self.addressbook and not self.is_mine(address):
                self.addressbook.append(address)

        return tx



    def sendtx(self, tx):
        # synchronous
        h = self.send_tx(tx)
        self.tx_event.wait()
        return self.receive_tx(h)

    def send_tx(self, tx):
        # asynchronous
        self.tx_event.clear()
        self.interface.send([('blockchain.transaction.broadcast', [str(tx)])], 'synchronizer')
        return tx.hash()

    def receive_tx(self,tx_hash):
        out = self.tx_result 
        if out != tx_hash:
            return False, "error: " + out
        return True, out



    def update_password(self, seed, old_password, new_password):
        if new_password == '': new_password = None
        # this will throw an exception if unicode cannot be converted
        self.seed = pw_encode( seed, new_password)
        self.config.set_key('seed', self.seed, True)
        self.use_encryption = (new_password != None)
        self.config.set_key('use_encryption', self.use_encryption,True)
        for k in self.imported_keys.keys():
            a = self.imported_keys[k]
            b = pw_decode(a, old_password)
            c = pw_encode(b, new_password)
            self.imported_keys[k] = c
        self.config.set_key('imported_keys', self.imported_keys, True)


    def freeze(self,addr):
        if self.is_mine(addr) and addr not in self.frozen_addresses:
            self.unprioritize(addr)
            self.frozen_addresses.append(addr)
            self.config.set_key('frozen_addresses', self.frozen_addresses, True)
            return True
        else:
            return False

    def unfreeze(self,addr):
        if self.is_mine(addr) and addr in self.frozen_addresses:
            self.frozen_addresses.remove(addr)
            self.config.set_key('frozen_addresses', self.frozen_addresses, True)
            return True
        else:
            return False

    def prioritize(self,addr):
        if self.is_mine(addr) and addr not in self.prioritized_addresses:
            self.unfreeze(addr)
            self.prioritized_addresses.append(addr)
            self.config.set_key('prioritized_addresses', self.prioritized_addresses, True)
            return True
        else:
            return False

    def unprioritize(self,addr):
        if self.is_mine(addr) and addr in self.prioritized_addresses:
            self.prioritized_addresses.remove(addr)
            self.config.set_key('prioritized_addresses', self.prioritized_addresses, True)
            return True
        else:
            return False

    def set_fee(self, fee):
        if self.fee != fee:
            self.fee = fee
            self.config.set_key('fee_per_kb', self.fee, True)
        

    def save(self):
        print_error("Warning: wallet.save() is deprecated")
        tx = {}
        for k,v in self.transactions.items():
            tx[k] = str(v)
            
        s = {
            'use_change': self.use_change,
            'fee_per_kb': self.fee,
            'accounts': self.accounts,
            'addr_history': self.history, 
            'labels': self.labels,
            'contacts': self.addressbook,
            'num_zeros': self.num_zeros,
            'frozen_addresses': self.frozen_addresses,
            'prioritized_addresses': self.prioritized_addresses,
            'gap_limit': self.gap_limit,
            'transactions': tx,
        }
        for k, v in s.items():
            self.config.set_key(k,v)
        self.config.save()

    def set_verifier(self, verifier):
        self.verifier = verifier

        # review transactions that are in the history
        for addr, hist in self.history.items():
            if hist == ['*']: continue
            for tx_hash, tx_height in hist:
                if tx_height>0:
                    # add it in case it was previously unconfirmed
                    self.verifier.add(tx_hash, tx_height)


        # if we are on a pruning server, remove unverified transactions
        vr = self.verifier.transactions.keys() + self.verifier.verified_tx.keys()
        for tx_hash in self.transactions.keys():
            if tx_hash not in vr:
                self.transactions.pop(tx_hash)



    def check_new_history(self, addr, hist):
        
        # check that all tx in hist are relevant
        if hist != ['*']:
            for tx_hash, height in hist:
                tx = self.transactions.get(tx_hash)
                if not tx: continue
                if not tx.has_address(addr):
                    return False

        # check that we are not "orphaning" a transaction
        old_hist = self.history.get(addr,[])
        if old_hist == ['*']: return True

        for tx_hash, height in old_hist:
            if tx_hash in map(lambda x:x[0], hist): continue
            found = False
            for _addr, _hist in self.history.items():
                if _addr == addr: continue
                if _hist == ['*']: continue
                _tx_hist = map(lambda x:x[0], _hist)
                if tx_hash in _tx_hist:
                    found = True
                    break

            if not found:
                tx = self.transactions.get(tx_hash)
                # tx might not be there
                if not tx: continue
                
                # already verified?
                if self.verifier.get_height(tx_hash):
                    continue
                # unconfirmed tx
                print_error("new history is orphaning transaction:", tx_hash)
                # check that all outputs are not mine, request histories
                ext_requests = []
                for _addr, _v in tx.outputs:
                    # assert not self.is_mine(_addr)
                    ext_requests.append( ('blockchain.address.get_history', [_addr]) )

                ext_h = self.interface.synchronous_get(ext_requests)
                print_error("sync:", ext_requests, ext_h)
                height = None
                for h in ext_h:
                    if h == ['*']: continue
                    for item in h:
                        if item.get('tx_hash') == tx_hash:
                            height = item.get('height')
                if height:
                    print_error("found height for", tx_hash, height)
                    self.verifier.add(tx_hash, height)
                else:
                    print_error("removing orphaned tx from history", tx_hash)
                    self.transactions.pop(tx_hash)

        return True



    def check_new_tx(self, tx_hash, tx):
        # 1 check that tx is referenced in addr_history. 
        addresses = []
        for addr, hist in self.history.items():
            if hist == ['*']:continue
            for txh, height in hist:
                if txh == tx_hash: 
                    addresses.append(addr)

        if not addresses:
            return False

        # 2 check that referencing addresses are in the tx
        for addr in addresses:
            if not tx.has_address(addr):
                return False

        return True




class WalletSynchronizer(threading.Thread):


    def __init__(self, wallet, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.wallet = wallet
        wallet.synchronizer = self
        self.interface = self.wallet.interface
        self.interface.register_channel('synchronizer')
        self.wallet.interface.register_callback('connected', lambda: self.wallet.set_up_to_date(False))
        self.was_updated = True
        self.running = False
        self.lock = threading.Lock()

    def stop(self):
        with self.lock: self.running = False
        self.interface.poke('synchronizer')

    def is_running(self):
        with self.lock: return self.running

    
    def subscribe_to_addresses(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.interface.send( messages, 'synchronizer')


    def run(self):
        with self.lock: self.running = True

        requested_tx = []
        missing_tx = []
        requested_histories = {}

        # request any missing transactions
        for history in self.wallet.history.values():
            if history == ['*']: continue
            for tx_hash, tx_height in history:
                if self.wallet.transactions.get(tx_hash) is None and (tx_hash, tx_height) not in missing_tx:
                    missing_tx.append( (tx_hash, tx_height) )
        print_error("missing tx", missing_tx)

        # wait until we are connected, in case the user is not connected
        while not self.interface.is_connected:
            time.sleep(1)
        
        # subscriptions
        self.subscribe_to_addresses(self.wallet.addresses(True))

        while self.is_running():
            # 1. create new addresses
            new_addresses = self.wallet.synchronize()

            # request missing addresses
            if new_addresses:
                self.subscribe_to_addresses(new_addresses)

            # request missing transactions
            for tx_hash, tx_height in missing_tx:
                if (tx_hash, tx_height) not in requested_tx:
                    self.interface.send([ ('blockchain.transaction.get',[tx_hash, tx_height]) ], 'synchronizer')
                    requested_tx.append( (tx_hash, tx_height) )
            missing_tx = []

            # detect if situation has changed
            if not self.interface.is_up_to_date('synchronizer'):
                if self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(False)
                    self.was_updated = True
            else:
                if not self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(True)
                    self.was_updated = True

            if self.was_updated:
                self.interface.trigger_callback('updated')
                self.was_updated = False

            # 2. get a response
            r = self.interface.get_response('synchronizer')

            # poke sends None. (needed during stop)
            if not r: continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r.get('result')
            error = r.get('error')
            if error:
                print "error", r
                continue

            if method == 'blockchain.address.subscribe':
                addr = params[0]
                if self.wallet.get_status(self.wallet.get_history(addr)) != result:
                    if requested_histories.get(addr) is None:
                        self.interface.send([('blockchain.address.get_history', [addr])], 'synchronizer')
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
                        raise BaseException("error: server sent history with non-unique txid", result)

                    # check that the status corresponds to what was announced
                    rs = requested_histories.pop(addr)
                    if self.wallet.get_status(hist) != rs:
                        raise BaseException("error: status mismatch: %s"%addr)
                
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
                assert tx_hash == hash_encode(Hash(result.decode('hex')))
                tx = Transaction(result)
                self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
                self.was_updated = True
                requested_tx.remove( (tx_hash, tx_height) )
                print_error("received tx:", tx_hash, len(tx.raw))

            elif method == 'blockchain.transaction.broadcast':
                self.wallet.tx_result = result
                self.wallet.tx_event.set()

            else:
                print_error("Error: Unknown message:" + method + ", " + repr(params) + ", " + repr(result) )

            if self.was_updated and not requested_tx:
                self.interface.trigger_callback('updated')
                self.interface.trigger_callback("new_transaction") # Updated gets called too many times from other places as well; if we use that signal we get the notification three times
                

                self.was_updated = False
