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
import math

from util import print_msg, print_error, format_satoshis
from bitcoin import *
from account import *
from transaction import Transaction
from plugins import run_hook
import bitcoin
from synchronizer import WalletSynchronizer

COINBASE_MATURITY = 100
DUST_THRESHOLD = 5430

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
        except Exception:
            raise Exception('Invalid password')
        return d
    else:
        return s





from version import *


class WalletStorage:

    def __init__(self, config):
        self.lock = threading.Lock()
        self.config = config
        self.data = {}
        self.file_exists = False
        self.path = self.init_path(config)
        print_error( "wallet path", self.path )
        if self.path:
            self.read(self.path)


    def init_path(self, config):
        """Set the path of the wallet."""

        # command line -w option
        path = config.get('wallet_path')
        if path:
            return path

        # path in config file
        path = config.get('default_wallet_path')
        if path:
            return path

        # default path
        dirpath = os.path.join(config.path, "wallets")
        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

        new_path = os.path.join(config.path, "wallets", "default_wallet")

        # default path in pre 1.9 versions
        old_path = os.path.join(config.path, "electrum.dat")
        if os.path.exists(old_path) and not os.path.exists(new_path):
            os.rename(old_path, new_path)

        return new_path


    def read(self, path):
        """Read the contents of the wallet file."""
        try:
            with open(self.path, "r") as f:
                data = f.read()
        except IOError:
            return
        try:
            d = ast.literal_eval( data )  #parse raw data from reading wallet file
        except Exception:
            raise IOError("Cannot read wallet file.")

        self.data = d
        self.file_exists = True


    def get(self, key, default=None):
        v = self.data.get(key)
        if v is None: 
            v = default
        return v

    def put(self, key, value, save = True):

        with self.lock:
            if value is not None:
                self.data[key] = value
            else:
                self.data.pop(key)
            if save: 
                self.write()

    def write(self):
        s = repr(self.data)
        f = open(self.path,"w")
        f.write( s )
        f.close()
        if 'ANDROID_DATA' not in os.environ:
            import stat
            os.chmod(self.path,stat.S_IREAD | stat.S_IWRITE)



    

        

class Abstract_Wallet:

    def __init__(self, storage):

        self.storage = storage
        self.electrum_version = ELECTRUM_VERSION
        self.gap_limit_for_change = 3 # constant
        # saved fields
        self.seed_version          = storage.get('seed_version', NEW_SEED_VERSION)
        self.gap_limit             = storage.get('gap_limit', 5)
        self.use_change            = storage.get('use_change',True)
        self.use_encryption        = storage.get('use_encryption', False)
        self.seed                  = storage.get('seed', '')               # encrypted
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = storage.get('frozen_addresses',[])
        self.addressbook           = storage.get('contacts', [])

        self.imported_keys         = storage.get('imported_keys',{})
        self.history               = storage.get('addr_history',{})        # address -> list(txid, height)

        self.fee                   = int(storage.get('fee_per_kb', 10000))

        self.master_public_keys = storage.get('master_public_keys',{})
        self.master_private_keys = storage.get('master_private_keys', {})

        self.next_addresses = storage.get('next_addresses',{})


        # This attribute is set when wallet.start_threads is called.
        self.synchronizer = None

        self.load_accounts()

        self.transactions = {}
        tx_list = self.storage.get('transactions',{})
        for k,v in tx_list.items():
            try:
                tx = Transaction(v)
            except Exception:
                print_msg("Warning: Cannot deserialize transactions. skipping")
                continue

            self.add_extra_addresses(tx)
            self.transactions[k] = tx

        for h,tx in self.transactions.items():
            if not self.check_new_tx(h, tx):
                print_error("removing unreferenced tx", h)
                self.transactions.pop(h)


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

        for tx_hash, tx in self.transactions.items():
            self.update_tx_outputs(tx_hash)


    def add_extra_addresses(self, tx):
        h = tx.hash()
        # find the address corresponding to pay-to-pubkey inputs
        tx.add_extra_addresses(self.transactions)
        for o in tx.d.get('outputs'):
            if o.get('is_pubkey'):
                for tx2 in self.transactions.values():
                    tx2.add_extra_addresses({h:tx})


    def get_action(self):
        pass

    def load_accounts(self):
        self.accounts = {}

    def synchronize(self):
        pass

    def get_pending_accounts(self):
        return {}
            
    def can_create_accounts(self):
        return False

    def check_password(self, password):
        pass


    def set_up_to_date(self,b):
        with self.lock: self.up_to_date = b


    def is_up_to_date(self):
        with self.lock: return self.up_to_date


    def update(self):
        self.up_to_date = False
        while not self.is_up_to_date(): 
            time.sleep(0.1)


    def import_key(self, sec, password):
        self.check_password(password)
        try:
            address = address_from_private_key(sec)
        except Exception:
            raise Exception('Invalid private key')

        if self.is_mine(address):
            raise Exception('Address already in wallet')
        
        # store the originally requested keypair into the imported keys table
        self.imported_keys[address] = pw_encode(sec, password )
        self.storage.put('imported_keys', self.imported_keys, True)
        if self.synchronizer:
            self.synchronizer.subscribe_to_addresses([address])
        return address
        

    def delete_imported_key(self, addr):
        if addr in self.imported_keys:
            self.imported_keys.pop(addr)
            self.storage.put('imported_keys', self.imported_keys, True)



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
            self.storage.put('labels', self.labels, True)

        run_hook('set_label', name, text, changed)
        return changed




    def addresses(self, include_change = True, _next=True):
        o = self.get_account_addresses(-1, include_change)
        for a in self.accounts.keys():
            o += self.get_account_addresses(a, include_change)

        if _next:
            for addr in self.next_addresses.values():
                if addr not in o:
                    o += [addr]
        return o


    def is_mine(self, address):
        return address in self.addresses(True)


    def is_change(self, address):
        if not self.is_mine(address): return False
        if address in self.imported_keys.keys(): return False
        acct, s = self.get_address_index(address)
        if s is None: return False
        return s[0] == 1


    def get_address_index(self, address):
        if address in self.imported_keys.keys():
            return -1, None

        for account in self.accounts.keys():
            for for_change in [0,1]:
                addresses = self.accounts[account].get_addresses(for_change)
                for addr in addresses:
                    if address == addr:
                        return account, (for_change, addresses.index(addr))

        for k,v in self.next_addresses.items():
            if v == address:
                return k, (0,0)

        raise Exception("Address not found", address)


    def getpubkeys(self, addr):
        assert is_valid(addr) and self.is_mine(addr)
        account, sequence = self.get_address_index(addr)
        if account != -1:
            a = self.accounts[account]
            return a.get_pubkeys( sequence )



    def get_private_key(self, address, password):
        if self.is_watching_only():
            return []

        # first check the provided password
        seed = self.get_seed(password)

        out = []
        if address in self.imported_keys.keys():
            out.append( pw_decode( self.imported_keys[address], password ) )
        else:
            account_id, sequence = self.get_address_index(address)
            account = self.accounts[account_id]
            xpubs = account.get_master_pubkeys()
            roots = [k for k, v in self.master_public_keys.iteritems() if v in xpubs]
            for root in roots:
                xpriv = self.get_master_private_key(root, password)
                if not xpriv:
                    continue
                _, _, _, c, k = deserialize_xkey(xpriv)
                pk = bip32_private_key( sequence, k, c )
                out.append(pk)
                    
        return out


    def get_public_keys(self, address):
        account_id, sequence = self.get_address_index(address)
        return self.accounts[account_id].get_pubkeys(sequence)


    def add_keypairs_from_wallet(self, tx, keypairs, password):
        for txin in tx.inputs:
            address = txin['address']
            if not self.is_mine(address):
                continue
            private_keys = self.get_private_key(address, password)
            for sec in private_keys:
                pubkey = public_key_from_private_key(sec)
                keypairs[ pubkey ] = sec
                if address in self.imported_keys.keys():
                    txin['redeemPubkey'] = pubkey


    def add_keypairs_from_KeyID(self, tx, keypairs, password):
        # first check the provided password
        seed = self.get_seed(password)

        for txin in tx.inputs:
            keyid = txin.get('KeyID')
            if keyid:
                roots = []
                for s in keyid.split('&'):
                    m = re.match("bip32\((.*),(/\d+/\d+)\)", s)
                    if not m: continue
                    xpub = m.group(1)
                    sequence = m.group(2)
                    root = self.find_root_by_master_key(xpub)
                    if not root: continue
                    sequence = map(lambda x:int(x), sequence.strip('/').split('/'))
                    root = root + '%d'%sequence[0]
                    sequence = sequence[1:]
                    roots.append((root,sequence)) 

                account_id = " & ".join( map(lambda x:x[0], roots) )
                account = self.accounts.get(account_id)
                if not account: continue
                addr = account.get_address(*sequence)
                txin['address'] = addr # fixme: side effect
                pk = self.get_private_key(addr, password)
                for sec in pk:
                    pubkey = public_key_from_private_key(sec)
                    keypairs[pubkey] = sec



    def signrawtransaction(self, tx, input_info, private_keys, password):

        # check that the password is correct
        seed = self.get_seed(password)

        # if input_info is not known, build it using wallet UTXOs
        if not input_info:
            input_info = []
            unspent_coins = self.get_unspent_coins()
            for txin in tx.inputs:
                for item in unspent_coins:
                    if txin['prevout_hash'] == item['prevout_hash'] and txin['prevout_n'] == item['prevout_n']:
                        info = { 'address':item['address'], 'scriptPubKey':item['scriptPubKey'] }
                        self.add_input_info(info)
                        input_info.append(info)
                        break
                else:
                    print_error( "input not in UTXOs" )
                    input_info.append(None)

        # add input_info to the transaction
        print_error("input_info", input_info)
        tx.add_input_info(input_info)

        # build a list of public/private keys
        keypairs = {}

        # add private keys from parameter
        for sec in private_keys:
            pubkey = public_key_from_private_key(sec)
            keypairs[ pubkey ] = sec

        # add private_keys from KeyID
        self.add_keypairs_from_KeyID(tx, keypairs, password)
        # add private keys from wallet
        self.add_keypairs_from_wallet(tx, keypairs, password)
        # sign the transaction
        self.sign_transaction(tx, keypairs, password)


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
        return decrypted[0]



    def is_found(self):
        return self.history.values() != [[]] * len(self.history) 


    def add_contact(self, address, label=None):
        self.addressbook.append(address)
        self.storage.put('contacts', self.addressbook, True)
        if label:  
            self.set_label(address, label)


    def delete_contact(self, addr):
        if addr in self.addressbook:
            self.addressbook.remove(addr)
            self.storage.put('addressbook', self.addressbook, True)


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
        flags += "F" if addr in self.frozen_addresses else "-"
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


    def get_account_name(self, k):
        default = "Unnamed account"
        m = re.match("m/0'/(\d+)", k)
        if m:
            num = m.group(1)
            if num == '0':
                default = "Main account"
            else:
                default = "Account %s"%num
                    
        m = re.match("m/1'/(\d+) & m/2'/(\d+)", k)
        if m:
            num = m.group(1)
            default = "2of2 account %s"%num
        name = self.labels.get(k, default)
        return name


    def get_account_names(self):
        accounts = {}
        for k, account in self.accounts.items():
            accounts[k] = self.get_account_name(k)
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
            o = ac.get_addresses(0)
            if include_change: o += ac.get_addresses(1)
        return o

    def get_imported_balance(self):
        return self.get_balance(self.imported_keys.keys())

    def get_account_balance(self, account):
        return self.get_balance(self.get_account_addresses(account))

    def get_frozen_balance(self):
        return self.get_balance(self.frozen_addresses)
        
    def get_balance(self, domain=None):
        if domain is None: domain = self.addresses(True)
        cc = uu = 0
        for addr in domain:
            c, u = self.get_addr_balance(addr)
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
                if tx is None: raise Exception("Wallet not synchronized")
                is_coinbase = tx.inputs[0].get('prevout_hash') == '0'*64
                for o in tx.d.get('outputs'):
                    output = o.copy()
                    if output.get('address') != addr: continue
                    key = tx_hash + ":%d" % output.get('prevout_n')
                    if key in self.spent_outputs: continue
                    output['prevout_hash'] = tx_hash
                    output['height'] = tx_height
                    output['coinbase'] = is_coinbase
                    coins.append((tx_height, output))

        # sort by age
        if coins:
            coins = sorted(coins)
            if coins[-1][0] != 0:
                while coins[0][0] == 0: 
                    coins = coins[1:] + [ coins[0] ]
        return [x[1] for x in coins]


    def choose_tx_inputs( self, amount, fixed_fee, num_outputs, domain = None ):
        """ todo: minimize tx size """
        total = 0
        fee = self.fee if fixed_fee is None else fixed_fee
        if domain is None:
            domain = self.addresses(True)

        for i in self.frozen_addresses:
            if i in domain: domain.remove(i)

        coins = self.get_unspent_coins(domain)
        inputs = []

        for item in coins:
            if item.get('coinbase') and item.get('height') + COINBASE_MATURITY > self.network.get_local_height():
                continue
            addr = item.get('address')
            v = item.get('value')
            total += v
            inputs.append(item)
            fee = self.estimated_fee(inputs, num_outputs) if fixed_fee is None else fixed_fee
            if total >= amount + fee: break
        else:
            inputs = []

        return inputs, total, fee


    def set_fee(self, fee):
        if self.fee != fee:
            self.fee = fee
            self.storage.put('fee_per_kb', self.fee, True)
        
    def estimated_fee(self, inputs, num_outputs):
        estimated_size =  len(inputs) * 180 + num_outputs * 34    # this assumes non-compressed keys
        fee = self.fee * int(math.ceil(estimated_size/1000.))
        return fee


    def add_tx_change( self, inputs, outputs, amount, fee, total, change_addr=None):
        "add change to a transaction"
        change_amount = total - ( amount + fee )
        if change_amount > DUST_THRESHOLD:
            if not change_addr:

                # send change to one of the accounts involved in the tx
                address = inputs[0].get('address')
                account, _ = self.get_address_index(address)

                if not self.use_change or account == -1:
                    change_addr = inputs[-1]['address']
                else:
                    change_addr = self.accounts[account].get_addresses(1)[-self.gap_limit_for_change]

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

        with self.transaction_lock:
            self.add_extra_addresses(tx)
            if not self.check_new_tx(tx_hash, tx):
                # may happen due to pruning
                print_error("received transaction that is no longer referenced in history", tx_hash)
                return
            self.transactions[tx_hash] = tx
            self.network.pending_transactions_for_notifications.append(tx)
            self.save_transactions()
            if self.verifier and tx_height>0: 
                self.verifier.add(tx_hash, tx_height)
            self.update_tx_outputs(tx_hash)


    def save_transactions(self):
        tx = {}
        for k,v in self.transactions.items():
            tx[k] = str(v)
        self.storage.put('transactions', tx, True)

    def receive_history_callback(self, addr, hist):

        if not self.check_new_history(addr, hist):
            raise Exception("error: received history for %s is not consistent with known transactions"%addr)
            
        with self.lock:
            self.history[addr] = hist
            self.storage.put('addr_history', self.history, True)

        if hist != ['*']:
            for tx_hash, tx_height in hist:
                if tx_height>0:
                    # add it in case it was previously unconfirmed
                    if self.verifier: self.verifier.add(tx_hash, tx_height)


    def get_tx_history(self, account=None):
        if not self.verifier:
            return []

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
                            default_label = '>' + o_addr
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
                        default_label = '<' + o_addr

        return default_label


    def make_unsigned_transaction(self, outputs, fee=None, change_addr=None, domain=None ):
        for address, x in outputs:
            assert is_valid(address), "Address " + address + " is invalid!"
        amount = sum( map(lambda x:x[1], outputs) )
        inputs, total, fee = self.choose_tx_inputs( amount, fee, len(outputs), domain )
        if not inputs:
            raise ValueError("Not enough funds")
        for txin in inputs:
            self.add_input_info(txin)
        outputs = self.add_tx_change(inputs, outputs, amount, fee, total, change_addr)
        return Transaction.from_io(inputs, outputs)


    def mktx(self, outputs, password, fee=None, change_addr=None, domain= None ):
        tx = self.make_unsigned_transaction(outputs, fee, change_addr, domain)
        keypairs = {}
        self.add_keypairs_from_wallet(tx, keypairs, password)
        if keypairs:
            self.sign_transaction(tx, keypairs, password)
        return tx


    def add_input_info(self, txin):
        address = txin['address']
        if address in self.imported_keys.keys():
            return
        account_id, sequence = self.get_address_index(address)
        account = self.accounts[account_id]
        txin['KeyID'] = account.get_keyID(sequence)
        redeemScript = account.redeem_script(sequence)
        if redeemScript: 
            txin['redeemScript'] = redeemScript
        else:
            txin['redeemPubkey'] = account.get_pubkey(*sequence)


    def sign_transaction(self, tx, keypairs, password):
        tx.sign(keypairs)
        run_hook('sign_transaction', tx, password)


    def sendtx(self, tx):
        # synchronous
        h = self.send_tx(tx)
        self.tx_event.wait()
        return self.receive_tx(h, tx)

    def send_tx(self, tx):
        # asynchronous
        self.tx_event.clear()
        self.network.send([('blockchain.transaction.broadcast', [str(tx)])], self.on_broadcast)
        return tx.hash()

    def on_broadcast(self, i, r):
        self.tx_result = r.get('result')
        self.tx_event.set()

    def receive_tx(self, tx_hash, tx):
        out = self.tx_result 
        if out != tx_hash:
            return False, "error: " + out
        run_hook('receive_tx', tx, self)
        return True, out


    def update_password(self, old_password, new_password):
        if new_password == '': new_password = None
        decoded = self.get_seed(old_password)
        self.seed = pw_encode( decoded, new_password)
        self.storage.put('seed', self.seed, True)
        self.use_encryption = (new_password != None)
        self.storage.put('use_encryption', self.use_encryption,True)
        for k in self.imported_keys.keys():
            a = self.imported_keys[k]
            b = pw_decode(a, old_password)
            c = pw_encode(b, new_password)
            self.imported_keys[k] = c
        self.storage.put('imported_keys', self.imported_keys, True)

        for k, v in self.master_private_keys.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.master_private_keys[k] = c
        self.storage.put('master_private_keys', self.master_private_keys, True)


    def freeze(self,addr):
        if self.is_mine(addr) and addr not in self.frozen_addresses:
            self.frozen_addresses.append(addr)
            self.storage.put('frozen_addresses', self.frozen_addresses, True)
            return True
        else:
            return False


    def unfreeze(self,addr):
        if self.is_mine(addr) and addr in self.frozen_addresses:
            self.frozen_addresses.remove(addr)
            self.storage.put('frozen_addresses', self.frozen_addresses, True)
            return True
        else:
            return False


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

                ext_h = self.network.synchronous_get(ext_requests)
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


    def start_threads(self, network):
        from verifier import TxVerifier
        self.network = network
        if self.network is not None:
            self.verifier = TxVerifier(self.network, self.storage)
            self.verifier.start()
            self.set_verifier(self.verifier)
            self.synchronizer = WalletSynchronizer(self, network)
            self.synchronizer.start()
        else:
            self.verifier = None
            self.synchronizer =None

    def stop_threads(self):
        if self.network:
            self.verifier.stop()
            self.synchronizer.stop()

    def restore(self, cb):
        pass



class Imported_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    def is_watching_only(self):
        n = self.imported_keys.values()
        return n == [''] * len(n)

    def has_seed(self):
        return False



class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    def has_seed(self):
        return self.seed == ''

    def is_watching_only(self):
        return self.has_seed()

    def check_password(self, password):
        self.get_seed(password)

    def get_seed(self, password):
        s = pw_decode(self.seed, password)
        seed = mnemonic_to_seed(s,'').encode('hex')
        return seed

    def get_mnemonic(self, password):
        return pw_decode(self.seed, password)
        
    def change_gap_limit(self, value):
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit, True)
            #self.interface.poke('synchronizer')
            return True

        elif value >= self.min_acceptable_gap():
            for key, account in self.accounts.items():
                addresses = account[0]
                k = self.num_unused_trailing_addresses(addresses)
                n = len(addresses) - k + value
                addresses = addresses[0:n]
                self.accounts[key][0] = addresses

            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit, True)
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


    def address_is_old(self, address):
        age = -1
        h = self.history.get(address, [])
        if h == ['*']:
            return True
        for tx_hash, tx_height in h:
            if tx_height == 0:
                tx_age = 0
            else:
                tx_age = self.network.get_local_height() - tx_height + 1
            if tx_age > age:
                age = tx_age
        return age > 2


    def synchronize_sequence(self, account, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        new_addresses = []
        while True:
            addresses = account.get_addresses(for_change)
            if len(addresses) < limit:
                address = account.create_new_address(for_change)
                self.history[address] = []
                new_addresses.append( address )
                continue

            if map( lambda a: self.address_is_old(a), addresses[-limit:] ) == limit*[False]:
                break
            else:
                address = account.create_new_address(for_change)
                self.history[address] = []
                new_addresses.append( address )

        return new_addresses
        

    def check_pending_accounts(self):
        for account_id, addr in self.next_addresses.items():
            if self.address_is_old(addr):
                print_error( "creating account", account_id )
                xpub = self.master_public_keys[account_id]
                account = BIP32_Account({'xpub':xpub})
                self.add_account(account_id, account)
                self.next_addresses.pop(account_id)


    def synchronize_account(self, account):
        new = []
        new += self.synchronize_sequence(account, 0)
        new += self.synchronize_sequence(account, 1)
        return new


    def synchronize(self):
        self.check_pending_accounts()
        new = []
        for account in self.accounts.values():
            new += self.synchronize_account(account)
        if new:
            self.save_accounts()
            self.storage.put('addr_history', self.history, True)
        return new


    def restore(self, callback):
        from i18n import _
        def wait_for_wallet():
            self.set_up_to_date(False)
            while not self.is_up_to_date():
                msg = "%s\n%s %d\n%s %.1f"%(
                    _("Please wait..."),
                    _("Addresses generated:"),
                    len(self.addresses(True)), 
                    _("Kilobytes received:"), 
                    self.network.interface.bytes_received/1024.)

                apply(callback, (msg,))
                time.sleep(0.1)

        def wait_for_network():
            while not self.network.is_connected():
                msg = "%s \n" % (_("Connecting..."))
                apply(callback, (msg,))
                time.sleep(0.1)

        # wait until we are connected, because the user might have selected another server
        if self.network:
            wait_for_network()
            wait_for_wallet()
        else:
            self.synchronize()
            
        self.fill_addressbook()


    def create_account(self, name, password):
        i = self.num_accounts()
        account_id = self.account_id(i)
        account = self.make_account(account_id, password)
        self.add_account(account_id, account)
        if name:
            self.set_label(account_id, name)

        # add address of the next account
        _, _ = self.next_account_address(password)


    def add_account(self, account_id, account):
        self.accounts[account_id] = account
        if account_id in self.pending_accounts:
            self.pending_accounts.pop(account_id)
            self.storage.put('pending_accounts', self.pending_accounts)
        self.save_accounts()


    def save_accounts(self):
        d = {}
        for k, v in self.accounts.items():
            d[k] = v.dump()
        self.storage.put('accounts', d, True)

    

    def load_accounts(self):
        d = self.storage.get('accounts', {})
        self.accounts = {}
        for k, v in d.items():
            if k == 0:
                v['mpk'] = self.storage.get('master_public_key')
                self.accounts[k] = OldAccount(v)
            elif v.get('xpub3'):
                self.accounts[k] = BIP32_Account_2of3(v)
            elif v.get('xpub2'):
                self.accounts[k] = BIP32_Account_2of2(v)
            elif v.get('xpub'):
                self.accounts[k] = BIP32_Account(v)
            else:
                raise

        self.pending_accounts = self.storage.get('pending_accounts',{})


    def delete_pending_account(self, k):
        self.pending_accounts.pop(k)
        self.storage.put('pending_accounts', self.pending_accounts)

    def account_is_pending(self, k):
        return k in self.pending_accounts

    def create_pending_account(self, name, password):
        account_id, addr = self.next_account_address(password)
        self.set_label(account_id, name)
        self.pending_accounts[account_id] = addr
        self.storage.put('pending_accounts', self.pending_accounts)

    def get_pending_accounts(self):
        return self.pending_accounts.items()



class NewWallet(Deterministic_Wallet):

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def can_create_accounts(self):
        return not self.is_watching_only()

    def get_master_public_key(self):
        return self.master_public_keys["m/"]

    def get_master_public_keys(self):
        out = {}
        for k, account in self.accounts.items():
            name = self.get_account_name(k)
            mpk_text = '\n\n'.join( account.get_master_pubkeys() )
            out[name] = mpk_text
        return out

    def get_master_private_key(self, account, password):
        k = self.master_private_keys.get(account)
        if not k: return
        xpriv = pw_decode( k, password)
        return xpriv

    def add_seed(self, seed, password):
        if self.seed: 
            raise Exception("a seed exists")
        
        self.seed_version, self.seed = self.prepare_seed(seed)
        if password: 
            self.seed = pw_encode( self.seed, password)
            self.use_encryption = True
        else:
            self.use_encryption = False

        self.storage.put('seed', self.seed, True)
        self.storage.put('seed_version', self.seed_version, True)
        self.storage.put('use_encryption', self.use_encryption,True)
        self.create_master_keys(password)


    def create_watching_only_wallet(self, xpub):
        self.storage.put('seed_version', self.seed_version, True)
        self.add_master_public_key("m/", xpub)
        account = BIP32_Account({'xpub':xpub})
        self.add_account("m/", account)


    def create_accounts(self, password):
        seed = pw_decode(self.seed, password)
        self.create_account('Main account', password)


    def add_master_public_key(self, name, mpk):
        self.master_public_keys[name] = mpk
        self.storage.put('master_public_keys', self.master_public_keys, True)


    def add_master_private_key(self, name, xpriv, password):
        self.master_private_keys[name] = pw_encode(xpriv, password)
        self.storage.put('master_private_keys', self.master_private_keys, True)


    def add_master_keys(self, root, account_id, password):
        x = self.master_private_keys.get(root)
        if x: 
            master_xpriv = pw_decode(x, password )
            xpriv, xpub = bip32_private_derivation(master_xpriv, root, account_id)
            self.add_master_public_key(account_id, xpub)
            self.add_master_private_key(account_id, xpriv, password)
        else:
            master_xpub = self.master_public_keys[root]
            xpub = bip32_public_derivation(master_xpub, root, account_id)
            self.add_master_public_key(account_id, xpub)
        return xpub


    def create_master_keys(self, password):
        xpriv, xpub = bip32_root(self.get_seed(password))
        self.add_master_public_key("m/", xpub)
        self.add_master_private_key("m/", xpriv, password)


    def find_root_by_master_key(self, xpub):
        for key, xpub2 in self.master_public_keys.items():
            if key == "m/":continue
            if xpub == xpub2:
                return key


    def num_accounts(self):
        keys = self.accounts.keys()
        i = 0
        while True:
            account_id = self.account_id(i)
            if account_id not in keys: break
            i += 1
        return i


    def next_account_address(self, password):
        i = self.num_accounts()
        account_id = self.account_id(i)

        addr = self.next_addresses.get(account_id)
        if not addr: 
            account = self.make_account(account_id, password)
            addr = account.first_address()
            self.next_addresses[account_id] = addr
            self.storage.put('next_addresses', self.next_addresses)

        return account_id, addr

    def account_id(self, i):
        return "m/%d'"%i

    def make_account(self, account_id, password):
        """Creates and saves the master keys, but does not save the account"""
        xpub = self.add_master_keys("m/", account_id, password)
        account = BIP32_Account({'xpub':xpub})
        return account


    def make_seed(self):
        import mnemonic, ecdsa
        entropy = ecdsa.util.randrange( pow(2,160) )
        nonce = 0
        while True:
            ss = "%040x"%(entropy+nonce)
            s = hashlib.sha256(ss.decode('hex')).digest().encode('hex')
            # we keep only 13 words, that's approximately 139 bits of entropy
            words = mnemonic.mn_encode(s)[0:13] 
            seed = ' '.join(words)
            if is_new_seed(seed):
                break  # this will remove 8 bits of entropy
            nonce += 1
        return seed

    def prepare_seed(self, seed):
        import unicodedata
        return NEW_SEED_VERSION, unicodedata.normalize('NFC', unicode(seed.strip()))



class Wallet_2of2(NewWallet):

    def __init__(self, storage):
        NewWallet.__init__(self, storage)
        self.storage.put('wallet_type', '2of2', True)

    def create_account(self):
        xpub1 = self.master_public_keys.get("m/")
        xpub2 = self.master_public_keys.get("cold/")
        account = BIP32_Account_2of2({'xpub':xpub1, 'xpub2':xpub2})
        self.add_account('m/', account)

    def get_master_public_keys(self):
        xpub1 = self.master_public_keys.get("m/")
        xpub2 = self.master_public_keys.get("cold/")
        return {'hot':xpub1, 'cold':xpub2}

    def get_action(self):
        xpub1 = self.master_public_keys.get("m/")
        xpub2 = self.master_public_keys.get("cold/")
        if xpub1 is None:
            return 'create_2of2_1'
        if xpub2 is None:
            return 'create_2of2_2'



class Wallet_2of3(Wallet_2of2):

    def __init__(self, storage):
        Wallet_2of2.__init__(self, storage)
        self.storage.put('wallet_type', '2of3', True)

    def create_account(self):
        xpub1 = self.master_public_keys.get("m/")
        xpub2 = self.master_public_keys.get("cold/")
        xpub3 = self.master_public_keys.get("remote/")
        account = BIP32_Account_2of3({'xpub':xpub1, 'xpub2':xpub2, 'xpub3':xpub3})
        self.add_account('m/', account)

    def get_master_public_keys(self):
        xpub1 = self.master_public_keys.get("m/")
        xpub2 = self.master_public_keys.get("cold/")
        xpub3 = self.master_public_keys.get("remote/")
        return {'hot':xpub1, 'cold':xpub2, 'remote':xpub3}

    def get_action(self):
        xpub1 = self.master_public_keys.get("m/")
        xpub2 = self.master_public_keys.get("cold/")
        xpub3 = self.master_public_keys.get("remote/")
        if xpub2 is None:
            return 'create_2of3_1'
        if xpub1 is None:
            return 'create_2of3_2'
        if xpub3 is None:
            return 'create_2of3_3'





class OldWallet(Deterministic_Wallet):

    def make_seed(self):
        import mnemonic
        seed = random_seed(128)
        return ' '.join(mnemonic.mn_encode(seed))

    def prepare_seed(self, seed):
        import mnemonic
        # see if seed was entered as hex
        seed = seed.strip()
        try:
            assert seed
            seed.decode('hex')
            return OLD_SEED_VERSION, str(seed)
        except Exception:
            pass

        words = seed.split()
        seed = mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
            
        return OLD_SEED_VERSION, seed


    def create_master_keys(self, password):
        seed = pw_decode(self.seed, password)
        mpk = OldAccount.mpk_from_seed(seed)
        self.storage.put('master_public_key', mpk, True)

    def get_master_public_key(self):
        return self.storage.get("master_public_key")

    def get_master_public_keys(self):
        return {'Main Account':self.get_master_public_key()}

    def create_accounts(self, password):
        mpk = self.storage.get("master_public_key")
        self.create_account(mpk)

    def create_account(self, mpk):
        self.accounts[0] = OldAccount({'mpk':mpk, 0:[], 1:[]})
        self.save_accounts()

    def create_watching_only_wallet(self, mpk):
        self.seed_version = OLD_SEED_VERSION
        self.storage.put('seed_version', self.seed_version, True)
        self.storage.put('master_public_key', mpk, True)
        self.create_account(mpk)

    def get_seed(self, password):
        seed = pw_decode(self.seed, password)
        self.accounts[0].check_seed(seed)
        return seed

    def get_mnemonic(self, password):
        import mnemonic
        s = pw_decode(self.seed, password)
        return ' '.join(mnemonic.mn_encode(s))


    def add_keypairs_from_KeyID(self, tx, keypairs, password):
        # first check the provided password
        seed = self.get_seed(password)
        for txin in tx.inputs:
            keyid = txin.get('KeyID')
            if keyid:
                m = re.match("old\(([0-9a-f]+),(\d+),(\d+)", keyid)
                if not m: continue
                mpk = m.group(1)
                if mpk != self.storage.get('master_public_key'): continue 
                for_change = int(m.group(2))
                num = int(m.group(3))
                account = self.accounts[0]
                addr = account.get_address(for_change, num)
                txin['address'] = addr # fixme: side effect
                pk = account.get_private_key(seed, (for_change, num))
                pubkey = public_key_from_private_key(pk)
                keypairs[pubkey] = pk


    def get_account_name(self, k):
        assert k == 0
        return 'Main account'


    def get_private_key(self, address, password):
        if self.is_watching_only():
            return []

        # first check the provided password
        seed = self.get_seed(password)
        
        out = []
        if address in self.imported_keys.keys():
            out.append( pw_decode( self.imported_keys[address], password ) )
        else:
            account_id, sequence = self.get_address_index(address)
            pk = self.accounts[0].get_private_key(seed, sequence)
            out.append(pk)
        return out

    def check_pending_accounts(self):
        pass


# former WalletFactory
class Wallet(object):

    def __new__(self, storage):
        config = storage.config
        if config.get('bitkey', False):
            # if user requested support for Bitkey device,
            # import Bitkey driver
            from wallet_bitkey import WalletBitkey
            return WalletBitkey(config)

        if storage.get('wallet_type') == '2of2':
            return Wallet_2of2(storage)

        if storage.get('wallet_type') == '2of3':
            return Wallet_2of3(storage)

        if storage.file_exists and not storage.get('seed'):
            # wallet made of imported keys
            return Imported_Wallet(storage)


        if not storage.file_exists:
            seed_version = NEW_SEED_VERSION if config.get('bip32') is True else OLD_SEED_VERSION
        else:
            seed_version = storage.get('seed_version')
            if not seed_version:
                seed_version = OLD_SEED_VERSION if len(storage.get('master_public_key')) == 128 else NEW_SEED_VERSION

        if seed_version == OLD_SEED_VERSION:
            return OldWallet(storage)
        elif seed_version == NEW_SEED_VERSION:
            return NewWallet(storage)
        else:
            msg = "This wallet seed is not supported."
            if seed_version in [5]:
                msg += "\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
            print msg
            sys.exit(1)



    @classmethod
    def is_seed(self, seed):
        if not seed:
            return False
        elif is_old_seed(seed):
            return True
        elif is_new_seed(seed):
            return True
        else: 
            return False

    @classmethod
    def is_mpk(self, mpk):
        try:
            int(mpk, 16)
            old = True
        except:
            old = False
            
        if old:
            return len(mpk) == 128
        else:
            try:
                deserialize_xkey(mpk)
                return True
            except:
                return False

    @classmethod
    def is_address(self, text):
        for x in text.split():
            if not bitcoin.is_address(x):
                return False
        return True

    @classmethod
    def is_private_key(self, text):
        for x in text.split():
            if not bitcoin.is_private_key(x):
                return False
        return True

    @classmethod
    def from_seed(self, seed, storage):
        if is_old_seed(seed):
            klass = OldWallet
        elif is_new_seed(seed):
            klass = NewWallet
        w = klass(storage)
        return w

    @classmethod
    def from_address(self, text, storage):
        w = Imported_Wallet(storage)
        for x in text.split():
            w.imported_keys[x] = ''
        w.storage.put('imported_keys', w.imported_keys, True)
        return w

    @classmethod
    def from_private_key(self, text, storage):
        w = Imported_Wallet(storage)
        for x in text.split():
            w.import_key(x, None)
        return w

    @classmethod
    def from_mpk(self, mpk, storage):

        try:
            int(mpk, 16)
            old = True
        except:
            old = False

        if old:
            w = OldWallet(storage)
            w.seed = ''
            w.create_watching_only_wallet(mpk)
        else:
            w = NewWallet(storage)
            w.create_watching_only_wallet(mpk)

        return w
