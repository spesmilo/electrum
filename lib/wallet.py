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
import bisect

from util import print_msg, print_error, format_satoshis
from bitcoin import *
from account import *
from transaction import Transaction
from plugins import run_hook

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
        return self.data.get(key, default)

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


class Wallet:

    def __init__(self, storage):

        self.storage = storage
        self.electrum_version = ELECTRUM_VERSION
        self.gap_limit_for_change = 3 # constant

        # saved fields
        self.seed_version          = storage.get('seed_version', SEED_VERSION)

        self.gap_limit             = storage.get('gap_limit', 5)
        self.use_change            = storage.get('use_change',True)
        self.use_encryption        = storage.get('use_encryption', False)
        self.seed                  = storage.get('seed', '')               # encrypted
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = storage.get('frozen_addresses',[])
        self.prioritized_addresses = storage.get('prioritized_addresses',[])
        self.addressbook           = storage.get('contacts', [])

        self.imported_keys         = storage.get('imported_keys',{})
        self.history               = storage.get('addr_history',{})        # address -> list(txid, height)

        self.fee                   = int(storage.get('fee_per_kb',20000))

        self.master_public_keys = storage.get('master_public_keys',{})
        self.master_private_keys = storage.get('master_private_keys', {})

        self.next_addresses = storage.get('next_addresses',{})

        if self.seed_version not in [4, 6]:
            msg = "This wallet seed is not supported."
            if self.seed_version in [5]:
                msg += "\nTo open this wallet, try 'git checkout seed_v%d'"%self.seed_version
                print msg
                sys.exit(1)


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

            


    def set_up_to_date(self,b):
        with self.lock: self.up_to_date = b


    def is_up_to_date(self):
        with self.lock: return self.up_to_date


    def update(self):
        self.up_to_date = False
        while not self.is_up_to_date(): 
            time.sleep(0.1)


    def import_key(self, sec, password):
        # check password
        seed = self.get_seed(password)
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
            if mnemonic_hash(seed).startswith(SEED_PREFIX): 
                break  # this removes 12 bits of entropy 
            nonce += 1

        return seed


    def init_seed(self, seed):
        import mnemonic
        
        if self.seed: 
            raise Exception("a seed exists")

        if not seed:
            self.seed = random_seed(128)
            self.seed_version = 4
            return

        #if not seed:
        #    self.seed = self.make_seed()
        #    self.seed_version = SEED_VERSION
        #    return

        # find out what kind of wallet we are
        try:
            seed.strip().decode('hex')
            self.seed_version = 4
            self.seed = str(seed)
            return
        except Exception:
            pass

        words = seed.split()
        self.seed_version = 4
        self.seed = mnemonic.mn_decode(words)
        
        #try:
        #    mnemonic.mn_decode(words)
        #    uses_electrum_words = True
        #except Exception:
        #    uses_electrum_words = False
        #
        #if uses_electrum_words and len(words) != 13:
        #    self.seed_version = 4
        #    self.seed = mnemonic.mn_decode(words)
        #else:
        #    assert mnemonic_hash(seed).startswith(SEED_PREFIX)
        #    self.seed_version = SEED_VERSION
        #    self.seed = seed
            

    def save_seed(self):
        self.storage.put('seed', self.seed, True)
        self.storage.put('seed_version', self.seed_version, True)
        self.create_accounts()


    def create_watching_only_wallet(self, params):
        K0, c0 = params
        if not K0:
            return

        if not c0:
            self.seed_version = 4
            self.storage.put('seed_version', self.seed_version, True)
            self.create_old_account(K0)
            return

        cK0 = ""
        self.master_public_keys = {
            "m/0'/": (c0, K0, cK0),
            }
        self.storage.put('master_public_keys', self.master_public_keys, True)
        self.storage.put('seed_version', self.seed_version, True)
        self.create_account('1','Main account')


    def create_accounts(self): 
        if self.seed_version == 4:
            mpk = OldAccount.mpk_from_seed(self.seed)
            self.create_old_account(mpk)
        else:
            # create default account
            self.create_master_keys('1')
            self.create_account('1','Main account')


    def create_master_keys(self, account_type):
        master_k, master_c, master_K, master_cK = bip32_init(self.get_seed(None))
        if account_type == '1':
            k0, c0, K0, cK0 = bip32_private_derivation(master_k, master_c, "m/", "m/0'/")
            self.master_public_keys["m/0'/"] = (c0, K0, cK0)
            self.master_private_keys["m/0'/"] = k0
        elif account_type == '2of2':
            k1, c1, K1, cK1 = bip32_private_derivation(master_k, master_c, "m/", "m/1'/")
            k2, c2, K2, cK2 = bip32_private_derivation(master_k, master_c, "m/", "m/2'/")
            self.master_public_keys["m/1'/"] = (c1, K1, cK1)
            self.master_public_keys["m/2'/"] = (c2, K2, cK2)
            self.master_private_keys["m/1'/"] = k1
            self.master_private_keys["m/2'/"] = k2
        elif account_type == '2of3':
            k3, c3, K3, cK3 = bip32_private_derivation(master_k, master_c, "m/", "m/3'/")
            k4, c4, K4, cK4 = bip32_private_derivation(master_k, master_c, "m/", "m/4'/")
            k5, c5, K5, cK5 = bip32_private_derivation(master_k, master_c, "m/", "m/5'/")
            self.master_public_keys["m/3'/"] = (c3, K3, cK3)
            self.master_public_keys["m/4'/"] = (c4, K4, cK4)
            self.master_public_keys["m/5'/"] = (c5, K5, cK5)
            self.master_private_keys["m/3'/"] = k3
            self.master_private_keys["m/4'/"] = k4
            self.master_private_keys["m/5'/"] = k5

        self.storage.put('master_public_keys', self.master_public_keys, True)
        self.storage.put('master_private_keys', self.master_private_keys, True)

    def has_master_public_keys(self, account_type):
        if account_type == '1':
            return "m/0'/" in self.master_public_keys
        elif account_type == '2of2':
            return set(["m/1'/", "m/2'/"]) <= set(self.master_public_keys.keys())
        elif account_type == '2of3':
            return set(["m/3'/", "m/4'/", "m/5'/"]) <= set(self.master_public_keys.keys())

    def find_root_by_master_key(self, c, K):
        for key, v in self.master_public_keys.items():
            if key == "m/":continue
            cc, KK, _ = v
            if (c == cc) and (K == KK):
                return key

    def deseed_root(self, seed, password):
        # for safety, we ask the user to enter their seed
        assert seed == self.get_seed(password)
        self.seed = ''
        self.storage.put('seed', '', True)


    def deseed_branch(self, k):
        # check that parent has no seed
        assert self.seed == ''
        self.master_private_keys.pop(k)
        self.storage.put('master_private_keys', self.master_private_keys, True)

    def is_watching_only(self):
        return (self.seed == '') and (self.master_private_keys == {})



    def account_id(self, account_type, i):
        if account_type == '1':
            return "m/0'/%d"%i
        elif account_type == '2of2':
            return "m/1'/%d & m/2'/%d"%(i,i)
        elif account_type == '2of3':
            return "m/3'/%d & m/4'/%d & m/5'/%d"%(i,i,i)
        else:
            raise Exception('unknown account type')


    def num_accounts(self, account_type):
        keys = self.accounts.keys()
        i = 0
        while True:
            account_id = self.account_id(account_type, i)
            if account_id not in keys: break
            i += 1
        return i


    def new_account_address(self, account_type = '1'):
        i = self.num_accounts(account_type)
        k = self.account_id(account_type,i)

        addr = self.next_addresses.get(k)
        if not addr: 
            account_id, account = self.next_account(account_type)
            addr = account.first_address()
            self.next_addresses[k] = addr
            self.storage.put('next_addresses',self.next_addresses)

        return k, addr


    def next_account(self, account_type = '1'):

        i = self.num_accounts(account_type)
        account_id = self.account_id(account_type,i)

        if account_type is '1':
            master_c0, master_K0, _ = self.master_public_keys["m/0'/"]
            c0, K0, cK0 = bip32_public_derivation(master_c0.decode('hex'), master_K0.decode('hex'), "m/0'/", "m/0'/%d"%i)
            account = BIP32_Account({ 'c':c0, 'K':K0, 'cK':cK0 })

        elif account_type == '2of2':
            master_c1, master_K1, _ = self.master_public_keys["m/1'/"]
            c1, K1, cK1 = bip32_public_derivation(master_c1.decode('hex'), master_K1.decode('hex'), "m/1'/", "m/1'/%d"%i)
            master_c2, master_K2, _ = self.master_public_keys["m/2'/"]
            c2, K2, cK2 = bip32_public_derivation(master_c2.decode('hex'), master_K2.decode('hex'), "m/2'/", "m/2'/%d"%i)
            account = BIP32_Account_2of2({ 'c':c1, 'K':K1, 'cK':cK1, 'c2':c2, 'K2':K2, 'cK2':cK2 })

        elif account_type == '2of3':
            master_c3, master_K3, _ = self.master_public_keys["m/3'/"]
            c3, K3, cK3 = bip32_public_derivation(master_c3.decode('hex'), master_K3.decode('hex'), "m/3'/", "m/3'/%d"%i)
            master_c4, master_K4, _ = self.master_public_keys["m/4'/"]
            c4, K4, cK4 = bip32_public_derivation(master_c4.decode('hex'), master_K4.decode('hex'), "m/4'/", "m/4'/%d"%i)
            master_c5, master_K5, _ = self.master_public_keys["m/5'/"]
            c5, K5, cK5 = bip32_public_derivation(master_c5.decode('hex'), master_K5.decode('hex'), "m/5'/", "m/5'/%d"%i)
            account = BIP32_Account_2of3({ 'c':c3, 'K':K3, 'cK':cK3, 'c2':c4, 'K2':K4, 'cK2':cK4, 'c3':c5, 'K3':K5, 'cK3':cK5 })

        return account_id, account


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



    def create_account(self, account_type = '1', name = None):
        k, account = self.next_account(account_type)
        if k in self.pending_accounts:
            self.pending_accounts.pop(k)
            self.storage.put('pending_accounts', self.pending_accounts)

        self.accounts[k] = account
        self.save_accounts()
        if name:
            self.set_label(k, name)


    def create_old_account(self, mpk):
        self.storage.put('master_public_key', mpk, True)
        self.accounts[0] = OldAccount({'mpk':mpk, 0:[], 1:[]})
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
            elif '&' in k:
                self.accounts[k] = BIP32_Account_2of2(v)
            else:
                self.accounts[k] = BIP32_Account(v)

        self.pending_accounts = self.storage.get('pending_accounts',{})


    def delete_pending_account(self, k):
        self.pending_accounts.pop(k)
        self.storage.put('pending_accounts', self.pending_accounts)

    def account_is_pending(self, k):
        return k in self.pending_accounts

    def create_pending_account(self, acct_type, name):
        k, addr = self.new_account_address(acct_type)
        self.set_label(k, name)
        self.pending_accounts[k] = addr
        self.storage.put('pending_accounts', self.pending_accounts)

    def get_pending_accounts(self):
        return self.pending_accounts.items()


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

    def get_master_public_key(self):
        if self.seed_version == 4:
            return self.storage.get("master_public_key")
        else:
            c, K, cK = self.storage.get("master_public_keys")["m/0'/"]
            return repr((c, K))

    def get_master_private_key(self, account, password):
        master_k = pw_decode( self.master_private_keys[account], password)
        master_c, master_K, master_Kc = self.master_public_keys[account]
        try:
            K, Kc = get_pubkeys_from_secret(master_k.decode('hex'))
            assert K.encode('hex') == master_K
        except Exception:
            raise Exception("Invalid password")
        return master_k


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


    def get_roots(self, account):
        roots = []
        for a in account.split('&'):
            s = a.strip()
            m = re.match("(m/\d+'/)(\d+)", s)
            roots.append( m.group(1) )
        return roots

    def is_seeded(self, account):
        if type(account) is int:
            return self.seed is not None

        for root in self.get_roots(account):
            if root not in self.master_private_keys.keys(): 
                return False
        return True

    def rebase_sequence(self, account, sequence):
        c, i = sequence
        dd = []
        for a in account.split('&'):
            s = a.strip()
            m = re.match("(m/\d+'/)(\d+)", s)
            root = m.group(1)
            num = int(m.group(2))
            dd.append( (root, [num,c,i] ) )
        return dd
        

    def get_keyID(self, account, sequence):
        if account == 0:
            a, b = sequence
            mpk = self.storage.get('master_public_key')
            return 'old(%s,%d,%d)'%(mpk,a,b)

        rs = self.rebase_sequence(account, sequence)
        dd = []
        for root, public_sequence in rs:
            c, K, _ = self.master_public_keys[root]
            s = '/' + '/'.join( map(lambda x:str(x), public_sequence) )
            dd.append( 'bip32(%s,%s,%s)'%(c,K, s) )
        return '&'.join(dd)



    def get_seed(self, password):
        s = pw_decode(self.seed, password)
        if self.seed_version == 4:
            seed = s
            self.accounts[0].check_seed(seed)
        else:
            seed = mnemonic_hash(s)
        return seed
        

    def get_mnemonic(self, password):
        import mnemonic
        s = pw_decode(self.seed, password)
        if self.seed_version == 4:
            return ' '.join(mnemonic.mn_encode(s))
        else:
            return s

        

    def get_private_key(self, address, password):
        if self.is_watching_only():
            return []

        # first check the provided password
        seed = self.get_seed(password)
        
        out = []
        if address in self.imported_keys.keys():
            out.append( pw_decode( self.imported_keys[address], password ) )
        else:
            account, sequence = self.get_address_index(address)
            if account == 0:
                pk = self.accounts[account].get_private_key(seed, sequence)
                out.append(pk)
                return out

            # assert address == self.accounts[account].get_address(*sequence)
            rs = self.rebase_sequence( account, sequence)
            for root, public_sequence in rs:

                if root not in self.master_private_keys.keys(): continue
                master_k = self.get_master_private_key(root, password)
                master_c, _, _ = self.master_public_keys[root]
                pk = bip32_private_key( public_sequence, master_k.decode('hex'), master_c.decode('hex'))
                out.append(pk)
                    
        return out


    def add_keypairs_from_wallet(self, tx, keypairs, password):
        for txin in tx.inputs:
            address = txin['address']
            private_keys = self.get_private_key(address, password)
            for sec in private_keys:
                pubkey = public_key_from_private_key(sec)
                keypairs[ pubkey ] = sec
                if address in self.imported_keys.keys():
                    txin['redeemPubkey'] = pubkey


    def add_keypairs_from_KeyID(self, tx, keypairs, password):
        for txin in tx.inputs:
            keyid = txin.get('KeyID')
            if keyid:

                if self.seed_version==4:
                    m = re.match("old\(([0-9a-f]+),(\d+),(\d+)", keyid)
                    if not m: continue
                    mpk = m.group(1)
                    if mpk != self.storage.get('master_public_key'): continue 
                    index = int(m.group(2))
                    num = int(m.group(3))
                    account = self.accounts[0]
                    addr = account.get_address(index, num)
                    txin['address'] = addr # fixme: side effect
                    pk = self.get_private_key(addr, password)
                    for sec in pk:
                        pubkey = public_key_from_private_key(sec)
                        keypairs[pubkey] = sec
                    continue


                roots = []
                for s in keyid.split('&'):
                    m = re.match("bip32\(([0-9a-f]+),([0-9a-f]+),(/\d+/\d+/\d+)", s)
                    if not m: continue
                    c = m.group(1)
                    K = m.group(2)
                    sequence = m.group(3)
                    root = self.find_root_by_master_key(c,K)
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

        # add input info
        tx.add_input_info(input_info)

        # add redeem script for coins that are in the wallet
        # FIXME: add redeemPubkey too!
        unspent_coins = self.get_unspent_coins()
        for txin in tx.inputs:
            for item in unspent_coins:
                if txin['prevout_hash'] == item['prevout_hash'] and txin['prevout_n'] == item['prevout_n']:
                    print_error( "tx input is in unspent coins" )
                    txin['scriptPubKey'] = item['scriptPubKey']
                    account, sequence = self.get_address_index(item['address'])
                    if account != -1:
                        txin['redeemScript'] = self.accounts[account].redeem_script(sequence)
                        print_error("added redeemScript", txin['redeemScript'])
                    break


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
        self.sign_transaction(tx, keypairs)


    def sign_message(self, address, message, password):
        keys = self.get_private_key(address, password)
        assert len(keys) == 1
        sec = keys[0]
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed, address)


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
                tx_age = self.verifier.blockchain.height() - tx_height + 1
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
        


    def create_pending_accounts(self):
        for account_type in ['1','2of2','2of3']:
            if not self.has_master_public_keys(account_type):
                continue
            k, a = self.new_account_address(account_type)
            if self.address_is_old(a):
                print_error( "creating account", a )
                self.create_account(account_type)
                self.next_addresses.pop(k)


    def synchronize_account(self, account):
        new = []
        new += self.synchronize_sequence(account, 0)
        new += self.synchronize_sequence(account, 1)
        return new


    def synchronize(self):
        if self.master_public_keys:
            self.create_pending_accounts()
        new = []
        for account in self.accounts.values():
            new += self.synchronize_account(account)
        if new:
            self.save_accounts()
            self.storage.put('addr_history', self.history, True)
        return new


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


    def get_account_name(self, k):
        if k == 0:
            if self.seed_version == 4: 
                name = 'Main account'
            else:
                name = 'Old account'
        else:
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
                    coins.append(output)

        # sort by age
        coins = sorted(coins, key=lambda i: i['height'])
        if coins and coins[-1]['height'] != 0:
            while coins[0]['height'] == 0: 
                coins = coins[1:] + [ coins[0] ]
        return coins



    def choose_tx_inputs_from_account( self, amount, fixed_fee, account ):
        domain = self.get_account_addresses(account) if account else None
        return self.choose_tx_inputs( amount, fixed_fee, domain )


    def choose_tx_inputs( self, amount, fixed_fee, domain = None ):
        domain = self.addresses(True) if domain is None else domain

        prioritized, unprioritized = [], []
        for i in self.get_spendable_coins(domain):
            if i['address'] in self.prioritized_addresses:
                prioritized.append(i)
            else:
                unprioritized.append(i)

        inputs, total, fee = self.pick_coins_smalltx(prioritized, amount, fixed_fee)
        if total < amount:
            i, t, fee = self.pick_coins_smalltx(unprioritized, amount-total, fixed_fee, len(inputs))
            inputs += i
            total += t
        if total < amount:
            inputs = []

        return inputs, total, fee


    def get_spendable_coins(self, domain=None):
        for c in self.get_unspent_coins(domain):
            if c['coinbase'] and self.network.blockchain.height < c['height'] + COINBASE_MATURITY:
                continue
            if c['address'] in self.frozen_addresses:
                continue
            yield c


    def pick_coins_smalltx(self, coins, amount, fixed_fee, other_coins=0):
        """Choose a subset of coins totalling at least amount.
        This algorithm always minimizes the size of the transaction; it then
        tries to minimize addresses used together.
        An ideal optimizer would also take ages into account.
        An exact optimization would take at least pseudo-polynomial time.
        """
        # find the fewest inputs we can use
        coins_needed = 0
        coins.sort(key=lambda i: -i['value'])
        total, fee = 0, fixed_fee
        for item in coins:
            total += item['value']
            coins_needed += 1
            if fixed_fee is None: fee = self.estimated_fee(coins_needed+other_coins)
            if total >= amount + fee: break
        else:
            return coins, total, fee

        # group by address
        by_addr = {}
        for item in coins:
            bisect.insort(by_addr.setdefault(item['address'], []),
                    (-item['value'], item))

        # compose a sufficient set of coins_needed inputs from few addresses,
        # while trying inputs from at most coins_needed addresses
        inputs, total = [], 0
        for item in coins:
            for v, i in by_addr.pop(item['address'], []):
                if len(inputs) == coins_needed and inputs[-1][1]['value'] >= -v:
                    break
                bisect.insort(inputs, (v, i))
                total += -v
                if len(inputs) > coins_needed: total -= inputs.pop()[1]['value']
                if total >= amount + fee:
                    return [i[1] for i in inputs], total, fee


    def set_fee(self, fee):
        if self.fee != fee:
            self.fee = fee
            self.storage.put('fee_per_kb', self.fee, True)
        
    def estimated_fee(self, inputs):
        estimated_size = inputs * 180 + 80     # this assumes non-compressed keys
        fee = self.fee * int(round(estimated_size/1024.))
        if fee == 0: fee = self.fee
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
            self.network.interface.pending_transactions_for_notifications.append(tx)
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


    def make_unsigned_transaction(self, outputs, fee=None, change_addr=None, domain=None ):
        for address, x in outputs:
            assert is_valid(address)
        amount = sum( map(lambda x:x[1], outputs) )
        inputs, total, fee = self.choose_tx_inputs( amount, fee, domain )
        if not inputs:
            raise ValueError("Not enough funds")
        self.add_input_info(inputs)
        outputs = self.add_tx_change(inputs, outputs, amount, fee, total, change_addr)
        return Transaction.from_io(inputs, outputs)


    def mktx_from_account(self, outputs, password, fee=None, account=None):
        domain = self.get_account_addresses(account) if account else None
        return self.mktx(outputs, password, fee, change_addr=None, domain=domain)


    def mktx(self, outputs, password, fee=None, change_addr=None, domain= None ):
        tx = self.make_unsigned_transaction(outputs, fee, change_addr, domain)
        keypairs = {}
        self.add_keypairs_from_wallet(tx, keypairs, password)
        if keypairs:
            self.sign_transaction(tx, keypairs)
        return tx


    def add_input_info(self, inputs):
        for txin in inputs:
            address = txin['address']
            if address in self.imported_keys.keys():
                continue
            account, sequence = self.get_address_index(address)
            txin['KeyID'] = self.get_keyID(account, sequence)
            redeemScript = self.accounts[account].redeem_script(sequence)
            if redeemScript: 
                txin['redeemScript'] = redeemScript
            else:
                txin['redeemPubkey'] = self.accounts[account].get_pubkey(*sequence)


    def sign_transaction(self, tx, keypairs):
        tx.sign(keypairs)
        run_hook('sign_transaction', tx)


    def sendtx(self, tx):
        # synchronous
        h = self.send_tx(tx)
        self.tx_event.wait()
        return self.receive_tx(h)

    def send_tx(self, tx):
        # asynchronous
        self.tx_event.clear()
        self.network.interface.send([('blockchain.transaction.broadcast', [str(tx)])], self.on_broadcast)
        return tx.hash()

    def on_broadcast(self, i, r):
        self.tx_result = r.get('result')
        self.tx_event.set()

    def receive_tx(self,tx_hash):
        out = self.tx_result 
        if out != tx_hash:
            return False, "error: " + out
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
            self.unprioritize(addr)
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

    def prioritize(self,addr):
        if self.is_mine(addr) and addr not in self.prioritized_addresses:
            self.unfreeze(addr)
            self.prioritized_addresses.append(addr)
            self.storage.put('prioritized_addresses', self.prioritized_addresses, True)
            return True
        else:
            return False

    def unprioritize(self,addr):
        if self.is_mine(addr) and addr in self.prioritized_addresses:
            self.prioritized_addresses.remove(addr)
            self.storage.put('prioritized_addresses', self.prioritized_addresses, True)
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
        if self.network:
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




class WalletSynchronizer(threading.Thread):


    def __init__(self, wallet, network):
        threading.Thread.__init__(self)
        self.daemon = True
        self.wallet = wallet
        self.network = network
        self.was_updated = True
        self.running = False
        self.lock = threading.Lock()
        self.queue = Queue.Queue()

    def stop(self):
        with self.lock: self.running = False

    def is_running(self):
        with self.lock: return self.running

    
    def subscribe_to_addresses(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.network.subscribe( messages, lambda i,r: self.queue.put(r))


    def run(self):
        with self.lock:
            self.running = True

        while self.is_running():
            
            if not self.network.is_connected():
                print_error("synchronizer: waiting for interface")
                self.network.wait_until_connected()
                
            self.run_interface(self.network.interface)


    def run_interface(self, interface):

        print_error("synchronizer: connected to", interface.server)

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
            new_addresses = self.wallet.synchronize()

            # request missing addresses
            if new_addresses:
                self.subscribe_to_addresses(new_addresses)

            # request missing transactions
            for tx_hash, tx_height in missing_tx:
                if (tx_hash, tx_height) not in requested_tx:
                    interface.send([ ('blockchain.transaction.get',[tx_hash, tx_height]) ], lambda i,r: self.queue.put(r))
                    requested_tx.append( (tx_hash, tx_height) )
            missing_tx = []

            # detect if situation has changed
            if interface.is_up_to_date() and self.queue.empty():
                if not self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(True)
                    self.was_updated = True
            else:
                if self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(False)
                    self.was_updated = True

            if self.was_updated:
                self.wallet.network.trigger_callback('updated')
                self.was_updated = False

            # 2. get a response
            try:
                r = self.queue.get(block=True, timeout=1)
            except Queue.Empty:
                continue

            if interface != self.network.interface:
                break
            
            if not r:
                continue

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
                        interface.send([('blockchain.address.get_history', [addr])], lambda i,r:self.queue.put(r))
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
                assert tx_hash == hash_encode(Hash(result.decode('hex')))
                tx = Transaction(result)
                self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
                self.was_updated = True
                requested_tx.remove( (tx_hash, tx_height) )
                print_error("received tx:", tx_hash, len(tx.raw))

            else:
                print_error("Error: Unknown message:" + method + ", " + repr(params) + ", " + repr(result) )

            if self.was_updated and not requested_tx:
                self.wallet.network.trigger_callback('updated')
                self.wallet.network.trigger_callback("new_transaction") # Updated gets called too many times from other places as well; if we use that signal we get the notification three times

                self.was_updated = False
