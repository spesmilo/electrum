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
import ast
import threading
import json
import copy
import re
import stat
import hmac, hashlib
import base64
import zlib
from collections import defaultdict

from . import util, bitcoin, ecc
from .util import PrintError, profiler, InvalidPassword, WalletFileException, bfh
from .plugin import run_hook, plugin_loaders
from .keystore import bip44_derivation


# seed_version is now used for the version of the wallet file

OLD_SEED_VERSION = 4        # electrum versions < 2.0
NEW_SEED_VERSION = 11       # electrum versions >= 2.0
FINAL_SEED_VERSION = 17     # electrum >= 2.7 will set this to prevent
                            # old versions from overwriting new format



def multisig_type(wallet_type):
    '''If wallet_type is mofn multi-sig, return [m, n],
    otherwise return None.'''
    if not wallet_type:
        return None
    match = re.match('(\d+)of(\d+)', wallet_type)
    if match:
        match = [int(x) for x in match.group(1, 2)]
    return match

def get_derivation_used_for_hw_device_encryption():
    return ("m"
            "/4541509'"      # ascii 'ELE'  as decimal ("BIP43 purpose")
            "/1112098098'")  # ascii 'BIE2' as decimal

# storage encryption version
STO_EV_PLAINTEXT, STO_EV_USER_PW, STO_EV_XPUB_PW = range(0, 3)


class JsonDB(PrintError):

    def __init__(self, path):
        self.db_lock = threading.RLock()
        self.data = {}
        self.path = path
        self.modified = False

    def get(self, key, default=None):
        with self.db_lock:
            v = self.data.get(key)
            if v is None:
                v = default
            else:
                v = copy.deepcopy(v)
        return v

    def put(self, key, value):
        try:
            json.dumps(key, cls=util.MyEncoder)
            json.dumps(value, cls=util.MyEncoder)
        except:
            self.print_error("json error: cannot save", key)
            return
        with self.db_lock:
            if value is not None:
                if self.data.get(key) != value:
                    self.modified = True
                    self.data[key] = copy.deepcopy(value)
            elif key in self.data:
                self.modified = True
                self.data.pop(key)

    @profiler
    def write(self):
        with self.db_lock:
            self._write()

    def _write(self):
        if threading.currentThread().isDaemon():
            self.print_error('warning: daemon thread cannot write db')
            return
        if not self.modified:
            return
        s = json.dumps(self.data, indent=4, sort_keys=True, cls=util.MyEncoder)
        s = self.encrypt_before_writing(s)

        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w", encoding='utf-8') as f:
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

    def encrypt_before_writing(self, plaintext: str) -> str:
        return plaintext

    def file_exists(self):
        return self.path and os.path.exists(self.path)


class WalletStorage(JsonDB):

    def __init__(self, path, manual_upgrades=False):
        self.print_error("wallet path", path)
        JsonDB.__init__(self, path)
        self.manual_upgrades = manual_upgrades
        self.pubkey = None
        if self.file_exists():
            with open(self.path, "r", encoding='utf-8') as f:
                self.raw = f.read()
            self._encryption_version = self._init_encryption_version()
            if not self.is_encrypted():
                self.load_data(self.raw)
        else:
            self._encryption_version = STO_EV_PLAINTEXT
            # avoid new wallets getting 'upgraded'
            self.put('seed_version', FINAL_SEED_VERSION)

    def load_data(self, s):
        try:
            self.data = json.loads(s)
        except:
            try:
                d = ast.literal_eval(s)
                labels = d.get('labels', {})
            except Exception as e:
                raise IOError("Cannot read wallet file '%s'" % self.path)
            self.data = {}
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    self.print_error('Failed to convert label to json format', key)
                    continue
                self.data[key] = value

        # check here if I need to load a plugin
        t = self.get('wallet_type')
        l = plugin_loaders.get(t)
        if l: l()

        if not self.manual_upgrades:
            if self.requires_split():
                raise WalletFileException("This wallet has multiple accounts and must be split")
            if self.requires_upgrade():
                self.upgrade()

    def is_past_initial_decryption(self):
        """Return if storage is in a usable state for normal operations.

        The value is True exactly
            if encryption is disabled completely (self.is_encrypted() == False),
            or if encryption is enabled but the contents have already been decrypted.
        """
        return bool(self.data)

    def is_encrypted(self):
        """Return if storage encryption is currently enabled."""
        return self.get_encryption_version() != STO_EV_PLAINTEXT

    def is_encrypted_with_user_pw(self):
        return self.get_encryption_version() == STO_EV_USER_PW

    def is_encrypted_with_hw_device(self):
        return self.get_encryption_version() == STO_EV_XPUB_PW

    def get_encryption_version(self):
        """Return the version of encryption used for this storage.

        0: plaintext / no encryption

        ECIES, private key derived from a password,
        1: password is provided by user
        2: password is derived from an xpub; used with hw wallets
        """
        return self._encryption_version

    def _init_encryption_version(self):
        try:
            magic = base64.b64decode(self.raw)[0:4]
            if magic == b'BIE1':
                return STO_EV_USER_PW
            elif magic == b'BIE2':
                return STO_EV_XPUB_PW
            else:
                return STO_EV_PLAINTEXT
        except:
            return STO_EV_PLAINTEXT

    @staticmethod
    def get_eckey_from_password(password):
        secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
        ec_key = ecc.ECPrivkey.from_arbitrary_size_secret(secret)
        return ec_key

    def _get_encryption_magic(self):
        v = self._encryption_version
        if v == STO_EV_USER_PW:
            return b'BIE1'
        elif v == STO_EV_XPUB_PW:
            return b'BIE2'
        else:
            raise WalletFileException('no encryption magic for version: %s' % v)

    def decrypt(self, password):
        ec_key = self.get_eckey_from_password(password)
        if self.raw:
            enc_magic = self._get_encryption_magic()
            s = zlib.decompress(ec_key.decrypt_message(self.raw, enc_magic))
        else:
            s = None
        self.pubkey = ec_key.get_public_key_hex()
        s = s.decode('utf8')
        self.load_data(s)

    def encrypt_before_writing(self, plaintext: str) -> str:
        s = plaintext
        if self.pubkey:
            s = bytes(s, 'utf8')
            c = zlib.compress(s)
            enc_magic = self._get_encryption_magic()
            public_key = ecc.ECPubkey(bfh(self.pubkey))
            s = public_key.encrypt_message(c, enc_magic)
            s = s.decode('utf8')
        return s

    def check_password(self, password):
        """Raises an InvalidPassword exception on invalid password"""
        if not self.is_encrypted():
            return
        if self.pubkey and self.pubkey != self.get_eckey_from_password(password).get_public_key_hex():
            raise InvalidPassword()

    def set_keystore_encryption(self, enable):
        self.put('use_encryption', enable)

    def set_password(self, password, enc_version=None):
        """Set a password to be used for encrypting this storage."""
        if enc_version is None:
            enc_version = self._encryption_version
        if password and enc_version != STO_EV_PLAINTEXT:
            ec_key = self.get_eckey_from_password(password)
            self.pubkey = ec_key.get_public_key_hex()
            self._encryption_version = enc_version
        else:
            self.pubkey = None
            self._encryption_version = STO_EV_PLAINTEXT
        # make sure next storage.write() saves changes
        with self.db_lock:
            self.modified = True

    def requires_split(self):
        d = self.get('accounts', {})
        return len(d) > 1

    def split_accounts(storage):
        result = []
        # backward compatibility with old wallets
        d = storage.get('accounts', {})
        if len(d) < 2:
            return
        wallet_type = storage.get('wallet_type')
        if wallet_type == 'old':
            assert len(d) == 2
            storage1 = WalletStorage(storage.path + '.deterministic')
            storage1.data = copy.deepcopy(storage.data)
            storage1.put('accounts', {'0': d['0']})
            storage1.upgrade()
            storage1.write()
            storage2 = WalletStorage(storage.path + '.imported')
            storage2.data = copy.deepcopy(storage.data)
            storage2.put('accounts', {'/x': d['/x']})
            storage2.put('seed', None)
            storage2.put('seed_version', None)
            storage2.put('master_public_key', None)
            storage2.put('wallet_type', 'imported')
            storage2.upgrade()
            storage2.write()
            result = [storage1.path, storage2.path]
        elif wallet_type in ['bip44', 'trezor', 'keepkey', 'ledger', 'btchip', 'digitalbitbox', 'safe_t']:
            mpk = storage.get('master_public_keys')
            for k in d.keys():
                i = int(k)
                x = d[k]
                if x.get("pending"):
                    continue
                xpub = mpk["x/%d'"%i]
                new_path = storage.path + '.' + k
                storage2 = WalletStorage(new_path)
                storage2.data = copy.deepcopy(storage.data)
                # save account, derivation and xpub at index 0
                storage2.put('accounts', {'0': x})
                storage2.put('master_public_keys', {"x/0'": xpub})
                storage2.put('derivation', bip44_derivation(k))
                storage2.upgrade()
                storage2.write()
                result.append(new_path)
        else:
            raise WalletFileException("This wallet has multiple accounts and must be split")
        return result

    def requires_upgrade(self):
        return self.file_exists() and self.get_seed_version() < FINAL_SEED_VERSION

    @profiler
    def upgrade(self):
        self.print_error('upgrading wallet format')

        self.convert_imported()
        self.convert_wallet_type()
        self.convert_account()
        self.convert_version_13_b()
        self.convert_version_14()
        self.convert_version_15()
        self.convert_version_16()
        self.convert_version_17()

        self.put('seed_version', FINAL_SEED_VERSION)  # just to be sure
        self.write()

    def convert_wallet_type(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        wallet_type = self.get('wallet_type')
        if wallet_type == 'btchip': wallet_type = 'ledger'
        if self.get('keystore') or self.get('x1/') or wallet_type=='imported':
            return False
        assert not self.requires_split()
        seed_version = self.get_seed_version()
        seed = self.get('seed')
        xpubs = self.get('master_public_keys')
        xprvs = self.get('master_private_keys', {})
        mpk = self.get('master_public_key')
        keypairs = self.get('keypairs')
        key_type = self.get('key_type')
        if seed_version == OLD_SEED_VERSION or wallet_type == 'old':
            d = {
                'type': 'old',
                'seed': seed,
                'mpk': mpk,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif key_type == 'imported':
            d = {
                'type': 'imported',
                'keypairs': keypairs,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['xpub', 'standard']:
            xpub = xpubs["x/"]
            xprv = xprvs.get("x/")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
                'seed': seed,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['bip44']:
            xpub = xpubs["x/0'"]
            xprv = xprvs.get("x/0'")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['trezor', 'keepkey', 'ledger', 'digitalbitbox', 'safe_t']:
            xpub = xpubs["x/0'"]
            derivation = self.get('derivation', bip44_derivation(0))
            d = {
                'type': 'hardware',
                'hw_type': wallet_type,
                'xpub': xpub,
                'derivation': derivation,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif (wallet_type == '2fa') or multisig_type(wallet_type):
            for key in xpubs.keys():
                d = {
                    'type': 'bip32',
                    'xpub': xpubs[key],
                    'xprv': xprvs.get(key),
                }
                if key == 'x1/' and seed:
                    d['seed'] = seed
                self.put(key, d)
        else:
            raise WalletFileException('Unable to tell wallet type. Is this even a wallet file?')
        # remove junk
        self.put('master_public_key', None)
        self.put('master_public_keys', None)
        self.put('master_private_keys', None)
        self.put('derivation', None)
        self.put('seed', None)
        self.put('keypairs', None)
        self.put('key_type', None)

    def convert_version_13_b(self):
        # version 13 is ambiguous, and has an earlier and a later structure
        if not self._is_upgrade_method_needed(0, 13):
            return

        if self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type') == 'imported':
                pubkeys = self.get('keystore').get('keypairs').keys()
                d = {'change': []}
                receiving_addresses = []
                for pubkey in pubkeys:
                    addr = bitcoin.pubkey_to_address('p2pkh', pubkey)
                    receiving_addresses.append(addr)
                d['receiving'] = receiving_addresses
                self.put('addresses', d)
                self.put('pubkeys', None)

        self.put('seed_version', 13)

    def convert_version_14(self):
        # convert imported wallets for 3.0
        if not self._is_upgrade_method_needed(13, 13):
            return

        if self.get('wallet_type') =='imported':
            addresses = self.get('addresses')
            if type(addresses) is list:
                addresses = dict([(x, None) for x in addresses])
                self.put('addresses', addresses)
        elif self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type')=='imported':
                addresses = set(self.get('addresses').get('receiving'))
                pubkeys = self.get('keystore').get('keypairs').keys()
                assert len(addresses) == len(pubkeys)
                d = {}
                for pubkey in pubkeys:
                    addr = bitcoin.pubkey_to_address('p2pkh', pubkey)
                    assert addr in addresses
                    d[addr] = {
                        'pubkey': pubkey,
                        'redeem_script': None,
                        'type': 'p2pkh'
                    }
                self.put('addresses', d)
                self.put('pubkeys', None)
                self.put('wallet_type', 'imported')
        self.put('seed_version', 14)

    def convert_version_15(self):
        if not self._is_upgrade_method_needed(14, 14):
            return
        if self.get('seed_type') == 'segwit':
            # should not get here; get_seed_version should have caught this
            raise Exception('unsupported derivation (development segwit, v14)')
        self.put('seed_version', 15)

    def convert_version_16(self):
        # fixes issue #3193 for Imported_Wallets with addresses
        # also, previous versions allowed importing any garbage as an address
        #       which we now try to remove, see pr #3191
        if not self._is_upgrade_method_needed(15, 15):
            return

        def remove_address(addr):
            def remove_from_dict(dict_name):
                d = self.get(dict_name, None)
                if d is not None:
                    d.pop(addr, None)
                    self.put(dict_name, d)

            def remove_from_list(list_name):
                lst = self.get(list_name, None)
                if lst is not None:
                    s = set(lst)
                    s -= {addr}
                    self.put(list_name, list(s))

            # note: we don't remove 'addr' from self.get('addresses')
            remove_from_dict('addr_history')
            remove_from_dict('labels')
            remove_from_dict('payment_requests')
            remove_from_list('frozen_addresses')

        if self.get('wallet_type') == 'imported':
            addresses = self.get('addresses')
            assert isinstance(addresses, dict)
            addresses_new = dict()
            for address, details in addresses.items():
                if not bitcoin.is_address(address):
                    remove_address(address)
                    continue
                if details is None:
                    addresses_new[address] = {}
                else:
                    addresses_new[address] = details
            self.put('addresses', addresses_new)

        self.put('seed_version', 16)

    def convert_version_17(self):
        # delete pruned_txo; construct spent_outpoints
        if not self._is_upgrade_method_needed(16, 16):
            return

        self.put('pruned_txo', None)

        from .transaction import Transaction
        transactions = self.get('transactions', {})  # txid -> raw_tx
        spent_outpoints = defaultdict(dict)
        for txid, raw_tx in transactions.items():
            tx = Transaction(raw_tx)
            for txin in tx.inputs():
                if txin['type'] == 'coinbase':
                    continue
                prevout_hash = txin['prevout_hash']
                prevout_n = txin['prevout_n']
                spent_outpoints[prevout_hash][prevout_n] = txid
        self.put('spent_outpoints', spent_outpoints)

        self.put('seed_version', 17)

    def convert_imported(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        # '/x' is the internal ID for imported accounts
        d = self.get('accounts', {}).get('/x', {}).get('imported',{})
        if not d:
            return False
        addresses = []
        keypairs = {}
        for addr, v in d.items():
            pubkey, privkey = v
            if privkey:
                keypairs[pubkey] = privkey
            else:
                addresses.append(addr)
        if addresses and keypairs:
            raise WalletFileException('mixed addresses and privkeys')
        elif addresses:
            self.put('addresses', addresses)
            self.put('accounts', None)
        elif keypairs:
            self.put('wallet_type', 'standard')
            self.put('key_type', 'imported')
            self.put('keypairs', keypairs)
            self.put('accounts', None)
        else:
            raise WalletFileException('no addresses or privkeys')

    def convert_account(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        self.put('accounts', None)

    def _is_upgrade_method_needed(self, min_version, max_version):
        cur_version = self.get_seed_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise WalletFileException(
                'storage upgrade: unexpected version {} (should be {}-{})'
                .format(cur_version, min_version, max_version))
        else:
            return True

    def get_action(self):
        action = run_hook('get_action', self)
        if self.file_exists() and self.requires_upgrade():
            if action:
                raise WalletFileException('Incomplete wallet files cannot be upgraded.')
            return 'upgrade_storage'
        if action:
            return action
        if not self.file_exists():
            return 'new'

    def get_seed_version(self):
        seed_version = self.get('seed_version')
        if not seed_version:
            seed_version = OLD_SEED_VERSION if len(self.get('master_public_key','')) == 128 else NEW_SEED_VERSION
        if seed_version > FINAL_SEED_VERSION:
            raise WalletFileException('This version of Electrum is too old to open this wallet.\n'
                                      '(highest supported storage version: {}, version of this file: {})'
                                      .format(FINAL_SEED_VERSION, seed_version))
        if seed_version==14 and self.get('seed_type') == 'segwit':
            self.raise_unsupported_version(seed_version)
        if seed_version >=12:
            return seed_version
        if seed_version not in [OLD_SEED_VERSION, NEW_SEED_VERSION]:
            self.raise_unsupported_version(seed_version)
        return seed_version

    def raise_unsupported_version(self, seed_version):
        msg = "Your wallet has an unsupported seed version."
        msg += '\n\nWallet file: %s' % os.path.abspath(self.path)
        if seed_version in [5, 7, 8, 9, 10, 14]:
            msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
        if seed_version == 6:
            # version 1.9.8 created v6 wallets when an incorrect seed was entered in the restore dialog
            msg += '\n\nThis file was created because of a bug in version 1.9.8.'
            if self.get('master_public_keys') is None and self.get('master_private_keys') is None and self.get('imported_keys') is None:
                # pbkdf2 (at that time an additional dependency) was not included with the binaries, and wallet creation aborted.
                msg += "\nIt does not contain any keys, and can safely be removed."
            else:
                # creation was complete if electrum was run from source
                msg += "\nPlease open this file with Electrum 1.9.8, and move your coins to a new wallet."
        raise WalletFileException(msg)
