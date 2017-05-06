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
import random
import time
import json
import copy
import re
import stat
import pbkdf2, hmac, hashlib
import base64
import zlib

from i18n import _
from util import NotEnoughFunds, PrintError, profiler
from plugins import run_hook, plugin_loaders
from keystore import bip44_derivation
import bitcoin


# seed_version is now used for the version of the wallet file

OLD_SEED_VERSION = 4        # electrum versions < 2.0
NEW_SEED_VERSION = 11       # electrum versions >= 2.0
FINAL_SEED_VERSION = 13     # electrum >= 2.7 will set this to prevent
                            # old versions from overwriting new format



def multisig_type(wallet_type):
    '''If wallet_type is mofn multi-sig, return [m, n],
    otherwise return None.'''
    match = re.match('(\d+)of(\d+)', wallet_type)
    if match:
        match = [int(x) for x in match.group(1, 2)]
    return match


class WalletStorage(PrintError):

    def __init__(self, path):
        self.print_error("wallet path", path)
        self.lock = threading.RLock()
        self.data = {}
        self.path = path
        self.modified = False
        self.pubkey = None
        if self.file_exists():
            with open(self.path, "r") as f:
                self.raw = f.read()
            if not self.is_encrypted():
                self.load_data(self.raw)

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

        # check here if I need to load a plugin
        t = self.get('wallet_type')
        l = plugin_loaders.get(t)
        if l: l()

    def is_encrypted(self):
        try:
            return base64.b64decode(self.raw).startswith('BIE1')
        except:
            return False

    def file_exists(self):
        return self.path and os.path.exists(self.path)

    def get_key(self, password):
        secret = pbkdf2.PBKDF2(password, '', iterations = 1024, macmodule = hmac, digestmodule = hashlib.sha512).read(64)
        ec_key = bitcoin.EC_KEY(secret)
        return ec_key

    def decrypt(self, password):
        ec_key = self.get_key(password)
        s = zlib.decompress(ec_key.decrypt_message(self.raw)) if self.raw else None
        self.pubkey = ec_key.get_public_key()
        self.load_data(s)

    def set_password(self, password, encrypt):
        self.put('use_encryption', bool(password))
        if encrypt and password:
            ec_key = self.get_key(password)
            self.pubkey = ec_key.get_public_key()
        else:
            self.pubkey = None

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

    @profiler
    def write(self):
        # this ensures that previous versions of electrum won't open the wallet
        self.put('seed_version', FINAL_SEED_VERSION)
        with self.lock:
            self._write()

    def _write(self):
        if threading.currentThread().isDaemon():
            self.print_error('warning: daemon thread cannot write wallet')
            return
        if not self.modified:
            return
        s = json.dumps(self.data, indent=4, sort_keys=True)
        if self.pubkey:
            s = bitcoin.encrypt_message(zlib.compress(s), self.pubkey)

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
        elif wallet_type in ['bip44', 'trezor', 'keepkey', 'ledger', 'btchip', 'digitalbitbox']:
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
            raise BaseException("This wallet has multiple accounts and must be split")
        return result

    def requires_upgrade(self):
        return self.file_exists() and self.get_seed_version() != FINAL_SEED_VERSION

    def upgrade(self):
        self.convert_imported()
        self.convert_wallet_type()
        self.convert_account()
        self.write()

    def convert_wallet_type(self):
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

        elif wallet_type in ['trezor', 'keepkey', 'ledger', 'digitalbitbox']:
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
            raise
        # remove junk
        self.put('master_public_key', None)
        self.put('master_public_keys', None)
        self.put('master_private_keys', None)
        self.put('derivation', None)
        self.put('seed', None)
        self.put('keypairs', None)
        self.put('key_type', None)

    def convert_imported(self):
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
            raise BaseException('mixed addresses and privkeys')
        elif addresses:
            self.put('addresses', addresses)
            self.put('accounts', None)
        elif keypairs:
            self.put('wallet_type', 'standard')
            self.put('key_type', 'imported')
            self.put('keypairs', keypairs)
            self.put('accounts', None)
        else:
            raise BaseException('no addresses or privkeys')

    def convert_account(self):
        self.put('accounts', None)
        self.put('pubkeys', None)

    def get_action(self):
        action = run_hook('get_action', self)
        if action:
            return action
        if not self.file_exists():
            return 'new'

    def get_seed_version(self):
        seed_version = self.get('seed_version')
        if not seed_version:
            seed_version = OLD_SEED_VERSION if len(self.get('master_public_key','')) == 128 else NEW_SEED_VERSION
        if seed_version >=12:
            return seed_version
        if seed_version not in [OLD_SEED_VERSION, NEW_SEED_VERSION]:
            msg = "Your wallet has an unsupported seed version."
            msg += '\n\nWallet file: %s' % os.path.abspath(self.path)
            if seed_version in [5, 7, 8, 9, 10]:
                msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
            if seed_version == 6:
                # version 1.9.8 created v6 wallets when an incorrect seed was entered in the restore dialog
                msg += '\n\nThis file was created because of a bug in version 1.9.8.'
                if self.get('master_public_keys') is None and self.get('master_private_keys') is None and self.get('imported_keys') is None:
                    # pbkdf2 was not included with the binaries, and wallet creation aborted.
                    msg += "\nIt does not contain any keys, and can safely be removed."
                else:
                    # creation was complete if electrum was run from source
                    msg += "\nPlease open this file with Electrum 1.9.8, and move your coins to a new wallet."
            raise BaseException(msg)
        return seed_version
