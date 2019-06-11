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
import threading
import stat
import hashlib
import base64
import zlib

from . import ecc
from .util import profiler, InvalidPassword, WalletFileException, bfh, standardize_path
from .plugin import run_hook, plugin_loaders

from .json_db import JsonDB
from .logging import Logger


def get_derivation_used_for_hw_device_encryption():
    return ("m"
            "/4541509'"      # ascii 'ELE'  as decimal ("BIP43 purpose")
            "/1112098098'")  # ascii 'BIE2' as decimal

# storage encryption version
STO_EV_PLAINTEXT, STO_EV_USER_PW, STO_EV_XPUB_PW = range(0, 3)



class WalletStorage(Logger):

    def __init__(self, path, *, manual_upgrades=False):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self.path = standardize_path(path)
        self._file_exists = self.path and os.path.exists(self.path)

        DB_Class = JsonDB
        self.logger.info(f"wallet path {self.path}")
        self.pubkey = None
        # TODO we should test r/w permissions here (whether file exists or not)
        if self.file_exists():
            with open(self.path, "r", encoding='utf-8') as f:
                self.raw = f.read()
            self._encryption_version = self._init_encryption_version()
            if not self.is_encrypted():
                self.db = DB_Class(self.raw, manual_upgrades=manual_upgrades)
                self.load_plugins()
        else:
            self._encryption_version = STO_EV_PLAINTEXT
            # avoid new wallets getting 'upgraded'
            self.db = DB_Class('', manual_upgrades=False)


    def load_plugins(self):
        wallet_type = self.db.get('wallet_type')
        if wallet_type in plugin_loaders:
            plugin_loaders[wallet_type]()

    def put(self, key,value):
        self.db.put(key, value)

    def get(self, key, default=None):
        return self.db.get(key, default)

    @profiler
    def write(self):
        with self.lock:
            self._write()

    def _write(self):
        if threading.currentThread().isDaemon():
            self.logger.warning('daemon thread cannot write db')
            return
        if not self.db.modified():
            return
        self.db.commit()
        s = self.encrypt_before_writing(self.db.dump())
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w", encoding='utf-8') as f:
            f.write(s)
            f.flush()
            os.fsync(f.fileno())

        mode = os.stat(self.path).st_mode if self.file_exists() else stat.S_IREAD | stat.S_IWRITE
        if not self.file_exists():
            assert not os.path.exists(self.path)
        os.replace(temp_path, self.path)
        os.chmod(self.path, mode)
        self._file_exists = True
        self.logger.info(f"saved {self.path}")
        self.db.set_modified(False)

    def file_exists(self):
        return self._file_exists

    def is_past_initial_decryption(self):
        """Return if storage is in a usable state for normal operations.

        The value is True exactly
            if encryption is disabled completely (self.is_encrypted() == False),
            or if encryption is enabled but the contents have already been decrypted.
        """
        try:
            return bool(self.db.data)
        except AttributeError:
            return False

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
        self.db = JsonDB(s, manual_upgrades=True)
        self.load_plugins()

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
        self.db.set_modified(True)

    def requires_upgrade(self):
        if not self.is_past_initial_decryption():
            raise Exception("storage not yet decrypted!")
        return self.db.requires_upgrade()

    def is_ready_to_be_used_by_wallet(self):
        return not self.requires_upgrade() and self.db._called_after_upgrade_tasks

    def upgrade(self):
        self.db.upgrade()
        self.write()

    def requires_split(self):
        return self.db.requires_split()

    def split_accounts(self):
        out = []
        result = self.db.split_accounts()
        for data in result:
            path = self.path + '.' + data['suffix']
            storage = WalletStorage(path)
            storage.db.data = data
            storage.db._called_after_upgrade_tasks = False
            storage.db.upgrade()
            storage.write()
            out.append(path)
        return out

    def get_action(self):
        action = run_hook('get_action', self)
        return action
