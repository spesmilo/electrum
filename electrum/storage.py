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
from enum import IntEnum
from typing import Optional

from . import ecc, crypto
from .util import (profiler, InvalidPassword, WalletFileException, bfh, standardize_path,
                   test_read_write_permissions, os_chmod)

from .wallet_db import WalletDB
from .logging import Logger


def get_derivation_used_for_hw_device_encryption():
    return ("m"
            "/4541509'"      # ascii 'ELE'  as decimal ("BIP43 purpose")
            "/1112098098'")  # ascii 'BIE2' as decimal


class StorageEncryptionVersion(IntEnum):
    PLAINTEXT = 0
    USER_PASSWORD = 1
    XPUB_PASSWORD = 2


class StorageReadWriteError(Exception): pass


class StorageOnDiskUnexpectedlyChanged(Exception): pass


# TODO: Rename to Storage
class WalletStorage(Logger):

    # TODO maybe split this into separate create() and open() classmethods, to prevent some bugs.
    #      Until then, the onus is on the caller to check file_exists().
    def __init__(self, path):
        Logger.__init__(self)
        self.path = standardize_path(path)
        self._file_exists = bool(self.path and os.path.exists(self.path))
        self.logger.info(f"wallet path {self.path}")
        self.pubkey = None
        self.decrypted = ''
        try:
            test_read_write_permissions(self.path)
        except IOError as e:
            raise StorageReadWriteError(e) from e
        if self.file_exists():
            with open(self.path, "rb") as f:
                self.raw = f.read().decode("utf-8")
                self.pos = f.seek(0, os.SEEK_END)
                self.init_pos = self.pos
            self._encryption_version = self._init_encryption_version()
        else:
            self.raw = ''
            self._encryption_version = StorageEncryptionVersion.PLAINTEXT
            self.pos = 0
            self.init_pos = 0

    def read(self):
        return self.decrypted if self.is_encrypted() else self.raw

    def write(self, data: str) -> None:
        try:
            mode = os.stat(self.path).st_mode
        except FileNotFoundError:
            mode = stat.S_IREAD | stat.S_IWRITE
        s = self.encrypt_before_writing(data)
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "wb") as f:
            os_chmod(temp_path, mode)  # set restrictive perms *before* we write data
            f.write(s.encode("utf-8"))
            self.pos = f.seek(0, os.SEEK_END)
            f.flush()
            os.fsync(f.fileno())
        # assert that wallet file does not exist, to prevent wallet corruption (see issue #5082)
        if not self.file_exists():
            assert not os.path.exists(self.path)
        os.replace(temp_path, self.path)
        self._file_exists = True
        self.logger.info(f"saved {self.path}")

    def append(self, data: str) -> None:
        """ append data to file. for the moment, only non-encrypted file"""
        assert not self.is_encrypted()
        with open(self.path, "rb+") as f:
            pos = f.seek(0, os.SEEK_END)
            if pos != self.pos:
                raise StorageOnDiskUnexpectedlyChanged(f"expected size {self.pos}, found {pos}")
            f.write(data.encode("utf-8"))
            self.pos = f.seek(0, os.SEEK_END)
            f.flush()
            os.fsync(f.fileno())

    def needs_consolidation(self):
        return self.pos > 2 * self.init_pos

    def file_exists(self) -> bool:
        return self._file_exists

    def is_past_initial_decryption(self) -> bool:
        """Return if storage is in a usable state for normal operations.

        The value is True exactly
            if encryption is disabled completely (self.is_encrypted() == False),
            or if encryption is enabled but the contents have already been decrypted.
        """
        return not self.is_encrypted() or bool(self.pubkey)

    def is_encrypted(self) -> bool:
        """Return if storage encryption is currently enabled."""
        return self.get_encryption_version() != StorageEncryptionVersion.PLAINTEXT

    def is_encrypted_with_user_pw(self) -> bool:
        return self.get_encryption_version() == StorageEncryptionVersion.USER_PASSWORD

    def is_encrypted_with_hw_device(self) -> bool:
        return self.get_encryption_version() == StorageEncryptionVersion.XPUB_PASSWORD

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
                return StorageEncryptionVersion.USER_PASSWORD
            elif magic == b'BIE2':
                return StorageEncryptionVersion.XPUB_PASSWORD
            else:
                return StorageEncryptionVersion.PLAINTEXT
        except Exception:
            return StorageEncryptionVersion.PLAINTEXT

    @staticmethod
    def get_eckey_from_password(password):
        if password is None:
            password = ""
        secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
        ec_key = ecc.ECPrivkey.from_arbitrary_size_secret(secret)
        return ec_key

    def _get_encryption_magic(self):
        v = self._encryption_version
        if v == StorageEncryptionVersion.USER_PASSWORD:
            return b'BIE1'
        elif v == StorageEncryptionVersion.XPUB_PASSWORD:
            return b'BIE2'
        else:
            raise WalletFileException('no encryption magic for version: %s' % v)

    def decrypt(self, password) -> None:
        """Raises an InvalidPassword exception on invalid password"""
        if self.is_past_initial_decryption():
            return
        ec_key = self.get_eckey_from_password(password)
        if self.raw:
            enc_magic = self._get_encryption_magic()
            s = zlib.decompress(crypto.ecies_decrypt_message(ec_key, self.raw, magic=enc_magic))
            s = s.decode('utf8')
        else:
            s = ''
        self.pubkey = ec_key.get_public_key_hex()
        self.decrypted = s

    def encrypt_before_writing(self, plaintext: str) -> str:
        s = plaintext
        if self.pubkey:
            self.decrypted = plaintext
            s = bytes(s, 'utf8')
            c = zlib.compress(s, level=zlib.Z_BEST_SPEED)
            enc_magic = self._get_encryption_magic()
            public_key = ecc.ECPubkey(bfh(self.pubkey))
            s = crypto.ecies_encrypt_message(public_key, c, magic=enc_magic)
            s = s.decode('utf8')
        return s

    def check_password(self, password: Optional[str]) -> None:
        """Raises an InvalidPassword exception on invalid password"""
        if not self.is_encrypted():
            if password is not None:
                raise InvalidPassword("password given but wallet has no password")
            return
        if not self.is_past_initial_decryption():
            self.decrypt(password)  # this sets self.pubkey
        assert self.pubkey is not None
        if self.pubkey != self.get_eckey_from_password(password).get_public_key_hex():
            raise InvalidPassword()

    def set_password(self, password, enc_version=None):
        """Set a password to be used for encrypting this storage."""
        if not self.is_past_initial_decryption():
            raise Exception("storage needs to be decrypted before changing password")
        if enc_version is None:
            enc_version = self._encryption_version
        if password and enc_version != StorageEncryptionVersion.PLAINTEXT:
            ec_key = self.get_eckey_from_password(password)
            self.pubkey = ec_key.get_public_key_hex()
            self._encryption_version = enc_version
        else:
            self.pubkey = None
            self._encryption_version = StorageEncryptionVersion.PLAINTEXT

    def basename(self) -> str:
        return os.path.basename(self.path)

