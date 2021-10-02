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
import hmac
from enum import IntEnum
from secrets import token_bytes

from . import ecc
from .util import (profiler, InvalidPassword, WalletFileException, bfh, standardize_path,
                   test_read_write_permissions)

from .wallet_db import WalletDB
from .logging import Logger

from .crypto import aes_encrypt_with_iv, aes_decrypt_with_iv
from .crypto import strip_PKCS7_padding, InvalidPadding
from .bitcoin import var_int
from .transaction import BCDataStream


def get_derivation_used_for_hw_device_encryption():
    return ("m"
            "/4541509'"      # ascii 'ELE'  as decimal ("BIP43 purpose")
            "/1112098098'")  # ascii 'BIE2' as decimal


class StorageEncryptionType(IntEnum):
    PLAINTEXT = 0
    USER_PASSWORD = 1
    XPUB_PASSWORD = 2


class StorageReadWriteError(Exception): pass


# TODO: Rename to Storage
class WalletStorage(Logger):

    def __init__(self, path):
        Logger.__init__(self)
        self.path = standardize_path(path)
        self._file_exists = bool(self.path and os.path.exists(self.path))
        self.logger.info(f"wallet path {self.path}")
        self.master_key = None
        self.decrypted = ''
        try:
            test_read_write_permissions(self.path)
        except IOError as e:
            raise StorageReadWriteError(e) from e
        if self.file_exists():
            self.read_header()
        else:
            self.raw = b''
            self._encryption_type = StorageEncryptionType.PLAINTEXT

    def read(self):
        return self.decrypted if self.is_encrypted() else self.raw.decode('utf-8')

    def write(self, data: str) -> None:
        """ rewrite the entire file """
        s = self.encrypt_for_write(data)
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "wb") as f:
            f.write(s)
            f.flush()
            os.fsync(f.fileno())
        try:
            mode = os.stat(self.path).st_mode
        except FileNotFoundError:
            mode = stat.S_IREAD | stat.S_IWRITE
        # assert that wallet file does not exist, to prevent wallet corruption (see issue #5082)
        if not self.file_exists():
            assert not os.path.exists(self.path)
        os.replace(temp_path, self.path)
        os.chmod(self.path, mode)
        self._file_exists = True
        self.logger.info(f"saved {self.path}")

    def append(self, data: str) -> None:
        """ append data to encrypted file"""
        s, mac = self.encrypt_for_append(data)
        with open(self.path, "rb+") as f:
            f.seek(0, os.SEEK_END)
            f.write(s)
            if mac is not None:
                f.seek(self.mac_offset, 0)
                f.write(mac)
            f.flush()
            os.fsync(f.fileno())

    def file_exists(self) -> bool:
        return self._file_exists

    def is_past_initial_decryption(self):
        """Return if storage is in a usable state for normal operations.

        The value is True exactly
            if encryption is disabled completely (self.is_encrypted() == False),
            or if encryption is enabled but the contents have already been decrypted.
        """
        return not self.is_encrypted() or bool(self.master_key)

    def is_encrypted(self):
        """Return if storage encryption is currently enabled."""
        return self.get_encryption_type() != StorageEncryptionType.PLAINTEXT

    def is_encrypted_with_user_pw(self):
        return self.get_encryption_type() == StorageEncryptionType.USER_PASSWORD

    def is_encrypted_with_hw_device(self):
        return self.get_encryption_type() == StorageEncryptionType.XPUB_PASSWORD

    def get_encryption_type(self):
        """Return the type of encryption used for this storage.

        0: plaintext / no encryption
        1: password is provided by user
        2: password is derived from an xpub; used with hw wallets
        """
        return self._encryption_type

    def read_header(self):
        f = open(self.path, "rb")
        first_bytes = f.read(8)
        if first_bytes.startswith(base64.b64encode(b'BIE')):
            data = first_bytes + f.read()
            self.raw = base64.b64decode(data)
            self._is_old_base64 = True
            magic = self.raw[0:4]
            if magic == b'BIE1':
                self._encryption_type = StorageEncryptionType.USER_PASSWORD
            elif magic == b'BIE2':
                self._encryption_type = StorageEncryptionType.XPUB_PASSWORD
            else:
                raise Exception('unknown file format')
        else:
            self._is_old_base64 = False
            if first_bytes != b'Electrum':
                self._encryption_type = StorageEncryptionType.PLAINTEXT
                self.raw = first_bytes + f.read()
            else:
                self._encryption_type = StorageEncryptionType.USER_PASSWORD
                version = f.read(1)
                assert version == b'\x00', version
                flags = f.read(1)
                num_passwords = ord(f.read(1))
                assert num_passwords == 1, num_passwords
                self.encrypted_keys = []
                for i in range(num_passwords):
                    kdf_flags = f.read(1)
                    kdf_rounds = ord(f.read(1))
                    encrypted_master_key = f.read(32)
                    self.encrypted_keys.append((kdf_flags, kdf_rounds, encrypted_master_key))
                self.master_key_mac = f.read(32)
                header_size = f.tell()
                f.seek(0)
                self.header = f.read(header_size)
        f.close()

    def create_header(self, pw_list, is_zipped=False) -> bytes:
        magic = b'Electrum'
        version = 0
        flags = 0 # TODO: add is_zipped
        N = len(pw_list)
        header = magic + bytes([version, flags]) + bytes([N])
        for pw in pw_list:
            kdf_flags = 0
            kdf_rounds = 10
            password_key = self.get_secret_from_password(pw, pow(2, kdf_rounds))
            encrypted_master_key = aes_encrypt_with_iv(password_key[0:16], password_key[16:32], self.master_key, append_pkcs7=False)
            assert len(encrypted_master_key) == 32
            header += bytes([kdf_flags, kdf_rounds]) + encrypted_master_key
        mac = hmac.new(self.master_key, None, hashlib.sha256).digest()
        assert len(mac) == 32
        header += mac
        self.header = header

    @staticmethod
    def get_eckey_from_password(password):
        secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
        ec_key = ecc.ECPrivkey.from_arbitrary_size_secret(secret)
        return ec_key

    def get_secret_from_password(self, password, rounds):
        return hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=rounds)

    def read_all(self):
        with open(self.path, "rb") as f:
            self.raw = f.read()

    def decrypt_old(self, password) -> None:
        self.read_all()
        ec_key = self.get_eckey_from_password(password)
        enc_magic = b'BIE1' if self._encryption_type == StorageEncryptionType.USER_PASSWORD else b'BIE2'
        s = ec_key.decrypt_message(self.raw, enc_magic)
        s = zlib.decompress(s)
        # convert to new scheme
        self.init_master_key(password)
        self.decrypted = s.decode('utf8')
        self.write(self.decrypted)

    def decrypt(self, password) -> None:
        if self.is_past_initial_decryption():
            return
        if self._is_old_base64:
            self.decrypt_old(password)
            return
        self.check_password(password)
        self.read_all()
        header_size = len(self.header)
        mac = self.raw[header_size:header_size+32]
        ciphertext = self.raw[header_size+32:]
        key_e, key_m = self.master_key[0:16], self.master_key[16:32]
        decrypted = aes_decrypt_with_iv(key_e, key_m, ciphertext, strip_pkcs7=False)
        vds = BCDataStream()
        vds.write(decrypted)
        s = b''
        self.mac = hmac.new(key_m, b'', hashlib.sha256)
        # break if the remaining bytes have not been commited
        while self.mac.digest() != mac:
            n = vds.read_compact_size()
            n_size = len(bytes.fromhex(var_int(n)))
            vds.read_cursor -= n_size
            # this may raise if the file has been corrupted
            blob = vds.read_bytes(n*16)
            blob = strip_PKCS7_padding(blob)
            blob = blob[n_size:]
            s += blob
            self.mac.update(blob)
        s = s.decode('utf8')
        self.decrypted = s

    def block_size(self, s: bytes) -> bytes:
        """ number of 16 bytes blocks required, including bytes used for size and the padding"""
        for x in [1,3,5,9]:
            size = len(s) + x
            n = size // 16 + 1 # add one for pkcs7 padding
            header = bytes.fromhex(var_int(n))
            if len(header)==x:
                return header
        else:
            raise Exception('block too large for var_int')

    def init_master_key(self, password):
        self.master_key = token_bytes(32)
        self.create_header([password])

    def encrypt_for_write(self, plaintext: str) -> str:
        s = bytes(plaintext, 'utf8')
        if self.master_key:
            blob = self.block_size(s) + s
            key_e, key_m = self.master_key[0:16], self.master_key[16:32]
            #iv = key_m
            ciphertext = aes_encrypt_with_iv(key_e, key_m, blob)
            # save mac, key_e, key_m, and iv, for subsequent writes
            self.iv = ciphertext[-16:]
            self.mac_offset = len(self.header)
            self.mac = hmac.new(key_m, s, hashlib.sha256)
            mac = self.mac.digest()
            s = self.header + mac + ciphertext
        return s

    def encrypt_for_append(self, plaintext: str) -> str:
        s = bytes(plaintext, 'utf8')
        if self.master_key:
            self.mac.update(s)
            mac = self.mac.digest()
            blob = self.block_size(s) + s
            key_e, key_m = self.master_key[0:16], self.master_key[16:32]
            ciphertext = aes_encrypt_with_iv(key_e, self.iv, blob)
            self.iv = ciphertext[-16:]
            return ciphertext, mac
        else:
            return s, None

    def check_password_old(self, password) -> None:
        if not self.is_past_initial_decryption():
            self.decrypt(password)  # this sets self.master_key
        assert self.master_key is not None
        if self.pubkey != self.get_eckey_from_password(password).get_public_key_hex():
            raise InvalidPassword()

    def check_password(self, password) -> None:
        """Raises an InvalidPassword exception on invalid password"""
        if not self.is_encrypted():
            return
        if self._is_old_base64:
            self.check_password_old(password)
        # decrypt master_key and compare mac
        for item in self.encrypted_keys:
            kdf_flags, kdf_rounds, encrypted_master_key = item
            password_key = self.get_secret_from_password(password, pow(2, kdf_rounds))
            decrypted_master_key = aes_decrypt_with_iv(password_key[0:16], password_key[16:32], encrypted_master_key, strip_pkcs7=False)
            if hmac.new(decrypted_master_key, None, hashlib.sha256).digest() == self.master_key_mac:
                self.master_key = decrypted_master_key
                break
        else:
            raise InvalidPassword()

    def set_password(self, password, enc_version=None):
        """Set a password to be used for encrypting this storage."""
        if not self.is_past_initial_decryption():
            raise Exception("storage needs to be decrypted before changing password")
        if enc_version is None:
            enc_version = self._encryption_type
        if password and enc_version != StorageEncryptionType.PLAINTEXT:
            self.init_master_key(password)
            self._encryption_version = enc_version
        else:
            self.master_key = None
            self._encryption_type = StorageEncryptionType.PLAINTEXT

    def basename(self) -> str:
        return os.path.basename(self.path)

