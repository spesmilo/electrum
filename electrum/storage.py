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
import stat
import hashlib
import base64
import zlib
import hmac
from enum import IntEnum
from typing import Optional
from secrets import token_bytes

import electrum_ecc as ecc

from . import crypto
from .util import InvalidPassword, standardize_path, test_read_write_permissions, os_chmod
from .logging import Logger
from .crypto import aes_encrypt_with_iv, aes_decrypt_with_iv, strip_PKCS7_padding

# todo: remove those deps?
from .bitcoin import var_int
from .transaction import BCDataStream


STORAGE_VERSION = 0
STORAGE_MAGIC_BYTES = b'Electrum'

STORAGE_FLAG_ZIP_FIRST_BLOB = 0x01
STORAGE_FLAGS = STORAGE_FLAG_ZIP_FIRST_BLOB

KDF_FLAGS = 0  # update when we change the kdf
KDF_POWER = 10 # rounds = pow(2, kdf_power)


def get_derivation_used_for_hw_device_encryption():
    return ("m"
            "/4541509'"      # ascii 'ELE'  as decimal ("BIP43 purpose")
            "/1112098098'")  # ascii 'BIE2' as decimal


class PasswordType(IntEnum):
    USER = 1
    XPUB = 2


class StorageReadWriteError(Exception): pass


class StorageOnDiskUnexpectedlyChanged(Exception): pass


# TODO: Rename to Storage
class WalletStorage(Logger):

    # TODO maybe split this into separate create() and open() classmethods, to prevent some bugs.
    #      Until then, the onus is on the caller to check file_exists().
    def __init__(
        self,
        path,
        *,
        allow_partial_writes: bool = False,
    ):
        Logger.__init__(self)
        self.path = standardize_path(path)
        self._file_exists = bool(self.path and os.path.exists(self.path))
        self.logger.info(f"wallet path {self.path}")
        self._allow_partial_writes = allow_partial_writes
        self.master_key = None
        self.decrypted = ''
        self._is_old_base64 = False
        self.encrypted_keys = []
        try:
            test_read_write_permissions(self.path)
        except IOError as e:
            raise StorageReadWriteError(e) from e
        if self.file_exists():
            self.read_header()
            with open(self.path, "rb") as f:
                self.pos = f.seek(0, os.SEEK_END)
                self.init_pos = self.pos
        else:
            self.raw = b''
            self.pos = 0
            self.init_pos = 0
            self.encrypted_keys = []

    @property
    def mac_offset(self):
        return len(self.header)

    def read(self):
        return self.decrypted if self.is_encrypted() else self.raw.decode('utf-8')

    def write(self, data: str) -> None:
        try:
            mode = os.stat(self.path).st_mode
        except FileNotFoundError:
            mode = stat.S_IREAD | stat.S_IWRITE
        s = self.encrypt_before_writing(data)
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "wb") as f:
            try:
                os_chmod(temp_path, mode)  # set restrictive perms *before* we write data
            except PermissionError as e:  # tolerate NFS or similar weirdness?
                self.logger.warning(f"cannot chmod temp wallet file: {e!r}")
            f.write(s)
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
        """ append data to encrypted file"""
        assert self._allow_partial_writes
        s, mac = self.encrypt_for_append(data)
        with open(self.path, "rb+") as f:
            pos = f.seek(0, os.SEEK_END)
            if pos != self.pos:
                raise StorageOnDiskUnexpectedlyChanged(f"expected size {self.pos}, found {pos}")
            f.write(s)
            if mac is not None:
                f.seek(self.mac_offset, 0)
                f.write(mac)
            self.pos = f.seek(0, os.SEEK_END)
            f.flush()
            os.fsync(f.fileno())

    def _needs_consolidation(self):
        return self.pos > 2 * self.init_pos

    def should_do_full_write_next(self) -> bool:
        """If false, next action can be a partial-write ('append')."""
        return (
            not self.file_exists()
            or self._needs_consolidation()
            or not self._allow_partial_writes
        )

    def file_exists(self) -> bool:
        return self._file_exists

    def is_past_initial_decryption(self) -> bool:
        """Return if storage is in a usable state for normal operations.

        The value is True exactly
            if encryption is disabled completely (self.is_encrypted() == False),
            or if encryption is enabled but the contents have already been decrypted.
        """
        return not self.is_encrypted() or bool(self.master_key)

    def is_encrypted(self) -> bool:
        """Return if storage encryption is currently enabled."""
        return self._is_old_base64 or len(self.encrypted_keys) > 0

    def is_encrypted_with_user_pw(self) -> bool:
        return PasswordType.USER in self.get_encryption_versions()

    def is_encrypted_with_hw_device(self) -> bool:
        return PasswordType.XPUB in self.get_encryption_versions()

    def get_encryption_versions(self) -> list[PasswordType]:
        """
        Returns a list of encryption versions (password types) used for this storage.
        Empty list if unencrypted.
        """
        if self._is_old_base64:
            return [self._encryption_version]
        return [x[0] for x in self.encrypted_keys]

    def read_header(self):
        f = open(self.path, "rb")
        first_bytes = f.read(8)
        if first_bytes.startswith(base64.b64encode(b'BIE')):
            self._is_old_base64 = True
            data = first_bytes + f.read()
            self.raw = base64.b64decode(data, validate=True)
            self._magic = self.raw[0:4]
            if self._magic not in [b'BIE1', b'BIE2']:
                raise Exception('unknown file format')
            self._encryption_version = PasswordType.USER if self._magic == b'BIE1' else PasswordType.XPUB
        else:
            self._is_old_base64 = False
            if first_bytes != STORAGE_MAGIC_BYTES:
                self.raw = first_bytes + f.read()
            else:
                version = ord(f.read(1))
                assert version == STORAGE_VERSION
                self._storage_flags = ord(f.read(1))
                num_passwords = ord(f.read(1))
                self.encrypted_keys = []
                for i in range(num_passwords):
                    password_type = PasswordType(ord(f.read(1)))
                    kdf_flags = ord(f.read(1))
                    kdf_power = ord(f.read(1))
                    encrypted_master_key = f.read(32)
                    self.encrypted_keys.append((password_type, kdf_flags, kdf_power, encrypted_master_key))
                self.master_key_mac = f.read(32)
                header_size = f.tell()
                f.seek(0)
                self.header = f.read(header_size)
        f.close()

    def update_header(self, is_zipped=False) -> bytes:
        N = len(self.encrypted_keys)
        assert N < 256
        self._storage_flags = STORAGE_FLAGS
        header = STORAGE_MAGIC_BYTES + bytes([STORAGE_VERSION, self._storage_flags]) + bytes([N])
        for item in self.encrypted_keys:
            pw_type, kdf_flags, kdf_power, encrypted_master_key = item
            header += bytes([pw_type, kdf_flags, kdf_power]) + encrypted_master_key
        mac = hmac.new(self.master_key, None, hashlib.sha256).digest()
        assert len(mac) == 32
        header += mac
        self.header = header
        self.master_key_mac = mac

    @staticmethod
    def get_old_eckey_from_password(password):
        if password is None:
            password = ""
        secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
        ec_key = ecc.ECPrivkey.from_arbitrary_size_secret(secret)
        return ec_key

    def get_secret_from_password(self, password, kdf_flags, rounds):
        # kdf flags are not used for the moment
        return hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=rounds)

    def read_all(self):
        with open(self.path, "rb") as f:
            self.raw = f.read()

    def decrypt_old(self, password) -> None:
        self.read_all()
        ec_key = self.get_old_eckey_from_password(password)
        s = crypto.ecies_decrypt_message(ec_key, self.raw, magic=self._magic)
        s = zlib.decompress(s)
        # convert to new scheme
        self.init_master_key()
        self._add_password_to_header(password, self._encryption_version)
        self.update_header()
        self.decrypted = s.decode('utf8')
        self.write(self.decrypted)

    def decrypt(self, password) -> None:
        """Raises an InvalidPassword exception on invalid password"""
        if self.is_past_initial_decryption():
            return
        if self._is_old_base64:
            self.decrypt_old(password)
            return
        self.check_password(password)
        self.read_all()
        mac = self.raw[self.mac_offset:self.mac_offset + 32]
        ciphertext = self.raw[self.mac_offset + 32:]
        self.iv = ciphertext[-16:]
        key_e, key_m = self.master_key[0:16], self.master_key[16:32]
        decrypted = aes_decrypt_with_iv(key_e, key_m, ciphertext, strip_pkcs7=False)
        vds = BCDataStream()
        vds.write(decrypted)
        s = b''
        self.mac = hmac.new(key_m, b'', hashlib.sha256)
        # break if the remaining bytes have not been commited
        while self.mac.digest() != mac:
            n = vds.read_compact_size()
            n_size = len(var_int(n))
            vds.read_cursor -= n_size
            # this may raise if the file has been corrupted
            blob = vds.read_bytes(n*16)
            blob = strip_PKCS7_padding(blob)
            blob = blob[n_size:]
            self.mac.update(blob)
            if len(s) == 0:
                if self._storage_flags & STORAGE_FLAG_ZIP_FIRST_BLOB:
                    blob = zlib.decompress(blob)
            s += blob
        s = s.decode('utf8')
        self.decrypted = s

    def get_prefixed_blob(self, s: bytes) -> bytes:
        """return data prefixed by its size (number of 16 bytes blocks required, including bytes used for size and the padding) """
        for x in [1,3,5,9]:
            size = len(s) + x
            n = size // 16 + 1 # add one for pkcs7 padding
            header = var_int(n)
            if len(header) == x:
                return header + s
        else:
            raise Exception('blob too large for var_int')

    def init_master_key(self):
        self.master_key = token_bytes(32)

    def encrypt_before_writing(self, plaintext: str) -> bytes:
        s = bytes(plaintext, 'utf8')
        if self.master_key:
            if self._storage_flags & STORAGE_FLAG_ZIP_FIRST_BLOB:
                s = zlib.compress(s, level=zlib.Z_BEST_SPEED)
            blob = self.get_prefixed_blob(s)
            key_e, key_m = self.master_key[0:16], self.master_key[16:32]
            ciphertext = aes_encrypt_with_iv(key_e, key_m, blob)
            # save mac, key_e, key_m, and iv, for subsequent writes
            self.iv = ciphertext[-16:]
            self.mac = hmac.new(key_m, s, hashlib.sha256)
            mac = self.mac.digest()
            s = self.header + mac + ciphertext
        return s

    def encrypt_for_append(self, plaintext: str) -> str:
        s = bytes(plaintext, 'utf8')
        if self.master_key:
            self.mac.update(s)
            mac = self.mac.digest()
            blob = self.get_prefixed_blob(s)
            key_e = self.master_key[0:16]
            ciphertext = aes_encrypt_with_iv(key_e, self.iv, blob)
            self.iv = ciphertext[-16:]
            return ciphertext, mac
        else:
            return s, None

    def _old_check_password(self, password) -> None:
        if not self.is_past_initial_decryption():
            self.decrypt(password)  # this sets self.master_key
        assert self.master_key is not None
        if self.pubkey != self.get_old_eckey_from_password(password).get_public_key_hex():
            raise InvalidPassword()

    def _check_update_password(self, password: Optional[str], new_password: Optional[str], new_password_type: Optional[PasswordType]) -> None:
        """
        if old_password == new_password, only check password
        otherwise, check and update password
        """
        assert self.is_encrypted()
        # decrypt master_key and compare mac
        for i, item in enumerate(self.encrypted_keys):
            password_type, kdf_flags, kdf_power, encrypted_master_key = item
            decrypted_master_key = self._get_decrypted_master_key(encrypted_master_key, password, kdf_flags, kdf_power)
            if hmac.new(decrypted_master_key, None, hashlib.sha256).digest() == self.master_key_mac:
                break
        else:
            raise InvalidPassword()
        self.master_key = decrypted_master_key
        if new_password:
            if new_password != password:
                assert new_password_type is not None
                kdf_flags, kdf_power, encrypted_master_key = self._get_encrypted_master_key(new_password, new_password_type)
                self.encrypted_keys[i] = new_password_type, kdf_flags, kdf_power, encrypted_master_key
        else:
            assert new_password_type is None
            del self.encrypted_keys[i]

    def _get_encrypted_master_key(self, password, password_type):
        # password_type not used currently.
        # we could use it to make KDF dependent on it
        kdf_flags, kdf_power = KDF_FLAGS, KDF_POWER
        password_key = self.get_secret_from_password(password, kdf_flags, rounds=pow(2, kdf_power))
        key_e, key_m = password_key[0:16], password_key[16:32]
        encrypted_master_key = aes_encrypt_with_iv(key_e, key_m, self.master_key, append_pkcs7=False)
        assert len(encrypted_master_key) == 32
        return kdf_flags, kdf_power, encrypted_master_key

    def _get_decrypted_master_key(self, encrypted_master_key, password, kdf_flags, kdf_power):
        password_key = self.get_secret_from_password(password, kdf_flags, rounds=pow(2, kdf_power))
        key_e, key_m = password_key[0:16], password_key[16:32]
        decrypted_master_key = aes_decrypt_with_iv(key_e, key_m, encrypted_master_key, strip_pkcs7=False)
        assert len(encrypted_master_key) == 32
        return decrypted_master_key

    def _add_password_to_header(self, password, password_type):
        kdf_flags, kdf_power, encrypted_master_key = self._get_encrypted_master_key(password, password_type)
        self.encrypted_keys.append((password_type, kdf_flags, kdf_power, encrypted_master_key))

    def check_password(self, password: Optional[str]) -> None:
        """Raises an InvalidPassword exception on invalid password
        """
        if not self.is_encrypted():
            if password is not None:
                raise InvalidPassword("password given but wallet has no password")
            return
        if self._is_old_base64:
            self._old_check_password(password)
            return
        self._check_update_password(password, password, None)

    def update_password(self, password, new_password, new_password_type):
        self._check_update_password(password, new_password, new_password_type)
        self.update_header()

    def remove_password(self, password):
        """ remove password from list. disable encryption ig list is empty."""
        if not self.is_past_initial_decryption():
            raise Exception("storage needs to be decrypted before changing password")
        self._check_update_password(password, None, None)
        if len(self.encrypted_keys) == 0:
            self.master_key = None
        else:
            self.update_header()

    def add_password(self, password, password_type):
        """Set a password to be used for encrypting this storage."""
        assert password
        if not self.is_past_initial_decryption():
            raise Exception("storage needs to be decrypted before changing password")
        if len(self.encrypted_keys) == 0:
            self.init_master_key()
        self._add_password_to_header(password, password_type)
        self.update_header()

    def basename(self) -> str:
        return os.path.basename(self.path)

