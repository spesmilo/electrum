# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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

import base64
import os
import hashlib
import hmac
from typing import Union

import pyaes

from .util import assert_bytes, InvalidPassword, to_bytes, to_string, WalletFileException
from .i18n import _


try:
    from Cryptodome.Cipher import AES
except:
    AES = None


class InvalidPadding(Exception):
    pass


def append_PKCS7_padding(data: bytes) -> bytes:
    assert_bytes(data)
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data: bytes) -> bytes:
    assert_bytes(data)
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if not (0 < padlen <= 16):
        raise InvalidPadding("invalid padding byte (out of range)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]


def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    data = append_PKCS7_padding(data)
    if AES:
        e = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    if AES:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise InvalidPassword()


def EncodeAES_base64(secret: bytes, msg: bytes) -> bytes:
    """Returns base64 encoded ciphertext."""
    e = EncodeAES_bytes(secret, msg)
    return base64.b64encode(e)


def EncodeAES_bytes(secret: bytes, msg: bytes) -> bytes:
    assert_bytes(msg)
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, msg)
    return iv + ct


def DecodeAES_base64(secret: bytes, ciphertext_b64: Union[bytes, str]) -> bytes:
    ciphertext = bytes(base64.b64decode(ciphertext_b64))
    return DecodeAES_bytes(secret, ciphertext)


def DecodeAES_bytes(secret: bytes, ciphertext: bytes) -> bytes:
    assert_bytes(ciphertext)
    iv, e = ciphertext[:16], ciphertext[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s


PW_HASH_VERSION_LATEST = 1
KNOWN_PW_HASH_VERSIONS = (1, 2, )
SUPPORTED_PW_HASH_VERSIONS = (1, )
assert PW_HASH_VERSION_LATEST in KNOWN_PW_HASH_VERSIONS
assert PW_HASH_VERSION_LATEST in SUPPORTED_PW_HASH_VERSIONS


class UnexpectedPasswordHashVersion(InvalidPassword, WalletFileException):
    def __init__(self, version):
        self.version = version

    def __str__(self):
        return "{unexpected}: {version}\n{instruction}".format(
            unexpected=_("Unexpected password hash version"),
            version=self.version,
            instruction=_('You are most likely using an outdated version of Electrum. Please update.'))


class UnsupportedPasswordHashVersion(InvalidPassword, WalletFileException):
    def __init__(self, version):
        self.version = version

    def __str__(self):
        return "{unsupported}: {version}\n{instruction}".format(
            unsupported=_("Unsupported password hash version"),
            version=self.version,
            instruction=f"To open this wallet, try 'git checkout password_v{self.version}'.\n"
                        "Alternatively, restore from seed.")


def _hash_password(password: Union[bytes, str], *, version: int) -> bytes:
    pw = to_bytes(password, 'utf8')
    if version not in SUPPORTED_PW_HASH_VERSIONS:
        raise UnsupportedPasswordHashVersion(version)
    if version == 1:
        return sha256d(pw)
    else:
        assert version not in KNOWN_PW_HASH_VERSIONS
        raise UnexpectedPasswordHashVersion(version)


def pw_encode(data: str, password: Union[bytes, str, None], *, version: int) -> str:
    if not password:
        return data
    if version not in KNOWN_PW_HASH_VERSIONS:
        raise UnexpectedPasswordHashVersion(version)
    # derive key from password
    secret = _hash_password(password, version=version)
    # encrypt given data
    ciphertext = EncodeAES_bytes(secret, to_bytes(data, "utf8"))
    ciphertext_b64 = base64.b64encode(ciphertext)
    return ciphertext_b64.decode('utf8')


def pw_decode(data: str, password: Union[bytes, str, None], *, version: int) -> str:
    if password is None:
        return data
    if version not in KNOWN_PW_HASH_VERSIONS:
        raise UnexpectedPasswordHashVersion(version)
    data_bytes = bytes(base64.b64decode(data))
    # derive key from password
    secret = _hash_password(password, version=version)
    # decrypt given data
    try:
        d = to_string(DecodeAES_bytes(secret, data_bytes), "utf8")
    except Exception as e:
        raise InvalidPassword() from e
    return d


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out


def hash_160(x: bytes) -> bytes:
    return ripemd(sha256(public_key))

def ripemd(x):
    try:
        md = hashlib.new('ripemd160')
        md.update(x)
        return md.digest()
    except BaseException:
        from . import ripemd
        md = ripemd.new(x)
        return md.digest()

def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, msg, digest)
    else:
        return hmac.new(key, msg, digest).digest()
