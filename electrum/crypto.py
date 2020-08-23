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
import sys
import hashlib
import hmac
from typing import Union

import pyaes

from .util import assert_bytes, InvalidPassword, to_bytes, to_string, WalletFileException
from .i18n import _


HAS_CRYPTODOME = False
try:
    from Cryptodome.Cipher import ChaCha20_Poly1305 as CD_ChaCha20_Poly1305
    from Cryptodome.Cipher import ChaCha20 as CD_ChaCha20
    from Cryptodome.Cipher import AES as CD_AES
except:
    pass
else:
    HAS_CRYPTODOME = True

HAS_CRYPTOGRAPHY = False
try:
    import cryptography
    from cryptography import exceptions
    from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
    from cryptography.hazmat.primitives.ciphers import modes as CG_modes
    from cryptography.hazmat.backends import default_backend as CG_default_backend
    import cryptography.hazmat.primitives.ciphers.aead as CG_aead
except:
    pass
else:
    HAS_CRYPTOGRAPHY = True


if not (HAS_CRYPTODOME or HAS_CRYPTOGRAPHY):
    sys.exit(f"Error: at least one of ('pycryptodomex', 'cryptography') needs to be installed.")


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
    if HAS_CRYPTODOME:
        e = CD_AES.new(key, CD_AES.MODE_CBC, iv).encrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        encryptor = cipher.encryptor()
        e = encryptor.update(data) + encryptor.finalize()
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    if HAS_CRYPTODOME:
        cipher = CD_AES.new(key, CD_AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
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


def _pw_encode_raw(data: bytes, password: Union[bytes, str], *, version: int) -> bytes:
    if version not in KNOWN_PW_HASH_VERSIONS:
        raise UnexpectedPasswordHashVersion(version)
    # derive key from password
    secret = _hash_password(password, version=version)
    # encrypt given data
    ciphertext = EncodeAES_bytes(secret, data)
    return ciphertext


def _pw_decode_raw(data_bytes: bytes, password: Union[bytes, str], *, version: int) -> bytes:
    if version not in KNOWN_PW_HASH_VERSIONS:
        raise UnexpectedPasswordHashVersion(version)
    # derive key from password
    secret = _hash_password(password, version=version)
    # decrypt given data
    try:
        d = DecodeAES_bytes(secret, data_bytes)
    except Exception as e:
        raise InvalidPassword() from e
    return d


def pw_encode_bytes(data: bytes, password: Union[bytes, str], *, version: int) -> str:
    """plaintext bytes -> base64 ciphertext"""
    ciphertext = _pw_encode_raw(data, password, version=version)
    ciphertext_b64 = base64.b64encode(ciphertext)
    return ciphertext_b64.decode('utf8')


def pw_decode_bytes(data: str, password: Union[bytes, str], *, version:int) -> bytes:
    """base64 ciphertext -> plaintext bytes"""
    if version not in KNOWN_PW_HASH_VERSIONS:
        raise UnexpectedPasswordHashVersion(version)
    data_bytes = bytes(base64.b64decode(data))
    return _pw_decode_raw(data_bytes, password, version=version)


def pw_encode_with_version_and_mac(data: bytes, password: Union[bytes, str]) -> str:
    """plaintext bytes -> base64 ciphertext"""
    # https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
    # Encrypt-and-MAC. The MAC will be used to detect invalid passwords
    version = PW_HASH_VERSION_LATEST
    mac = sha256(data)[0:4]
    ciphertext = _pw_encode_raw(data, password, version=version)
    ciphertext_b64 = base64.b64encode(bytes([version]) + ciphertext + mac)
    return ciphertext_b64.decode('utf8')


def pw_decode_with_version_and_mac(data: str, password: Union[bytes, str]) -> bytes:
    """base64 ciphertext -> plaintext bytes"""
    data_bytes = bytes(base64.b64decode(data))
    version = int(data_bytes[0])
    encrypted = data_bytes[1:-4]
    mac = data_bytes[-4:]
    if version not in KNOWN_PW_HASH_VERSIONS:
        raise UnexpectedPasswordHashVersion(version)
    decrypted = _pw_decode_raw(encrypted, password, version=version)
    if sha256(decrypted)[0:4] != mac:
        raise InvalidPassword()
    return decrypted


def pw_encode(data: str, password: Union[bytes, str, None], *, version: int) -> str:
    """plaintext str -> base64 ciphertext"""
    if not password:
        return data
    plaintext_bytes = to_bytes(data, "utf8")
    return pw_encode_bytes(plaintext_bytes, password, version=version)


def pw_decode(data: str, password: Union[bytes, str, None], *, version: int) -> str:
    """base64 ciphertext -> plaintext str"""
    if password is None:
        return data
    plaintext_bytes = pw_decode_bytes(data, password, version=version)
    try:
        plaintext_str = to_string(plaintext_bytes, "utf8")
    except UnicodeDecodeError as e:
        raise InvalidPassword() from e
    return plaintext_str


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out


def hash_160(x: bytes) -> bytes:
    return ripemd(sha256(x))

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


def chacha20_poly1305_encrypt(
        *,
        key: bytes,
        nonce: bytes,
        associated_data: bytes = None,
        data: bytes
) -> bytes:
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(associated_data, (bytes, bytearray, type(None)))
    assert isinstance(data, (bytes, bytearray))
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if associated_data is not None:
            cipher.update(associated_data)
        ciphertext, mac = cipher.encrypt_and_digest(plaintext=data)
        return ciphertext + mac
    if HAS_CRYPTOGRAPHY:
        a = CG_aead.ChaCha20Poly1305(key)
        return a.encrypt(nonce, data, associated_data)
    raise Exception("no chacha20 backend found")


def chacha20_poly1305_decrypt(
        *,
        key: bytes,
        nonce: bytes,
        associated_data: bytes = None,
        data: bytes
) -> bytes:
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(associated_data, (bytes, bytearray, type(None)))
    assert isinstance(data, (bytes, bytearray))
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if associated_data is not None:
            cipher.update(associated_data)
        # raises ValueError if not valid (e.g. incorrect MAC)
        return cipher.decrypt_and_verify(ciphertext=data[:-16], received_mac_tag=data[-16:])
    if HAS_CRYPTOGRAPHY:
        a = CG_aead.ChaCha20Poly1305(key)
        try:
            return a.decrypt(nonce, data, associated_data)
        except cryptography.exceptions.InvalidTag as e:
            raise ValueError("invalid tag") from e
    raise Exception("no chacha20 backend found")


def chacha20_encrypt(*, key: bytes, nonce: bytes, data: bytes) -> bytes:
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(data, (bytes, bytearray))
    assert len(nonce) == 8, f"unexpected nonce size: {len(nonce)} (expected: 8)"
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20.new(key=key, nonce=nonce)
        return cipher.encrypt(data)
    if HAS_CRYPTOGRAPHY:
        nonce = bytes(8) + nonce  # cryptography wants 16 byte nonces
        algo = CG_algorithms.ChaCha20(key=key, nonce=nonce)
        cipher = CG_Cipher(algo, mode=None, backend=CG_default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    raise Exception("no chacha20 backend found")
