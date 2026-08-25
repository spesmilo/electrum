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
import binascii
import os
import sys
import hashlib
import hmac
from typing import Union, Mapping, Optional

import electrum_ecc as ecc

from .util import assert_bytes, InvalidPassword, to_bytes, to_string, WalletFileException, versiontuple
from .i18n import _
from .logging import get_logger

_logger = get_logger(__name__)


HAS_PYAES = False
try:
    import pyaes
except Exception:
    pass
else:
    HAS_PYAES = True

HAS_CRYPTODOME = False
MIN_CRYPTODOME_VERSION = "3.7"
try:
    import Cryptodome
    if versiontuple(Cryptodome.__version__) < versiontuple(MIN_CRYPTODOME_VERSION):
        _logger.warning(f"found module 'Cryptodome' but it is too old: {Cryptodome.__version__}<{MIN_CRYPTODOME_VERSION}")
        raise Exception()
    from Cryptodome.Cipher import ChaCha20_Poly1305 as CD_ChaCha20_Poly1305
    from Cryptodome.Cipher import ChaCha20 as CD_ChaCha20
    from Cryptodome.Cipher import AES as CD_AES
except Exception:
    pass
else:
    HAS_CRYPTODOME = True

HAS_CRYPTOGRAPHY = False
MIN_CRYPTOGRAPHY_VERSION = "2.1"
try:
    import cryptography
    if versiontuple(cryptography.__version__) < versiontuple(MIN_CRYPTOGRAPHY_VERSION):
        _logger.warning(f"found module 'cryptography' but it is too old: {cryptography.__version__}<{MIN_CRYPTOGRAPHY_VERSION}")
        raise Exception()
    from cryptography import exceptions
    from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
    from cryptography.hazmat.primitives.ciphers import modes as CG_modes
    from cryptography.hazmat.backends import default_backend as CG_default_backend
    import cryptography.hazmat.primitives.ciphers.aead as CG_aead
except Exception:
    pass
else:
    HAS_CRYPTOGRAPHY = True


if not (HAS_CRYPTODOME or HAS_CRYPTOGRAPHY):
    raise ImportError(f"Error: at least one of ('pycryptodomex', 'cryptography') needs to be installed.")


def version_info() -> Mapping[str, Optional[str]]:
    ret = {}
    if HAS_PYAES:
        ret["pyaes.version"] = ".".join(map(str, pyaes.VERSION[:3]))
    else:
        ret["pyaes.version"] = None
    if HAS_CRYPTODOME:
        ret["cryptodome.version"] = Cryptodome.__version__
        if hasattr(Cryptodome, "__path__"):
            ret["cryptodome.path"] = ", ".join(Cryptodome.__path__ or [])
    else:
        ret["cryptodome.version"] = None
    if HAS_CRYPTOGRAPHY:
        ret["cryptography.version"] = cryptography.__version__
        if hasattr(cryptography, "__path__"):
            ret["cryptography.path"] = ", ".join(cryptography.__path__ or [])
    else:
        ret["cryptography.version"] = None
    return ret


class InvalidPadding(Exception):
    pass


class CiphertextFormatError(Exception):
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
    assert len(key) in (16, 32), f"unexpected key size: {len(key)} (expected: 16 or 32)"
    assert len(iv) == 16, f"unexpected iv size: {len(iv)} (expected: 16)"
    data = append_PKCS7_padding(data)
    if HAS_CRYPTODOME:
        e = CD_AES.new(key, CD_AES.MODE_CBC, iv).encrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        encryptor = cipher.encryptor()
        e = encryptor.update(data) + encryptor.finalize()
    elif HAS_PYAES:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    else:
        raise Exception("no AES backend found")
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    assert len(key) in (16, 32), f"unexpected key size: {len(key)} (expected: 16 or 32)"
    assert len(iv) == 16, f"unexpected iv size: {len(iv)} (expected: 16)"
    if HAS_CRYPTODOME:
        cipher = CD_AES.new(key, CD_AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
    elif HAS_PYAES:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    else:
        raise Exception("no AES backend found")
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise InvalidPassword()


def EncodeAES_bytes(secret: bytes, msg: bytes) -> bytes:
    assert_bytes(msg)
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, msg)
    return iv + ct


def DecodeAES_bytes(secret: bytes, ciphertext: bytes) -> bytes:
    assert_bytes(ciphertext)
    iv, e = ciphertext[:16], ciphertext[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s


PW_HASH_VERSION_LATEST = 1
KNOWN_PW_HASH_VERSIONS = (1, 2,)
SUPPORTED_PW_HASH_VERSIONS = (1,)
assert PW_HASH_VERSION_LATEST in KNOWN_PW_HASH_VERSIONS
assert PW_HASH_VERSION_LATEST in SUPPORTED_PW_HASH_VERSIONS


class UnexpectedPasswordHashVersion(InvalidPassword, WalletFileException):
    def __init__(self, version):
        InvalidPassword.__init__(self)
        WalletFileException.__init__(self)
        self.version = version

    def __str__(self):
        return "{unexpected}: {version}\n{instruction}".format(
            unexpected=_("Unexpected password hash version"),
            version=self.version,
            instruction=_('You are most likely using an outdated version of Electrum. Please update.'))


class UnsupportedPasswordHashVersion(InvalidPassword, WalletFileException):
    def __init__(self, version):
        InvalidPassword.__init__(self)
        WalletFileException.__init__(self)
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
    try:
        data_bytes = bytes(base64.b64decode(data, validate=True))
    except binascii.Error as e:
        raise CiphertextFormatError("ciphertext not valid base64") from e
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
    try:
        data_bytes = bytes(base64.b64decode(data, validate=True))
    except binascii.Error as e:
        raise CiphertextFormatError("ciphertext not valid base64") from e
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

def ripemd(x: bytes) -> bytes:
    try:
        md = hashlib.new('ripemd160')
        md.update(x)
        return md.digest()
    except BaseException:
        # ripemd160 is not guaranteed to be available in hashlib on all platforms.
        # Historically, our Android builds had hashlib/openssl which did not have it.
        # see https://github.com/spesmilo/electrum/issues/7093
        # We bundle a pure python implementation as fallback that gets used now:
        from . import ripemd
        md = ripemd.new(x)
        return md.digest()


def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    return hmac.digest(key, msg, digest)


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
    assert len(key) == 32, f"unexpected key size: {len(key)} (expected: 32)"
    assert len(nonce) == 12, f"unexpected nonce size: {len(nonce)} (expected: 12)"
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
    assert len(key) == 32, f"unexpected key size: {len(key)} (expected: 32)"
    assert len(nonce) == 12, f"unexpected nonce size: {len(nonce)} (expected: 12)"
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
    """note: for any new protocol you design, please consider using chacha20_poly1305_encrypt instead
             (for its Authenticated Encryption property).
    """
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(data, (bytes, bytearray))
    assert len(key) == 32, f"unexpected key size: {len(key)} (expected: 32)"
    assert len(nonce) in (8, 12), f"unexpected nonce size: {len(nonce)} (expected: 8 or 12)"
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20.new(key=key, nonce=nonce)
        return cipher.encrypt(data)
    if HAS_CRYPTOGRAPHY:
        nonce = bytes(16 - len(nonce)) + nonce  # cryptography wants 16 byte nonces
        algo = CG_algorithms.ChaCha20(key=key, nonce=nonce)
        cipher = CG_Cipher(algo, mode=None, backend=CG_default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    raise Exception("no chacha20 backend found")


def chacha20_decrypt(*, key: bytes, nonce: bytes, data: bytes) -> bytes:
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(data, (bytes, bytearray))
    assert len(key) == 32, f"unexpected key size: {len(key)} (expected: 32)"
    assert len(nonce) in (8, 12), f"unexpected nonce size: {len(nonce)} (expected: 8 or 12)"
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(data)
    if HAS_CRYPTOGRAPHY:
        nonce = bytes(16 - len(nonce)) + nonce  # cryptography wants 16 byte nonces
        algo = CG_algorithms.ChaCha20(key=key, nonce=nonce)
        cipher = CG_Cipher(algo, mode=None, backend=CG_default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data)
    raise Exception("no chacha20 backend found")


def ecies_encrypt_message(
    ec_pubkey: 'ecc.ECPubkey',
    message: bytes,
    *,
    magic: bytes = b'BIE1',
) -> bytes:
    """
        ECIES encryption/decryption methods; AES-128-CBC with PKCS7 is used as the cipher; hmac-sha256 is used as the mac
    """
    assert_bytes(message)
    ephemeral = ecc.ECPrivkey.generate_random_key()
    ecdh_key = (ec_pubkey * ephemeral.secret_scalar).get_public_key_bytes(compressed=True)
    key = hashlib.sha512(ecdh_key).digest()
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    ciphertext = aes_encrypt_with_iv(key_e, iv, message)
    ephemeral_pubkey = ephemeral.get_public_key_bytes(compressed=True)
    encrypted = magic + ephemeral_pubkey + ciphertext
    mac = hmac_oneshot(key_m, encrypted, hashlib.sha256)
    return base64.b64encode(encrypted + mac)


def ecies_decrypt_message(
    ec_privkey: 'ecc.ECPrivkey',
    encrypted: Union[str, bytes],
    *,
    magic: bytes = b'BIE1',
) -> bytes:
    encrypted = base64.b64decode(encrypted, validate=True)  # type: bytes
    if len(encrypted) < 85:
        raise Exception('invalid ciphertext: length')
    magic_found = encrypted[:4]
    ephemeral_pubkey_bytes = encrypted[4:37]
    ciphertext = encrypted[37:-32]
    mac = encrypted[-32:]
    if magic_found != magic:
        raise Exception('invalid ciphertext: invalid magic bytes')
    try:
        ephemeral_pubkey = ecc.ECPubkey(ephemeral_pubkey_bytes)
    except ecc.InvalidECPointException as e:
        raise Exception('invalid ciphertext: invalid ephemeral pubkey') from e
    ecdh_key = (ephemeral_pubkey * ec_privkey.secret_scalar).get_public_key_bytes(compressed=True)
    key = hashlib.sha512(ecdh_key).digest()
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    if mac != hmac_oneshot(key_m, encrypted[:-32], hashlib.sha256):
        raise InvalidPassword()
    return aes_decrypt_with_iv(key_e, iv, ciphertext)


def get_ecdh(priv: bytes, pub: bytes) -> bytes:
    pt = ecc.ECPubkey(pub) * ecc.string_to_number(priv)
    return sha256(pt.get_public_key_bytes())

def privkey_to_pubkey(priv: bytes) -> bytes:
    return ecc.ECPrivkey(priv[:32]).get_public_key_bytes()


########################################
# Run-time sanity checks.
# - If one of the important cryptographic primitives is broken, we better panic.
# - For several primitives we support multiple backends. By now at runtime,
#   we have already selected the backend: check if it really works and fail early if not.
# - This whole section takes 5-10 msec.
#
# Hash functions. SHA2. single backend: hashlib
assert sha256(b"satoshi_nakamoto").hex() == "5f94a8490efe9e06c590dd34e37b5ab8f482f1af7578c6a41542761938a42426"
assert hashlib.sha512(b"satoshi_nakamoto").digest().hex() \
        == "cae681a7f07bd26128f8536c59a38f10c9e648898426cd1dd94144c7d3ea0512186400edc5d38ac677d43e97ebb877bf76d69c44de1f6e074435adc79caf8f14"
# Hash functions. ripemd. two supported backends: hashlib, ripemd.py
assert ripemd(b"satoshi_nakamoto").hex() == "a9a1c16007c20fa031f97f712c5eabd6f2ec54c4"
# AES-128: three supported backends: pycryptodomex, cryptography, pyaes
assert aes_encrypt_with_iv(
    key=b"satoshi_nakamoto",
    iv=b"thetimes20090103",
    data=b"The quick brown fox jumps over the lazy dog").hex() \
       == "9128466a087892f5f945ca48fe8c4b1d34e126d19fb0c50ce7f127a19508146734152f38d65377cd0add2599042a55e2"
assert aes_decrypt_with_iv(
    key=b"satoshi_nakamoto",
    iv=b"thetimes20090103",
    data=bytes.fromhex("9128466a087892f5f945ca48fe8c4b1d34e126d19fb0c50ce7f127a19508146734152f38d65377cd0add2599042a55e2")) \
       == b"The quick brown fox jumps over the lazy dog"
# AES-256: three supported backends: pycryptodomex, cryptography, pyaes
assert aes_encrypt_with_iv(
    key=b"satoshi_nakamoto_wanted_32_bytes",
    iv=b"thetimes20090103",
    data=b"The quick brown fox jumps over the lazy dog").hex() \
       == "65e532e8fb643e192d66cfebd3328ea6d52c9d43b18c8c8c7754b6a7c5927b7395201ff221315b51bfb1ad1c6184afce"
assert aes_decrypt_with_iv(
    key=b"satoshi_nakamoto_wanted_32_bytes",
    iv=b"thetimes20090103",
    data=bytes.fromhex("65e532e8fb643e192d66cfebd3328ea6d52c9d43b18c8c8c7754b6a7c5927b7395201ff221315b51bfb1ad1c6184afce")) \
       == b"The quick brown fox jumps over the lazy dog"
# chacha20: two supported backends: pycryptodomex, cryptography
assert chacha20_encrypt(
    key=b"satoshi_nakamoto_wanted_32_bytes",
    nonce=b"thetimes2009",
    data=b"The quick brown fox jumps over the lazy dog").hex() \
       == "b34faa354952d09a5c052e490678866f0d1ad37e567b2ea9247438c0d91f5a00343dc8a681a60bb4b2973b"
assert chacha20_decrypt(
    key=b"satoshi_nakamoto_wanted_32_bytes",
    nonce=b"thetimes2009",
    data=bytes.fromhex("b34faa354952d09a5c052e490678866f0d1ad37e567b2ea9247438c0d91f5a00343dc8a681a60bb4b2973b")) \
       == b"The quick brown fox jumps over the lazy dog"
# chacha20-poly1305: two supported backends: pycryptodomex, cryptography
assert chacha20_poly1305_encrypt(
    key=b"satoshi_nakamoto_wanted_32_bytes",
    nonce=b"thetimes2009",
    associated_data=b"loremipsum",
    data=b"The quick brown fox jumps over the lazy dog").hex() \
       == "10861cab9d587356da776c6bca2320f39f6f0a5111a74929108ba27fda87e8777dcf6416a4ca9d443dba94b9891e48a1618a7347ac648970a38265"
assert chacha20_poly1305_decrypt(
    key=b"satoshi_nakamoto_wanted_32_bytes",
    nonce=b"thetimes2009",
    associated_data=b"loremipsum",
    data=bytes.fromhex("10861cab9d587356da776c6bca2320f39f6f0a5111a74929108ba27fda87e8777dcf6416a4ca9d443dba94b9891e48a1618a7347ac648970a38265")) \
       == b"The quick brown fox jumps over the lazy dog"
