#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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
"""
An encryption / decryption scheme

Format of encrypted blob:

    <33 byte ephemeral secp256k1 compressed point><16N byte ciphertext><16 byte HMAC>

key is sha256(diffie hellman secp256k1 compressed point)
ciphertext is AES256 in CBC mode (iv=0) from the following plaintext string:

    <32-bit length of message, big endian><message><arbitrary padding to any multiple of 16 bytes>

The reason for flexible padding is to allow a variety of messages to be
all padded to equivalent size.

Also a special facility is provided for decryption: you can get the symmetric
key, or provide the symmetric key (in which case you don't need to know the
private key).
"""

import pyaes
try:
    from Cryptodome.Cipher import AES
except ImportError:
    AES = None

import hashlib, hmac
import ecdsa
from electroncash.bitcoin import ser_to_point, point_to_ser

try:
    hmacdigest = hmac.digest # python 3.7+
except AttributeError:
    def hmacdigest(key, msg, digest):
        return hmac.new(key, msg, digest).digest()


G = ecdsa.SECP256k1.generator
order = ecdsa.SECP256k1.generator.order()

class EncryptionFailed(Exception):
    pass
class DecryptionFailed(Exception):
    pass

def encrypt(message, pubkey, pad_to_length = None):
    """
    pad_to_length must be a multiple of 16, and equal to or larger than
    len(message)+4. Default is to choose the smallest possible value.

    If the `pubkey` is not a valid point, raises EncryptionFailed.
    """
    try:
        pubpoint = ser_to_point(pubkey)
    except:
        raise EncryptionFailed
    nonce_sec = ecdsa.util.randrange(order)
    nonce_pub = point_to_ser(nonce_sec*G, comp=True)
    key = hashlib.sha256(point_to_ser(nonce_sec*pubpoint, comp=True)).digest()

    plaintext = len(message).to_bytes(4,'big') + message
    if pad_to_length is None:
        plaintext += b'\0' * ( -len(plaintext) % 16 )
    else:
        if pad_to_length % 16 != 0:
            raise ValueError(f'{pad_to_length} not multiple of 16')
        need = pad_to_length - len(plaintext)
        if need < 0:
            raise ValueError(f'{pad_to_length} < {len(plaintext)}')
        plaintext += b'\0' * need
    iv = b'\0'*16
    if AES:
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        ciphertext = aes.feed(plaintext) + aes.feed()  # empty aes.feed() flushes buffer
    mac = hmacdigest(key, ciphertext, 'sha256')[:16]
    return nonce_pub + ciphertext + mac

def decrypt_with_symmkey(data, key):
    """ Decrypt but using the symmetric key directly. The first 33 bytes are
    ignored entirely. """
    if len(data) < 33+16+16: # key, at least 1 block, and mac
        raise DecryptionFailed
    ciphertext = data[33:-16]
    if len(ciphertext) % 16 != 0:
        raise DecryptionFailed
    mac = hmacdigest(key, ciphertext, 'sha256')[:16]
    if not hmac.compare_digest(data[-16:], mac):
        raise DecryptionFailed

    iv = b'\0'*16
    if AES:
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(bytes(key), iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        plaintext = aes.feed(bytes(ciphertext)) + aes.feed()  # empty aes.feed() flushes buffer
    assert len(plaintext) > 4
    msglen = int.from_bytes(plaintext[:4], 'big')
    if 4 + msglen > len(plaintext):
        raise DecryptionFailed

    return plaintext[4:4+msglen]

def decrypt(data, privkey):
    """ Decrypt using the private key; returns (message, key) or raises
    DecryptionFailed on failure. """
    if len(data) < 33+16+16: # key, at least 1 block, and mac
        raise DecryptionFailed
    try:
        nonce_pub = ser_to_point(data[:33])
    except:
        raise DecryptionFailed
    sec = int.from_bytes(privkey, 'big')
    key = hashlib.sha256(point_to_ser(sec*nonce_pub, comp=True)).digest()
    return decrypt_with_symmkey(data, key), key
