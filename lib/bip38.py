# -*- coding: utf-8 -*-
#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import scrypt
import hashlib

from bitcoin import public_key_from_private_key, address_from_private_key, SecretToASecret, b58decode, aes_ecb_block_decrypt

def priv_decode(priv, derivedhalf1):
    priv_long = long(priv.encode('hex'),16)
    derivedhalf1_long = long(derivedhalf1.encode('hex'),16)
    priv_hex = '%064x' % (priv_long ^ derivedhalf1_long)
    return priv_hex.decode('hex')

def bip38_decrypt(encrypted_privkey,u_passphrase):
    '''BIP0038 non-ec-multiply decryption. Returns WIF privkey.'''
    try:
        passphrase = str(u_passphrase)
    except Exception:
        import unicodedata
        passphrase = unicodedata.normalize('NFC', u_passphrase).encode('utf8')
   
    d = b58decode(encrypted_privkey, None)
    ecflag = d[1:2]
    if ecflag == '\x42':
        ecmult = False
    elif ecflag == '\x43':
        ecmult = True
        raise Exception('Not currently supported')
    d = d[2:]
    flagbyte = d[0:1]
    d = d[1:]
    if flagbyte == '\xc0' or flagbyte == '\x00':
        compressed = False
    if flagbyte == '\xe0' or flagbyte == '\x20':
        compressed = True
    addresshash = d[0:4]
    d = d[4:-4]
    key = scrypt.hash(passphrase, addresshash, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    decryptedhalf1 = aes_ecb_block_decrypt(derivedhalf2, encryptedhalf1)
    decryptedhalf2 = aes_ecb_block_decrypt(derivedhalf2, encryptedhalf2)
    priv = decryptedhalf1 + decryptedhalf2
    priv = priv_decode(priv, derivedhalf1)
    wif_priv = SecretToASecret(priv, compressed=compressed)
    addr = address_from_private_key(wif_priv)
    if hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4] != addresshash:
        raise Exception('Addresshash verification failed! Password is likely incorrect.')
    return wif_priv

