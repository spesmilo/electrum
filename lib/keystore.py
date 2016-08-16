#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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


from unicodedata import normalize

from version import *
import bitcoin
from bitcoin import pw_encode, pw_decode, bip32_root, bip32_private_derivation, bip32_public_derivation, bip32_private_key, deserialize_xkey
from bitcoin import public_key_from_private_key, public_key_to_bc_address
from bitcoin import *

from bitcoin import is_old_seed, is_new_seed
from util import PrintError, InvalidPassword
from mnemonic import Mnemonic


class KeyStore(PrintError):

    def has_seed(self):
        return False

    def has_password(self):
        return False

    def is_watching_only(self):
        return False

    def can_import(self):
        return False


class Software_KeyStore(KeyStore):

    def __init__(self):
        KeyStore.__init__(self)
        self.use_encryption = False

    def has_password(self):
        return self.use_encryption

    def sign_message(self, sequence, message, password):
        sec = self.get_private_key(sequence, password)
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed)

    def decrypt_message(self, sequence, message, password):
        sec = self.get_private_key(sequence, password)
        ec = regenerate_key(sec)
        decrypted = ec.decrypt_message(message)
        return decrypted



class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys

    def __init__(self):
        Software_KeyStore.__init__(self)
        self.keypairs = {}

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def load(self, storage, name):
        self.keypairs = storage.get('keypairs', {})
        self.use_encryption = storage.get('use_encryption', False)
        self.receiving_pubkeys = self.keypairs.keys()
        self.change_pubkeys = []

    def save(self, storage, root_name):
        storage.put('key_type', 'imported')
        storage.put('keypairs', self.keypairs)
        storage.put('use_encryption', self.use_encryption)

    def can_import(self):
        return True

    def check_password(self, password):
        self.get_private_key((0,0), password)

    def import_key(self, sec, password):
        if not self.can_import():
            raise BaseException('This wallet cannot import private keys')
        try:
            pubkey = public_key_from_private_key(sec)
        except Exception:
            raise Exception('Invalid private key')
        self.keypairs[pubkey] = sec
        return pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def get_public_key(self, sequence):
        for_change, i = sequence
        pubkey = (self.change_pubkeys if for_change else self.receiving_pubkeys)[i]
        return pubkey

    def get_private_key(self, sequence, password):
        for_change, i = sequence
        assert for_change == 0
        pubkey = (self.change_pubkeys if for_change else self.receiving_pubkeys)[i]
        pk = pw_decode(self.keypairs[pubkey], password)
        # this checks the password
        if pubkey != public_key_from_private_key(pk):
            raise InvalidPassword()
        return pk

    def update_password(self, old_password, new_password):
        if old_password is not None:
            self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = b
        self.use_encryption = (new_password is not None)


class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self):
        Software_KeyStore.__init__(self)
        self.seed = ''

    def is_deterministic(self):
        return True

    def load(self, storage, name):
        self.seed = storage.get('seed', '')
        self.use_encryption = storage.get('use_encryption', False)

    def save(self, storage, name):
        storage.put('seed', self.seed)
        storage.put('use_encryption', self.use_encryption)

    def has_seed(self):
        return self.seed != ''

    def can_change_password(self):
        return not self.is_watching_only()

    def add_seed(self, seed, password):
        if self.seed:
            raise Exception("a seed exists")
        self.seed_version, self.seed = self.format_seed(seed)
        if password:
            self.seed = pw_encode(self.seed, password)
        self.use_encryption = (password is not None)

    def get_seed(self, password):
        return pw_decode(self.seed, password).encode('utf8')


class Xpub:

    def __init__(self):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

    def add_master_public_key(self, xpub):
        self.xpub = xpub

    def get_master_public_key(self):
        return self.xpub

    def derive_pubkey(self, for_change, n):
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_public_derivation(self.xpub, "", "/%d"%for_change)
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        _, _, _, c, cK = deserialize_xkey(xpub)
        cK, c = CKD_pub(cK, c, n)
        result = cK.encode('hex')
        return result

    def get_xpubkey(self, c, i):
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (c, i)))
        return 'ff' + bitcoin.DecodeBase58Check(self.xpub).encode('hex') + s


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    def __init__(self):
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self)
        self.xprv = None

    def format_seed(self, seed):
        return NEW_SEED_VERSION, ' '.join(seed.split())

    def load(self, storage, name):
        Deterministic_KeyStore.load(self, storage, name)
        self.xpub = storage.get('master_public_keys', {}).get(name)
        self.xprv = storage.get('master_private_keys', {}).get(name)

    def save(self, storage, name):
        Deterministic_KeyStore.save(self, storage, name)
        d = storage.get('master_public_keys', {})
        d[name] = self.xpub
        storage.put('master_public_keys', d)
        d = storage.get('master_private_keys', {})
        d[name] = self.xprv
        storage.put('master_private_keys', d)

    def add_master_private_key(self, xprv, password):
        self.xprv = pw_encode(xprv, password)

    def get_master_private_key(self, password):
        return pw_decode(self.xprv, password)

    def check_password(self, password):
        xprv = pw_decode(self.xprv, password)
        if deserialize_xkey(xprv)[3] != deserialize_xkey(self.xpub)[3]:
            raise InvalidPassword()

    def update_password(self, old_password, new_password):
        if old_password is not None:
            self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode( decoded, new_password)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password)
            self.xprv = pw_encode(b, new_password)
        self.use_encryption = (new_password is not None)

    def is_watching_only(self):
        return self.xprv is None

    def get_keypairs_for_sig(self, tx, password):
        keypairs = {}
        for txin in tx.inputs():
            num_sig = txin.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin['signatures']
            signatures = filter(None, x_signatures)
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                derivation = txin['derivation']
                sec = self.get_private_key(derivation, password)
                if sec:
                    keypairs[x_pubkey] = sec

        return keypairs

    def sign_transaction(self, tx, password):
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_keypairs_for_sig(tx, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)

    def get_mnemonic(self, password):
        return self.get_seed(password)

    def add_xprv(self, xprv, password):
        xpub = bitcoin.xpub_from_xprv(xprv)
        self.add_master_private_key(xprv, password)
        self.add_master_public_key(xpub)

    def add_xprv_from_seed(self, bip32_seed, derivation, password):
        xprv, xpub = bip32_root(bip32_seed)
        xprv, xpub = bip32_private_derivation(xprv, "m/", derivation)
        self.add_xprv(xprv, password)

    def can_sign(self, xpub):
        return xpub == self.xpub and self.xprv is not None

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        _, _, _, c, k = deserialize_xkey(xprv)
        pk = bip32_private_key(sequence, k, c)
        return pk


class Old_KeyStore(Deterministic_KeyStore):

    def __init__(self):
        Deterministic_KeyStore.__init__(self)
        self.mpk = None

    def load(self, storage, name):
        Deterministic_KeyStore.load(self, storage, name)
        self.mpk = storage.get('master_public_key').decode('hex')

    def save(self, storage, name):
        Deterministic_KeyStore.save(self, storage, name)
        storage.put('wallet_type', 'old')
        storage.put('master_public_key', self.mpk.encode('hex'))

    def add_seed(self, seed, password):
        Deterministic_KeyStore.add_seed(self, seed, password)
        self.mpk = self.mpk_from_seed(self.get_seed(password))

    def add_master_public_key(self, mpk):
        self.mpk = mpk.decode('hex')

    def format_seed(self, seed):
        import old_mnemonic
        # see if seed was entered as hex
        seed = seed.strip()
        if seed:
            try:
                seed.decode('hex')
                return OLD_SEED_VERSION, str(seed)
            except Exception:
                pass
        words = seed.split()
        seed = old_mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
        return OLD_SEED_VERSION, seed

    def get_mnemonic(self, password):
        import old_mnemonic
        s = self.get_seed(password)
        return ' '.join(old_mnemonic.mn_encode(s))

    @classmethod
    def mpk_from_seed(klass, seed):
        secexp = klass.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent(secexp, curve = SECP256k1)
        master_public_key = master_private_key.get_verifying_key().to_string()
        return master_public_key

    @classmethod
    def stretch_key(self, seed):
        x = seed
        for i in range(100000):
            x = hashlib.sha256(x + seed).digest()
        return string_to_number(x)

    @classmethod
    def get_sequence(self, mpk, for_change, n):
        return string_to_number(Hash("%d:%d:"%(n, for_change) + mpk))

    def get_address(self, for_change, n):
        pubkey = self.get_pubkey(for_change, n)
        address = public_key_to_bc_address(pubkey.decode('hex'))
        return address

    @classmethod
    def get_pubkey_from_mpk(self, mpk, for_change, n):
        z = self.get_sequence(mpk, for_change, n)
        master_public_key = ecdsa.VerifyingKey.from_string(mpk, curve = SECP256k1)
        pubkey_point = master_public_key.pubkey.point + z*SECP256k1.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point(pubkey_point, curve = SECP256k1)
        return '04' + public_key2.to_string().encode('hex')

    def derive_pubkey(self, for_change, n):
        return self.get_pubkey_from_mpk(self.mpk, for_change, n)

    def get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        order = generator_secp256k1.order()
        secexp = (secexp + self.get_sequence(self.mpk, for_change, n)) % order
        pk = number_to_string(secexp, generator_secp256k1.order())
        compressed = False
        return SecretToASecret(pk, compressed)

    def get_private_key(self, sequence, password):
        seed = self.get_seed(password)
        self.check_seed(seed)
        for_change, n = sequence
        secexp = self.stretch_key(seed)
        pk = self.get_private_key_from_stretched_exponent(for_change, n, secexp)
        return pk

    def check_seed(self, seed):
        secexp = self.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string()
        if master_public_key != self.mpk:
            print_error('invalid password (mpk)', self.mpk.encode('hex'), master_public_key.encode('hex'))
            raise InvalidPassword()

    def check_password(self, password):
        seed = self.get_seed(password)
        self.check_seed(seed)

    def get_master_public_key(self):
        return self.mpk.encode('hex')

    def get_xpubkeys(self, for_change, n):
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (for_change, n)))
        mpk = self.mpk.encode('hex')
        x_pubkey = 'fe' + mpk + s
        return [ x_pubkey ]

    @classmethod
    def parse_xpubkey(self, x_pubkey):
        assert is_extended_pubkey(x_pubkey)
        pk = x_pubkey[2:]
        mpk = pk[0:128]
        dd = pk[128:]
        s = []
        while dd:
            n = int(bitcoin.rev_hex(dd[0:4]), 16)
            dd = dd[4:]
            s.append(n)
        assert len(s) == 2
        return mpk, s

    def update_password(self, old_password, new_password):
        if old_password is not None:
            self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password)
        self.use_encryption = (new_password is not None)


class Hardware_KeyStore(KeyStore, Xpub):
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type

    #restore_wallet_class = BIP32_RD_Wallet
    max_change_outputs = 1

    def __init__(self):
        Xpub.__init__(self)
        KeyStore.__init__(self)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None

    def is_deterministic(self):
        return True

    def load(self, storage, name):
        self.xpub = storage.get('master_public_keys', {}).get(name)

    def save(self, storage, name):
        d = storage.get('master_public_keys', {})
        d[name] = self.xpub
        storage.put('master_public_keys', d)

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        self.print_error("unpaired")

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        self.print_error("paired")

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

    def can_change_password(self):
        return False



def bip39_normalize_passphrase(passphrase):
    return normalize('NFKD', unicode(passphrase or ''))

def bip39_to_seed(mnemonic, passphrase):
    import pbkdf2, hashlib, hmac
    PBKDF2_ROUNDS = 2048
    mnemonic = normalize('NFKD', ' '.join(mnemonic.split()))
    passphrase = bip39_normalize_passphrase(passphrase)
    return pbkdf2.PBKDF2(mnemonic, 'mnemonic' + passphrase,
                         iterations = PBKDF2_ROUNDS, macmodule = hmac,
                         digestmodule = hashlib.sha512).read(64)



keystores = []

def load_keystore(storage, name):
    w = storage.get('wallet_type')
    t = storage.get('key_type', 'seed')
    seed_version = storage.get_seed_version()
    if seed_version == OLD_SEED_VERSION or w == 'old':
        k = Old_KeyStore()
    elif t == 'imported':
        k = Imported_KeyStore()
    elif name and name not in [ 'x/', 'x1/' ]:
        k = BIP32_KeyStore()
    elif t in ['seed', 'hw_seed']:
        k = BIP32_KeyStore()
    elif t == 'hardware':
        hw_type = storage.get('hardware_type')
        for cat, _type, constructor in keystores:
            if cat == 'hardware' and _type == hw_type:
                k = constructor()
                break
        else:
            raise BaseException('unknown hardware type')
    else:
        raise BaseException('unknown wallet type', t)
    k.load(storage, name)
    return k


def register_keystore(category, type, constructor):
    keystores.append((category, type, constructor))


def is_old_mpk(mpk):
    try:
        int(mpk, 16)
    except:
        return False
    return len(mpk) == 128

def is_xpub(text):
    if text[0:4] not in ('xpub', 'Ltub'):
        return False
    try:
        deserialize_xkey(text)
        return True
    except:
        return False

def is_xprv(text):
    if text[0:4] not in ('xprv', 'Ltpv'):
        return False
    try:
        deserialize_xkey(text)
        return True
    except:
        return False

def is_address_list(text):
    parts = text.split()
    return bool(parts) and all(bitcoin.is_address(x) for x in parts)

def is_private_key_list(text):
    parts = text.split()
    return bool(parts) and all(bitcoin.is_private_key(x) for x in parts)

is_seed = lambda x: is_old_seed(x) or is_new_seed(x)
is_mpk = lambda x: is_old_mpk(x) or is_xpub(x)
is_private = lambda x: is_seed(x) or is_xprv(x) or is_private_key_list(x)
is_any_key = lambda x: is_old_mpk(x) or is_xprv(x) or is_xpub(x) or is_address_list(x) or is_private_key_list(x)
is_private_key = lambda x: is_xprv(x) or is_private_key_list(x)
is_bip32_key = lambda x: is_xprv(x) or is_xpub(x)


def from_seed(seed, password):
    if is_old_seed(seed):
        keystore = Old_KeyStore()
        keystore.add_seed(seed, password)
    elif is_new_seed(seed):
        keystore = BIP32_KeyStore()
        keystore.add_seed(seed, password)
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, '')
        keystore.add_xprv_from_seed(bip32_seed, "m/", password)
    return keystore

def from_private_key_list(text, password):
    keystore = Imported_KeyStore()
    for x in text.split():
        keystore.import_key(x, None)
    keystore.update_password(None, password)
    return keystore

def from_old_mpk(mpk):
    keystore = Old_KeyStore()
    keystore.add_master_public_key(mpk)
    return keystore

def from_xpub(xpub):
    keystore = BIP32_KeyStore()
    keystore.add_master_public_key(xpub)
    return keystore

def from_xprv(xprv, password):
    xpub = bitcoin.xpub_from_xprv(xprv)
    keystore = BIP32_KeyStore()
    keystore.add_master_private_key(xprv, password)
    keystore.add_master_public_key(xpub)
    return keystore

def xprv_from_seed(seed, password):
    # do not store the seed, only the master xprv
    xprv, xpub = bip32_root(Mnemonic.mnemonic_to_seed(seed, ''))
    return from_xprv(xprv, password)

def xpub_from_seed(seed):
    # store only master xpub
    xprv, xpub = bip32_root(Mnemonic.mnemonic_to_seed(seed,''))
    return from_xpub(xpub)

def from_text(text, password):
    if is_xprv(text):
        k = from_xprv(text, password)
    elif is_old_mpk(text):
        k = from_old_mpk(text)
    elif is_xpub(text):
        k = from_xpub(text)
    elif is_private_key_list(text):
        k = from_private_key_list(text, password)
    elif is_seed(text):
        k = from_seed(text, password)
    else:
        raise BaseException('Invalid seedphrase or key')
    return k
