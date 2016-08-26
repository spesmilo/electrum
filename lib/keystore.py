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

    def is_watching_only(self):
        return False

    def can_import(self):
        return False


class Software_KeyStore(KeyStore):

    def __init__(self):
        KeyStore.__init__(self)

    def may_have_password(self):
        return not self.is_watching_only()

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

    def __init__(self, d):
        Software_KeyStore.__init__(self)
        self.keypairs = d.get('keypairs', {})
        self.receiving_pubkeys = self.keypairs.keys()
        self.change_pubkeys = []

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': 'imported',
            'keypairs': self.keypairs,
        }

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
            raise BaseException('Invalid private key')
        if pubkey in self.keypairs:
            raise BaseException('Private key already in keystore')
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
            self.keypairs[k] = c
        print self.keypairs


class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d):
        Software_KeyStore.__init__(self)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        return True

    def dump(self):
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        return self.seed != ''

    def can_change_password(self):
        return not self.is_watching_only()

    def add_seed(self, seed):
        if self.seed:
            raise Exception("a seed exists")
        self.seed_version, self.seed = self.format_seed(seed)

    def get_seed(self, password):
        return pw_decode(self.seed, password).encode('utf8')

    def get_passphrase(self, password):
        return pw_decode(self.passphrase, password).encode('utf8')



class Xpub:

    def __init__(self):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

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

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert pubkey[0:2] == 'ff'
        pk = pubkey.decode('hex')
        pk = pk[1:]
        xkey = bitcoin.EncodeBase58Check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = int(bitcoin.rev_hex(dd[0:2].encode('hex')), 16)
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s



class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    def __init__(self, d):
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, d)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')

    def format_seed(self, seed):
        return NEW_SEED_VERSION, ' '.join(seed.split())

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['type'] = 'bip32'
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        return d

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
            self.seed = pw_encode(decoded, new_password)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password)
            self.xprv = pw_encode(b, new_password)

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

    def add_xprv(self, xprv):
        self.xprv = xprv
        self.xpub = bitcoin.xpub_from_xprv(xprv)

    def add_xprv_from_seed(self, bip32_seed, derivation):
        xprv, xpub = bip32_root(bip32_seed)
        xprv, xpub = bip32_private_derivation(xprv, "m/", derivation)
        self.add_xprv(xprv)

    def can_sign(self, xpub):
        return xpub == self.xpub and self.xprv is not None

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        _, _, _, c, k = deserialize_xkey(xprv)
        pk = bip32_private_key(sequence, k, c)
        return pk


class Old_KeyStore(Deterministic_KeyStore):

    def __init__(self, d):
        Deterministic_KeyStore.__init__(self, d)
        self.mpk = d.get('mpk').decode('hex')

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['mpk'] = self.mpk.encode('hex')
        return d

    def add_seed(self, seed):
        Deterministic_KeyStore.add_seed(self, seed)
        self.mpk = self.mpk_from_seed(seed)

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

    def get_xpubkey(self, for_change, n):
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (for_change, n)))
        mpk = self.mpk.encode('hex')
        x_pubkey = 'fe' + mpk + s
        return x_pubkey

    @classmethod
    def parse_xpubkey(self, x_pubkey):
        assert x_pubkey[0:2] == 'fe'
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


class Hardware_KeyStore(KeyStore, Xpub):
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type

    #restore_wallet_class = BIP32_RD_Wallet
    max_change_outputs = 1

    def __init__(self, d):
        Xpub.__init__(self)
        KeyStore.__init__(self)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = d.get('xpub')
        self.label = d.get('label')
        self.derivation = d.get('derivation')
        self.handler = None

    def set_label(self, label):
        self.label = label

    def may_have_password(self):
        return False

    def is_deterministic(self):
        return True

    def dump(self):
        return {
            'type': 'hardware',
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation':self.derivation,
            'label':self.label,
        }

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



# extended pubkeys

def is_xpubkey(x_pubkey):
    return x_pubkey[0:2] == 'ff'

def parse_xpubkey(x_pubkey):
    assert x_pubkey[0:2] == 'ff'
    return BIP32_KeyStore.parse_xpubkey(x_pubkey)

def xpubkey_to_address(x_pubkey):
    if x_pubkey[0:2] in ['02','03','04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        xpub, s = BIP32_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = BIP32_KeyStore.derive_pubkey_from_xpub(xpub, s[0], s[1])
    elif x_pubkey[0:2] == 'fe':
        mpk, s = Old_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = Old_KeyStore.get_pubkey_from_mpk(mpk.decode('hex'), s[0], s[1])
    elif x_pubkey[0:2] == 'fd':
        addrtype = ord(x_pubkey[2:4].decode('hex'))
        hash160 = x_pubkey[4:].decode('hex')
        pubkey = None
        address = hash_160_to_bc_address(hash160, addrtype)
    else:
        raise BaseException("Cannnot parse pubkey")
    if pubkey:
        address = public_key_to_bc_address(pubkey.decode('hex'))
    return pubkey, address


hw_keystores = {}

def register_keystore(hw_type, constructor):
    hw_keystores[hw_type] = constructor

def hardware_keystore(d):
    hw_type = d['hw_type']
    if hw_type in hw_keystores:
        constructor = hw_keystores[hw_type]
        return constructor(d)
    raise BaseException('unknown hardware type', hw_type)

def load_keystore(storage, name):
    w = storage.get('wallet_type', 'standard')
    d = storage.get(name, {})
    t = d.get('type')
    if not t:
        raise BaseException('wallet format requires update')
    if t == 'old':
        k = Old_KeyStore(d)
    elif t == 'imported':
        k = Imported_KeyStore(d)
    elif t == 'bip32':
        k = BIP32_KeyStore(d)
    elif t == 'hardware':
        k = hardware_keystore(d)
    else:
        raise BaseException('unknown wallet type', t)
    return k



def is_old_mpk(mpk):
    try:
        int(mpk, 16)
    except:
        return False
    return len(mpk) == 128

def is_xpub(text):
    if text[0:4] != 'xpub':
        return False
    try:
        deserialize_xkey(text)
        return True
    except:
        return False

def is_xprv(text):
    if text[0:4] != 'xprv':
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

def bip44_derivation(account_id):
    return "m/44'/0'/%d'"% int(account_id)

def from_seed(seed, passphrase):
    if is_old_seed(seed):
        keystore = Old_KeyStore({})
        keystore.add_seed(seed)
    elif is_new_seed(seed):
        keystore = BIP32_KeyStore({})
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        keystore.add_xprv_from_seed(bip32_seed, "m/")
    return keystore

def from_private_key_list(text):
    keystore = Imported_KeyStore({})
    for x in text.split():
        keystore.import_key(x, None)
    return keystore

def from_old_mpk(mpk):
    keystore = Old_KeyStore({})
    keystore.add_master_public_key(mpk)
    return keystore

def from_xpub(xpub):
    k = BIP32_KeyStore({})
    k.xpub = xpub
    return k

def from_xprv(xprv):
    xpub = bitcoin.xpub_from_xprv(xprv)
    k = BIP32_KeyStore({})
    k.xprv = xprv
    k.xpub = xpub
    return k

def xprv_from_seed(seed):
    # do not store the seed, only the master xprv
    xprv, xpub = bip32_root(Mnemonic.mnemonic_to_seed(seed, ''))
    return from_xprv(xprv)

def xpub_from_seed(seed):
    # store only master xpub
    xprv, xpub = bip32_root(Mnemonic.mnemonic_to_seed(seed,''))
    return from_xpub(xpub)

def from_keys(text):
    if is_xprv(text):
        k = from_xprv(text)
    elif is_old_mpk(text):
        k = from_old_mpk(text)
    elif is_xpub(text):
        k = from_xpub(text)
    elif is_private_key_list(text):
        k = from_private_key_list(text)
    else:
        raise BaseException('Invalid key')
    return k
