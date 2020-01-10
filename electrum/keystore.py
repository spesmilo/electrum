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
import hashlib
import re
from typing import Tuple, TYPE_CHECKING, Union, Sequence, Optional, Dict, List, NamedTuple
from functools import lru_cache
from abc import ABC, abstractmethod

from . import bitcoin, ecc, constants, bip32
from .bitcoin import deserialize_privkey, serialize_privkey
from .bip32 import (convert_bip32_path_to_list_of_uint32, BIP32_PRIME,
                    is_xpub, is_xprv, BIP32Node, normalize_bip32_derivation,
                    convert_bip32_intpath_to_strpath)
from .ecc import string_to_number, number_to_string
from .crypto import (pw_decode, pw_encode, sha256, sha256d, PW_HASH_VERSION_LATEST,
                     SUPPORTED_PW_HASH_VERSIONS, UnsupportedPasswordHashVersion, hash_160)
from .util import (InvalidPassword, WalletFileException,
                   BitcoinException, bh2u, bfh, inv_dict)
from .mnemonic import Mnemonic, load_wordlist, seed_type, is_seed
from .plugin import run_hook
from .logging import Logger

if TYPE_CHECKING:
    from .gui.qt.util import TaskThread
    from .transaction import Transaction, PartialTransaction, PartialTxInput, PartialTxOutput
    from .plugins.hw_wallet import HW_PluginBase, HardwareClientBase


class KeyStore(Logger, ABC):
    type: str

    def __init__(self):
        Logger.__init__(self)
        self.is_requesting_to_be_rewritten_to_wallet_file = False  # type: bool

    def has_seed(self) -> bool:
        return False

    def is_watching_only(self) -> bool:
        return False

    def can_import(self) -> bool:
        return False

    def get_type_text(self) -> str:
        return f'{self.type}'

    @abstractmethod
    def may_have_password(self):
        """Returns whether the keystore can be encrypted with a password."""
        pass

    def get_tx_derivations(self, tx: 'PartialTransaction') -> Dict[str, Union[Sequence[int], str]]:
        keypairs = {}
        for txin in tx.inputs():
            if txin.is_complete():
                continue
            for pubkey in txin.pubkeys:
                if pubkey in txin.part_sigs:
                    # this pubkey already signed
                    continue
                derivation = self.get_pubkey_derivation(pubkey, txin)
                if not derivation:
                    continue
                keypairs[pubkey.hex()] = derivation
        return keypairs

    def can_sign(self, tx) -> bool:
        if self.is_watching_only():
            return False
        return bool(self.get_tx_derivations(tx))

    def ready_to_sign(self) -> bool:
        return not self.is_watching_only()

    @abstractmethod
    def dump(self) -> dict:
        pass

    @abstractmethod
    def is_deterministic(self) -> bool:
        pass

    @abstractmethod
    def sign_message(self, sequence: 'AddressIndexGeneric', message, password) -> bytes:
        pass

    @abstractmethod
    def decrypt_message(self, sequence: 'AddressIndexGeneric', message, password) -> bytes:
        pass

    @abstractmethod
    def sign_transaction(self, tx: 'PartialTransaction', password) -> None:
        pass

    @abstractmethod
    def get_pubkey_derivation(self, pubkey: bytes,
                              txinout: Union['PartialTxInput', 'PartialTxOutput'],
                              *, only_der_suffix=True) \
            -> Union[Sequence[int], str, None]:
        """Returns either a derivation int-list if the pubkey can be HD derived from this keystore,
        the pubkey itself (hex) if the pubkey belongs to the keystore but not HD derived,
        or None if the pubkey is unrelated.
        """
        pass

    def find_my_pubkey_in_txinout(
            self, txinout: Union['PartialTxInput', 'PartialTxOutput'],
            *, only_der_suffix: bool = False
    ) -> Tuple[Optional[bytes], Optional[List[int]]]:
        # note: we assume that this cosigner only has one pubkey in this txin/txout
        for pubkey in txinout.bip32_paths:
            path = self.get_pubkey_derivation(pubkey, txinout, only_der_suffix=only_der_suffix)
            if path and not isinstance(path, (str, bytes)):
                return pubkey, list(path)
        return None, None


class Software_KeyStore(KeyStore):

    def __init__(self, d):
        KeyStore.__init__(self)
        self.pw_hash_version = d.get('pw_hash_version', 1)
        if self.pw_hash_version not in SUPPORTED_PW_HASH_VERSIONS:
            raise UnsupportedPasswordHashVersion(self.pw_hash_version)

    def may_have_password(self):
        return not self.is_watching_only()

    def sign_message(self, sequence, message, password) -> bytes:
        privkey, compressed = self.get_private_key(sequence, password)
        key = ecc.ECPrivkey(privkey)
        return key.sign_message(message, compressed)

    def decrypt_message(self, sequence, message, password) -> bytes:
        privkey, compressed = self.get_private_key(sequence, password)
        ec = ecc.ECPrivkey(privkey)
        decrypted = ec.decrypt_message(message)
        return decrypted

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)

    @abstractmethod
    def update_password(self, old_password, new_password):
        pass

    @abstractmethod
    def check_password(self, password):
        pass

    @abstractmethod
    def get_private_key(self, sequence: 'AddressIndexGeneric', password) -> Tuple[bytes, bool]:
        """Returns (privkey, is_compressed)"""
        pass


class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys

    type = 'imported'

    def __init__(self, d):
        Software_KeyStore.__init__(self, d)
        self.keypairs = d.get('keypairs', {})  # type: Dict[str, str]

    def is_deterministic(self):
        return False

    def dump(self):
        return {
            'type': self.type,
            'keypairs': self.keypairs,
            'pw_hash_version': self.pw_hash_version,
        }

    def can_import(self):
        return True

    def check_password(self, password):
        pubkey = list(self.keypairs.keys())[0]
        self.get_private_key(pubkey, password)

    def import_privkey(self, sec, password):
        txin_type, privkey, compressed = deserialize_privkey(sec)
        pubkey = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
        # re-serialize the key so the internal storage format is consistent
        serialized_privkey = serialize_privkey(
            privkey, compressed, txin_type, internal_use=True)
        # NOTE: if the same pubkey is reused for multiple addresses (script types),
        # there will only be one pubkey-privkey pair for it in self.keypairs,
        # and the privkey will encode a txin_type but that txin_type cannot be trusted.
        # Removing keys complicates this further.
        self.keypairs[pubkey] = pw_encode(serialized_privkey, password, version=self.pw_hash_version)
        return txin_type, pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def get_private_key(self, pubkey: str, password):
        sec = pw_decode(self.keypairs[pubkey], password, version=self.pw_hash_version)
        txin_type, privkey, compressed = deserialize_privkey(sec)
        # this checks the password
        if pubkey != ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed):
            raise InvalidPassword()
        return privkey, compressed

    def get_pubkey_derivation(self, pubkey, txin, *, only_der_suffix=True):
        if pubkey.hex() in self.keypairs:
            return pubkey.hex()
        return None

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password, version=self.pw_hash_version)
            c = pw_encode(b, new_password, version=PW_HASH_VERSION_LATEST)
            self.keypairs[k] = c
        self.pw_hash_version = PW_HASH_VERSION_LATEST


class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d):
        Software_KeyStore.__init__(self, d)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        return True

    def dump(self):
        d = {
            'type': self.type,
            'pw_hash_version': self.pw_hash_version,
        }
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        return bool(self.seed)

    def is_watching_only(self):
        return not self.has_seed()

    @abstractmethod
    def format_seed(self, seed: str) -> str:
        pass

    def add_seed(self, seed):
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def get_seed(self, password):
        if not self.has_seed():
            raise Exception("This wallet has no seed words")
        return pw_decode(self.seed, password, version=self.pw_hash_version)

    def get_passphrase(self, password):
        if self.passphrase:
            return pw_decode(self.passphrase, password, version=self.pw_hash_version)
        else:
            return ''


class MasterPublicKeyMixin(ABC):

    @abstractmethod
    def get_master_public_key(self) -> str:
        pass

    @abstractmethod
    def get_derivation_prefix(self) -> Optional[str]:
        """Returns to bip32 path from some root node to self.xpub
        Note that the return value might be None; if it is unknown.
        """
        pass

    @abstractmethod
    def get_root_fingerprint(self) -> Optional[str]:
        """Returns the bip32 fingerprint of the top level node.
        This top level node is the node at the beginning of the derivation prefix,
        i.e. applying the derivation prefix to it will result self.xpub
        Note that the return value might be None; if it is unknown.
        """
        pass

    @abstractmethod
    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        """Returns fingerprint and derivation path corresponding to a derivation suffix.
        The fingerprint is either the root fp or the intermediate fp, depending on what is available
        and 'only_der_suffix', and the derivation path is adjusted accordingly.
        """
        pass

    @abstractmethod
    def derive_pubkey(self, for_change: int, n: int) -> bytes:
        pass

    def get_pubkey_derivation(self, pubkey: bytes,
                              txinout: Union['PartialTxInput', 'PartialTxOutput'],
                              *, only_der_suffix=True) \
            -> Union[Sequence[int], str, None]:
        def test_der_suffix_against_pubkey(der_suffix: Sequence[int], pubkey: bytes) -> bool:
            if len(der_suffix) != 2:
                return False
            if pubkey != self.derive_pubkey(*der_suffix):
                return False
            return True

        if pubkey not in txinout.bip32_paths:
            return None
        fp_found, path_found = txinout.bip32_paths[pubkey]
        der_suffix = None
        full_path = None
        # try fp against our root
        my_root_fingerprint_hex = self.get_root_fingerprint()
        my_der_prefix_str = self.get_derivation_prefix()
        ks_der_prefix = convert_bip32_path_to_list_of_uint32(my_der_prefix_str) if my_der_prefix_str else None
        if (my_root_fingerprint_hex is not None and ks_der_prefix is not None and
                fp_found.hex() == my_root_fingerprint_hex):
            if path_found[:len(ks_der_prefix)] == ks_der_prefix:
                der_suffix = path_found[len(ks_der_prefix):]
                if not test_der_suffix_against_pubkey(der_suffix, pubkey):
                    der_suffix = None
        # try fp against our intermediate fingerprint
        if (der_suffix is None and isinstance(self, Xpub) and
                fp_found == self.get_bip32_node_for_xpub().calc_fingerprint_of_this_node()):
            der_suffix = path_found
            if not test_der_suffix_against_pubkey(der_suffix, pubkey):
                der_suffix = None
        if der_suffix is None:
            return None
        if ks_der_prefix is not None:
            full_path = ks_der_prefix + list(der_suffix)
        return der_suffix if only_der_suffix else full_path


class Xpub(MasterPublicKeyMixin):

    def __init__(self, *, derivation_prefix: str = None, root_fingerprint: str = None):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None
        self._xpub_bip32_node = None  # type: Optional[BIP32Node]

        # "key origin" info (subclass should persist these):
        self._derivation_prefix = derivation_prefix  # type: Optional[str]
        self._root_fingerprint = root_fingerprint  # type: Optional[str]

    def get_master_public_key(self):
        return self.xpub

    def get_bip32_node_for_xpub(self) -> Optional[BIP32Node]:
        if self._xpub_bip32_node is None:
            if self.xpub is None:
                return None
            self._xpub_bip32_node = BIP32Node.from_xkey(self.xpub)
        return self._xpub_bip32_node

    def get_derivation_prefix(self) -> Optional[str]:
        return self._derivation_prefix

    def get_root_fingerprint(self) -> Optional[str]:
        return self._root_fingerprint

    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        fingerprint_hex = self.get_root_fingerprint()
        der_prefix_str = self.get_derivation_prefix()
        if not only_der_suffix and fingerprint_hex is not None and der_prefix_str is not None:
            # use root fp, and true full path
            fingerprint_bytes = bfh(fingerprint_hex)
            der_prefix_ints = convert_bip32_path_to_list_of_uint32(der_prefix_str)
        else:
            # use intermediate fp, and claim der suffix is the full path
            fingerprint_bytes = self.get_bip32_node_for_xpub().calc_fingerprint_of_this_node()
            der_prefix_ints = convert_bip32_path_to_list_of_uint32('m')
        der_full = der_prefix_ints + list(der_suffix)
        return fingerprint_bytes, der_full

    def get_xpub_to_be_used_in_partial_tx(self, *, only_der_suffix: bool) -> str:
        assert self.xpub
        fp_bytes, der_full = self.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix=[],
                                                                                 only_der_suffix=only_der_suffix)
        bip32node = self.get_bip32_node_for_xpub()
        depth = len(der_full)
        child_number_int = der_full[-1] if len(der_full) >= 1 else 0
        child_number_bytes = child_number_int.to_bytes(length=4, byteorder="big")
        fingerprint = bytes(4) if depth == 0 else bip32node.fingerprint
        bip32node = bip32node._replace(depth=depth,
                                       fingerprint=fingerprint,
                                       child_number=child_number_bytes)
        return bip32node.to_xpub()

    def add_key_origin_from_root_node(self, *, derivation_prefix: str, root_node: BIP32Node):
        assert self.xpub
        # try to derive ourselves from what we were given
        child_node1 = root_node.subkey_at_private_derivation(derivation_prefix)
        child_pubkey_bytes1 = child_node1.eckey.get_public_key_bytes(compressed=True)
        child_node2 = self.get_bip32_node_for_xpub()
        child_pubkey_bytes2 = child_node2.eckey.get_public_key_bytes(compressed=True)
        if child_pubkey_bytes1 != child_pubkey_bytes2:
            raise Exception("(xpub, derivation_prefix, root_node) inconsistency")
        self.add_key_origin(derivation_prefix=derivation_prefix,
                            root_fingerprint=root_node.calc_fingerprint_of_this_node().hex().lower())

    def add_key_origin(self, *, derivation_prefix: Optional[str], root_fingerprint: Optional[str]):
        assert self.xpub
        self._root_fingerprint = root_fingerprint
        self._derivation_prefix = normalize_bip32_derivation(derivation_prefix)

    @lru_cache(maxsize=None)
    def derive_pubkey(self, for_change: int, n: int) -> bytes:
        for_change = int(for_change)
        assert for_change in (0, 1)
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            rootnode = self.get_bip32_node_for_xpub()
            xpub = rootnode.subkey_at_public_derivation((for_change,)).to_xpub()
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        return self.get_pubkey_from_xpub(xpub, (n,))

    @classmethod
    def get_pubkey_from_xpub(self, xpub: str, sequence) -> bytes:
        node = BIP32Node.from_xkey(xpub).subkey_at_public_derivation(sequence)
        return node.eckey.get_public_key_bytes(compressed=True)


class BIP32_KeyStore(Xpub, Deterministic_KeyStore):

    type = 'bip32'

    def __init__(self, d):
        Xpub.__init__(self, derivation_prefix=d.get('derivation'), root_fingerprint=d.get('root_fingerprint'))
        Deterministic_KeyStore.__init__(self, d)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        d['derivation'] = self.get_derivation_prefix()
        d['root_fingerprint'] = self.get_root_fingerprint()
        return d

    def get_master_private_key(self, password):
        return pw_decode(self.xprv, password, version=self.pw_hash_version)

    def check_password(self, password):
        xprv = pw_decode(self.xprv, password, version=self.pw_hash_version)
        if BIP32Node.from_xkey(xprv).chaincode != self.get_bip32_node_for_xpub().chaincode:
            raise InvalidPassword()

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password, version=PW_HASH_VERSION_LATEST)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password, version=PW_HASH_VERSION_LATEST)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password, version=self.pw_hash_version)
            self.xprv = pw_encode(b, new_password, version=PW_HASH_VERSION_LATEST)
        self.pw_hash_version = PW_HASH_VERSION_LATEST

    def is_watching_only(self):
        return self.xprv is None

    def add_xpub(self, xpub):
        assert is_xpub(xpub)
        self.xpub = xpub
        root_fingerprint, derivation_prefix = bip32.root_fp_and_der_prefix_from_xkey(xpub)
        self.add_key_origin(derivation_prefix=derivation_prefix, root_fingerprint=root_fingerprint)

    def add_xprv(self, xprv):
        assert is_xprv(xprv)
        self.xprv = xprv
        self.add_xpub(bip32.xpub_from_xprv(xprv))

    def add_xprv_from_seed(self, bip32_seed, xtype, derivation):
        rootnode = BIP32Node.from_rootseed(bip32_seed, xtype=xtype)
        node = rootnode.subkey_at_private_derivation(derivation)
        self.add_xprv(node.to_xprv())
        self.add_key_origin_from_root_node(derivation_prefix=derivation, root_node=rootnode)

    def get_private_key(self, sequence: Sequence[int], password):
        xprv = self.get_master_private_key(password)
        node = BIP32Node.from_xkey(xprv).subkey_at_private_derivation(sequence)
        pk = node.eckey.get_secret_bytes()
        return pk, True

    def get_keypair(self, sequence, password):
        k, _ = self.get_private_key(sequence, password)
        cK = ecc.ECPrivkey(k).get_public_key_bytes()
        return cK, k


class Old_KeyStore(MasterPublicKeyMixin, Deterministic_KeyStore):

    type = 'old'

    def __init__(self, d):
        Deterministic_KeyStore.__init__(self, d)
        self.mpk = d.get('mpk')
        self._root_fingerprint = None

    def get_hex_seed(self, password):
        return pw_decode(self.seed, password, version=self.pw_hash_version).encode('utf8')

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['mpk'] = self.mpk
        return d

    def add_seed(self, seedphrase):
        Deterministic_KeyStore.add_seed(self, seedphrase)
        s = self.get_hex_seed(None)
        self.mpk = self.mpk_from_seed(s)

    def add_master_public_key(self, mpk):
        self.mpk = mpk

    def format_seed(self, seed):
        from . import old_mnemonic, mnemonic
        seed = mnemonic.normalize_text(seed)
        # see if seed was entered as hex
        if seed:
            try:
                bfh(seed)
                return str(seed)
            except Exception:
                pass
        words = seed.split()
        seed = old_mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
        return seed

    def get_seed(self, password):
        from . import old_mnemonic
        s = self.get_hex_seed(password)
        return ' '.join(old_mnemonic.mn_encode(s))

    @classmethod
    def mpk_from_seed(klass, seed):
        secexp = klass.stretch_key(seed)
        privkey = ecc.ECPrivkey.from_secret_scalar(secexp)
        return privkey.get_public_key_hex(compressed=False)[2:]

    @classmethod
    def stretch_key(self, seed):
        x = seed
        for i in range(100000):
            x = hashlib.sha256(x + seed).digest()
        return string_to_number(x)

    @classmethod
    def get_sequence(self, mpk, for_change, n):
        return string_to_number(sha256d(("%d:%d:"%(n, for_change)).encode('ascii') + bfh(mpk)))

    @classmethod
    def get_pubkey_from_mpk(cls, mpk, for_change, n) -> bytes:
        z = cls.get_sequence(mpk, for_change, n)
        master_public_key = ecc.ECPubkey(bfh('04'+mpk))
        public_key = master_public_key + z*ecc.generator()
        return public_key.get_public_key_bytes(compressed=False)

    @lru_cache(maxsize=None)
    def derive_pubkey(self, for_change, n) -> bytes:
        for_change = int(for_change)
        assert for_change in (0, 1)
        return self.get_pubkey_from_mpk(self.mpk, for_change, n)

    def _get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        secexp = (secexp + self.get_sequence(self.mpk, for_change, n)) % ecc.CURVE_ORDER
        pk = number_to_string(secexp, ecc.CURVE_ORDER)
        return pk

    def get_private_key(self, sequence: Sequence[int], password):
        seed = self.get_hex_seed(password)
        secexp = self.stretch_key(seed)
        self._check_seed(seed, secexp=secexp)
        for_change, n = sequence
        pk = self._get_private_key_from_stretched_exponent(for_change, n, secexp)
        return pk, False

    def _check_seed(self, seed, *, secexp=None):
        if secexp is None:
            secexp = self.stretch_key(seed)
        master_private_key = ecc.ECPrivkey.from_secret_scalar(secexp)
        master_public_key = master_private_key.get_public_key_bytes(compressed=False)[1:]
        if master_public_key != bfh(self.mpk):
            raise InvalidPassword()

    def check_password(self, password):
        seed = self.get_hex_seed(password)
        self._check_seed(seed)

    def get_master_public_key(self):
        return self.mpk

    def get_derivation_prefix(self) -> str:
        return 'm'

    def get_root_fingerprint(self) -> str:
        if self._root_fingerprint is None:
            master_public_key = ecc.ECPubkey(bfh('04'+self.mpk))
            xfp = hash_160(master_public_key.get_public_key_bytes(compressed=True))[0:4]
            self._root_fingerprint = xfp.hex().lower()
        return self._root_fingerprint

    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        fingerprint_hex = self.get_root_fingerprint()
        der_prefix_str = self.get_derivation_prefix()
        fingerprint_bytes = bfh(fingerprint_hex)
        der_prefix_ints = convert_bip32_path_to_list_of_uint32(der_prefix_str)
        der_full = der_prefix_ints + list(der_suffix)
        return fingerprint_bytes, der_full

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = pw_decode(self.seed, old_password, version=self.pw_hash_version)
            self.seed = pw_encode(decoded, new_password, version=PW_HASH_VERSION_LATEST)
        self.pw_hash_version = PW_HASH_VERSION_LATEST


class Hardware_KeyStore(Xpub, KeyStore):
    hw_type: str
    device: str
    plugin: 'HW_PluginBase'
    thread: Optional['TaskThread'] = None

    type = 'hardware'

    def __init__(self, d):
        Xpub.__init__(self, derivation_prefix=d.get('derivation'), root_fingerprint=d.get('root_fingerprint'))
        KeyStore.__init__(self)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = d.get('xpub')
        self.label = d.get('label')
        self.handler = None
        run_hook('init_keystore', self)

    def set_label(self, label):
        self.label = label

    def may_have_password(self):
        return False

    def is_deterministic(self):
        return True

    def get_type_text(self) -> str:
        return f'hw[{self.hw_type}]'

    def dump(self):
        return {
            'type': self.type,
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation': self.get_derivation_prefix(),
            'root_fingerprint': self.get_root_fingerprint(),
            'label':self.label,
        }

    def unpaired(self):
        '''A device paired with the wallet was disconnected.  This can be
        called in any thread context.'''
        self.logger.info("unpaired")

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        self.logger.info("paired")

    def is_watching_only(self):
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

    def get_password_for_storage_encryption(self) -> str:
        from .storage import get_derivation_used_for_hw_device_encryption
        client = self.plugin.get_client(self)
        derivation = get_derivation_used_for_hw_device_encryption()
        xpub = client.get_xpub(derivation, "standard")
        password = self.get_pubkey_from_xpub(xpub, ()).hex()
        return password

    def has_usable_connection_with_device(self) -> bool:
        if not hasattr(self, 'plugin'):
            return False
        client = self.plugin.get_client(self, force_pair=False)
        if client is None:
            return False
        return client.has_usable_connection_with_device()

    def ready_to_sign(self):
        return super().ready_to_sign() and self.has_usable_connection_with_device()

    def opportunistically_fill_in_missing_info_from_device(self, client: 'HardwareClientBase'):
        assert client is not None
        if self._root_fingerprint is None:
            self._root_fingerprint = client.request_root_fingerprint_from_device()
            self.is_requesting_to_be_rewritten_to_wallet_file = True
        if self.label != client.label():
            self.label = client.label()
            self.is_requesting_to_be_rewritten_to_wallet_file = True


KeyStoreWithMPK = Union[KeyStore, MasterPublicKeyMixin]  # intersection really...
AddressIndexGeneric = Union[Sequence[int], str]  # can be hex pubkey str


def bip39_normalize_passphrase(passphrase):
    return normalize('NFKD', passphrase or '')

def bip39_to_seed(mnemonic, passphrase):
    import hashlib, hmac
    PBKDF2_ROUNDS = 2048
    mnemonic = normalize('NFKD', ' '.join(mnemonic.split()))
    passphrase = bip39_normalize_passphrase(passphrase)
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'),
        b'mnemonic' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)


def bip39_is_checksum_valid(mnemonic: str) -> Tuple[bool, bool]:
    """Test checksum of bip39 mnemonic assuming English wordlist.
    Returns tuple (is_checksum_valid, is_wordlist_valid)
    """
    words = [ normalize('NFKD', word) for word in mnemonic.split() ]
    words_len = len(words)
    wordlist = load_wordlist("english.txt")
    n = len(wordlist)
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist.index(w)
        except ValueError:
            return False, False
        i = i*n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True
    checksum_length = 11 * words_len // 33  # num bits
    entropy_length = 32 * checksum_length  # num bits
    entropy = i >> checksum_length
    checksum = i % 2**checksum_length
    entropy_bytes = int.to_bytes(entropy, length=entropy_length//8, byteorder="big")
    hashed = int.from_bytes(sha256(entropy_bytes), byteorder="big")
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True


def from_bip39_seed(seed, passphrase, derivation, xtype=None):
    k = BIP32_KeyStore({})
    bip32_seed = bip39_to_seed(seed, passphrase)
    if xtype is None:
        xtype = xtype_from_derivation(derivation)
    k.add_xprv_from_seed(bip32_seed, xtype, derivation)
    return k


PURPOSE48_SCRIPT_TYPES = {
    'p2wsh-p2sh': 1,  # specifically multisig
    'p2wsh': 2,       # specifically multisig
}
PURPOSE48_SCRIPT_TYPES_INV = inv_dict(PURPOSE48_SCRIPT_TYPES)


def xtype_from_derivation(derivation: str) -> str:
    """Returns the script type to be used for this derivation."""
    bip32_indices = convert_bip32_path_to_list_of_uint32(derivation)
    if len(bip32_indices) >= 1:
        if bip32_indices[0] == 84 + BIP32_PRIME:
            return 'p2wpkh'
        elif bip32_indices[0] == 49 + BIP32_PRIME:
            return 'p2wpkh-p2sh'
        elif bip32_indices[0] == 44 + BIP32_PRIME:
            return 'standard'
        elif bip32_indices[0] == 45 + BIP32_PRIME:
            return 'standard'

    if len(bip32_indices) >= 4:
        if bip32_indices[0] == 48 + BIP32_PRIME:
            # m / purpose' / coin_type' / account' / script_type' / change / address_index
            script_type_int = bip32_indices[3] - BIP32_PRIME
            script_type = PURPOSE48_SCRIPT_TYPES_INV.get(script_type_int)
            if script_type is not None:
                return script_type
    return 'standard'


hw_keystores = {}

def register_keystore(hw_type, constructor):
    hw_keystores[hw_type] = constructor

def hardware_keystore(d) -> Hardware_KeyStore:
    hw_type = d['hw_type']
    if hw_type in hw_keystores:
        constructor = hw_keystores[hw_type]
        return constructor(d)
    raise WalletFileException(f'unknown hardware type: {hw_type}. '
                              f'hw_keystores: {list(hw_keystores)}')

def load_keystore(storage, name) -> KeyStore:
    d = storage.get(name, {})
    t = d.get('type')
    if not t:
        raise WalletFileException(
            'Wallet format requires update.\n'
            'Cannot find keystore for name {}'.format(name))
    keystore_constructors = {ks.type: ks for ks in [Old_KeyStore, Imported_KeyStore, BIP32_KeyStore]}
    keystore_constructors['hardware'] = hardware_keystore
    try:
        ks_constructor = keystore_constructors[t]
    except KeyError:
        raise WalletFileException(f'Unknown type {t} for keystore named {name}')
    k = ks_constructor(d)
    return k


def is_old_mpk(mpk: str) -> bool:
    try:
        int(mpk, 16)  # test if hex string
    except:
        return False
    if len(mpk) != 128:
        return False
    try:
        ecc.ECPubkey(bfh('04' + mpk))
    except:
        return False
    return True


def is_address_list(text):
    parts = text.split()
    return bool(parts) and all(bitcoin.is_address(x) for x in parts)


def get_private_keys(text, *, allow_spaces_inside_key=True, raise_on_error=False):
    if allow_spaces_inside_key:  # see #1612
        parts = text.split('\n')
        parts = map(lambda x: ''.join(x.split()), parts)
        parts = list(filter(bool, parts))
    else:
        parts = text.split()
    if bool(parts) and all(bitcoin.is_private_key(x, raise_on_error=raise_on_error) for x in parts):
        return parts


def is_private_key_list(text, *, allow_spaces_inside_key=True, raise_on_error=False):
    return bool(get_private_keys(text,
                                 allow_spaces_inside_key=allow_spaces_inside_key,
                                 raise_on_error=raise_on_error))


def is_master_key(x):
    return is_old_mpk(x) or is_bip32_key(x)


def is_bip32_key(x):
    return is_xprv(x) or is_xpub(x)


def bip44_derivation(account_id, bip43_purpose=44):
    coin = constants.net.BIP44_COIN_TYPE
    der = "m/%d'/%d'/%d'" % (bip43_purpose, coin, int(account_id))
    return normalize_bip32_derivation(der)


def purpose48_derivation(account_id: int, xtype: str) -> str:
    # m / purpose' / coin_type' / account' / script_type' / change / address_index
    bip43_purpose = 48
    coin = constants.net.BIP44_COIN_TYPE
    account_id = int(account_id)
    script_type_int = PURPOSE48_SCRIPT_TYPES.get(xtype)
    if script_type_int is None:
        raise Exception('unknown xtype: {}'.format(xtype))
    der = "m/%d'/%d'/%d'/%d'" % (bip43_purpose, coin, account_id, script_type_int)
    return normalize_bip32_derivation(der)


def from_seed(seed, passphrase, is_p2sh=False):
    t = seed_type(seed)
    if t == 'old':
        keystore = Old_KeyStore({})
        keystore.add_seed(seed)
    elif t in ['standard', 'segwit']:
        keystore = BIP32_KeyStore({})
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        if t == 'standard':
            der = "m/"
            xtype = 'standard'
        else:
            der = "m/1'/" if is_p2sh else "m/0'/"
            xtype = 'p2wsh' if is_p2sh else 'p2wpkh'
        keystore.add_xprv_from_seed(bip32_seed, xtype, der)
    else:
        raise BitcoinException('Unexpected seed type {}'.format(repr(t)))
    return keystore

def from_private_key_list(text):
    keystore = Imported_KeyStore({})
    for x in get_private_keys(text):
        keystore.import_privkey(x, None)
    return keystore

def from_old_mpk(mpk):
    keystore = Old_KeyStore({})
    keystore.add_master_public_key(mpk)
    return keystore

def from_xpub(xpub):
    k = BIP32_KeyStore({})
    k.add_xpub(xpub)
    return k

def from_xprv(xprv):
    k = BIP32_KeyStore({})
    k.add_xprv(xprv)
    return k

def from_master_key(text):
    if is_xprv(text):
        k = from_xprv(text)
    elif is_old_mpk(text):
        k = from_old_mpk(text)
    elif is_xpub(text):
        k = from_xpub(text)
    else:
        raise BitcoinException('Invalid master key')
    return k
