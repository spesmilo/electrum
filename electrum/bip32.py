# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import binascii
import hashlib
import struct
from typing import List, Tuple, NamedTuple, Union, Iterable, Sequence, Optional

from .util import bfh, BitcoinException
from . import constants
from . import ecc
from .crypto import hash_160, hmac_oneshot
from .bitcoin import EncodeBase58Check, DecodeBase58Check
from .logging import get_logger


_logger = get_logger(__name__)
BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1

BIP32_HARDENED_CHAR = "h"  # default "hardened" char we put in str paths


def protect_against_invalid_ecpoint(func):
    def func_wrapper(*args):
        child_index = args[-1]
        while True:
            is_prime = child_index & BIP32_PRIME
            try:
                return func(*args[:-1], child_index=child_index)
            except ecc.InvalidECPointException:
                _logger.warning('bip32 protect_against_invalid_ecpoint: skipping index')
                child_index += 1
                is_prime2 = child_index & BIP32_PRIME
                if is_prime != is_prime2: raise OverflowError()
    return func_wrapper


@protect_against_invalid_ecpoint
def CKD_priv(parent_privkey: bytes, parent_chaincode: bytes, child_index: int) -> Tuple[bytes, bytes]:
    """Child private key derivation function (from master private key)
    If n is hardened (i.e. the 32nd bit is set), the resulting private key's
    corresponding public key can NOT be determined without the master private key.
    However, if n is not hardened, the resulting private key's corresponding
    public key can be determined without the master private key.
    """
    if child_index < 0: raise ValueError('the bip32 index needs to be non-negative')
    is_hardened_child = bool(child_index & BIP32_PRIME)
    return _CKD_priv(parent_privkey=parent_privkey,
                     parent_chaincode=parent_chaincode,
                     child_index=int.to_bytes(child_index, length=4, byteorder="big", signed=False),
                     is_hardened_child=is_hardened_child)


def _CKD_priv(parent_privkey: bytes, parent_chaincode: bytes,
              child_index: bytes, is_hardened_child: bool) -> Tuple[bytes, bytes]:
    try:
        keypair = ecc.ECPrivkey(parent_privkey)
    except ecc.InvalidECPointException as e:
        raise BitcoinException('Impossible xprv (not within curve order)') from e
    parent_pubkey = keypair.get_public_key_bytes(compressed=True)
    if is_hardened_child:
        data = bytes([0]) + parent_privkey + child_index
    else:
        data = parent_pubkey + child_index
    I = hmac_oneshot(parent_chaincode, data, hashlib.sha512)
    I_left = ecc.string_to_number(I[0:32])
    child_privkey = (I_left + ecc.string_to_number(parent_privkey)) % ecc.CURVE_ORDER
    if I_left >= ecc.CURVE_ORDER or child_privkey == 0:
        raise ecc.InvalidECPointException()
    child_privkey = int.to_bytes(child_privkey, length=32, byteorder='big', signed=False)
    child_chaincode = I[32:]
    return child_privkey, child_chaincode



@protect_against_invalid_ecpoint
def CKD_pub(parent_pubkey: bytes, parent_chaincode: bytes, child_index: int) -> Tuple[bytes, bytes]:
    """Child public key derivation function (from public key only)
    This function allows us to find the nth public key, as long as n is
    not hardened. If n is hardened, we need the master private key to find it.
    """
    if child_index < 0: raise ValueError('the bip32 index needs to be non-negative')
    if child_index & BIP32_PRIME: raise Exception('not possible to derive hardened child from parent pubkey')
    return _CKD_pub(parent_pubkey=parent_pubkey,
                    parent_chaincode=parent_chaincode,
                    child_index=int.to_bytes(child_index, length=4, byteorder="big", signed=False))


# helper function, callable with arbitrary 'child_index' byte-string.
# i.e.: 'child_index' does not need to fit into 32 bits here! (c.f. trustedcoin billing)
def _CKD_pub(parent_pubkey: bytes, parent_chaincode: bytes, child_index: bytes) -> Tuple[bytes, bytes]:
    I = hmac_oneshot(parent_chaincode, parent_pubkey + child_index, hashlib.sha512)
    pubkey = ecc.ECPrivkey(I[0:32]) + ecc.ECPubkey(parent_pubkey)
    if pubkey.is_at_infinity():
        raise ecc.InvalidECPointException()
    child_pubkey = pubkey.get_public_key_bytes(compressed=True)
    child_chaincode = I[32:]
    return child_pubkey, child_chaincode


def xprv_header(xtype: str, *, net=None) -> bytes:
    if net is None:
        net = constants.net
    return net.XPRV_HEADERS[xtype].to_bytes(length=4, byteorder="big")


def xpub_header(xtype: str, *, net=None) -> bytes:
    if net is None:
        net = constants.net
    return net.XPUB_HEADERS[xtype].to_bytes(length=4, byteorder="big")


class InvalidMasterKeyVersionBytes(BitcoinException): pass


class BIP32Node(NamedTuple):
    xtype: str
    eckey: Union[ecc.ECPubkey, ecc.ECPrivkey]
    chaincode: bytes
    depth: int = 0
    fingerprint: bytes = b'\x00'*4  # as in serialized format, this is the *parent's* fingerprint
    child_number: bytes = b'\x00'*4

    @classmethod
    def from_xkey(
        cls,
        xkey: str,
        *,
        net=None,
        allow_custom_headers: bool = True,  # to also accept ypub/zpub
    ) -> 'BIP32Node':
        if net is None:
            net = constants.net
        xkey = DecodeBase58Check(xkey)
        if len(xkey) != 78:
            raise BitcoinException('Invalid length for extended key: {}'
                                   .format(len(xkey)))
        depth = xkey[4]
        fingerprint = xkey[5:9]
        child_number = xkey[9:13]
        chaincode = xkey[13:13 + 32]
        header = int.from_bytes(xkey[0:4], byteorder='big')
        if header in net.XPRV_HEADERS_INV:
            headers_inv = net.XPRV_HEADERS_INV
            is_private = True
        elif header in net.XPUB_HEADERS_INV:
            headers_inv = net.XPUB_HEADERS_INV
            is_private = False
        else:
            raise InvalidMasterKeyVersionBytes(f'Invalid extended key format: {hex(header)}')
        xtype = headers_inv[header]
        if not allow_custom_headers and xtype != "standard":
            raise ValueError(f"only standard xpub/xprv allowed. found custom xtype={xtype}")
        if is_private:
            eckey = ecc.ECPrivkey(xkey[13 + 33:])
        else:
            eckey = ecc.ECPubkey(xkey[13 + 32:])
        return BIP32Node(xtype=xtype,
                         eckey=eckey,
                         chaincode=chaincode,
                         depth=depth,
                         fingerprint=fingerprint,
                         child_number=child_number)

    @classmethod
    def from_rootseed(cls, seed: bytes, *, xtype: str) -> 'BIP32Node':
        I = hmac_oneshot(b"Bitcoin seed", seed, hashlib.sha512)
        master_k = I[0:32]
        master_c = I[32:]
        return BIP32Node(xtype=xtype,
                         eckey=ecc.ECPrivkey(master_k),
                         chaincode=master_c)

    @classmethod
    def from_bytes(cls, b: bytes) -> 'BIP32Node':
        if len(b) != 78:
            raise Exception(f"unexpected xkey raw bytes len {len(b)} != 78")
        xkey = EncodeBase58Check(b)
        return cls.from_xkey(xkey)

    def to_xprv(self, *, net=None) -> str:
        payload = self.to_xprv_bytes(net=net)
        return EncodeBase58Check(payload)

    def to_xprv_bytes(self, *, net=None) -> bytes:
        if not self.is_private():
            raise Exception("cannot serialize as xprv; private key missing")
        payload = (xprv_header(self.xtype, net=net) +
                   bytes([self.depth]) +
                   self.fingerprint +
                   self.child_number +
                   self.chaincode +
                   bytes([0]) +
                   self.eckey.get_secret_bytes())
        assert len(payload) == 78, f"unexpected xprv payload len {len(payload)}"
        return payload

    def to_xpub(self, *, net=None) -> str:
        payload = self.to_xpub_bytes(net=net)
        return EncodeBase58Check(payload)

    def to_xpub_bytes(self, *, net=None) -> bytes:
        payload = (xpub_header(self.xtype, net=net) +
                   bytes([self.depth]) +
                   self.fingerprint +
                   self.child_number +
                   self.chaincode +
                   self.eckey.get_public_key_bytes(compressed=True))
        assert len(payload) == 78, f"unexpected xpub payload len {len(payload)}"
        return payload

    def to_xkey(self, *, net=None) -> str:
        if self.is_private():
            return self.to_xprv(net=net)
        else:
            return self.to_xpub(net=net)

    def to_bytes(self, *, net=None) -> bytes:
        if self.is_private():
            return self.to_xprv_bytes(net=net)
        else:
            return self.to_xpub_bytes(net=net)

    def convert_to_public(self) -> 'BIP32Node':
        if not self.is_private():
            return self
        pubkey = ecc.ECPubkey(self.eckey.get_public_key_bytes())
        return self._replace(eckey=pubkey)

    def is_private(self) -> bool:
        return isinstance(self.eckey, ecc.ECPrivkey)

    def subkey_at_private_derivation(self, path: Union[str, Iterable[int]]) -> 'BIP32Node':
        if path is None:
            raise Exception("derivation path must not be None")
        if isinstance(path, str):
            path = convert_bip32_strpath_to_intpath(path)
        if not self.is_private():
            raise Exception("cannot do bip32 private derivation; private key missing")
        if not path:
            return self
        depth = self.depth
        chaincode = self.chaincode
        privkey = self.eckey.get_secret_bytes()
        for child_index in path:
            parent_privkey = privkey
            privkey, chaincode = CKD_priv(privkey, chaincode, child_index)
            depth += 1
        parent_pubkey = ecc.ECPrivkey(parent_privkey).get_public_key_bytes(compressed=True)
        fingerprint = hash_160(parent_pubkey)[0:4]
        child_number = child_index.to_bytes(length=4, byteorder="big")
        return BIP32Node(xtype=self.xtype,
                         eckey=ecc.ECPrivkey(privkey),
                         chaincode=chaincode,
                         depth=depth,
                         fingerprint=fingerprint,
                         child_number=child_number)

    def subkey_at_public_derivation(self, path: Union[str, Iterable[int]]) -> 'BIP32Node':
        if path is None:
            raise Exception("derivation path must not be None")
        if isinstance(path, str):
            path = convert_bip32_strpath_to_intpath(path)
        if not path:
            return self.convert_to_public()
        depth = self.depth
        chaincode = self.chaincode
        pubkey = self.eckey.get_public_key_bytes(compressed=True)
        for child_index in path:
            parent_pubkey = pubkey
            pubkey, chaincode = CKD_pub(pubkey, chaincode, child_index)
            depth += 1
        fingerprint = hash_160(parent_pubkey)[0:4]
        child_number = child_index.to_bytes(length=4, byteorder="big")
        return BIP32Node(xtype=self.xtype,
                         eckey=ecc.ECPubkey(pubkey),
                         chaincode=chaincode,
                         depth=depth,
                         fingerprint=fingerprint,
                         child_number=child_number)

    def calc_fingerprint_of_this_node(self) -> bytes:
        """Returns the fingerprint of this node.
        Note that self.fingerprint is of the *parent*.
        """
        # TODO cache this
        return hash_160(self.eckey.get_public_key_bytes(compressed=True))[0:4]


def xpub_type(x: str):
    assert x is not None
    return BIP32Node.from_xkey(x).xtype


def is_xpub(text):
    try:
        node = BIP32Node.from_xkey(text)
        return not node.is_private()
    except Exception:
        return False


def is_xprv(text):
    try:
        node = BIP32Node.from_xkey(text)
        return node.is_private()
    except Exception:
        return False


def xpub_from_xprv(xprv):
    return BIP32Node.from_xkey(xprv).to_xpub()


def convert_bip32_strpath_to_intpath(n: str) -> List[int]:
    """Convert bip32 path str to list of uint32 integers with prime flags
    m/0/-1/1' -> [0, 0x80000001, 0x80000001]

    based on code in trezorlib
    """
    if not n:
        return []
    if n.endswith("/"):
        n = n[:-1]
    n = n.split('/')
    # cut leading "m" if present, but do not require it
    if n[0] == "m":
        n = n[1:]
    path = []
    for x in n:
        if x == '':
            # gracefully allow repeating "/" chars in path.
            # makes concatenating paths easier
            continue
        prime = 0
        if x.endswith("'") or x.endswith("h"):  # note: some implementations also accept "H", "p", "P"
            x = x[:-1]
            prime = BIP32_PRIME
        if x.startswith('-'):
            if prime:
                raise ValueError(f"bip32 path child index is signalling hardened level in multiple ways")
            prime = BIP32_PRIME
        try:
            x_int = int(x)
        except ValueError as e:
            raise ValueError(f"failed to parse bip32 path: {(str(e))}") from None
        child_index = abs(x_int) | prime
        if child_index > UINT32_MAX:
            raise ValueError(f"bip32 path child index too large: {child_index} > {UINT32_MAX}")
        path.append(child_index)
    return path


def convert_bip32_intpath_to_strpath(path: Sequence[int], *, hardened_char=BIP32_HARDENED_CHAR) -> str:
    assert isinstance(hardened_char, str), hardened_char
    assert len(hardened_char) == 1, hardened_char
    s = "m/"
    for child_index in path:
        if not isinstance(child_index, int):
            raise TypeError(f"bip32 path child index must be int: {child_index}")
        if not (0 <= child_index <= UINT32_MAX):
            raise ValueError(f"bip32 path child index out of range: {child_index}")
        prime = ""
        if child_index & BIP32_PRIME:
            prime = hardened_char
            child_index = child_index ^ BIP32_PRIME
        s += str(child_index) + prime + '/'
    # cut trailing "/"
    s = s[:-1]
    return s


def is_bip32_derivation(s: str) -> bool:
    try:
        if not (s == 'm' or s.startswith('m/')):
            return False
        convert_bip32_strpath_to_intpath(s)
    except Exception:
        return False
    else:
        return True


def normalize_bip32_derivation(s: Optional[str], *, hardened_char=BIP32_HARDENED_CHAR) -> Optional[str]:
    if s is None:
        return None
    if not is_bip32_derivation(s):
        raise ValueError(f"invalid bip32 derivation: {s}")
    ints = convert_bip32_strpath_to_intpath(s)
    return convert_bip32_intpath_to_strpath(ints, hardened_char=hardened_char)


def is_all_public_derivation(path: Union[str, Iterable[int]]) -> bool:
    """Returns whether all levels in path use non-hardened derivation."""
    if isinstance(path, str):
        path = convert_bip32_strpath_to_intpath(path)
    for child_index in path:
        if child_index < 0:
            raise ValueError('the bip32 index needs to be non-negative')
        if child_index & BIP32_PRIME:
            return False
    return True


def root_fp_and_der_prefix_from_xkey(xkey: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns the root bip32 fingerprint and the derivation path from the
    root to the given xkey, if they can be determined. Otherwise (None, None).
    """
    node = BIP32Node.from_xkey(xkey)
    derivation_prefix = None
    root_fingerprint = None
    assert node.depth >= 0, node.depth
    if node.depth == 0:
        derivation_prefix = 'm'
        root_fingerprint = node.calc_fingerprint_of_this_node().hex().lower()
    elif node.depth == 1:
        child_number_int = int.from_bytes(node.child_number, 'big')
        derivation_prefix = convert_bip32_intpath_to_strpath([child_number_int])
        root_fingerprint = node.fingerprint.hex()
    return root_fingerprint, derivation_prefix


def is_xkey_consistent_with_key_origin_info(xkey: str, *,
                                            derivation_prefix: str = None,
                                            root_fingerprint: str = None) -> bool:
    bip32node = BIP32Node.from_xkey(xkey)
    int_path = None
    if derivation_prefix is not None:
        int_path = convert_bip32_strpath_to_intpath(derivation_prefix)
    if int_path is not None and len(int_path) != bip32node.depth:
        return False
    if bip32node.depth == 0:
        if bfh(root_fingerprint) != bip32node.calc_fingerprint_of_this_node():
            return False
        if bip32node.child_number != bytes(4):
            return False
    if int_path is not None and bip32node.depth > 0:
        if int.from_bytes(bip32node.child_number, 'big') != int_path[-1]:
            return False
    if bip32node.depth == 1:
        if bfh(root_fingerprint) != bip32node.fingerprint:
            return False
    return True


class KeyOriginInfo:
    """
    Object representing the origin of a key.

    from https://github.com/bitcoin-core/HWI/blob/5f300d3dee7b317a6194680ad293eaa0962a3cc7/hwilib/key.py
    # Copyright (c) 2020 The HWI developers
    # Distributed under the MIT software license.
    """
    def __init__(self, fingerprint: bytes, path: Sequence[int]) -> None:
        """
        :param fingerprint: The 4 byte BIP 32 fingerprint of a parent key from which this key is derived from
        :param path: The derivation path to reach this key from the key at ``fingerprint``
        """
        self.fingerprint: bytes = fingerprint
        self.path: Sequence[int] = path

    @classmethod
    def deserialize(cls, s: bytes) -> 'KeyOriginInfo':
        """
        Deserialize a serialized KeyOriginInfo.
        They will be serialized in the same way that PSBTs serialize derivation paths
        """
        fingerprint = s[0:4]
        s = s[4:]
        path = list(struct.unpack("<" + "I" * (len(s) // 4), s))
        return cls(fingerprint, path)

    def serialize(self) -> bytes:
        """
        Serializes the KeyOriginInfo in the same way that derivation paths are stored in PSBTs
        """
        r = self.fingerprint
        r += struct.pack("<" + "I" * len(self.path), *self.path)
        return r

    def _path_string(self) -> str:
        strpath = self.get_derivation_path()
        if len(strpath) >= 2:
            assert strpath.startswith("m/")
        return strpath[1:]  # cut leading "m"

    def to_string(self) -> str:
        """
        Return the KeyOriginInfo as a string in the form <fingerprint>/<index>/<index>/...
        This is the same way that KeyOriginInfo is shown in descriptors
        """
        s = binascii.hexlify(self.fingerprint).decode()
        s += self._path_string()
        return s

    @classmethod
    def from_string(cls, s: str) -> 'KeyOriginInfo':
        """
        Create a KeyOriginInfo from the string
        :param s: The string to parse
        """
        s = s.lower()
        entries = s.split("/")
        fingerprint = binascii.unhexlify(s[0:8])
        path: Sequence[int] = []
        if len(entries) > 1:
            path = convert_bip32_strpath_to_intpath(s[9:])
        return cls(fingerprint, path)

    def get_derivation_path(self) -> str:
        """
        Return the string for just the path
        """
        return convert_bip32_intpath_to_strpath(self.path)

    def get_full_int_list(self) -> List[int]:
        """
        Return a list of ints representing this KeyOriginInfo.
        The first int is the fingerprint, followed by the path
        """
        xfp = [struct.unpack("<I", self.fingerprint)[0]]
        xfp.extend(self.path)
        return xfp

