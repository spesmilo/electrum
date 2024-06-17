# Copyright (c) 2017 Andrew Chow
# Copyright (c) 2023 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# forked from https://github.com/bitcoin-core/HWI/blob/5f300d3dee7b317a6194680ad293eaa0962a3cc7/hwilib/descriptor.py
#
# Output Script Descriptors
# See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
#
# TODO allow xprv
# TODO hardened derivation
# TODO allow WIF privkeys
# TODO impl ADDR descriptors
# TODO impl RAW descriptors

from binascii import unhexlify
import enum
from enum import Enum
from typing import (
    List,
    NamedTuple,
    Optional,
    Tuple,
    Sequence,
    Mapping,
    Set,
    Union,
)

from .bip32 import convert_bip32_strpath_to_intpath, BIP32Node, KeyOriginInfo, BIP32_PRIME
from . import bitcoin
from .bitcoin import construct_script, opcodes, construct_witness, taproot_output_script
from . import constants
from .crypto import hash_160, sha256
from . import ecc
from . import segwit_addr


MAX_TAPROOT_DEPTH = 128

# we guess that signatures will be 72 bytes long
# note: DER-encoded ECDSA signatures are 71 or 72 bytes in practice
#       See https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature
#       We assume low S (as that is a bitcoin standardness rule).
#       We do not assume low R (even though the sigs we create conform), as external sigs,
#       e.g. from a hw signer cannot be expected to have a low R.
DUMMY_DER_SIG = 72 * b"\x00"


class ExpandedScripts:

    def __init__(
        self,
        *,
        output_script: bytes,  # "scriptPubKey"
        redeem_script: Optional[bytes] = None,
        witness_script: Optional[bytes] = None,
        scriptcode_for_sighash: Optional[bytes] = None
    ):
        self.output_script = output_script
        self.redeem_script = redeem_script
        self.witness_script = witness_script
        self.scriptcode_for_sighash = scriptcode_for_sighash

    @property
    def scriptcode_for_sighash(self) -> Optional[bytes]:
        if self._scriptcode_for_sighash:
            return self._scriptcode_for_sighash
        return self.witness_script or self.redeem_script or self.output_script

    @scriptcode_for_sighash.setter
    def scriptcode_for_sighash(self, value: Optional[bytes]):
        self._scriptcode_for_sighash = value

    def address(self, *, net=None) -> Optional[str]:
        return bitcoin.script_to_address(self.output_script, net=net)


class ScriptSolutionInner(NamedTuple):
    witness_items: Optional[Sequence] = None


class ScriptSolutionTop(NamedTuple):
    witness: Optional[bytes] = None
    script_sig: Optional[bytes] = None


class MissingSolutionPiece(Exception): pass


def PolyMod(c: int, val: int) -> int:
    """
    :meta private:
    Function to compute modulo over the polynomial used for descriptor checksums
    From: https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp
    """
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if (c0 & 1):
        c ^= 0xf5dee51989
    if (c0 & 2):
        c ^= 0xa9fdca3312
    if (c0 & 4):
        c ^= 0x1bab10e32d
    if (c0 & 8):
        c ^= 0x3706b1677a
    if (c0 & 16):
        c ^= 0x644d626ffd
    return c


_INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
_INPUT_CHARSET_INV = {c: i for (i, c) in enumerate(_INPUT_CHARSET)}
_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def DescriptorChecksum(desc: str) -> str:
    """
    Compute the checksum for a descriptor

    :param desc: The descriptor string to compute a checksum for
    :return: A checksum
    """
    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        try:
            pos = _INPUT_CHARSET_INV[ch]
        except KeyError:
            return ""
        c = PolyMod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = PolyMod(c, cls)
            cls = 0
            clscount = 0
    if clscount > 0:
        c = PolyMod(c, cls)
    for j in range(0, 8):
        c = PolyMod(c, 0)
    c ^= 1

    ret = [''] * 8
    for j in range(0, 8):
        ret[j] = _CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31]
    return ''.join(ret)

def AddChecksum(desc: str) -> str:
    """
    Compute and attach the checksum for a descriptor

    :param desc: The descriptor string to add a checksum to
    :return: Descriptor with checksum
    """
    return desc + "#" + DescriptorChecksum(desc)


class PubkeyProvider(object):
    """
    A public key expression in a descriptor.
    Can contain the key origin info, the pubkey itself, and subsequent derivation paths for derivation from the pubkey
    The pubkey can be a typical pubkey or an extended pubkey.
    """
    def __init__(
        self,
        origin: Optional['KeyOriginInfo'],
        pubkey: str,
        deriv_path: Optional[str]
    ) -> None:
        """
        :param origin: The key origin if one is available
        :param pubkey: The public key. Either a hex string or a serialized extended pubkey
        :param deriv_path: Additional derivation path (suffix) if the pubkey is an extended pubkey
        """
        self.origin = origin
        self.pubkey = pubkey
        self.deriv_path = deriv_path
        if deriv_path:
            wildcard_count = deriv_path.count("*")
            if wildcard_count > 1:
                raise ValueError("only one wildcard(*) is allowed in a descriptor")
            if wildcard_count == 1:
                if deriv_path[-1] != "*":
                    raise ValueError("wildcard in descriptor only allowed in last position")
            if deriv_path[0] != "/":
                raise ValueError(f"deriv_path suffix must start with a '/'. got {deriv_path!r}")
        # Make ExtendedKey from pubkey if it isn't hex
        self.extkey = None
        try:
            unhexlify(self.pubkey)
            # Is hex, normal pubkey
        except Exception:
            # Not hex, maybe xpub (but don't allow ypub/zpub)
            self.extkey = BIP32Node.from_xkey(pubkey, allow_custom_headers=False)
        if deriv_path and self.extkey is None:
            raise ValueError("deriv_path suffix present for simple pubkey")

    @classmethod
    def parse(cls, s: str) -> 'PubkeyProvider':
        """
        Deserialize a key expression from the string into a ``PubkeyProvider``.

        :param s: String containing the key expression
        :return: A new ``PubkeyProvider`` containing the details given by ``s``
        """
        origin = None
        deriv_path = None

        if s[0] == "[":
            end = s.index("]")
            origin = KeyOriginInfo.from_string(s[1:end])
            s = s[end + 1:]

        pubkey = s
        slash_idx = s.find("/")
        if slash_idx != -1:
            pubkey = s[:slash_idx]
            deriv_path = s[slash_idx:]

        return cls(origin, pubkey, deriv_path)

    def to_string(self) -> str:
        """
        Serialize the pubkey expression to a string to be used in a descriptor

        :return: The pubkey expression as a string
        """
        s = ""
        if self.origin:
            s += "[{}]".format(self.origin.to_string())
        s += self.pubkey
        if self.deriv_path:
            s += self.deriv_path
        return s

    def get_pubkey_bytes(self, *, pos: Optional[int] = None) -> bytes:
        if self.is_range() and pos is None:
            raise ValueError("pos must be set for ranged descriptor")
        # note: if not ranged, we ignore pos.
        if self.extkey is not None:
            compressed = True  # bip32 implies compressed pubkeys
            if self.deriv_path is None:
                assert not self.is_range()
                return self.extkey.eckey.get_public_key_bytes(compressed=compressed)
            else:
                path_str = self.deriv_path[1:]
                if self.is_range():
                    assert path_str[-1] == "*"
                    path_str = path_str[:-1] + str(pos)
                path = convert_bip32_strpath_to_intpath(path_str)
                child_key = self.extkey.subkey_at_public_derivation(path)
                return child_key.eckey.get_public_key_bytes(compressed=compressed)
        else:
            assert not self.is_range()
            return unhexlify(self.pubkey)

    def get_full_derivation_path(self, *, pos: Optional[int] = None) -> str:
        """
        Returns the full derivation path at the given position, including the origin
        """
        if self.is_range() and pos is None:
            raise ValueError("pos must be set for ranged descriptor")
        path = self.origin.get_derivation_path() if self.origin is not None else "m"
        path += self.deriv_path if self.deriv_path is not None else ""
        if path[-1] == "*":
            path = path[:-1] + str(pos)
        return path

    def get_full_derivation_int_list(self, *, pos: Optional[int] = None) -> List[int]:
        """
        Returns the full derivation path as an integer list at the given position.
        Includes the origin and master key fingerprint as an int
        """
        if self.is_range() and pos is None:
            raise ValueError("pos must be set for ranged descriptor")
        path: List[int] = self.origin.get_full_int_list() if self.origin is not None else []
        path.extend(self.get_der_suffix_int_list(pos=pos))
        return path

    def get_der_suffix_int_list(self, *, pos: Optional[int] = None) -> List[int]:
        if not self.deriv_path:
            return []
        der_suffix = self.deriv_path
        assert (wc_count := der_suffix.count("*")) <= 1, wc_count
        der_suffix = der_suffix.replace("*", str(pos))
        return convert_bip32_strpath_to_intpath(der_suffix)

    def __lt__(self, other: 'PubkeyProvider') -> bool:
        return self.pubkey < other.pubkey

    def is_range(self) -> bool:
        if not self.deriv_path:
            return False
        if self.deriv_path[-1] == "*":  # TODO hardened
            return True
        return False

    def has_uncompressed_pubkey(self) -> bool:
        if self.is_range():  # bip32 implies compressed
            return False
        return b"\x04" == self.get_pubkey_bytes()[:1]


class Descriptor(object):
    r"""
    An abstract class for Descriptors themselves.
    Descriptors can contain multiple :class:`PubkeyProvider`\ s and multiple ``Descriptor`` as subdescriptors.

    Note: a significant portion of input validation logic is in parse_descriptor(),
          maybe these checks should be moved to (or also done in) this class?
          For example, sh() must be top-level, or segwit mandates compressed pubkeys,
          or bare-multisig cannot have >3 pubkeys.
    """
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        subdescriptors: List['Descriptor'],
        name: str
    ) -> None:
        r"""
        :param pubkeys: The :class:`PubkeyProvider`\ s that are part of this descriptor
        :param subdescriptor: The ``Descriptor``\ s that are part of this descriptor
        :param name: The name of the function for this descriptor
        """
        self.pubkeys = pubkeys
        self.subdescriptors = subdescriptors
        self.name = name

    def to_string_no_checksum(self) -> str:
        """
        Serializes the descriptor as a string without the descriptor checksum

        :return: The descriptor string
        """
        return "{}({}{})".format(
            self.name,
            ",".join([p.to_string() for p in self.pubkeys]),
            self.subdescriptors[0].to_string_no_checksum() if len(self.subdescriptors) > 0 else ""
        )

    def to_string(self) -> str:
        """
        Serializes the descriptor as a string with the checksum

        :return: The descriptor with a checksum
        """
        return AddChecksum(self.to_string_no_checksum())

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        """
        Returns the scripts for a descriptor at the given `pos` for ranged descriptors.
        """
        raise NotImplementedError("The Descriptor base class does not implement this method")

    def _satisfy_inner(
        self,
        *,
        sigdata: Mapping[bytes, bytes] = None,  # pubkey -> sig
        allow_dummy: bool = False,
    ) -> ScriptSolutionInner:
        raise NotImplementedError("The Descriptor base class does not implement this method")

    def satisfy(
        self,
        *,
        sigdata: Mapping[bytes, bytes] = None,  # pubkey -> sig
        allow_dummy: bool = False,
    ) -> ScriptSolutionTop:
        """Construct a witness and/or scriptSig to be used in a txin, to satisfy the bitcoin SCRIPT.

        Raises MissingSolutionPiece if satisfaction is not yet possible due to e.g. missing a signature,
        unless `allow_dummy` is set to True, in which case dummy data is used where needed (e.g. for size estimation).
        """
        assert not self.is_range()
        sol = self._satisfy_inner(sigdata=sigdata, allow_dummy=allow_dummy)
        witness = None
        script_sig = None
        if self.is_segwit():
            witness = construct_witness(sol.witness_items)
        else:
            script_sig = construct_script(sol.witness_items)
        return ScriptSolutionTop(
            witness=witness,
            script_sig=script_sig,
        )

    def get_satisfaction_progress(
        self,
        *,
        sigdata: Mapping[bytes, bytes] = None,  # pubkey -> sig
    ) -> Tuple[int, int]:
        """Returns (num_sigs_we_have, num_sigs_required) towards satisfying this script.
        Besides signatures, later this can also consider hash-preimages.
        """
        assert not self.is_range()
        nhave, nreq = 0, 0
        for desc in self.subdescriptors:
            a, b = desc.get_satisfaction_progress(sigdata=sigdata)
            nhave += a
            nreq += b
        return nhave, nreq

    def is_range(self) -> bool:
        for pubkey in self.pubkeys:
            if pubkey.is_range():
                return True
        for desc in self.subdescriptors:
            if desc.is_range():
                return True
        return False

    def is_segwit(self) -> bool:
        return any([desc.is_segwit() for desc in self.subdescriptors])

    def is_taproot(self) -> bool:
        return False

    def get_all_pubkeys(self) -> Set[bytes]:
        """Returns set of pubkeys that appear at any level in this descriptor."""
        assert not self.is_range()
        all_pubkeys = set([p.get_pubkey_bytes() for p in self.pubkeys])
        for desc in self.subdescriptors:
            all_pubkeys |= desc.get_all_pubkeys()
        return all_pubkeys

    def get_simple_singlesig(self) -> Optional['Descriptor']:
        """Returns innermost pk/pkh/wpkh descriptor, or None if we are not a simple singlesig.

        note: besides pk,pkh,sh(wpkh),wpkh, overly complicated stuff such as sh(pk),wsh(sh(pkh),etc is also accepted
        """
        if len(self.subdescriptors) == 1:
            return self.subdescriptors[0].get_simple_singlesig()
        return None

    def get_simple_multisig(self) -> Optional['MultisigDescriptor']:
        """Returns innermost multi descriptor, or None if we are not a simple multisig."""
        if len(self.subdescriptors) == 1:
            return self.subdescriptors[0].get_simple_multisig()
        return None

    def to_legacy_electrum_script_type(self) -> str:
        if isinstance(self, PKDescriptor):
            return "p2pk"
        elif isinstance(self, PKHDescriptor):
            return "p2pkh"
        elif isinstance(self, WPKHDescriptor):
            return "p2wpkh"
        elif isinstance(self, SHDescriptor) and isinstance(self.subdescriptors[0], WPKHDescriptor):
            return "p2wpkh-p2sh"
        elif isinstance(self, SHDescriptor) and isinstance(self.subdescriptors[0], MultisigDescriptor):
            return "p2sh"
        elif isinstance(self, WSHDescriptor) and isinstance(self.subdescriptors[0], MultisigDescriptor):
            return "p2wsh"
        elif (isinstance(self, SHDescriptor) and isinstance(self.subdescriptors[0], WSHDescriptor)
              and isinstance(self.subdescriptors[0].subdescriptors[0], MultisigDescriptor)):
            return "p2wsh-p2sh"
        return "unknown"


class PKDescriptor(Descriptor):
    """
    A descriptor for ``pk()`` descriptors
    """
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        """
        :param pubkey: The :class:`PubkeyProvider` for this descriptor
        """
        super().__init__([pubkey], [], "pk")

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        pubkey = self.pubkeys[0].get_pubkey_bytes(pos=pos)
        script = construct_script([pubkey, opcodes.OP_CHECKSIG])
        return ExpandedScripts(output_script=script)

    def _satisfy_inner(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionInner:
        if sigdata is None: sigdata = {}
        assert not self.is_range()
        assert not self.subdescriptors
        pubkey = self.pubkeys[0].get_pubkey_bytes()
        sig = sigdata.get(pubkey)
        if sig is None and allow_dummy:
            sig = DUMMY_DER_SIG
        if sig is None:
            raise MissingSolutionPiece(f"no sig for {pubkey.hex()}")
        return ScriptSolutionInner(
            witness_items=(sig,),
        )

    def get_satisfaction_progress(self, *, sigdata=None) -> Tuple[int, int]:
        if sigdata is None: sigdata = {}
        signatures = list(sigdata.values())
        return len(signatures), 1

    def get_simple_singlesig(self) -> Optional['Descriptor']:
        return self


class PKHDescriptor(Descriptor):
    """
    A descriptor for ``pkh()`` descriptors
    """
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        """
        :param pubkey: The :class:`PubkeyProvider` for this descriptor
        """
        super().__init__([pubkey], [], "pkh")

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        pubkey = self.pubkeys[0].get_pubkey_bytes(pos=pos)
        pkh = hash_160(pubkey)
        script = bitcoin.pubkeyhash_to_p2pkh_script(pkh)
        return ExpandedScripts(output_script=script)

    def _satisfy_inner(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionInner:
        if sigdata is None: sigdata = {}
        assert not self.is_range()
        assert not self.subdescriptors
        pubkey = self.pubkeys[0].get_pubkey_bytes()
        sig = sigdata.get(pubkey)
        if sig is None and allow_dummy:
            sig = DUMMY_DER_SIG
        if sig is None:
            raise MissingSolutionPiece(f"no sig for {pubkey.hex()}")
        return ScriptSolutionInner(
            witness_items=(sig, pubkey),
        )

    def get_satisfaction_progress(self, *, sigdata=None) -> Tuple[int, int]:
        if sigdata is None: sigdata = {}
        signatures = list(sigdata.values())
        return len(signatures), 1

    def get_simple_singlesig(self) -> Optional['Descriptor']:
        return self


class WPKHDescriptor(Descriptor):
    """
    A descriptor for ``wpkh()`` descriptors
    """
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        """
        :param pubkey: The :class:`PubkeyProvider` for this descriptor
        """
        super().__init__([pubkey], [], "wpkh")

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        pkh = hash_160(self.pubkeys[0].get_pubkey_bytes(pos=pos))
        output_script = construct_script([0, pkh])
        scriptcode = bitcoin.pubkeyhash_to_p2pkh_script(pkh)
        return ExpandedScripts(
            output_script=output_script,
            scriptcode_for_sighash=scriptcode,
        )

    def _satisfy_inner(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionInner:
        if sigdata is None: sigdata = {}
        assert not self.is_range()
        assert not self.subdescriptors
        pubkey = self.pubkeys[0].get_pubkey_bytes()
        sig = sigdata.get(pubkey)
        if sig is None and allow_dummy:
            sig = DUMMY_DER_SIG
        if sig is None:
            raise MissingSolutionPiece(f"no sig for {pubkey.hex()}")
        return ScriptSolutionInner(
            witness_items=(sig, pubkey),
        )

    def get_satisfaction_progress(self, *, sigdata=None) -> Tuple[int, int]:
        if sigdata is None: sigdata = {}
        signatures = list(sigdata.values())
        return len(signatures), 1

    def is_segwit(self) -> bool:
        return True

    def get_simple_singlesig(self) -> Optional['Descriptor']:
        return self


class MultisigDescriptor(Descriptor):
    """
    A descriptor for ``multi()`` and ``sortedmulti()`` descriptors
    """
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        thresh: int,
        is_sorted: bool
    ) -> None:
        r"""
        :param pubkeys: The :class:`PubkeyProvider`\ s for this descriptor
        :param thresh: The number of keys required to sign this multisig
        :param is_sorted: Whether this is a ``sortedmulti()`` descriptor
        """
        super().__init__(pubkeys, [], "sortedmulti" if is_sorted else "multi")
        if not (1 <= thresh <= len(pubkeys) <= 15):
            raise ValueError(f'{thresh=}, {len(pubkeys)=}')
        self.thresh = thresh
        self.is_sorted = is_sorted
        if self.is_sorted:
            if not self.is_range():
                # sort xpubs using the order of pubkeys
                der_pks = [p.get_pubkey_bytes() for p in self.pubkeys]
                self.pubkeys = [x[1] for x in sorted(zip(der_pks, self.pubkeys))]
            else:
                # not possible to sort according to final order in expanded scripts,
                # but for easier visual comparison, we do a lexicographical sort
                self.pubkeys.sort()

    def to_string_no_checksum(self) -> str:
        return "{}({},{})".format(self.name, self.thresh, ",".join([p.to_string() for p in self.pubkeys]))

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        der_pks = [p.get_pubkey_bytes(pos=pos) for p in self.pubkeys]
        if self.is_sorted:
            der_pks.sort()
        script = construct_script([self.thresh, *der_pks, len(der_pks), opcodes.OP_CHECKMULTISIG])
        return ExpandedScripts(output_script=script)

    def _satisfy_inner(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionInner:
        if sigdata is None: sigdata = {}
        assert not self.is_range()
        assert not self.subdescriptors
        der_pks = [p.get_pubkey_bytes() for p in self.pubkeys]
        if self.is_sorted:
            der_pks.sort()
        signatures = []
        for pubkey in der_pks:
            if sig := sigdata.get(pubkey):
                signatures.append(sig)
                if len(signatures) >= self.thresh:
                    break
        if allow_dummy:
            dummy_sig = DUMMY_DER_SIG
            signatures += (self.thresh - len(signatures)) * [dummy_sig]
        if len(signatures) < self.thresh:
            raise MissingSolutionPiece(f"not enough sigs")
        assert len(signatures) == self.thresh, f"thresh={self.thresh}, but got {len(signatures)} sigs"
        return ScriptSolutionInner(
            witness_items=(0, *signatures),
        )

    def get_satisfaction_progress(self, *, sigdata=None) -> Tuple[int, int]:
        if sigdata is None: sigdata = {}
        signatures = list(sigdata.values())
        return len(signatures), self.thresh

    def get_simple_multisig(self) -> Optional['MultisigDescriptor']:
        return self


class SHDescriptor(Descriptor):
    """
    A descriptor for ``sh()`` descriptors
    """
    def __init__(
        self,
        subdescriptor: 'Descriptor'
    ) -> None:
        """
        :param subdescriptor: The :class:`Descriptor` that is a sub-descriptor for this descriptor
        """
        super().__init__([], [subdescriptor], "sh")

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        assert len(self.subdescriptors) == 1
        sub_scripts = self.subdescriptors[0].expand(pos=pos)
        redeem_script = sub_scripts.output_script
        witness_script = sub_scripts.witness_script
        script = construct_script([opcodes.OP_HASH160, hash_160(redeem_script), opcodes.OP_EQUAL])
        return ExpandedScripts(
            output_script=script,
            redeem_script=redeem_script,
            witness_script=witness_script,
            scriptcode_for_sighash=sub_scripts.scriptcode_for_sighash,
        )

    def _satisfy_inner(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionInner:
        raise Exception("does not make sense for sh()")

    def satisfy(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionTop:
        assert not self.is_range()
        assert len(self.subdescriptors) == 1
        subdesc = self.subdescriptors[0]
        redeem_script = self.expand().redeem_script
        witness = None
        if isinstance(subdesc, (WSHDescriptor, WPKHDescriptor)):  # witness_v0 nested in p2sh
            witness = subdesc.satisfy(sigdata=sigdata, allow_dummy=allow_dummy).witness
            script_sig = construct_script([redeem_script])
        else:  # legacy p2sh
            subsol = subdesc._satisfy_inner(sigdata=sigdata, allow_dummy=allow_dummy)
            script_sig = construct_script([*subsol.witness_items, redeem_script])
        return ScriptSolutionTop(
            witness=witness,
            script_sig=script_sig,
        )


class WSHDescriptor(Descriptor):
    """
    A descriptor for ``wsh()`` descriptors
    """
    def __init__(
        self,
        subdescriptor: 'Descriptor'
    ) -> None:
        """
        :param subdescriptor: The :class:`Descriptor` that is a sub-descriptor for this descriptor
        """
        super().__init__([], [subdescriptor], "wsh")

    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        assert len(self.subdescriptors) == 1
        sub_scripts = self.subdescriptors[0].expand(pos=pos)
        witness_script = sub_scripts.output_script
        output_script = construct_script([0, sha256(witness_script)])
        return ExpandedScripts(
            output_script=output_script,
            witness_script=witness_script,
        )

    def _satisfy_inner(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionInner:
        raise Exception("does not make sense for wsh()")

    def satisfy(self, *, sigdata=None, allow_dummy=False) -> ScriptSolutionTop:
        assert not self.is_range()
        assert len(self.subdescriptors) == 1
        subsol = self.subdescriptors[0]._satisfy_inner(sigdata=sigdata, allow_dummy=allow_dummy)
        witness_script = self.expand().witness_script
        witness = construct_witness([*subsol.witness_items, witness_script])
        return ScriptSolutionTop(
            witness=witness,
        )

    def is_segwit(self) -> bool:
        return True


class TRDescriptor(Descriptor):
    """
    A descriptor for ``tr()`` descriptors
    """
    def __init__(
        self,
        internal_key: 'PubkeyProvider',
        desc_tree: List[Union['Descriptor', List]] = None,
    ) -> None:
        r"""
        :param internal_key: The :class:`PubkeyProvider` that is the internal key for this descriptor
        :param desc_tree: Taproot script binary tree, as a nested list of Descriptors
        """
        if desc_tree is None:
            desc_tree = []
        self.desc_tree = desc_tree
        desc_list = []
        if desc_tree:
            if self.get_max_tree_depth() > MAX_TAPROOT_DEPTH:
                raise ValueError(f"tr() supports at most {MAX_TAPROOT_DEPTH} nesting levels")
            def flatten(tree_node):
                if isinstance(tree_node, Descriptor):
                    return [tree_node]
                assert len(tree_node) == 2, len(tree_node)
                return flatten(tree_node[0]) + flatten(tree_node[1])
            desc_list = flatten(desc_tree)
        super().__init__(
            pubkeys=[internal_key],
            subdescriptors=desc_list,  # FIXME we could do without the flattened list (dupl)
            name="tr",
        )

    def to_string_no_checksum(self) -> str:
        ret = f"{self.name}({self.pubkeys[0].to_string()}"
        if self.desc_tree:
            ret += ","
            def tree_to_str(tree_node):
                if isinstance(tree_node, Descriptor):
                    return tree_node.to_string_no_checksum()
                assert len(tree_node) == 2, len(tree_node)
                return "{" + tree_to_str(tree_node[0]) + "," + tree_to_str(tree_node[1]) + "}"
            ret += tree_to_str(self.desc_tree)
        ret += ")"
        return ret

    def is_segwit(self) -> bool:
        return True

    def is_taproot(self) -> bool:
        return True

    # TODO add more test vectors from BIP-0386
    def expand(self, *, pos: Optional[int] = None) -> "ExpandedScripts":
        internal_pubkey = self.pubkeys[0].get_pubkey_bytes(pos=pos)
        script_tree = None
        if self.desc_tree:
            def transform(tree_node):
                if isinstance(tree_node, Descriptor):
                    leaf_version = 0xc0
                    leaf_script = tree_node.expand(pos=pos).scriptcode_for_sighash  # FIXME maybe rename scriptcode_for_sighash
                    return (leaf_version, leaf_script)
                assert len(tree_node) == 2, len(tree_node)
                return [transform(tree_node[0]), transform(tree_node[1])]
            script_tree = transform(self.desc_tree)
        output_script = taproot_output_script(internal_pubkey, script_tree=script_tree)
        return ExpandedScripts(
            output_script=output_script,
        )

    def get_max_tree_depth(self) -> Optional[int]:
        if not self.desc_tree:
            return None
        def depth(tree_node) -> int:
            if isinstance(tree_node, Descriptor):
                return 0
            assert len(tree_node) == 2, len(tree_node)
            return 1 + max(depth(tree_node[0]), depth(tree_node[1]))
        return depth(self.desc_tree)


def _get_func_expr(s: str) -> Tuple[str, str]:
    """
    Get the function name and then the expression inside

    :param s: The string that begins with a function name
    :return: The function name as the first element of the tuple, and the expression contained within the function as the second element
    :raises: ValueError: if a matching pair of parentheses cannot be found
    """
    try:
        start = s.index("(")
        end = s.rindex(")")
        return s[0:start], s[start + 1:end]
    except ValueError:
        raise ValueError("A matching pair of parentheses cannot be found")


def _get_const(s: str, const: str) -> str:
    """
    Get the first character of the string, make sure it is the expected character,
    and return the rest of the string

    :param s: The string that begins with a constant character
    :param const: The constant character
    :return: The remainder of the string without the constant character
    :raises: ValueError: if the first character is not the constant character
    """
    if s[0] != const:
        raise ValueError(f"Expected '{const}' but got '{s[0]}'")
    return s[1:]


def _get_expr(s: str) -> Tuple[str, str]:
    """
    Extract the expression that ``s`` begins with.

    This will return the initial part of ``s``, up to the first comma or closing brace,
    skipping ones that are surrounded by braces.

    :param s: The string to extract the expression from
    :return: A pair with the first item being the extracted expression and the second the rest of the string
    """
    level: int = 0
    for i, c in enumerate(s):
        if c in ["(", "{"]:
            level += 1
        elif level > 0 and c in [")", "}"]:
            level -= 1
        elif level == 0 and c in [")", "}", ","]:
            break
    else:
        return s, ""
    return s[0:i], s[i:]

def parse_pubkey(expr: str, *, ctx: '_ParseDescriptorContext') -> Tuple['PubkeyProvider', str]:
    """
    Parses an individual pubkey expression from a string that may contain more than one pubkey expression.

    :param expr: The expression to parse a pubkey expression from
    :return: The :class:`PubkeyProvider` that is parsed as the first item of a tuple, and the remainder of the expression as the second item.
    """
    end = len(expr)
    comma_idx = expr.find(",")
    next_expr = ""
    if comma_idx != -1:
        end = comma_idx
        next_expr = expr[end + 1:]
    pubkey_provider = PubkeyProvider.parse(expr[:end])
    permit_uncompressed = ctx in (_ParseDescriptorContext.TOP, _ParseDescriptorContext.P2SH)
    if not permit_uncompressed and pubkey_provider.has_uncompressed_pubkey():
        raise ValueError("uncompressed pubkeys are not allowed")
    return pubkey_provider, next_expr


class _ParseDescriptorContext(Enum):
    """
    :meta private:

    Enum representing the level that we are in when parsing a descriptor.
    Some expressions aren't allowed at certain levels, this helps us track those.
    """

    TOP = enum.auto()     # The top level, not within any descriptor
    P2SH = enum.auto()    # Within an sh() descriptor
    P2WPKH = enum.auto()  # Within wpkh() descriptor
    P2WSH = enum.auto()   # Within a wsh() descriptor
    P2TR = enum.auto()    # Within a tr() descriptor


def _parse_descriptor(desc: str, *, ctx: '_ParseDescriptorContext') -> 'Descriptor':
    """
    :meta private:

    Parse a descriptor given the context level we are in.
    Used recursively to parse subdescriptors

    :param desc: The descriptor string to parse
    :param ctx: The :class:`_ParseDescriptorContext` indicating the level we are in
    :return: The parsed descriptor
    :raises: ValueError: if the descriptor is malformed
    """
    func, expr = _get_func_expr(desc)
    if func == "pk":
        pubkey, expr = parse_pubkey(expr, ctx=ctx)
        if expr:
            raise ValueError("more than one pubkey in pk descriptor")
        return PKDescriptor(pubkey)
    if func == "pkh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH or ctx == _ParseDescriptorContext.P2WSH):
            raise ValueError("Can only have pkh at top level, in sh(), or in wsh()")
        pubkey, expr = parse_pubkey(expr, ctx=ctx)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return PKHDescriptor(pubkey)
    if func == "sortedmulti" or func == "multi":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH or ctx == _ParseDescriptorContext.P2WSH):
            raise ValueError("Can only have multi/sortedmulti at top level, in sh(), or in wsh()")
        is_sorted = func == "sortedmulti"
        comma_idx = expr.index(",")
        thresh = int(expr[:comma_idx])
        expr = expr[comma_idx + 1:]
        pubkeys = []
        while expr:
            pubkey, expr = parse_pubkey(expr, ctx=ctx)
            pubkeys.append(pubkey)
        if len(pubkeys) == 0 or len(pubkeys) > 15:
            raise ValueError("Cannot have {} keys in a multisig; must have between 1 and 15 keys, inclusive".format(len(pubkeys)))
        elif thresh < 1:
            raise ValueError("Multisig threshold cannot be {}, must be at least 1".format(thresh))
        elif thresh > len(pubkeys):
            raise ValueError("Multisig threshold cannot be larger than the number of keys; threshold is {} but only {} keys specified".format(thresh, len(pubkeys)))
        if ctx == _ParseDescriptorContext.TOP and len(pubkeys) > 3:
            raise ValueError("Cannot have {} pubkeys in bare multisig: only at most 3 pubkeys")
        return MultisigDescriptor(pubkeys, thresh, is_sorted)
    if func == "wpkh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH):
            raise ValueError("Can only have wpkh() at top level or inside sh()")
        pubkey, expr = parse_pubkey(expr, ctx=_ParseDescriptorContext.P2WPKH)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return WPKHDescriptor(pubkey)
    if func == "sh":
        if ctx != _ParseDescriptorContext.TOP:
            raise ValueError("Can only have sh() at top level")
        subdesc = _parse_descriptor(expr, ctx=_ParseDescriptorContext.P2SH)
        return SHDescriptor(subdesc)
    if func == "wsh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH):
            raise ValueError("Can only have wsh() at top level or inside sh()")
        subdesc = _parse_descriptor(expr, ctx=_ParseDescriptorContext.P2WSH)
        return WSHDescriptor(subdesc)
    if func == "tr":
        if ctx != _ParseDescriptorContext.TOP:
            raise ValueError("Can only have tr at top level")
        internal_key, expr = parse_pubkey(expr, ctx=ctx)
        desc_tree = []
        if expr:
            def parse_tree(tree_str):
                if len(tree_str) == 0:
                    raise ValueError("Invalid Taproot tree expression")
                if tree_str[0] != "{":  # leaf
                    sarg, remaining = _get_expr(tree_str)
                    return _parse_descriptor(sarg, ctx=_ParseDescriptorContext.P2TR), remaining
                if len(tree_str) < len("{x,y}") or tree_str[-1] != "}":
                    raise ValueError("Invalid Taproot tree expression")
                left, remaining = parse_tree(tree_str[1:])
                if remaining[0] != ",": raise ValueError
                right, remaining = parse_tree(remaining[1:])
                if remaining[0] != "}": raise ValueError
                return [left, right], remaining[1:]
            desc_tree, _remaining = parse_tree(expr)
            if len(_remaining) != 0: raise ValueError
        return TRDescriptor(internal_key, desc_tree)
    if ctx == _ParseDescriptorContext.P2SH:
        raise ValueError("A function is needed within P2SH")
    elif ctx == _ParseDescriptorContext.P2WSH:
        raise ValueError("A function is needed within P2WSH")
    raise ValueError("{} is not a valid descriptor function".format(func))


def parse_descriptor(desc: str) -> 'Descriptor':
    """
    Parse a descriptor string into a :class:`Descriptor`.
    Validates the checksum if one is provided in the string

    :param desc: The descriptor string
    :return: The parsed :class:`Descriptor`
    :raises: ValueError: if the descriptor string is malformed
    """
    i = desc.find("#")
    if i != -1:
        checksum = desc[i + 1:]
        desc = desc[:i]
        computed = DescriptorChecksum(desc)
        if computed != checksum:
            raise ValueError("The checksum does not match; Got {}, expected {}".format(checksum, computed))
    return _parse_descriptor(desc, ctx=_ParseDescriptorContext.TOP)


#####


def get_singlesig_descriptor_from_legacy_leaf(*, pubkey: str, script_type: str) -> Optional[Descriptor]:
    pubkey = PubkeyProvider.parse(pubkey)
    if script_type == 'p2pk':
        return PKDescriptor(pubkey=pubkey)
    elif script_type == 'p2pkh':
        return PKHDescriptor(pubkey=pubkey)
    elif script_type == 'p2wpkh':
        return WPKHDescriptor(pubkey=pubkey)
    elif script_type == 'p2wpkh-p2sh':
        wpkh = WPKHDescriptor(pubkey=pubkey)
        return SHDescriptor(subdescriptor=wpkh)
    else:
        raise NotImplementedError(f"unexpected {script_type=}")


def create_dummy_descriptor_from_address(addr: Optional[str]) -> 'Descriptor':
    # It's not possible to tell the script type in general just from an address.
    # - "1" addresses are of course p2pkh
    # - "3" addresses are p2sh but we don't know the redeem script...
    # - "bc1" addresses (if they are 42-long) are p2wpkh
    # - "bc1" addresses that are 62-long are p2wsh but we don't know the script...
    # If we don't know the script, we _guess_ it is pubkeyhash.
    # As this method is used e.g. for tx size estimation,
    # the estimation will not be precise.
    def guess_script_type(addr: Optional[str]) -> str:
        if addr is None:
            return 'p2wpkh'  # the default guess
        witver, witprog = segwit_addr.decode_segwit_address(constants.net.SEGWIT_HRP, addr)
        if witprog is not None:
            return 'p2wpkh'
        addrtype, hash_160_ = bitcoin.b58_address_to_hash160(addr)
        if addrtype == constants.net.ADDRTYPE_P2PKH:
            return 'p2pkh'
        elif addrtype == constants.net.ADDRTYPE_P2SH:
            return 'p2wpkh-p2sh'
        raise Exception(f'unrecognized address: {repr(addr)}')

    script_type = guess_script_type(addr)
    # guess pubkey-len to be 33-bytes:
    pubkey = ecc.GENERATOR.get_public_key_bytes(compressed=True).hex()
    desc = get_singlesig_descriptor_from_legacy_leaf(pubkey=pubkey, script_type=script_type)
    return desc
