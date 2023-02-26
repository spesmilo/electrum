# Copyright (c) 2017 Andrew Chow
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# forked from https://github.com/bitcoin-core/HWI/blob/5f300d3dee7b317a6194680ad293eaa0962a3cc7/hwilib/descriptor.py
#
# Output Script Descriptors
# See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
#

from .bip32 import convert_bip32_path_to_list_of_uint32, BIP32Node, KeyOriginInfo
from .crypto import hash_160, sha256

from binascii import unhexlify
from collections import namedtuple
from enum import Enum
from typing import (
    List,
    Optional,
    Tuple,
)


MAX_TAPROOT_NODES = 128


ExpandedScripts = namedtuple("ExpandedScripts", ["output_script", "redeem_script", "witness_script"])

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

        # Make ExtendedKey from pubkey if it isn't hex
        self.extkey = None
        try:
            unhexlify(self.pubkey)
            # Is hex, normal pubkey
        except Exception:
            # Not hex, maybe xpub
            self.extkey = BIP32Node.from_xkey(pubkey)

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

    def get_pubkey_bytes(self, pos: int) -> bytes:
        if self.extkey is not None:
            if self.deriv_path is not None:
                path_str = self.deriv_path[1:]
                if path_str[-1] == "*":
                    path_str = path_str[:-1] + str(pos)
                path = convert_bip32_path_to_list_of_uint32(path_str)
                child_key = self.extkey.subkey_at_public_derivation(path)
                return child_key.eckey.get_public_key_bytes()
            else:
                return self.extkey.eckey.get_public_key_bytes()
        return unhexlify(self.pubkey)

    def get_full_derivation_path(self, pos: int) -> str:
        """
        Returns the full derivation path at the given position, including the origin
        """
        path = self.origin.get_derivation_path() if self.origin is not None else "m/"
        path += self.deriv_path if self.deriv_path is not None else ""
        if path[-1] == "*":
            path = path[:-1] + str(pos)
        return path

    def get_full_derivation_int_list(self, pos: int) -> List[int]:
        """
        Returns the full derivation path as an integer list at the given position.
        Includes the origin and master key fingerprint as an int
        """
        path: List[int] = self.origin.get_full_int_list() if self.origin is not None else []
        if self.deriv_path is not None:
            der_split = self.deriv_path.split("/")
            for p in der_split:
                if not p:
                    continue
                if p == "*":
                    i = pos
                elif p[-1] in "'phHP":
                    assert len(p) >= 2
                    i = int(p[:-1]) | 0x80000000
                else:
                    i = int(p)
                path.append(i)
        return path

    def __lt__(self, other: 'PubkeyProvider') -> bool:
        return self.pubkey < other.pubkey


class Descriptor(object):
    r"""
    An abstract class for Descriptors themselves.
    Descriptors can contain multiple :class:`PubkeyProvider`\ s and multiple ``Descriptor`` as subdescriptors.
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

    def expand(self, pos: int) -> "ExpandedScripts":
        """
        Returns the scripts for a descriptor at the given `pos` for ranged descriptors.
        """
        raise NotImplementedError("The Descriptor base class does not implement this method")


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

    def expand(self, pos: int) -> "ExpandedScripts":
        script = b"\x76\xa9\x14" + hash_160(self.pubkeys[0].get_pubkey_bytes(pos)) + b"\x88\xac"
        return ExpandedScripts(script, None, None)


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

    def expand(self, pos: int) -> "ExpandedScripts":
        script = b"\x00\x14" + hash_160(self.pubkeys[0].get_pubkey_bytes(pos))
        return ExpandedScripts(script, None, None)


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
        self.thresh = thresh
        self.is_sorted = is_sorted
        if self.is_sorted:
            self.pubkeys.sort()

    def to_string_no_checksum(self) -> str:
        return "{}({},{})".format(self.name, self.thresh, ",".join([p.to_string() for p in self.pubkeys]))

    def expand(self, pos: int) -> "ExpandedScripts":
        if self.thresh > 16:
            m = b"\x01" + self.thresh.to_bytes(1, "big")
        else:
            m = (self.thresh + 0x50).to_bytes(1, "big") if self.thresh > 0 else b"\x00"
        n = (len(self.pubkeys) + 0x50).to_bytes(1, "big") if len(self.pubkeys) > 0 else b"\x00"
        script: bytes = m
        der_pks = [p.get_pubkey_bytes(pos) for p in self.pubkeys]
        if self.is_sorted:
            der_pks.sort()
        for pk in der_pks:
            script += len(pk).to_bytes(1, "big") + pk
        script += n + b"\xae"

        return ExpandedScripts(script, None, None)


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

    def expand(self, pos: int) -> "ExpandedScripts":
        assert len(self.subdescriptors) == 1
        redeem_script, _, witness_script = self.subdescriptors[0].expand(pos)
        script = b"\xa9\x14" + hash_160(redeem_script) + b"\x87"
        return ExpandedScripts(script, redeem_script, witness_script)


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

    def expand(self, pos: int) -> "ExpandedScripts":
        assert len(self.subdescriptors) == 1
        witness_script, _, _ = self.subdescriptors[0].expand(pos)
        script = b"\x00\x20" + sha256(witness_script)
        return ExpandedScripts(script, None, witness_script)


class TRDescriptor(Descriptor):
    """
    A descriptor for ``tr()`` descriptors
    """
    def __init__(
        self,
        internal_key: 'PubkeyProvider',
        subdescriptors: List['Descriptor'] = None,
        depths: List[int] = None,
    ) -> None:
        r"""
        :param internal_key: The :class:`PubkeyProvider` that is the internal key for this descriptor
        :param subdescriptors: The :class:`Descriptor`\ s that are the leaf scripts for this descriptor
        :param depths: The depths of the leaf scripts in the same order as `subdescriptors`
        """
        if subdescriptors is None:
            subdescriptors = []
        if depths is None:
            depths = []
        super().__init__([internal_key], subdescriptors, "tr")
        self.depths = depths

    def to_string_no_checksum(self) -> str:
        r = f"{self.name}({self.pubkeys[0].to_string()}"
        path: List[bool] = [] # Track left or right for each depth
        for p, depth in enumerate(self.depths):
            r += ","
            while len(path) <= depth:
                if len(path) > 0:
                    r += "{"
                path.append(False)
            r += self.subdescriptors[p].to_string_no_checksum()
            while len(path) > 0 and path[-1]:
                if len(path) > 0:
                    r += "}"
                path.pop()
            if len(path) > 0:
                path[-1] = True
        r += ")"
        return r

def _get_func_expr(s: str) -> Tuple[str, str]:
    """
    Get the function name and then the expression inside

    :param s: The string that begins with a function name
    :return: The function name as the first element of the tuple, and the expression contained within the function as the second element
    :raises: ValueError: if a matching pair of parentheses cannot be found
    """
    start = s.index("(")
    end = s.rindex(")")
    return s[0:start], s[start + 1:end]


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
    return s[0:i], s[i:]

def parse_pubkey(expr: str) -> Tuple['PubkeyProvider', str]:
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
    return PubkeyProvider.parse(expr[:end]), next_expr


class _ParseDescriptorContext(Enum):
    """
    :meta private:

    Enum representing the level that we are in when parsing a descriptor.
    Some expressions aren't allowed at certain levels, this helps us track those.
    """

    TOP = 1
    """The top level, not within any descriptor"""

    P2SH = 2
    """Within a ``sh()`` descriptor"""

    P2WSH = 3
    """Within a ``wsh()`` descriptor"""

    P2TR = 4
    """Within a ``tr()`` descriptor"""


def _parse_descriptor(desc: str, ctx: '_ParseDescriptorContext') -> 'Descriptor':
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
        pubkey, expr = parse_pubkey(expr)
        if expr:
            raise ValueError("more than one pubkey in pk descriptor")
        return PKDescriptor(pubkey)
    if func == "pkh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH or ctx == _ParseDescriptorContext.P2WSH):
            raise ValueError("Can only have pkh at top level, in sh(), or in wsh()")
        pubkey, expr = parse_pubkey(expr)
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
            pubkey, expr = parse_pubkey(expr)
            pubkeys.append(pubkey)
        if len(pubkeys) == 0 or len(pubkeys) > 16:
            raise ValueError("Cannot have {} keys in a multisig; must have between 1 and 16 keys, inclusive".format(len(pubkeys)))
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
        pubkey, expr = parse_pubkey(expr)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return WPKHDescriptor(pubkey)
    if func == "sh":
        if ctx != _ParseDescriptorContext.TOP:
            raise ValueError("Can only have sh() at top level")
        subdesc = _parse_descriptor(expr, _ParseDescriptorContext.P2SH)
        return SHDescriptor(subdesc)
    if func == "wsh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH):
            raise ValueError("Can only have wsh() at top level or inside sh()")
        subdesc = _parse_descriptor(expr, _ParseDescriptorContext.P2WSH)
        return WSHDescriptor(subdesc)
    if func == "tr":
        if ctx != _ParseDescriptorContext.TOP:
            raise ValueError("Can only have tr at top level")
        internal_key, expr = parse_pubkey(expr)
        subscripts = []
        depths = []
        if expr:
            # Path from top of the tree to what we're currently processing.
            # branches[i] == False: left branch in the i'th step from the top
            # branches[i] == true: right branch
            branches = []
            while True:
                # Process open braces
                while True:
                    try:
                        expr = _get_const(expr, "{")
                        branches.append(False)
                    except ValueError:
                        break
                    if len(branches) > MAX_TAPROOT_NODES:
                        raise ValueError(f"tr() supports at most {MAX_TAPROOT_NODES} nesting levels")  # TODO xxxx fixed upstream bug here
                # Process script expression
                sarg, expr = _get_expr(expr)
                subscripts.append(_parse_descriptor(sarg, _ParseDescriptorContext.P2TR))
                depths.append(len(branches))
                # Process closing braces
                while len(branches) > 0 and branches[-1]:
                    expr = _get_const(expr, "}")
                    branches.pop()
                # If we're at the end of a left branch, expect a comma
                if len(branches) > 0 and not branches[-1]:
                    expr = _get_const(expr, ",")
                    branches[-1] = True

                if len(branches) == 0:
                    break
        return TRDescriptor(internal_key, subscripts, depths)
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
    return _parse_descriptor(desc, _ParseDescriptorContext.TOP)

