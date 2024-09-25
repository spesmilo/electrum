# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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

import hashlib
from typing import List, Tuple, TYPE_CHECKING, Optional, Union, Sequence, Any
import enum
from enum import IntEnum, Enum

from .util import bfh, BitcoinException, assert_bytes, to_bytes, inv_dict, is_hex_str, classproperty
from . import version
from . import segwit_addr
from . import constants
from . import ecc
from .crypto import sha256d, sha256, hash_160, hmac_oneshot

if TYPE_CHECKING:
    from .network import Network


################################## transactions

COINBASE_MATURITY = 100
COIN = 100000000
TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 21000000

NLOCKTIME_MIN = 0
NLOCKTIME_BLOCKHEIGHT_MAX = 500_000_000 - 1
NLOCKTIME_MAX = 2 ** 32 - 1

# supported types of transaction outputs
# TODO kill these with fire
TYPE_ADDRESS = 0
TYPE_PUBKEY  = 1
TYPE_SCRIPT  = 2


class opcodes(IntEnum):
    # push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99

    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4

    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    OP_INVALIDOPCODE = 0xff

    def hex(self) -> str:
        return bytes([self]).hex()


def script_num_to_bytes(i: int) -> bytes:
    """See CScriptNum in Bitcoin Core.
    Encodes an integer as bytes, to be used in script.

    ported from https://github.com/bitcoin/bitcoin/blob/8cbc5c4be4be22aca228074f087a374a7ec38be8/src/script/script.h#L326
    """
    if i == 0:
        return b""

    result = bytearray()
    neg = i < 0
    absvalue = abs(i)
    while absvalue > 0:
        result.append(absvalue & 0xff)
        absvalue >>= 8

    if result[-1] & 0x80:
        result.append(0x80 if neg else 0x00)
    elif neg:
        result[-1] |= 0x80

    return bytes(result)


def var_int(i: int) -> bytes:
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    # https://github.com/bitcoin/bitcoin/blob/efe1ee0d8d7f82150789f1f6840f139289628a2b/src/serialize.h#L247
    # "CompactSize"
    assert i >= 0, i
    if i < 0xfd:
        return int.to_bytes(i, length=1, byteorder="little", signed=False)
    elif i <= 0xffff:
        return b"\xfd" + int.to_bytes(i, length=2, byteorder="little", signed=False)
    elif i <= 0xffffffff:
        return b"\xfe" + int.to_bytes(i, length=4, byteorder="little", signed=False)
    else:
        return b"\xff" + int.to_bytes(i, length=8, byteorder="little", signed=False)


def witness_push(item: bytes) -> bytes:
    """Returns data in the form it should be present in the witness."""
    return var_int(len(item)) + item


def _op_push(i: int) -> bytes:
    if i < opcodes.OP_PUSHDATA1:
        return int.to_bytes(i, length=1, byteorder="little", signed=False)
    elif i <= 0xff:
        return bytes([opcodes.OP_PUSHDATA1]) + int.to_bytes(i, length=1, byteorder="little", signed=False)
    elif i <= 0xffff:
        return bytes([opcodes.OP_PUSHDATA2]) + int.to_bytes(i, length=2, byteorder="little", signed=False)
    else:
        return bytes([opcodes.OP_PUSHDATA4]) + int.to_bytes(i, length=4, byteorder="little", signed=False)


def push_script(data: bytes) -> bytes:
    """Returns pushed data to the script, automatically
    choosing canonical opcodes depending on the length of the data.

    ported from https://github.com/btcsuite/btcd/blob/fdc2bc867bda6b351191b5872d2da8270df00d13/txscript/scriptbuilder.go#L128
    """
    data_len = len(data)

    # "small integer" opcodes
    if data_len == 0 or data_len == 1 and data[0] == 0:
        return bytes([opcodes.OP_0])
    elif data_len == 1 and data[0] <= 16:
        return bytes([opcodes.OP_1 - 1 + data[0]])
    elif data_len == 1 and data[0] == 0x81:
        return bytes([opcodes.OP_1NEGATE])

    return _op_push(data_len) + data


def make_op_return(x: bytes) -> bytes:
    return bytes([opcodes.OP_RETURN]) + push_script(x)


def add_number_to_script(i: int) -> bytes:
    return push_script(script_num_to_bytes(i))


def construct_witness(items: Sequence[Union[str, int, bytes]]) -> bytes:
    """Constructs a witness from the given stack items."""
    witness = bytearray()
    witness += var_int(len(items))
    for item in items:
        if type(item) is int:
            item = script_num_to_bytes(item)
        elif isinstance(item, (bytes, bytearray)):
            pass  # use as-is
        else:
            assert is_hex_str(item), repr(item)
            item = bfh(item)
        witness += witness_push(item)
    return bytes(witness)


def construct_script(items: Sequence[Union[str, int, bytes, opcodes]], values=None) -> bytes:
    """Constructs bitcoin script from given items."""
    script = bytearray()
    values = values or {}
    for i, item in enumerate(items):
        if i in values:
            item = values[i]
        if isinstance(item, opcodes):
            script += bytes([item])
        elif type(item) is int:
            script += add_number_to_script(item)
        elif isinstance(item, (bytes, bytearray)):
            script += push_script(item)
        elif isinstance(item, str):
            assert is_hex_str(item)
            script += push_script(bfh(item))
        else:
            raise Exception(f'unexpected item for script: {item!r}')
    return bytes(script)


def relayfee(network: 'Network' = None) -> int:
    """Returns feerate in sat/kbyte."""
    from .simple_config import FEERATE_DEFAULT_RELAY, FEERATE_MAX_RELAY
    if network and network.relay_fee is not None:
        fee = network.relay_fee
    else:
        fee = FEERATE_DEFAULT_RELAY
    # sanity safeguards, as network.relay_fee is coming from a server:
    fee = min(fee, FEERATE_MAX_RELAY)
    fee = max(fee, FEERATE_DEFAULT_RELAY)
    return fee


# see https://github.com/bitcoin/bitcoin/blob/a62f0ed64f8bbbdfe6467ac5ce92ef5b5222d1bd/src/policy/policy.cpp#L14
# and https://github.com/lightningnetwork/lightning-rfc/blob/7e3dce42cbe4fa4592320db6a4e06c26bb99122b/03-transactions.md#dust-limits
DUST_LIMIT_P2PKH = 546
DUST_LIMIT_P2SH = 540
DUST_LIMIT_UNKNOWN_SEGWIT = 354
DUST_LIMIT_P2WSH = 330
DUST_LIMIT_P2WPKH = 294


def dust_threshold(network: 'Network' = None) -> int:
    """Returns the dust limit in satoshis."""
    # Change <= dust threshold is added to the tx fee
    dust_lim = 182 * 3 * relayfee(network)  # in msat
    # convert to sat, but round up:
    return (dust_lim // 1000) + (dust_lim % 1000 > 0)


def hash_encode(x: bytes) -> str:
    return x[::-1].hex()


def hash_decode(x: str) -> bytes:
    return bfh(x)[::-1]


############ functions from pywallet #####################

def hash160_to_b58_address(h160: bytes, addrtype: int) -> str:
    s = bytes([addrtype]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s, base=58)


def b58_address_to_hash160(addr: str) -> Tuple[int, bytes]:
    addr = to_bytes(addr, 'ascii')
    _bytes = DecodeBase58Check(addr)
    if len(_bytes) != 21:
        raise Exception(f'expected 21 payload bytes in base58 address. got: {len(_bytes)}')
    return _bytes[0], _bytes[1:21]


def hash160_to_p2pkh(h160: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_b58_address(h160, net.ADDRTYPE_P2PKH)

def hash160_to_p2sh(h160: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_b58_address(h160, net.ADDRTYPE_P2SH)

def public_key_to_p2pkh(public_key: bytes, *, net=None) -> str:
    return hash160_to_p2pkh(hash_160(public_key), net=net)

def hash_to_segwit_addr(h: bytes, witver: int, *, net=None) -> str:
    if net is None: net = constants.net
    addr = segwit_addr.encode_segwit_address(net.SEGWIT_HRP, witver, h)
    assert addr is not None
    return addr

def public_key_to_p2wpkh(public_key: bytes, *, net=None) -> str:
    return hash_to_segwit_addr(hash_160(public_key), witver=0, net=net)

def script_to_p2wsh(script: bytes, *, net=None) -> str:
    return hash_to_segwit_addr(sha256(script), witver=0, net=net)

def p2wsh_nested_script(witness_script: bytes) -> bytes:
    wsh = sha256(witness_script)
    return construct_script([0, wsh])

def pubkey_to_address(txin_type: str, pubkey: str, *, net=None) -> str:
    from . import descriptor
    desc = descriptor.get_singlesig_descriptor_from_legacy_leaf(pubkey=pubkey, script_type=txin_type)
    return desc.expand().address(net=net)


# TODO this method is confusingly named
def redeem_script_to_address(txin_type: str, scriptcode: bytes, *, net=None) -> str:
    assert isinstance(scriptcode, bytes)
    if txin_type == 'p2sh':
        # given scriptcode is a redeem_script
        return hash160_to_p2sh(hash_160(scriptcode), net=net)
    elif txin_type == 'p2wsh':
        # given scriptcode is a witness_script
        return script_to_p2wsh(scriptcode, net=net)
    elif txin_type == 'p2wsh-p2sh':
        # given scriptcode is a witness_script
        redeem_script = p2wsh_nested_script(scriptcode)
        return hash160_to_p2sh(hash_160(redeem_script), net=net)
    else:
        raise NotImplementedError(txin_type)


def script_to_address(script: bytes, *, net=None) -> Optional[str]:
    from .transaction import get_address_from_output_script
    return get_address_from_output_script(script, net=net)


def address_to_script(addr: str, *, net=None) -> bytes:
    if net is None: net = constants.net
    if not is_address(addr, net=net):
        raise BitcoinException(f"invalid bitcoin address: {addr}")
    witver, witprog = segwit_addr.decode_segwit_address(net.SEGWIT_HRP, addr)
    if witprog is not None:
        if not (0 <= witver <= 16):
            raise BitcoinException(f'impossible witness version: {witver}')
        return construct_script([witver, bytes(witprog)])
    addrtype, hash_160_ = b58_address_to_hash160(addr)
    if addrtype == net.ADDRTYPE_P2PKH:
        script = pubkeyhash_to_p2pkh_script(hash_160_)
    elif addrtype == net.ADDRTYPE_P2SH:
        script = construct_script([opcodes.OP_HASH160, hash_160_, opcodes.OP_EQUAL])
    else:
        raise BitcoinException(f'unknown address type: {addrtype}')
    return script


class OnchainOutputType(Enum):
    """Opaque types of scriptPubKeys.
    In case of p2sh, p2wsh and similar, no knowledge of redeem script, etc.
    """
    P2PKH = enum.auto()
    P2SH = enum.auto()
    WITVER0_P2WPKH = enum.auto()
    WITVER0_P2WSH = enum.auto()
    WITVER1_P2TR = enum.auto()


def address_to_payload(addr: str, *, net=None) -> Tuple[OnchainOutputType, bytes]:
    """Return (type, pubkey hash / witness program) for an address."""
    if net is None: net = constants.net
    if not is_address(addr, net=net):
        raise BitcoinException(f"invalid bitcoin address: {addr}")
    witver, witprog = segwit_addr.decode_segwit_address(net.SEGWIT_HRP, addr)
    if witprog is not None:
        if witver == 0:
            if len(witprog) == 20:
                return OnchainOutputType.WITVER0_P2WPKH, bytes(witprog)
            elif len(witprog) == 32:
                return OnchainOutputType.WITVER0_P2WSH, bytes(witprog)
            else:
                raise BitcoinException(f"unexpected length for segwit witver=0 witprog: len={len(witprog)}")
        elif witver == 1:
            if len(witprog) == 32:
                return OnchainOutputType.WITVER1_P2TR, bytes(witprog)
            else:
                raise BitcoinException(f"unexpected length for segwit witver=1 witprog: len={len(witprog)}")
        else:
            raise BitcoinException(f"not implemented handling for witver={witver}")
    addrtype, hash_160_ = b58_address_to_hash160(addr)
    if addrtype == net.ADDRTYPE_P2PKH:
        return OnchainOutputType.P2PKH, hash_160_
    elif addrtype == net.ADDRTYPE_P2SH:
        return OnchainOutputType.P2SH, hash_160_
    raise BitcoinException(f"unknown address type: {addrtype}")


def address_to_scripthash(addr: str, *, net=None) -> str:
    script = address_to_script(addr, net=net)
    return script_to_scripthash(script)


def script_to_scripthash(script: bytes) -> str:
    h = sha256(script)
    return h[::-1].hex()


def pubkeyhash_to_p2pkh_script(pubkey_hash160: bytes) -> bytes:
    return construct_script([
        opcodes.OP_DUP,
        opcodes.OP_HASH160,
        pubkey_hash160,
        opcodes.OP_EQUALVERIFY,
        opcodes.OP_CHECKSIG
    ])


__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58
__b58chars_inv = inv_dict(dict(enumerate(__b58chars)))

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43
__b43chars_inv = inv_dict(dict(enumerate(__b43chars)))


class BaseDecodeError(BitcoinException): pass


def base_encode(v: bytes, *, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars

    origlen = len(v)
    v = v.lstrip(b'\x00')
    newlen = len(v)

    num = int.from_bytes(v, byteorder='big')
    string = b""
    while num:
        num, idx = divmod(num, base)
        string = chars[idx:idx + 1] + string

    result = chars[0:1] * (origlen - newlen) + string
    return result.decode('ascii')


def base_decode(v: Union[bytes, str], *, base: int) -> Optional[bytes]:
    """ decode v into a string of len bytes.

    based on the work of David Keijser in https://github.com/keis/base58
    """
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    chars_inv = __b58chars_inv
    if base == 43:
        chars = __b43chars
        chars_inv = __b43chars_inv

    origlen = len(v)
    v = v.lstrip(chars[0:1])
    newlen = len(v)

    num = 0
    try:
        for char in v:
            num = num * base + chars_inv[char]
    except KeyError:
        raise BaseDecodeError('Forbidden character {} for base {}'.format(char, base))

    return num.to_bytes(origlen - newlen + (num.bit_length() + 7) // 8, 'big')


class InvalidChecksum(BaseDecodeError):
    pass


def EncodeBase58Check(vchIn: bytes) -> str:
    hash = sha256d(vchIn)
    return base_encode(vchIn + hash[0:4], base=58)


def DecodeBase58Check(psz: Union[bytes, str]) -> bytes:
    vchRet = base_decode(psz, base=58)
    payload = vchRet[0:-4]
    csum_found = vchRet[-4:]
    csum_calculated = sha256d(payload)[0:4]
    if csum_calculated != csum_found:
        raise InvalidChecksum(f'calculated {csum_calculated.hex()}, found {csum_found.hex()}')
    else:
        return payload


# backwards compat
# extended WIF for segwit (used in 3.0.x; but still used internally)
# the keys in this dict should be a superset of what Imported Wallets can import
WIF_SCRIPT_TYPES = {
    'p2pkh':0,
    'p2wpkh':1,
    'p2wpkh-p2sh':2,
    'p2sh':5,
    'p2wsh':6,
    'p2wsh-p2sh':7
}
WIF_SCRIPT_TYPES_INV = inv_dict(WIF_SCRIPT_TYPES)


def is_segwit_script_type(txin_type: str) -> bool:
    return txin_type in ('p2wpkh', 'p2wpkh-p2sh', 'p2wsh', 'p2wsh-p2sh')


def serialize_privkey(secret: bytes, compressed: bool, txin_type: str, *,
                      internal_use: bool = False) -> str:
    # we only export secrets inside curve range
    secret = ecc.ECPrivkey.normalize_secret_bytes(secret)
    if internal_use:
        prefix = bytes([(WIF_SCRIPT_TYPES[txin_type] + constants.net.WIF_PREFIX) & 255])
    else:
        prefix = bytes([constants.net.WIF_PREFIX])
    suffix = b'\01' if compressed else b''
    vchIn = prefix + secret + suffix
    base58_wif = EncodeBase58Check(vchIn)
    if internal_use:
        return base58_wif
    else:
        return '{}:{}'.format(txin_type, base58_wif)


def deserialize_privkey(key: str) -> Tuple[str, bytes, bool]:
    if is_minikey(key):
        return 'p2pkh', minikey_to_private_key(key), False

    txin_type = None
    if ':' in key:
        txin_type, key = key.split(sep=':', maxsplit=1)
        if txin_type not in WIF_SCRIPT_TYPES:
            raise BitcoinException('unknown script type: {}'.format(txin_type))
    try:
        vch = DecodeBase58Check(key)
    except Exception as e:
        neutered_privkey = str(key)[:3] + '..' + str(key)[-2:]
        raise BaseDecodeError(f"cannot deserialize privkey {neutered_privkey}") from e

    if txin_type is None:
        # keys exported in version 3.0.x encoded script type in first byte
        prefix_value = vch[0] - constants.net.WIF_PREFIX
        try:
            txin_type = WIF_SCRIPT_TYPES_INV[prefix_value]
        except KeyError as e:
            raise BitcoinException('invalid prefix ({}) for WIF key (1)'.format(vch[0])) from None
    else:
        # all other keys must have a fixed first byte
        if vch[0] != constants.net.WIF_PREFIX:
            raise BitcoinException('invalid prefix ({}) for WIF key (2)'.format(vch[0]))

    if len(vch) not in [33, 34]:
        raise BitcoinException('invalid vch len for WIF key: {}'.format(len(vch)))
    compressed = False
    if len(vch) == 34:
        if vch[33] == 0x01:
            compressed = True
        else:
            raise BitcoinException(f'invalid WIF key. length suggests compressed pubkey, '
                                   f'but last byte is {vch[33]} != 0x01')

    if is_segwit_script_type(txin_type) and not compressed:
        raise BitcoinException('only compressed public keys can be used in segwit scripts')

    secret_bytes = vch[1:33]
    # we accept secrets outside curve range; cast into range here:
    secret_bytes = ecc.ECPrivkey.normalize_secret_bytes(secret_bytes)
    return txin_type, secret_bytes, compressed


def is_compressed_privkey(sec: str) -> bool:
    return deserialize_privkey(sec)[2]


def address_from_private_key(sec: str) -> str:
    txin_type, privkey, compressed = deserialize_privkey(sec)
    public_key = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
    return pubkey_to_address(txin_type, public_key)

def is_segwit_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    try:
        witver, witprog = segwit_addr.decode_segwit_address(net.SEGWIT_HRP, addr)
    except Exception as e:
        return False
    return witprog is not None

def is_taproot_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    try:
        witver, witprog = segwit_addr.decode_segwit_address(net.SEGWIT_HRP, addr)
    except Exception as e:
        return False
    return witver == 1

def is_b58_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    try:
        # test length, checksum, encoding:
        addrtype, h = b58_address_to_hash160(addr)
    except Exception as e:
        return False
    if addrtype not in [net.ADDRTYPE_P2PKH, net.ADDRTYPE_P2SH]:
        return False
    return True

def is_address(addr: str, *, net=None) -> bool:
    return is_segwit_address(addr, net=net) \
           or is_b58_address(addr, net=net)


def is_private_key(key: str, *, raise_on_error=False) -> bool:
    try:
        deserialize_privkey(key)
        return True
    except BaseException as e:
        if raise_on_error:
            raise
        return False


########### end pywallet functions #######################

def is_minikey(text: str) -> bool:
    # Minikeys are typically 22 or 30 characters, but this routine
    # permits any length of 20 or more provided the minikey is valid.
    # A valid minikey must begin with an 'S', be in base58, and when
    # suffixed with '?' have its SHA256 hash begin with a zero byte.
    # They are widely used in Casascius physical bitcoins.
    return (len(text) >= 20 and text[0] == 'S'
            and all(ord(c) in __b58chars for c in text)
            and sha256(text + '?')[0] == 0x00)

def minikey_to_private_key(text: str) -> bytes:
    return sha256(text)


def _get_dummy_address(purpose: str) -> str:
    return redeem_script_to_address('p2wsh', sha256(bytes(purpose, "utf8")))

_dummy_addr_funcs = set()
class DummyAddress:
    """dummy address for fee estimation of funding tx
    Use e.g. as: DummyAddress.CHANNEL
    """
    def purpose(func):
        _dummy_addr_funcs.add(func)
        return classproperty(func)

    @purpose
    def CHANNEL(self) -> str:
        return _get_dummy_address("channel")
    @purpose
    def SWAP(self) -> str:
        return _get_dummy_address("swap")

    @classmethod
    def is_dummy_address(cls, addr: str) -> bool:
        return addr in (f(cls) for f in _dummy_addr_funcs)


class DummyAddressUsedInTxException(Exception): pass


def taproot_tweak_pubkey(pubkey32: bytes, h: bytes) -> Tuple[int, bytes]:
    assert isinstance(pubkey32, bytes), type(pubkey32)
    assert isinstance(h, bytes), type(h)
    assert len(pubkey32) == 32, len(pubkey32)
    int_from_bytes = lambda x: int.from_bytes(x, byteorder="big", signed=False)

    tweak = int_from_bytes(bip340_tagged_hash(b"TapTweak", pubkey32 + h))
    if tweak >= ecc.CURVE_ORDER:
        raise ValueError
    P = ecc.ECPubkey(b"\x02" + pubkey32)
    Q = P + (ecc.GENERATOR * tweak)
    return 0 if Q.has_even_y() else 1, Q.get_public_key_bytes(compressed=True)[1:]


def taproot_tweak_seckey(seckey0: bytes, h: bytes) -> bytes:
    assert isinstance(seckey0, bytes), type(seckey0)
    assert isinstance(h, bytes), type(h)
    assert len(seckey0) == 32, len(seckey0)
    int_from_bytes = lambda x: int.from_bytes(x, byteorder="big", signed=False)

    P = ecc.ECPrivkey(seckey0)
    seckey = P.secret_scalar if P.has_even_y() else ecc.CURVE_ORDER - P.secret_scalar
    pubkey32 = P.get_public_key_bytes(compressed=True)[1:]
    tweak = int_from_bytes(bip340_tagged_hash(b"TapTweak", pubkey32 + h))
    if tweak >= ecc.CURVE_ORDER:
        raise ValueError
    return int.to_bytes((seckey + tweak) % ecc.CURVE_ORDER, length=32, byteorder="big", signed=False)


# a TapTree is either:
#  - a (leaf_version, script) tuple (leaf_version is 0xc0 for BIP-0342 scripts)
#  - a list of two elements, each with the same structure as TapTree itself
TapTreeLeaf = Tuple[int, bytes]
TapTree = Union[TapTreeLeaf, Sequence['TapTree']]

def bip340_tagged_hash(tag: bytes, msg: bytes) -> bytes:
    # note: _libsecp256k1.secp256k1_tagged_sha256 benchmarks about 70% slower than this (on my machine)
    return sha256(sha256(tag) + sha256(tag) + msg)

def taproot_tree_helper(script_tree: TapTree):
    if isinstance(script_tree, tuple):
        leaf_version, script = script_tree
        h = bip340_tagged_hash(b"TapLeaf", bytes([leaf_version]) + witness_push(script))
        return ([((leaf_version, script), bytes())], h)
    left, left_h = taproot_tree_helper(script_tree[0])
    right, right_h = taproot_tree_helper(script_tree[1])
    ret = [(l, c + right_h) for l, c in left] + [(l, c + left_h) for l, c in right]
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (ret, bip340_tagged_hash(b"TapBranch", left_h + right_h))


def taproot_output_script(internal_pubkey: bytes, *, script_tree: Optional[TapTree]) -> bytes:
    """Given an internal public key and a tree of scripts, compute the output script."""
    assert isinstance(internal_pubkey, bytes), type(internal_pubkey)
    assert len(internal_pubkey) == 32, len(internal_pubkey)
    if script_tree is None:
        merkle_root = bytes()
    else:
        _, merkle_root = taproot_tree_helper(script_tree)
    _, output_pubkey = taproot_tweak_pubkey(internal_pubkey, merkle_root)
    return construct_script([1, output_pubkey])


def control_block_for_taproot_script_spend(
    *, internal_pubkey: bytes, script_tree: TapTree, script_num: int,
) -> Tuple[bytes, bytes]:
    """Constructs the control block necessary for spending a taproot UTXO using a script.
    script_num indicates which script to use, which indexes into (flattened) script_tree.
    """
    assert isinstance(internal_pubkey, bytes), type(internal_pubkey)
    assert len(internal_pubkey) == 32, len(internal_pubkey)
    info, merkle_root = taproot_tree_helper(script_tree)
    (leaf_version, leaf_script), merkle_path = info[script_num]
    output_pubkey_y_parity, _ = taproot_tweak_pubkey(internal_pubkey, merkle_root)
    pubkey_data = bytes([output_pubkey_y_parity + leaf_version]) + internal_pubkey
    control_block = pubkey_data + merkle_path
    return (leaf_script, control_block)


# user message signing
def usermessage_magic(message: bytes) -> bytes:
    length = var_int(len(message))
    return b"\x18Bitcoin Signed Message:\n" + length + message

def ecdsa_sign_usermessage(ec_privkey, message: Union[bytes, str], *, is_compressed: bool) -> bytes:
    message = to_bytes(message, 'utf8')
    msg32 = sha256d(usermessage_magic(message))
    return ec_privkey.ecdsa_sign_recoverable(msg32, is_compressed=is_compressed)

def verify_usermessage_with_address(address: str, sig65: bytes, message: bytes, *, net=None) -> bool:
    from .ecc import ECPubkey
    assert_bytes(sig65, message)
    if net is None: net = constants.net
    h = sha256d(usermessage_magic(message))
    try:
        public_key, compressed, txin_type_guess = ECPubkey.from_ecdsa_sig65(sig65, h)
    except Exception as e:
        return False
    # check public key using the address
    pubkey_hex = public_key.get_public_key_hex(compressed)
    txin_types = (txin_type_guess,) if txin_type_guess else ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh')
    for txin_type in txin_types:
        addr = pubkey_to_address(txin_type, pubkey_hex, net=net)
        if address == addr:
            break
    else:
        return False
    # check message
    # note: `$ bitcoin-cli verifymessage` does NOT enforce the low-S rule for ecdsa sigs
    return public_key.ecdsa_verify(sig65[1:], h, enforce_low_s=False)
