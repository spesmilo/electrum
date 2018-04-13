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
from typing import List, Tuple, TYPE_CHECKING, Optional, Union

from .util import bfh, bh2u, BitcoinException, assert_bytes, to_bytes, inv_dict
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

# supported types of transaction outputs
TYPE_ADDRESS = 0
TYPE_PUBKEY  = 1
TYPE_SCRIPT  = 2


def rev_hex(s: str) -> str:
    return bh2u(bfh(s)[::-1])


def int_to_hex(i: int, length: int=1) -> str:
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -(range_size//2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def script_num_to_hex(i: int) -> str:
    """See CScriptNum in Bitcoin Core.
    Encodes an integer as hex, to be used in script.

    ported from https://github.com/bitcoin/bitcoin/blob/8cbc5c4be4be22aca228074f087a374a7ec38be8/src/script/script.h#L326
    """
    if i == 0:
        return ''

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

    return bh2u(result)

def var_int(i: int) -> str:
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i<0xfd:
        return int_to_hex(i)
    elif i<=0xffff:
        return "fd"+int_to_hex(i,2)
    elif i<=0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)


def witness_push(item: str) -> str:
    """Returns data in the form it should be present in the witness.
    hex -> hex
    """
    return var_int(len(item) // 2) + item


def op_push(i: int) -> str:
    if i<0x4c:  # OP_PUSHDATA1
        return int_to_hex(i)
    elif i<=0xff:
        return '4c' + int_to_hex(i)
    elif i<=0xffff:
        return '4d' + int_to_hex(i,2)
    else:
        return '4e' + int_to_hex(i,4)


def push_script(data: str) -> str:
    """Returns pushed data to the script, automatically
    choosing canonical opcodes depending on the length of the data.
    hex -> hex

    ported from https://github.com/btcsuite/btcd/blob/fdc2bc867bda6b351191b5872d2da8270df00d13/txscript/scriptbuilder.go#L128
    """
    data = bfh(data)
    from .transaction import opcodes

    data_len = len(data)

    # "small integer" opcodes
    if data_len == 0 or data_len == 1 and data[0] == 0:
        return bh2u(bytes([opcodes.OP_0]))
    elif data_len == 1 and data[0] <= 16:
        return bh2u(bytes([opcodes.OP_1 - 1 + data[0]]))
    elif data_len == 1 and data[0] == 0x81:
        return bh2u(bytes([opcodes.OP_1NEGATE]))

    return op_push(data_len) + bh2u(data)


def add_number_to_script(i: int) -> bytes:
    return bfh(push_script(script_num_to_hex(i)))


def relayfee(network: 'Network'=None) -> int:
    from .simple_config import FEERATE_DEFAULT_RELAY
    MAX_RELAY_FEE = 50000
    f = network.relay_fee if network and network.relay_fee else FEERATE_DEFAULT_RELAY
    return min(f, MAX_RELAY_FEE)


def dust_threshold(network: 'Network'=None) -> int:
    # Change <= dust threshold is added to the tx fee
    return 182 * 3 * relayfee(network) // 1000


def hash_encode(x: bytes) -> str:
    return bh2u(x[::-1])


def hash_decode(x: str) -> bytes:
    return bfh(x)[::-1]


################################## electrum seeds


def is_new_seed(x: str, prefix=version.SEED_PREFIX) -> bool:
    from . import mnemonic
    x = mnemonic.normalize_text(x)
    s = bh2u(hmac_oneshot(b"Seed version", x.encode('utf8'), hashlib.sha512))
    return s.startswith(prefix)


def is_old_seed(seed: str) -> bool:
    from . import old_mnemonic, mnemonic
    seed = mnemonic.normalize_text(seed)
    words = seed.split()
    try:
        # checks here are deliberately left weak for legacy reasons, see #3149
        old_mnemonic.mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        seed = bfh(seed)
        is_hex = (len(seed) == 16 or len(seed) == 32)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))


def seed_type(x: str) -> str:
    if is_old_seed(x):
        return 'old'
    elif is_new_seed(x):
        return 'standard'
    elif is_new_seed(x, version.SEED_PREFIX_SW):
        return 'segwit'
    elif is_new_seed(x, version.SEED_PREFIX_2FA):
        return '2fa'
    elif is_new_seed(x, version.SEED_PREFIX_2FA_SW):
        return '2fa_segwit'
    return ''


def is_seed(x: str) -> bool:
    return bool(seed_type(x))


def is_any_2fa_seed_type(seed_type):
    return seed_type in ['2fa', '2fa_segwit']


############ functions from pywallet #####################

def hash160_to_b58_address(h160: bytes, addrtype: int) -> str:
    s = bytes([addrtype]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s, base=58)


def b58_address_to_hash160(addr: str) -> Tuple[int, bytes]:
    addr = to_bytes(addr, 'ascii')
    _bytes = base_decode(addr, 25, base=58)
    return _bytes[0], _bytes[1:21]


def hash160_to_p2pkh(h160: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_b58_address(h160, net.ADDRTYPE_P2PKH)

def hash160_to_p2sh(h160: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_b58_address(h160, net.ADDRTYPE_P2SH)

def public_key_to_p2pkh(public_key: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_p2pkh(hash_160(public_key), net=net)

def hash_to_segwit_addr(h: bytes, witver: int, *, net=None) -> str:
    if net is None: net = constants.net
    return segwit_addr.encode(net.SEGWIT_HRP, witver, h)

def public_key_to_p2wpkh(public_key: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash_to_segwit_addr(hash_160(public_key), witver=0, net=net)

def script_to_p2wsh(script: str, *, net=None) -> str:
    if net is None: net = constants.net
    return hash_to_segwit_addr(sha256(bfh(script)), witver=0, net=net)

def p2wpkh_nested_script(pubkey: str) -> str:
    pkh = bh2u(hash_160(bfh(pubkey)))
    return '00' + push_script(pkh)

def p2wsh_nested_script(witness_script: str) -> str:
    wsh = bh2u(sha256(bfh(witness_script)))
    return '00' + push_script(wsh)

def pubkey_to_address(txin_type: str, pubkey: str, *, net=None) -> str:
    if net is None: net = constants.net
    if txin_type == 'p2pkh':
        return public_key_to_p2pkh(bfh(pubkey), net=net)
    elif txin_type == 'p2wpkh':
        return public_key_to_p2wpkh(bfh(pubkey), net=net)
    elif txin_type == 'p2wpkh-p2sh':
        scriptSig = p2wpkh_nested_script(pubkey)
        return hash160_to_p2sh(hash_160(bfh(scriptSig)), net=net)
    else:
        raise NotImplementedError(txin_type)

def redeem_script_to_address(txin_type: str, redeem_script: str, *, net=None) -> str:
    if net is None: net = constants.net
    if txin_type == 'p2sh':
        return hash160_to_p2sh(hash_160(bfh(redeem_script)), net=net)
    elif txin_type == 'p2wsh':
        return script_to_p2wsh(redeem_script, net=net)
    elif txin_type == 'p2wsh-p2sh':
        scriptSig = p2wsh_nested_script(redeem_script)
        return hash160_to_p2sh(hash_160(bfh(scriptSig)), net=net)
    else:
        raise NotImplementedError(txin_type)


def script_to_address(script: str, *, net=None) -> str:
    from .transaction import get_address_from_output_script
    t, addr = get_address_from_output_script(bfh(script), net=net)
    assert t == TYPE_ADDRESS
    return addr

def address_to_script(addr: str, *, net=None) -> str:
    if net is None: net = constants.net
    if not is_address(addr, net=net):
        raise BitcoinException(f"invalid bitcoin address: {addr}")
    witver, witprog = segwit_addr.decode(net.SEGWIT_HRP, addr)
    if witprog is not None:
        if not (0 <= witver <= 16):
            raise BitcoinException(f'impossible witness version: {witver}')
        OP_n = witver + 0x50 if witver > 0 else 0
        script = bh2u(bytes([OP_n]))
        script += push_script(bh2u(bytes(witprog)))
        return script
    addrtype, hash_160_ = b58_address_to_hash160(addr)
    if addrtype == net.ADDRTYPE_P2PKH:
        script = '76a9'                                      # op_dup, op_hash_160
        script += push_script(bh2u(hash_160_))
        script += '88ac'                                     # op_equalverify, op_checksig
    elif addrtype == net.ADDRTYPE_P2SH:
        script = 'a9'                                        # op_hash_160
        script += push_script(bh2u(hash_160_))
        script += '87'                                       # op_equal
    else:
        raise BitcoinException(f'unknown address type: {addrtype}')
    return script

def address_to_scripthash(addr: str) -> str:
    script = address_to_script(addr)
    return script_to_scripthash(script)

def script_to_scripthash(script: str) -> str:
    h = sha256(bfh(script))[0:32]
    return bh2u(bytes(reversed(h)))

def public_key_to_p2pk_script(pubkey: str) -> str:
    script = push_script(pubkey)
    script += 'ac'                                           # op_checksig
    return script

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


def base_encode(v: bytes, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c
    result = bytearray()
    while long_value >= base:
        div, mod = divmod(long_value, base)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0x00:
            nPad += 1
        else:
            break
    result.extend([chars[0]] * nPad)
    result.reverse()
    return result.decode('ascii')


def base_decode(v: Union[bytes, str], length: Optional[int], base: int) -> Optional[bytes]:
    """ decode v into a string of len bytes."""
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        digit = chars.find(bytes([c]))
        if digit == -1:
            raise ValueError('Forbidden character {} for base {}'.format(c, base))
        long_value += digit * (base**i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)


class InvalidChecksum(Exception):
    pass


def EncodeBase58Check(vchIn: bytes) -> str:
    hash = sha256d(vchIn)
    return base_encode(vchIn + hash[0:4], base=58)


def DecodeBase58Check(psz: Union[bytes, str]) -> bytes:
    vchRet = base_decode(psz, None, base=58)
    payload = vchRet[0:-4]
    csum_found = vchRet[-4:]
    csum_calculated = sha256d(payload)[0:4]
    if csum_calculated != csum_found:
        raise InvalidChecksum(f'calculated {bh2u(csum_calculated)}, found {bh2u(csum_found)}')
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



def serialize_privkey(secret: bytes, compressed: bool, txin_type: str,
                      internal_use: bool=False) -> str:
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
    except BaseException:
        neutered_privkey = str(key)[:3] + '..' + str(key)[-2:]
        raise BitcoinException("cannot deserialize privkey {}"
                               .format(neutered_privkey))

    if txin_type is None:
        # keys exported in version 3.0.x encoded script type in first byte
        prefix_value = vch[0] - constants.net.WIF_PREFIX
        try:
            txin_type = WIF_SCRIPT_TYPES_INV[prefix_value]
        except KeyError:
            raise BitcoinException('invalid prefix ({}) for WIF key (1)'.format(vch[0]))
    else:
        # all other keys must have a fixed first byte
        if vch[0] != constants.net.WIF_PREFIX:
            raise BitcoinException('invalid prefix ({}) for WIF key (2)'.format(vch[0]))

    if len(vch) not in [33, 34]:
        raise BitcoinException('invalid vch len for WIF key: {}'.format(len(vch)))
    compressed = len(vch) == 34
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
        witver, witprog = segwit_addr.decode(net.SEGWIT_HRP, addr)
    except Exception as e:
        return False
    return witprog is not None

def is_b58_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    try:
        addrtype, h = b58_address_to_hash160(addr)
    except Exception as e:
        return False
    if addrtype not in [net.ADDRTYPE_P2PKH, net.ADDRTYPE_P2SH]:
        return False
    return addr == hash160_to_b58_address(h, addrtype)

def is_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    return is_segwit_address(addr, net=net) \
           or is_b58_address(addr, net=net)


def is_private_key(key: str) -> bool:
    try:
        k = deserialize_privkey(key)
        return k is not False
    except:
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
