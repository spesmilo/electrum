# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2017 The Electron Cash Developers
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

# Many of the functions in this file are copied from ElectrumX

import hashlib
import struct

from .bitcoin import NetworkConstants
from .transaction import opcodes

_sha256 = hashlib.sha256
_new_hash = hashlib.new
hex_to_bytes = bytes.fromhex


# Utility functions

def hash_to_hex_str(x):
    '''Convert a big-endian binary hash to displayed hex string.

    Display form of a binary hash is reversed and converted to hex.
    '''
    return bytes(reversed(x)).hex()

def hex_str_to_hash(x):
    '''Convert a displayed hex string to a binary hash.'''
    return bytes(reversed(hex_to_bytes(x)))

def bytes_to_int(be_bytes):
    '''Interprets a big-endian sequence of bytes as an integer'''
    return int.from_bytes(be_bytes, 'big')

def int_to_bytes(value):
    '''Converts an integer to a big-endian sequence of bytes'''
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')

def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return _sha256(x).digest()

def double_sha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))

def ripemd160(x):
    '''Simple wrapper of hashlib ripemd160.'''
    h = _new_hash('ripemd160')
    h.update(x)
    return h.digest()

def hash160(x):
    '''RIPEMD-160 of SHA-256.

    Used to make bitcoin addresses from pubkeys.'''
    return ripemd160(sha256(x))


class AddressError(Exception):
    '''Exception used for Address errors.'''


class Address(object):

    # Address kinds
    ADDR_P2PKH = 0
    ADDR_P2SH = 1

    # Address formats
    FMT_CASHADDR = 0
    FMT_LEGACY = 1
    FMT_BITPAY = 2   # Supported temporarily only for compatibility

    # At some stage switch to FMT_CASHADDR
    FMT_STORAGE = FMT_LEGACY

    def __init__(self, hash160, kind):
        assert kind in (self.ADDR_P2PKH, self.ADDR_P2SH)
        assert isinstance(hash160, bytes) and len(hash160) == 20
        self.hash160 = hash160
        self.kind = kind

    @classmethod
    def from_string(cls, string):
        '''Construct from an address string.'''
        raw = Base58.decode_check(address)

        # Require version byte(s) plus hash160.
        if len(raw) != 21:
            raise AddressError('invalid address: {}'.format(string))

        verbyte, hash160 = raw[0], raw[1:]
        if verbyte in [NetworkConstants.ADDRTYPE_P2PKH,
                       NetworkConstants.ADDRTYPE_P2PKH_BITPAY]:
            kind = cls.ADDR_P2PKH
        elif verbyte in [NetworkConstants.ADDRTYPE_P2SH,
                         NetworkConstants.ADDRTYPE_P2SH_BITPAY]:
            kind = cls.ADDR_P2SH
        else:
            raise AddressError('unknown version byte: {}'.format(verbyte))

        return cls(hash160, kind)

    @classmethod
    def from_strings(cls, strings):
        '''Construct a list from an iterable of strings.'''
        return [cls.from_string(string) for string in strings]

    @classmethod
    def from_pubkey(cls, pubkey):
        '''Returns a P2PKH address from a public key.  The public key can
        be bytes or a hex string.'''
        if isinstance(pubkey, str):
            pubkey = hex_to_bytes(pubkey)
        return cls(hash160(pubkey), cls.ADDR_P2PKH)

    @classmethod
    def to_strings(cls, fmt, addrs):
        '''Construct a list of strings from an iterable of Address objects.'''
        return [addr.to_string(fmt) for addr in addrs]

    def to_string(self, fmt):
        '''Converts to a string of the given format.'''
        if self.kind == self.ADDR_P2PKH:
            if fmt == self.FMT_LEGACY:
                verbyte = NetworkConstants.ADDRTYPE_P2PKH
            elif fmt == self.FMT_BITPAY:
                verbyte = NetworkConstants.ADDRTYPE_P2PKH_BITPAY
            else:
                raise AddressError('unrecognised format')
        else:
            if fmt == self.FMT_LEGACY:
                verbyte = NetworkConstants.ADDRTYPE_P2SH
            elif fmt == self.FMT_BITPAY:
                verbyte = NetworkConstants.ADDRTYPE_P2SH_BITPAY
            else:
                raise AddressError('unrecognised format')

        return Base58.encode_check(bytes([verbyte]) + self.hash160)

    def to_script(self):
        '''Return a binary script to pay to the address.'''
        if self.kind == self.ADDR_P2PKH:
            return (bytes([opcodes.OP_DUP, opcodes.OP_HASH160])
                    + Script.push_data(self.hash160)
                    + bytes([opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]))
        else:
            return (bytes([opcodes.OP_HASH160])
                    + Script.push_data(self.hash160)
                    + bytes([opcodes.OP_EQUAL]))

    def to_script_hex(self):
        '''Return a script to pay to the address as a hex string.'''
        return self.to_script().hex()

    def to_scripthash(self):
        '''Returns the hash of the script in binary.'''
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        '''Like other bitcoin hashes this is reversed when written in hex.'''
        return hash_to_hex_str(self.to_scripthash())


class Script(object):

    @classmethod
    def push_data(cls, data):
        '''Returns the opcodes to push the data on the stack.'''
        assert isinstance(data, (bytes, bytearray))

        n = len(data)
        if n < opcodes.OP_PUSHDATA1:
            return bytes([n]) + data
        if n < 256:
            return bytes([opcodes.OP_PUSHDATA1, n]) + data
        if n < 65536:
            return bytes([opcodes.OP_PUSHDATA2]) + struct.pack('<H', n) + data
        return bytes([opcodes.OP_PUSHDATA4]) + struct.pack('<I', n) + data


class Base58Error(Exception):
    '''Exception used for Base58 errors.'''


class Base58(object):
    '''Class providing base 58 functionality.'''

    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    assert len(chars) == 58
    cmap = {c: n for n, c in enumerate(chars)}

    @staticmethod
    def char_value(c):
        val = Base58.cmap.get(c)
        if val is None:
            raise Base58Error('invalid base 58 character "{}"'.format(c))
        return val

    @staticmethod
    def decode(txt):
        """Decodes txt into a big-endian bytearray."""
        if not isinstance(txt, str):
            raise TypeError('a string is required')

        if not txt:
            raise Base58Error('string cannot be empty')

        value = 0
        for c in txt:
            value = value * 58 + Base58.char_value(c)

        result = int_to_bytes(value)

        # Prepend leading zero bytes if necessary
        count = 0
        for c in txt:
            if c != '1':
                break
            count += 1
        if count:
            result = bytes(count) + result

        return result

    @staticmethod
    def encode(be_bytes):
        """Converts a big-endian bytearray into a base58 string."""
        value = bytes_to_int(be_bytes)

        txt = ''
        while value:
            value, mod = divmod(value, 58)
            txt += Base58.chars[mod]

        for byte in be_bytes:
            if byte != 0:
                break
            txt += '1'

        return txt[::-1]

    @staticmethod
    def decode_check(txt):
        '''Decodes a Base58Check-encoded string to a payload.  The version
        prefixes it.'''
        be_bytes = Base58.decode(txt)
        result, check = be_bytes[:-4], be_bytes[-4:]
        if check != double_sha256(result)[:4]:
            raise Base58Error('invalid base 58 checksum for {}'.format(txt))
        return result

    @staticmethod
    def encode_check(payload):
        """Encodes a payload bytearray (which includes the version byte(s))
        into a Base58Check string."""
        be_bytes = payload + double_sha256(payload)[:4]
        return Base58.encode(be_bytes)
