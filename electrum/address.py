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

from collections import namedtuple
import hashlib
import struct

from . import constants, ecc
from enum import IntEnum
from .bitcoin import is_minikey, minikey_to_private_key, WIF_SCRIPT_TYPES, opcodes
from .util import cachedproperty, inv_dict

_sha256 = hashlib.sha256
_new_hash = hashlib.new
hex_to_bytes = bytes.fromhex


class AddressError(Exception):
    '''Exception used for Address errors.'''

class ScriptError(Exception):
    '''Exception used for Script errors.'''


P2PKH_prefix = bytes([opcodes.OP_DUP, opcodes.OP_HASH160, 20])
P2PKH_suffix = bytes([opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG])

P2SH_prefix = bytes([opcodes.OP_HASH160, 20])
P2SH_suffix = bytes([opcodes.OP_EQUAL])

# Utility functions

def to_bytes(x):
    '''Convert to bytes which is hashable.'''
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    raise TypeError('{} is not bytes ({})'.format(x, type(x)))

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

class UnknownAddress(namedtuple("UnknownAddress", "meta")):

    def __new__(cls, meta=None):
        return super(UnknownAddress, cls).__new__(cls, meta)

    def to_ui_string(self):
        if self.meta is not None:
            meta = self.meta
            meta = (isinstance(meta, (bytes, bytearray)) and meta.hex()) or meta
            if isinstance(meta, str) and len(meta) > 10:
                l = len(meta) // 2
                meta = "…" + meta[l-4:l+4] + "…"
            return f'<UnknownAddress meta={meta}>'
        return '<UnknownAddress>'

    def __str__(self):
        return self.to_ui_string()

    def __repr__(self):
        return self.to_ui_string()


class PublicKey(namedtuple("PublicKeyTuple", "pubkey")):

    TO_ADDRESS_OPS = [opcodes.OP_DUP, opcodes.OP_HASH160, -1,
                      opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]

    @classmethod
    def from_pubkey(cls, pubkey):
        '''Create from a public key expressed as binary bytes.'''
        if isinstance(pubkey, str):
            pubkey = hex_to_bytes(pubkey)
        cls.validate(pubkey)
        return cls(to_bytes(pubkey))

    @classmethod
    def privkey_from_WIF_privkey(cls, WIF_privkey, *, net=None):
        '''Given a WIF private key (or minikey), return the private key as
        binary and a boolean indicating whether it was encoded to
        indicate a compressed public key or not.
        '''
        if net is None: net = constants.net
        if is_minikey(WIF_privkey):
            # The Casascius coins were uncompressed
            return minikey_to_private_key(WIF_privkey), False
        raw = Base58.decode_check(WIF_privkey)
        if not raw:
            raise ValueError('Private key WIF decode error; unable to decode.')
        if raw[0] != net.WIF_PREFIX:
            # try and generate a helpful error message as this propagates up to the UI if they are creating a new wallet.
            extra = inv_dict(SCRIPT_TYPES).get(int(raw[0]-net.WIF_PREFIX), '')
            if extra:
                extra = "; this corresponds to a key of type: '{}' which is unsupported for importing from WIF key.".format(extra)
            raise ValueError("Private key has invalid WIF version byte (expected: 0x{:x} got: 0x{:x}){}".format(net.WIF_PREFIX, raw[0], extra))
        if len(raw) == 34 and raw[-1] == 1:
            return raw[1:33], True
        if len(raw) == 33:
            return raw[1:], False
        raise ValueError('invalid private key')

    @classmethod
    def from_WIF_privkey(cls, WIF_privkey):
        '''Create a compressed or uncompressed public key from a private
        key.'''
        privkey, compressed = cls.privkey_from_WIF_privkey(WIF_privkey)
        ec_key = EC_KEY(privkey)
        return cls.from_pubkey(ec_key.GetPubKey(compressed))

    @classmethod
    def from_string(cls, string):
        '''Create from a hex string.'''
        return cls.from_pubkey(hex_to_bytes(string))

    @classmethod
    def validate(cls, pubkey):
        if not isinstance(pubkey, (bytes, bytearray)):
            raise TypeError('pubkey must be of bytes type, not {}'
                            .format(type(pubkey)))
        if len(pubkey) == 33 and pubkey[0] in (2, 3):
            return  # Compressed
        if len(pubkey) == 65 and pubkey[0] == 4:
            return  # Uncompressed
        raise AddressError('invalid pubkey {}'.format(pubkey))

    @cachedproperty
    def address(self):
        '''Convert to an Address object.'''
        return Address(hash160(self.pubkey), Address.ADDR_P2PKH)

    def is_compressed(self):
        '''Returns True if the pubkey is compressed.'''
        return len(self.pubkey) == 33

    def to_ui_string(self):
        '''Convert to a hexadecimal string.'''
        return self.pubkey.hex()

    def to_storage_string(self):
        '''Convert to a hexadecimal string for storage.'''
        return self.pubkey.hex()

    def to_script(self):
        '''Note this returns the P2PK script.'''
        return Script.P2PK_script(self.pubkey)

    def to_script_hex(self):
        '''Return a script to pay to the address as a hex string.'''
        return self.to_script().hex()

    def to_scripthash(self):
        '''Returns the hash of the script in binary.'''
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        '''Like other bitcoin hashes this is reversed when written in hex.'''
        return hash_to_hex_str(self.to_scripthash())

    def to_P2PKH_script(self):
        '''Return a P2PKH script.'''
        return self.address.to_script()

    def __str__(self):
        return self.to_ui_string()

    def __repr__(self):
        return '<PubKey {}>'.format(self.__str__())


class ScriptOutput(namedtuple("ScriptAddressTuple", "script")):

    @classmethod
    def from_string(self, string):
        '''Instantiate from a mixture of opcodes and raw data.'''
        script = bytearray()
        for word in string.split():
            if word.startswith('OP_'):
                try:
                    opcode = opcodes[word]
                except KeyError:
                    raise AddressError('unknown opcode {}'.format(word))
                script.append(opcode)
            else:
                import binascii
                script.extend(Script.push_data(binascii.unhexlify(word)))
        return ScriptOutput.protocol_factory(bytes(script))

    def to_ui_string(self,ignored=None):
        '''Convert to user-readable OP-codes (plus pushdata as text if possible)
        eg OP_RETURN (12) "Hello there!"
        '''
        try:
            ops = Script.get_ops(self.script)
        except ScriptError:
            # Truncated script -- so just default to hex string.
            return 'Invalid script: ' + self.script.hex()
        def lookup(x):
            try:
                return opcodes(x).name
            except ValueError:
                return '('+str(x)+')'
        parts = []
        for op, data in ops:
            if data is not None:
                # Attempt to make a friendly string, or fail to hex
                try:
                    astext = data.decode('utf8')

                    friendlystring = repr(astext)

                    # if too many escaped characters, it's too ugly!
                    if friendlystring.count('\\')*3 > len(astext):
                        friendlystring = None
                except:
                    friendlystring = None

                if not friendlystring:
                    friendlystring = data.hex()

                parts.append(lookup(op) + " " + friendlystring)
            else: # isinstance(op, int):
                parts.append(lookup(op))
        return ', '.join(parts)

    def to_script(self):
        return self.script

    def is_opreturn(self):
        ''' Returns True iff this script is an OP_RETURN script (starts with
        the OP_RETURN byte)'''
        return bool(self.script and self.script[0] == opcodes.OP_RETURN)

    def __str__(self):
        return self.to_ui_string(True)

    def __repr__(self):
        return '<ScriptOutput {}>'.format(self.__str__())


    ###########################################
    # Protocol system methods and class attrs #
    ###########################################

    # subclasses of ScriptOutput that handle protocols. Currently this will
    # contain a cashacct.ScriptOutput instance.
    #
    # NOTE: All subclasses of this class must be hashable. Please implement
    # __hash__ for any subclasses. (This is because our is_mine cache in
    # wallet.py assumes all possible types that pass through it are hashable).
    #
    protocol_classes = set()

    def make_complete(self, block_height=None, block_hash=None, txid=None):
        ''' Subclasses implement this, noop here. '''
        pass

    def is_complete(self):
        ''' Subclasses implement this, noop here. '''
        return True

    @classmethod
    def find_protocol_class(cls, script_bytes):
        ''' Scans the protocol_classes set, and if the passed-in script matches
        a known protocol, returns that class, otherwise returns our class. '''
        for c in cls.protocol_classes:
            if c.protocol_match(script_bytes):
                return c
        return __class__

    @staticmethod
    def protocol_factory(script):
        ''' One shot -- find the right class and construct object based on script '''
        return __class__.find_protocol_class(script)(script)


# A namedtuple for easy comparison and unique hashing
class Address(namedtuple("AddressTuple", "hash160 kind")):

    # Address kinds
    ADDR_P2PKH = 0
    ADDR_P2SH = 1
    ADDR_P2CS = 2

    # Address formats
    FMT_LEGACY = 0

    _NUM_FMTS = 1  # <-- Be sure to update this if you add a format above!

    FMT_UI = FMT_LEGACY

    def __new__(cls, hash160, kind):
        assert kind in (cls.ADDR_P2PKH, cls.ADDR_P2SH, cls.ADDR_P2CS)
        hash160 = to_bytes(hash160)
        if kind == cls.ADDR_P2CS:
            assert len(hash160) == 40, "hash must be 40 bytes"
        else:
            assert len(hash160) == 20, "hash must be 20 bytes"
        ret = super().__new__(cls, hash160, kind)
        ret._addr2str_cache = [None] * cls._NUM_FMTS
        return ret

    @classmethod
    def from_string(cls, string, *, net=None):
        '''Construct from an address string.'''
        if net is None: net = constants.net
        # if len(string) > 35:
        #     try:
        #         return cls.from_cashaddr_string(string, net=net)
        #     except ValueError as e:
        #         raise AddressError(str(e))

        try:
            raw = Base58.decode_check(string)
        except Base58Error as e:
            raise AddressError(str(e))

        # Require version byte(s) plus hash160.
        if len(raw) != 21:
            raise AddressError('invalid address: {}'.format(string))

        verbyte, hash160 = raw[0], raw[1:]
        if verbyte in [net.ADDRTYPE_P2PKH,
                       net.ADDRTYPE_P2PKH_BITPAY]:
            kind = cls.ADDR_P2PKH
        elif verbyte in [net.ADDRTYPE_P2SH,
                         net.ADDRTYPE_P2SH_BITPAY]:
            kind = cls.ADDR_P2SH
        elif verbyte in [net.ADDRTYPE_P2CS]:
            kind = cls.ADDR_P2CS
        else:
            raise AddressError('unknown version byte: {}'.format(verbyte))

        return cls(hash160, kind)

    @classmethod
    def is_valid(cls, string, *, net=None):
        if net is None: net = constants.net
        try:
            cls.from_string(string, net=net)
            return True
        except Exception:
            return False

    @classmethod
    def from_strings(cls, strings, *, net=None):
        '''Construct a list from an iterable of strings.'''
        if net is None: net = constants.net
        return [cls.from_string(string, net=net) for string in strings]

    @classmethod
    def from_pubkey(cls, pubkey):
        '''Returns a P2PKH address from a public key.  The public key can
        be bytes or a hex string.'''
        if isinstance(pubkey, str):
            pubkey = hex_to_bytes(pubkey)
        PublicKey.validate(pubkey)
        return cls(hash160(pubkey), cls.ADDR_P2PKH)

    @classmethod
    def from_pubkey(cls, pubkey, pubkey2):
        '''Returns a P2CS address from a pair of public keys.  The public keys can
        be bytes or a hex string.'''
        if isinstance(pubkey, str):
            pubkey = hex_to_bytes(pubkey)
        if isinstance(pubkey2, str):
            pubkey2 = hex_to_bytes(pubkey2)
        PublicKey.validate(pubkey)
        PublicKey.validate(pubkey2)
        return cls(hash160(pubkey + pubkey2), cls.ADDR_P2CS)

    @classmethod
    def from_P2PKH_hash(cls, hash160):
        '''Construct from a P2PKH hash160.'''
        return cls(hash160, cls.ADDR_P2PKH)

    @classmethod
    def from_P2PKH_hash(cls, hash160, hash160_2):
        '''Construct from a P2PKH hash160.'''
        return cls(hash160 + hash160_2, cls.ADDR_P2CS)

    @classmethod
    def from_P2SH_hash(cls, hash160):
        '''Construct from a P2PKH hash160.'''
        return cls(hash160, cls.ADDR_P2SH)

    @classmethod
    def from_multisig_script(cls, script):
        return cls(hash160(script), cls.ADDR_P2SH)

    @classmethod
    def to_strings(cls, fmt, addrs, *, net=None):
        '''Construct a list of strings from an iterable of Address objects.'''
        if net is None: net = constants.net
        return [addr.to_string(fmt, net=net) for addr in addrs]

    def to_string(self, fmt, *, net=None):
        '''Converts to a string of the given format.'''
        if net is None: net = constants.net
        if net is constants.net:
            try:
                cached = self._addr2str_cache[fmt]
                if cached:
                    return cached
            except (IndexError, TypeError):
                raise AddressError('unrecognised format')

        try:
            cached = None

            if fmt == self.FMT_LEGACY:
                if self.kind == self.ADDR_P2PKH:
                    verbyte = net.ADDRTYPE_P2PKH
                else if self.kind == self.ADDR_P2CS:
                    verbyte = net.ADDRTYPE_P2CS
                else:
                    verbyte = net.ADDRTYPE_P2SH
            else:
                # This should never be reached due to cache-lookup check above. But leaving it in as it's a harmless sanity check.
                raise AddressError('unrecognised format')

            cached = Base58.encode_check(bytes([verbyte]) + self.hash160)
            return cached
        finally:
            if cached and net is constants.net:
                self._addr2str_cache[fmt] = cached

    def to_full_string(self, fmt, *, net=None):
        if net is None: net = constants.net
        text = self.to_string(fmt, net=net)
        return text

    def to_ui_string(self, *, net=None):
        '''Convert to text in the current UI format choice.'''
        if net is None: net = constants.net
        return self.to_string(self.FMT_UI, net=net)

    def to_full_ui_string(self, *, net=None):
        if net is None: net = constants.net
        return self.to_full_string(self.FMT_UI, net=net)

    def to_URI_components(self, *, net=None):
        '''Returns a (scheme, path) pair for building a URI.'''
        if net is None: net = constants.net
        scheme = "navcoin"
        path = self.to_ui_string(net=net)
        return scheme, path

    def to_storage_string(self, *, net=None):
        '''Convert to text in the storage format.'''
        if net is None: net = constants.net
        return self.to_string(self.FMT_LEGACY, net=net)

    def to_script(self):
        '''Return a binary script to pay to the address.'''
        if self.kind == self.ADDR_P2PKH:
            return Script.P2PKH_script(self.hash160)
        else:
            return Script.P2SH_script(self.hash160)

    def to_script_hex(self):
        '''Return a script to pay to the address as a hex string.'''
        return self.to_script().hex()

    def to_scripthash(self):
        '''Returns the hash of the script in binary.'''
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        '''Like other bitcoin hashes this is reversed when written in hex.'''
        return hash_to_hex_str(self.to_scripthash())

    def __str__(self):
        return self.to_ui_string()

    def __repr__(self):
        return '<Address {}>'.format(self.__str__())


def _match_ops(ops, pattern):
    if len(ops) != len(pattern):
        return False
    for op, pop in zip(ops, pattern):
        if pop != op:
            # -1 means 'data push', whose op is an (op, data) tuple
            if pop == -1 and isinstance(op, tuple):
                continue
            return False

    return True


class Script:

    @classmethod
    def P2SH_script(cls, hash160):
        assert len(hash160) == 20
        return P2SH_prefix + hash160 + P2SH_suffix

    @classmethod
    def P2PKH_script(cls, hash160):
        assert len(hash160) == 20
        return P2PKH_prefix + hash160 + P2PKH_suffix

    @classmethod
    def P2PK_script(cls, pubkey):
        return cls.push_data(pubkey) + bytes([opcodes.OP_CHECKSIG])

    @classmethod
    def multisig_script(cls, m, pubkeys):
        '''Returns the script for a pay-to-multisig transaction.'''
        n = len(pubkeys)
        if not 1 <= m <= n <= 15:
            raise ScriptError('{:d} of {:d} multisig script not possible'
                              .format(m, n))
        for pubkey in pubkeys:
            PublicKey.validate(pubkey)   # Can be compressed or not
        # See https://bitcoin.org/en/developer-guide
        # 2 of 3 is: OP_2 pubkey1 pubkey2 pubkey3 OP_3 OP_CHECKMULTISIG
        return (bytes([opcodes.OP_1 + m - 1])
                + b''.join(cls.push_data(pubkey) for pubkey in pubkeys)
                + bytes([opcodes.OP_1 + n - 1, opcodes.OP_CHECKMULTISIG]))

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

    @classmethod
    def get_ops(cls, script):
        ops = []

        # The unpacks or script[n] below throw on truncated scripts
        try:
            n = 0
            while n < len(script):
                op = script[n]
                n += 1

                if op <= opcodes.OP_PUSHDATA4:
                    if op < opcodes.OP_PUSHDATA1:
                        # Raw bytes follow
                        dlen = op
                    elif op == opcodes.OP_PUSHDATA1:
                        # One-byte length, then data
                        dlen = script[n]
                        n += 1
                    elif op == opcodes.OP_PUSHDATA2:
                        # Two-byte length, then data
                        dlen, = struct.unpack('<H', script[n: n + 2])
                        n += 2
                    else: # op == opcodes.OP_PUSHDATA4
                        # Four-byte length, then data
                        dlen, = struct.unpack('<I', script[n: n + 4])
                        n += 4
                    if n + dlen > len(script):
                        raise IndexError
                    data = script[n:n + dlen]
                    n += dlen
                else:
                    data = None

                ops.append((op, data))
        except Exception:
            # Truncated script; e.g. tx_hash
            # ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
            raise ScriptError('truncated script')

        return ops


class Base58Error(Exception):
    '''Exception used for Base58 errors.'''


class Base58:
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
