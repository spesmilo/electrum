#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
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



# Note: The deserialization code originally comes from ABE.

from typing import Sequence, Union

from .util import print_error, profiler

from . import ecc
from . import bitcoin
from .bitcoin import *
import struct
import traceback
import sys

#
# Workalike python implementation of Bitcoin's CDataStream class.
#
from .keystore import xpubkey_to_address, xpubkey_to_pubkey

NO_SIGNATURE = 'ff'
PARTIAL_TXN_HEADER_MAGIC = b'EPTF\xff'


class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """


class UnknownTxinType(Exception):
    pass


class NotRecognizedRedeemScript(Exception):
    pass


class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, _bytes):  # Initialize with string of _bytes
        if self.input is None:
            self.input = bytearray(_bytes)
        else:
            self.input += bytearray(_bytes)

    def read_string(self, encoding='ascii'):
        # Strings are encoded depending on length:
        # 0 to 252 :  1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        length = self.read_compact_size()

        return self.read_bytes(length).decode(encoding)

    def write_string(self, string, encoding='ascii'):
        string = to_bytes(string, encoding)
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor+length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def can_read_more(self) -> bool:
        if not self.input:
            return False
        return self.read_cursor < len(self.input)

    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int16(self): return self._read_num('<h')
    def read_uint16(self): return self._read_num('<H')
    def read_int32(self): return self._read_num('<i')
    def read_uint32(self): return self._read_num('<I')
    def read_int64(self): return self._read_num('<q')
    def read_uint64(self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
    def write_int16(self, val): return self._write_num('<h', val)
    def write_uint16(self, val): return self._write_num('<H', val)
    def write_int32(self, val): return self._write_num('<i', val)
    def write_uint32(self, val): return self._write_num('<I', val)
    def write_int64(self, val): return self._write_num('<q', val)
    def write_uint64(self, val): return self._write_num('<Q', val)

    def read_compact_size(self):
        try:
            size = self.input[self.read_cursor]
            self.read_cursor += 1
            if size == 253:
                size = self._read_num('<H')
            elif size == 254:
                size = self._read_num('<I')
            elif size == 255:
                size = self._read_num('<Q')
            return size
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(bytes([size]))
        elif size < 2**16:
            self.write(b'\xfd')
            self._write_num('<H', size)
        elif size < 2**32:
            self.write(b'\xfe')
            self._write_num('<I', size)
        elif size < 2**64:
            self.write(b'\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        try:
            (i,) = struct.unpack_from(format, self.input, self.read_cursor)
            self.read_cursor += struct.calcsize(format)
        except Exception as e:
            raise SerializationError(e)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


# enum-like type
# From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
class EnumException(Exception):
    pass


class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = { }
        reverseLookup = { }
        i = 0
        uniqueNames = [ ]
        uniqueValues = [ ]
        for x in enumList:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumException("enum name is not a string: " + x)
            if not isinstance(i, int):
                raise EnumException("enum value is not an integer: " + i)
            if x in uniqueNames:
                raise EnumException("enum name is not unique: " + x)
            if i in uniqueValues:
                raise EnumException("enum value is not unique for " + x)
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        if attr not in self.lookup:
            raise AttributeError
        return self.lookup[attr]
    def whatis(self, value):
        return self.reverseLookup[value]


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')

# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]



opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1",76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_NOP1", 0xB0),
    ("OP_CHECKLOCKTIMEVERIFY", 0xB1), ("OP_CHECKSEQUENCEVERIFY", 0xB2),
    "OP_NOP4", "OP_NOP5", "OP_NOP6", "OP_NOP7", "OP_NOP8", "OP_NOP9", "OP_NOP10",
    ("OP_INVALIDOPCODE", 0xFF),
])


def script_GetOp(_bytes : bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                nSize = _bytes[i]
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                (nSize,) = struct.unpack_from('<H', _bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', _bytes, i)
                i += 4
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


def script_GetOpName(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")


def decode_script(bytes):
    result = ''
    for (opcode, vch, i) in script_GetOp(bytes):
        if len(result) > 0: result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += "%d:"%(opcode,)
            result += short_hex(vch)
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False;
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4 and decoded[i][0]>0:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True


def parse_sig(x_sig):
    return [None if x == NO_SIGNATURE else x for x in x_sig]

def safe_parse_pubkey(x):
    try:
        return xpubkey_to_pubkey(x)
    except:
        return x

def parse_scriptSig(d, _bytes):
    try:
        decoded = [ x for x in script_GetOp(_bytes) ]
    except Exception as e:
        # coinbase transactions raise an exception
        print_error("parse_scriptSig: cannot find address in input script (coinbase?)",
                    bh2u(_bytes))
        return

    match = [ opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        item = decoded[0][1]
        if item[0] == 0:
            # segwit embedded into p2sh
            # witness version 0
            d['address'] = bitcoin.hash160_to_p2sh(bitcoin.hash_160(item))
            if len(item) == 22:
                d['type'] = 'p2wpkh-p2sh'
            elif len(item) == 34:
                d['type'] = 'p2wsh-p2sh'
            else:
                print_error("unrecognized txin type", bh2u(item))
        elif opcodes.OP_1 <= item[0] <= opcodes.OP_16:
            # segwit embedded into p2sh
            # witness version 1-16
            pass
        else:
            # assert item[0] == 0x30
            # pay-to-pubkey
            d['type'] = 'p2pk'
            d['address'] = "(pubkey)"
            d['signatures'] = [bh2u(item)]
            d['num_sig'] = 1
            d['x_pubkeys'] = ["(pubkey)"]
            d['pubkeys'] = ["(pubkey)"]
        return

    # p2pkh TxIn transactions push a signature
    # (71-73 bytes) and then their public key
    # (33 or 65 bytes) onto the stack:
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = bh2u(decoded[0][1])
        x_pubkey = bh2u(decoded[1][1])
        try:
            signatures = parse_sig([sig])
            pubkey, address = xpubkey_to_address(x_pubkey)
        except:
            print_error("parse_scriptSig: cannot find address in input script (p2pkh?)",
                        bh2u(_bytes))
            return
        d['type'] = 'p2pkh'
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, m of n
    match = [ opcodes.OP_0 ] + [ opcodes.OP_PUSHDATA4 ] * (len(decoded) - 1)
    if match_decoded(decoded, match):
        x_sig = [bh2u(x[1]) for x in decoded[1:-1]]
        redeem_script_unsanitized = decoded[-1][1]  # for partial multisig txn, this has x_pubkeys
        try:
            m, n, x_pubkeys, pubkeys, redeem_script = parse_redeemScript_multisig(redeem_script_unsanitized)
        except NotRecognizedRedeemScript:
            print_error("parse_scriptSig: cannot find address in input script (p2sh?)",
                        bh2u(_bytes))
            # we could still guess:
            # d['address'] = hash160_to_p2sh(hash_160(decoded[-1][1]))
            return
        # write result in d
        d['type'] = 'p2sh'
        d['num_sig'] = m
        d['signatures'] = parse_sig(x_sig)
        d['x_pubkeys'] = x_pubkeys
        d['pubkeys'] = pubkeys
        d['redeem_script'] = redeem_script
        d['address'] = hash160_to_p2sh(hash_160(bfh(redeem_script)))
        return

    # custom partial format for imported addresses
    match = [ opcodes.OP_INVALIDOPCODE, opcodes.OP_0, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        x_pubkey = bh2u(decoded[2][1])
        pubkey, address = xpubkey_to_address(x_pubkey)
        d['type'] = 'address'
        d['address'] = address
        d['num_sig'] = 1
        d['x_pubkeys'] = [x_pubkey]
        d['pubkeys'] = None  # get_sorted_pubkeys will populate this
        d['signatures'] = [None]
        return

    print_error("parse_scriptSig: cannot find address in input script (unknown)",
                bh2u(_bytes))


def parse_redeemScript_multisig(redeem_script: bytes):
    dec2 = [ x for x in script_GetOp(redeem_script) ]
    try:
        m = dec2[0][0] - opcodes.OP_1 + 1
        n = dec2[-2][0] - opcodes.OP_1 + 1
    except IndexError:
        raise NotRecognizedRedeemScript()
    op_m = opcodes.OP_1 + m - 1
    op_n = opcodes.OP_1 + n - 1
    match_multisig = [ op_m ] + [opcodes.OP_PUSHDATA4]*n + [ op_n, opcodes.OP_CHECKMULTISIG ]
    if not match_decoded(dec2, match_multisig):
        raise NotRecognizedRedeemScript()
    x_pubkeys = [bh2u(x[1]) for x in dec2[1:-2]]
    pubkeys = [safe_parse_pubkey(x) for x in x_pubkeys]
    redeem_script2 = bfh(multisig_script(x_pubkeys, m))
    if redeem_script2 != redeem_script:
        raise NotRecognizedRedeemScript()
    redeem_script_sanitized = multisig_script(pubkeys, m)
    return m, n, x_pubkeys, pubkeys, redeem_script_sanitized


def get_address_from_output_script(_bytes, *, net=None):
    decoded = [x for x in script_GetOp(_bytes)]

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]
    if match_decoded(decoded, match):
        return TYPE_PUBKEY, bh2u(decoded[0][1])

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [ opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash160_to_p2pkh(decoded[2][1], net=net)

    # p2sh
    match = [ opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL ]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash160_to_p2sh(decoded[1][1], net=net)

    # segwit address
    possible_witness_versions = [opcodes.OP_0] + list(range(opcodes.OP_1, opcodes.OP_16 + 1))
    for witver, opcode in enumerate(possible_witness_versions):
        match = [ opcode, opcodes.OP_PUSHDATA4 ]
        if match_decoded(decoded, match):
            return TYPE_ADDRESS, hash_to_segwit_addr(decoded[1][1], witver=witver, net=net)

    return TYPE_SCRIPT, bh2u(_bytes)


def parse_input(vds, full_parse: bool):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    sequence = vds.read_uint32()
    d['prevout_hash'] = prevout_hash
    d['prevout_n'] = prevout_n
    d['scriptSig'] = bh2u(scriptSig)
    d['sequence'] = sequence
    d['type'] = 'unknown' if prevout_hash != '00'*32 else 'coinbase'
    d['address'] = None
    d['num_sig'] = 0
    if not full_parse:
        return d
    d['x_pubkeys'] = []
    d['pubkeys'] = []
    d['signatures'] = {}
    if d['type'] != 'coinbase' and scriptSig:
        try:
            parse_scriptSig(d, scriptSig)
        except BaseException:
            traceback.print_exc(file=sys.stderr)
            print_error('failed to parse scriptSig', bh2u(scriptSig))
    return d


def construct_witness(items: Sequence[Union[str, int, bytes]]) -> str:
    """Constructs a witness from the given stack items."""
    witness = var_int(len(items))
    for item in items:
        if type(item) is int:
            item = bitcoin.script_num_to_hex(item)
        elif type(item) is bytes:
            item = bh2u(item)
        witness += bitcoin.witness_push(item)
    return witness


def parse_witness(vds, txin, full_parse: bool):
    n = vds.read_compact_size()
    if n == 0:
        txin['witness'] = '00'
        return
    if n == 0xffffffff:
        txin['value'] = vds.read_uint64()
        txin['witness_version'] = vds.read_uint16()
        n = vds.read_compact_size()
    # now 'n' is the number of items in the witness
    w = list(bh2u(vds.read_bytes(vds.read_compact_size())) for i in range(n))
    txin['witness'] = construct_witness(w)
    if not full_parse:
        return

    try:
        if txin.get('witness_version', 0) != 0:
            raise UnknownTxinType()
        if txin['type'] == 'coinbase':
            pass
        elif txin['type'] == 'address':
            pass
        elif txin['type'] == 'p2wsh-p2sh' or n > 2:
            witness_script_unsanitized = w[-1]  # for partial multisig txn, this has x_pubkeys
            try:
                m, n, x_pubkeys, pubkeys, witness_script = parse_redeemScript_multisig(bfh(witness_script_unsanitized))
            except NotRecognizedRedeemScript:
                raise UnknownTxinType()
            txin['signatures'] = parse_sig(w[1:-1])
            txin['num_sig'] = m
            txin['x_pubkeys'] = x_pubkeys
            txin['pubkeys'] = pubkeys
            txin['witness_script'] = witness_script
            if not txin.get('scriptSig'):  # native segwit script
                txin['type'] = 'p2wsh'
                txin['address'] = bitcoin.script_to_p2wsh(witness_script)
        elif txin['type'] == 'p2wpkh-p2sh' or n == 2:
            txin['num_sig'] = 1
            txin['x_pubkeys'] = [w[1]]
            txin['pubkeys'] = [safe_parse_pubkey(w[1])]
            txin['signatures'] = parse_sig([w[0]])
            if not txin.get('scriptSig'):  # native segwit script
                txin['type'] = 'p2wpkh'
                txin['address'] = bitcoin.public_key_to_p2wpkh(bfh(txin['pubkeys'][0]))
        else:
            raise UnknownTxinType()
    except UnknownTxinType:
        txin['type'] = 'unknown'
    except BaseException:
        txin['type'] = 'unknown'
        traceback.print_exc(file=sys.stderr)
        print_error('failed to parse witness', txin.get('witness'))


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    if d['value'] > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
        raise SerializationError('invalid output amount (too large)')
    if d['value'] < 0:
        raise SerializationError('invalid output amount (negative)')
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = bh2u(scriptPubKey)
    d['prevout_n'] = i
    return d


def deserialize(raw: str, force_full_parse=False) -> dict:
    raw_bytes = bfh(raw)
    d = {}
    if raw_bytes[:5] == PARTIAL_TXN_HEADER_MAGIC:
        d['partial'] = is_partial = True
        partial_format_version = raw_bytes[5]
        if partial_format_version != 0:
            raise SerializationError('unknown tx partial serialization format version: {}'
                                     .format(partial_format_version))
        raw_bytes = raw_bytes[6:]
    else:
        d['partial'] = is_partial = False
    full_parse = force_full_parse or is_partial
    vds = BCDataStream()
    vds.write(raw_bytes)
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    is_segwit = (n_vin == 0)
    if is_segwit:
        marker = vds.read_bytes(1)
        if marker != b'\x01':
            raise ValueError('invalid txn marker byte: {}'.format(marker))
        n_vin = vds.read_compact_size()
    d['segwit_ser'] = is_segwit
    d['inputs'] = [parse_input(vds, full_parse=full_parse) for i in range(n_vin)]
    n_vout = vds.read_compact_size()
    d['outputs'] = [parse_output(vds, i) for i in range(n_vout)]
    if is_segwit:
        for i in range(n_vin):
            txin = d['inputs'][i]
            parse_witness(vds, txin, full_parse=full_parse)
    d['lockTime'] = vds.read_uint32()
    if vds.can_read_more():
        raise SerializationError('extra junk at the end')
    return d


# pay & redeem scripts



def multisig_script(public_keys: Sequence[str], m: int) -> str:
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = format(opcodes.OP_1 + m - 1, 'x')
    op_n = format(opcodes.OP_1 + n - 1, 'x')
    keylist = [op_push(len(k)//2) + k for k in public_keys]
    return op_m + ''.join(keylist) + op_n + 'ae'




class Transaction:

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw):
        if raw is None:
            self.raw = None
        elif isinstance(raw, str):
            self.raw = raw.strip() if raw else None
        elif isinstance(raw, dict):
            self.raw = raw['hex']
        else:
            raise Exception("cannot initialize transaction", raw)
        self._inputs = None
        self._outputs = None
        self.locktime = 0
        self.version = 1
        # by default we assume this is a partial txn;
        # this value will get properly set when deserializing
        self.is_partial_originally = True
        self._segwit_ser = None  # None means "don't know"

    def update(self, raw):
        self.raw = raw
        self._inputs = None
        self.deserialize()

    def inputs(self):
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self):
        if self._outputs is None:
            self.deserialize()
        return self._outputs

    @classmethod
    def get_sorted_pubkeys(self, txin):
        # sort pubkeys and x_pubkeys, using the order of pubkeys
        if txin['type'] == 'coinbase':
            return [], []
        x_pubkeys = txin['x_pubkeys']
        pubkeys = txin.get('pubkeys')
        if pubkeys is None:
            pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
            pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
            txin['pubkeys'] = pubkeys = list(pubkeys)
            txin['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
        return pubkeys, x_pubkeys

    def update_signatures(self, signatures: Sequence[str]):
        """Add new signatures to a transaction

        `signatures` is expected to be a list of sigs with signatures[i]
        intended for self._inputs[i].
        This is used by the Trezor, KeepKey an Safe-T plugins.
        """
        if self.is_complete():
            return
        if len(self.inputs()) != len(signatures):
            raise Exception('expected {} signatures; got {}'.format(len(self.inputs()), len(signatures)))
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            sig = signatures[i]
            if sig in txin.get('signatures'):
                continue
            pre_hash = Hash(bfh(self.serialize_preimage(i)))
            sig_string = ecc.sig_string_from_der_sig(bfh(sig[:-2]))
            for recid in range(4):
                try:
                    public_key = ecc.ECPubkey.from_sig_string(sig_string, recid, pre_hash)
                except ecc.InvalidECPointException:
                    # the point might not be on the curve for some recid values
                    continue
                pubkey_hex = public_key.get_public_key_hex(compressed=True)
                if pubkey_hex in pubkeys:
                    try:
                        public_key.verify_message_hash(sig_string, pre_hash)
                    except Exception:
                        traceback.print_exc(file=sys.stderr)
                        continue
                    j = pubkeys.index(pubkey_hex)
                    print_error("adding sig", i, j, pubkey_hex, sig)
                    self.add_signature_to_txin(i, j, sig)
                    #self._inputs[i]['x_pubkeys'][j] = pubkey
                    break
        # redo raw
        self.raw = self.serialize()

    def add_signature_to_txin(self, i, signingPos, sig):
        txin = self._inputs[i]
        txin['signatures'][signingPos] = sig
        txin['scriptSig'] = None  # force re-serialization
        txin['witness'] = None    # force re-serialization
        self.raw = None

    def deserialize(self, force_full_parse=False):
        if self.raw is None:
            return
            #self.raw = self.serialize()
        if self._inputs is not None:
            return
        d = deserialize(self.raw, force_full_parse)
        self._inputs = d['inputs']
        self._outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        self.locktime = d['lockTime']
        self.version = d['version']
        self.is_partial_originally = d['partial']
        self._segwit_ser = d['segwit_ser']
        return d

    @classmethod
    def from_io(klass, inputs, outputs, locktime=0):
        self = klass(None)
        self._inputs = inputs
        self._outputs = outputs
        self.locktime = locktime
        return self

    @classmethod
    def pay_script(self, output_type, addr):
        if output_type == TYPE_SCRIPT:
            return addr
        elif output_type == TYPE_ADDRESS:
            return bitcoin.address_to_script(addr)
        elif output_type == TYPE_PUBKEY:
            return bitcoin.public_key_to_p2pk_script(addr)
        else:
            raise TypeError('Unknown output type')

    @classmethod
    def estimate_pubkey_size_from_x_pubkey(cls, x_pubkey):
        try:
            if x_pubkey[0:2] in ['02', '03']:  # compressed pubkey
                return 0x21
            elif x_pubkey[0:2] == '04':  # uncompressed pubkey
                return 0x41
            elif x_pubkey[0:2] == 'ff':  # bip32 extended pubkey
                return 0x21
            elif x_pubkey[0:2] == 'fe':  # old electrum extended pubkey
                return 0x41
        except Exception as e:
            pass
        return 0x21  # just guess it is compressed

    @classmethod
    def estimate_pubkey_size_for_txin(cls, txin):
        pubkeys = txin.get('pubkeys', [])
        x_pubkeys = txin.get('x_pubkeys', [])
        if pubkeys and len(pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(pubkeys[0])
        elif x_pubkeys and len(x_pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(x_pubkeys[0])
        else:
            return 0x21  # just guess it is compressed

    @classmethod
    def get_siglist(self, txin, estimate_size=False):
        # if we have enough signatures, we use the actual pubkeys
        # otherwise, use extended pubkeys (with bip32 derivation)
        if txin['type'] == 'coinbase':
            return [], []
        num_sig = txin.get('num_sig', 1)
        if estimate_size:
            pubkey_size = self.estimate_pubkey_size_for_txin(txin)
            pk_list = ["00" * pubkey_size] * len(txin.get('x_pubkeys', [None]))
            # we assume that signature will be 0x48 bytes long
            sig_list = [ "00" * 0x48 ] * num_sig
        else:
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            x_signatures = txin['signatures']
            signatures = list(filter(None, x_signatures))
            is_complete = len(signatures) == num_sig
            if is_complete:
                pk_list = pubkeys
                sig_list = signatures
            else:
                pk_list = x_pubkeys
                sig_list = [sig if sig else NO_SIGNATURE for sig in x_signatures]
        return pk_list, sig_list

    @classmethod
    def serialize_witness(self, txin, estimate_size=False):
        _type = txin['type']
        if not self.is_segwit_input(txin) and not self.is_input_value_needed(txin):
            return '00'
        if _type == 'coinbase':
            return txin['witness']

        witness = txin.get('witness', None)
        if witness is None or estimate_size:
            if _type == 'address' and estimate_size:
                _type = self.guess_txintype_from_address(txin['address'])
            pubkeys, sig_list = self.get_siglist(txin, estimate_size)
            if _type in ['p2wpkh', 'p2wpkh-p2sh']:
                witness = construct_witness([sig_list[0], pubkeys[0]])
            elif _type in ['p2wsh', 'p2wsh-p2sh']:
                witness_script = multisig_script(pubkeys, txin['num_sig'])
                witness = construct_witness([0] + sig_list + [witness_script])
            else:
                witness = txin.get('witness', '00')

        if self.is_txin_complete(txin) or estimate_size:
            partial_format_witness_prefix = ''
        else:
            input_value = int_to_hex(txin['value'], 8)
            witness_version = int_to_hex(txin.get('witness_version', 0), 2)
            partial_format_witness_prefix = var_int(0xffffffff) + input_value + witness_version
        return partial_format_witness_prefix + witness

    @classmethod
    def is_segwit_input(cls, txin, guess_for_address=False):
        _type = txin['type']
        if _type == 'address' and guess_for_address:
            _type = cls.guess_txintype_from_address(txin['address'])
        has_nonzero_witness = txin.get('witness', '00') not in ('00', None)
        return cls.is_segwit_inputtype(_type) or has_nonzero_witness

    @classmethod
    def is_segwit_inputtype(cls, txin_type):
        return txin_type in ('p2wpkh', 'p2wpkh-p2sh', 'p2wsh', 'p2wsh-p2sh')

    @classmethod
    def is_input_value_needed(cls, txin):
        return cls.is_segwit_input(txin) or txin['type'] == 'address'

    @classmethod
    def guess_txintype_from_address(cls, addr):
        # It's not possible to tell the script type in general
        # just from an address.
        # - "1" addresses are of course p2pkh
        # - "3" addresses are p2sh but we don't know the redeem script..
        # - "bc1" addresses (if they are 42-long) are p2wpkh
        # - "bc1" addresses that are 62-long are p2wsh but we don't know the script..
        # If we don't know the script, we _guess_ it is pubkeyhash.
        # As this method is used e.g. for tx size estimation,
        # the estimation will not be precise.
        witver, witprog = segwit_addr.decode(constants.net.SEGWIT_HRP, addr)
        if witprog is not None:
            return 'p2wpkh'
        addrtype, hash_160 = b58_address_to_hash160(addr)
        if addrtype == constants.net.ADDRTYPE_P2PKH:
            return 'p2pkh'
        elif addrtype == constants.net.ADDRTYPE_P2SH:
            return 'p2wpkh-p2sh'

    @classmethod
    def input_script(self, txin, estimate_size=False):
        _type = txin['type']
        if _type == 'coinbase':
            return txin['scriptSig']

        # If there is already a saved scriptSig, just return that.
        # This allows manual creation of txins of any custom type.
        # However, if the txin is not complete, we might have some garbage
        # saved from our partial txn ser format, so we re-serialize then.
        script_sig = txin.get('scriptSig', None)
        if script_sig is not None and self.is_txin_complete(txin):
            return script_sig

        pubkeys, sig_list = self.get_siglist(txin, estimate_size)
        script = ''.join(push_script(x) for x in sig_list)
        if _type == 'address' and estimate_size:
            _type = self.guess_txintype_from_address(txin['address'])
        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            # put op_0 before script
            script = '00' + script
            redeem_script = multisig_script(pubkeys, txin['num_sig'])
            script += push_script(redeem_script)
        elif _type == 'p2pkh':
            script += push_script(pubkeys[0])
        elif _type in ['p2wpkh', 'p2wsh']:
            return ''
        elif _type == 'p2wpkh-p2sh':
            pubkey = safe_parse_pubkey(pubkeys[0])
            scriptSig = bitcoin.p2wpkh_nested_script(pubkey)
            return push_script(scriptSig)
        elif _type == 'p2wsh-p2sh':
            if estimate_size:
                witness_script = ''
            else:
                witness_script = self.get_preimage_script(txin)
            scriptSig = bitcoin.p2wsh_nested_script(witness_script)
            return push_script(scriptSig)
        elif _type == 'address':
            return 'ff00' + push_script(pubkeys[0])  # fd extended pubkey
        elif _type == 'unknown':
            return txin['scriptSig']
        return script

    @classmethod
    def is_txin_complete(cls, txin):
        if txin['type'] == 'coinbase':
            return True
        num_sig = txin.get('num_sig', 1)
        if num_sig == 0:
            return True
        x_signatures = txin['signatures']
        signatures = list(filter(None, x_signatures))
        return len(signatures) == num_sig

    @classmethod
    def get_preimage_script(self, txin):
        preimage_script = txin.get('preimage_script', None)
        if preimage_script is not None:
            return preimage_script

        pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
        if txin['type'] == 'p2pkh':
            return bitcoin.address_to_script(txin['address'])
        elif txin['type'] in ['p2sh', 'p2wsh', 'p2wsh-p2sh']:
            return multisig_script(pubkeys, txin['num_sig'])
        elif txin['type'] in ['p2wpkh', 'p2wpkh-p2sh']:
            pubkey = pubkeys[0]
            pkh = bh2u(bitcoin.hash_160(bfh(pubkey)))
            return '76a9' + push_script(pkh) + '88ac'
        elif txin['type'] == 'p2pk':
            pubkey = pubkeys[0]
            return bitcoin.public_key_to_p2pk_script(pubkey)
        else:
            raise TypeError('Unknown txin type', txin['type'])

    @classmethod
    def serialize_outpoint(self, txin):
        return bh2u(bfh(txin['prevout_hash'])[::-1]) + int_to_hex(txin['prevout_n'], 4)

    @classmethod
    def get_outpoint_from_txin(cls, txin):
        if txin['type'] == 'coinbase':
            return None
        prevout_hash = txin['prevout_hash']
        prevout_n = txin['prevout_n']
        return prevout_hash + ':%d' % prevout_n

    @classmethod
    def serialize_input(self, txin, script):
        # Prev hash and index
        s = self.serialize_outpoint(txin)
        # Script length, script, sequence
        s += var_int(len(script)//2)
        s += script
        s += int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
        return s

    def set_rbf(self, rbf):
        nSequence = 0xffffffff - (2 if rbf else 1)
        for txin in self.inputs():
            txin['sequence'] = nSequence

    def BIP_LI01_sort(self):
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self._inputs.sort(key = lambda i: (i['prevout_hash'], i['prevout_n']))
        self._outputs.sort(key = lambda o: (o[2], self.pay_script(o[0], o[1])))

    def serialize_output(self, output):
        output_type, addr, amount = output
        s = int_to_hex(amount, 8)
        script = self.pay_script(output_type, addr)
        s += var_int(len(script)//2)
        s += script
        return s

    def serialize_preimage(self, i):
        nVersion = int_to_hex(self.version, 4)
        nHashType = int_to_hex(1, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txin = inputs[i]
        # TODO: py3 hex
        if self.is_segwit_input(txin):
            hashPrevouts = bh2u(Hash(bfh(''.join(self.serialize_outpoint(txin) for txin in inputs))))
            hashSequence = bh2u(Hash(bfh(''.join(int_to_hex(txin.get('sequence', 0xffffffff - 1), 4) for txin in inputs))))
            hashOutputs = bh2u(Hash(bfh(''.join(self.serialize_output(o) for o in outputs))))
            outpoint = self.serialize_outpoint(txin)
            preimage_script = self.get_preimage_script(txin)
            scriptCode = var_int(len(preimage_script) // 2) + preimage_script
            amount = int_to_hex(txin['value'], 8)
            nSequence = int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
            preimage = nVersion + hashPrevouts + hashSequence + outpoint + scriptCode + amount + nSequence + hashOutputs + nLocktime + nHashType
        else:
            txins = var_int(len(inputs)) + ''.join(self.serialize_input(txin, self.get_preimage_script(txin) if i==k else '') for k, txin in enumerate(inputs))
            txouts = var_int(len(outputs)) + ''.join(self.serialize_output(o) for o in outputs)
            preimage = nVersion + txins + txouts + nLocktime + nHashType
        return preimage

    def is_segwit(self, guess_for_address=False):
        if not self.is_partial_originally:
            return self._segwit_ser
        return any(self.is_segwit_input(x, guess_for_address=guess_for_address) for x in self.inputs())

    def serialize(self, estimate_size=False, witness=True):
        network_ser = self.serialize_to_network(estimate_size, witness)
        if estimate_size:
            return network_ser
        if self.is_partial_originally and not self.is_complete():
            partial_format_version = '00'
            return bh2u(PARTIAL_TXN_HEADER_MAGIC) + partial_format_version + network_ser
        else:
            return network_ser

    def serialize_to_network(self, estimate_size=False, witness=True):
        nVersion = int_to_hex(self.version, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txins = var_int(len(inputs)) + ''.join(self.serialize_input(txin, self.input_script(txin, estimate_size)) for txin in inputs)
        txouts = var_int(len(outputs)) + ''.join(self.serialize_output(o) for o in outputs)
        use_segwit_ser_for_estimate_size = estimate_size and self.is_segwit(guess_for_address=True)
        use_segwit_ser_for_actual_use = not estimate_size and \
                                        (self.is_segwit() or any(txin['type'] == 'address' for txin in inputs))
        use_segwit_ser = use_segwit_ser_for_estimate_size or use_segwit_ser_for_actual_use
        if witness and use_segwit_ser:
            marker = '00'
            flag = '01'
            witness = ''.join(self.serialize_witness(x, estimate_size) for x in inputs)
            return nVersion + marker + flag + txins + txouts + witness + nLocktime
        else:
            return nVersion + txins + txouts + nLocktime

    def txid(self):
        self.deserialize()
        all_segwit = all(self.is_segwit_input(x) for x in self.inputs())
        if not all_segwit and not self.is_complete():
            return None
        ser = self.serialize_to_network(witness=False)
        return bh2u(Hash(bfh(ser))[::-1])

    def wtxid(self):
        self.deserialize()
        if not self.is_complete():
            return None
        ser = self.serialize_to_network(witness=True)
        return bh2u(Hash(bfh(ser))[::-1])

    def add_inputs(self, inputs):
        self._inputs.extend(inputs)
        self.raw = None

    def add_outputs(self, outputs):
        self._outputs.extend(outputs)
        self.raw = None

    def input_value(self):
        return sum(x['value'] for x in self.inputs())

    def output_value(self):
        return sum(val for tp, addr, val in self.outputs())

    def get_fee(self):
        return self.input_value() - self.output_value()

    def is_final(self):
        return not any([x.get('sequence', 0xffffffff - 1) < 0xffffffff - 1 for x in self.inputs()])

    @profiler
    def estimated_size(self):
        """Return an estimated virtual tx size in vbytes.
        BIP-0141 defines 'Virtual transaction size' to be weight/4 rounded up.
        This definition is only for humans, and has little meaning otherwise.
        If we wanted sub-byte precision, fee calculation should use transaction
        weights, but for simplicity we approximate that with (virtual_size)x4
        """
        weight = self.estimated_weight()
        return self.virtual_size_from_weight(weight)

    @classmethod
    def estimated_input_weight(cls, txin, is_segwit_tx):
        '''Return an estimate of serialized input weight in weight units.'''
        script = cls.input_script(txin, True)
        input_size = len(cls.serialize_input(txin, script)) // 2

        if cls.is_segwit_input(txin, guess_for_address=True):
            witness_size = len(cls.serialize_witness(txin, True)) // 2
        else:
            witness_size = 1 if is_segwit_tx else 0

        return 4 * input_size + witness_size

    @classmethod
    def estimated_output_size(cls, address):
        """Return an estimate of serialized output size in bytes."""
        script = bitcoin.address_to_script(address)
        # 8 byte value + 1 byte script len + script
        return 9 + len(script) // 2

    @classmethod
    def virtual_size_from_weight(cls, weight):
        return weight // 4 + (weight % 4 > 0)

    def estimated_total_size(self):
        """Return an estimated total transaction size in bytes."""
        return len(self.serialize(True)) // 2 if not self.is_complete() or self.raw is None else len(self.raw) // 2  # ASCII hex string

    def estimated_witness_size(self):
        """Return an estimate of witness size in bytes."""
        estimate = not self.is_complete()
        if not self.is_segwit(guess_for_address=estimate):
            return 0
        inputs = self.inputs()
        witness = ''.join(self.serialize_witness(x, estimate) for x in inputs)
        witness_size = len(witness) // 2 + 2  # include marker and flag
        return witness_size

    def estimated_base_size(self):
        """Return an estimated base transaction size in bytes."""
        return self.estimated_total_size() - self.estimated_witness_size()

    def estimated_weight(self):
        """Return an estimate of transaction weight."""
        total_tx_size = self.estimated_total_size()
        base_tx_size = self.estimated_base_size()
        return 3 * base_tx_size + total_tx_size

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs():
            if txin['type'] == 'coinbase':
                continue
            signatures = list(filter(None, txin.get('signatures',[])))
            s += len(signatures)
            r += txin.get('num_sig',-1)
        return s, r

    def is_complete(self):
        if not self.is_partial_originally:
            return True
        s, r = self.signature_count()
        return r == s

    def sign(self, keypairs) -> None:
        # keypairs:  (x_)pubkey -> secret_bytes
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            for j, (pubkey, x_pubkey) in enumerate(zip(pubkeys, x_pubkeys)):
                if self.is_txin_complete(txin):
                    break
                if pubkey in keypairs:
                    _pubkey = pubkey
                elif x_pubkey in keypairs:
                    _pubkey = x_pubkey
                else:
                    continue
                print_error("adding signature for", _pubkey)
                sec, compressed = keypairs.get(_pubkey)
                sig = self.sign_txin(i, sec)
                self.add_signature_to_txin(i, j, sig)

        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()

    def sign_txin(self, txin_index, privkey_bytes) -> str:
        pre_hash = Hash(bfh(self.serialize_preimage(txin_index)))
        privkey = ecc.ECPrivkey(privkey_bytes)
        sig = privkey.sign_transaction(pre_hash)
        sig = bh2u(sig) + '01'
        return sig

    def get_outputs(self):
        """convert pubkeys to addresses"""
        o = []
        for type, x, v in self.outputs():
            if type == TYPE_ADDRESS:
                addr = x
            elif type == TYPE_PUBKEY:
                # TODO do we really want this conversion? it's not really that address after all
                addr = bitcoin.public_key_to_p2pkh(bfh(x))
            else:
                addr = 'SCRIPT ' + x
            o.append((addr,v))      # consider using yield (addr, v)
        return o

    def get_output_addresses(self):
        return [addr for addr, val in self.get_outputs()]


    def has_address(self, addr):
        return (addr in self.get_output_addresses()) or (addr in (tx.get("address") for tx in self.inputs()))

    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete(),
            'final': self.is_final(),
        }
        return out


def tx_from_str(txt):
    "json or raw hexadecimal"
    import json
    txt = txt.strip()
    if not txt:
        raise ValueError("empty string")
    try:
        bfh(txt)
        is_hex = True
    except:
        is_hex = False
    if is_hex:
        return txt
    tx_dict = json.loads(str(txt))
    assert "hex" in tx_dict.keys()
    return tx_dict["hex"]
