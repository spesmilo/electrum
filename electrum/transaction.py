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

import struct
import traceback
import sys
import io
import base64
from typing import (Sequence, Union, NamedTuple, Tuple, Optional, Iterable,
                    Callable, List, Dict, Set, TYPE_CHECKING, Mapping)
from collections import defaultdict
from enum import IntEnum
import itertools
import binascii
import copy

from . import ecc, bitcoin, constants, segwit_addr, bip32
from .bip32 import BIP32Node
from .i18n import _
from .util import profiler, to_bytes, bfh, chunks, is_hex_str, parse_max_spend
from .bitcoin import (TYPE_ADDRESS, TYPE_SCRIPT, hash_160,
                      hash160_to_p2sh, hash160_to_p2pkh, hash_to_segwit_addr,
                      var_int, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC, COIN,
                      opcodes, base_decode,
                      base_encode, construct_witness, construct_script,
                      taproot_tweak_seckey)
from .crypto import sha256d, sha256
from .logging import get_logger
from .util import ShortID, OldTaskGroup
from .bitcoin import DummyAddress
from .descriptor import Descriptor, MissingSolutionPiece, create_dummy_descriptor_from_address
from .json_db import stored_in

if TYPE_CHECKING:
    from .wallet import Abstract_Wallet
    from .network import Network
    from .simple_config import SimpleConfig


_logger = get_logger(__name__)
DEBUG_PSBT_PARSING = False


_NEEDS_RECALC = ...  # sentinel value


class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """


class UnknownTxinType(Exception):
    pass


class BadHeaderMagic(SerializationError):
    pass


class UnexpectedEndOfStream(SerializationError):
    pass


class PSBTInputConsistencyFailure(SerializationError):
    pass


class MalformedBitcoinScript(Exception):
    pass


class MissingTxInputAmount(Exception):
    pass


class TxinDataFetchProgress(NamedTuple):
    num_tasks_done: int
    num_tasks_total: int
    has_errored: bool
    has_finished: bool


class Sighash(IntEnum):
    # note: this is not an IntFlag, as ALL|NONE != SINGLE

    DEFAULT = 0  # taproot only (bip-0341)
    ALL = 1
    NONE = 2
    SINGLE = 3
    ANYONECANPAY = 0x80

    @classmethod
    def is_valid(cls, sighash: int, *, is_taproot: bool = False) -> bool:
        valid_flags = {
            0x01, 0x02, 0x03,
            0x81, 0x82, 0x83,
        }
        if is_taproot:
            valid_flags.add(0x00)
        return sighash in valid_flags

    @classmethod
    def to_sigbytes(cls, sighash: int) -> bytes:
        if sighash == Sighash.DEFAULT:
            return b""
        return sighash.to_bytes(length=1, byteorder="big")


class TxOutput:
    scriptpubkey: bytes
    value: Union[int, str]

    def __init__(self, *, scriptpubkey: bytes, value: Union[int, str]):
        self.scriptpubkey = scriptpubkey
        if not (isinstance(value, int) or parse_max_spend(value) is not None):
            raise ValueError(f"bad txout value: {value!r}")
        self.value = value  # int in satoshis; or spend-max-like str

    @classmethod
    def from_address_and_value(cls, address: str, value: Union[int, str]) -> Union['TxOutput', 'PartialTxOutput']:
        return cls(scriptpubkey=bitcoin.address_to_script(address),
                   value=value)

    def serialize_to_network(self) -> bytes:
        buf = int.to_bytes(self.value, 8, byteorder="little", signed=False)
        script = self.scriptpubkey
        buf += var_int(len(script))
        buf += script
        return buf

    @classmethod
    def from_network_bytes(cls, raw: bytes) -> 'TxOutput':
        vds = BCDataStream()
        vds.write(raw)
        txout = parse_output(vds)
        if vds.can_read_more():
            raise SerializationError('extra junk at the end of TxOutput bytes')
        return txout

    def to_legacy_tuple(self) -> Tuple[int, str, Union[int, str]]:
        if self.address:
            return TYPE_ADDRESS, self.address, self.value
        return TYPE_SCRIPT, self.scriptpubkey.hex(), self.value

    @classmethod
    def from_legacy_tuple(cls, _type: int, addr: str, val: Union[int, str]) -> Union['TxOutput', 'PartialTxOutput']:
        if _type == TYPE_ADDRESS:
            return cls.from_address_and_value(addr, val)
        if _type == TYPE_SCRIPT:
            return cls(scriptpubkey=bfh(addr), value=val)
        raise Exception(f"unexpected legacy address type: {_type}")

    @property
    def scriptpubkey(self) -> bytes:
        return self._scriptpubkey

    @scriptpubkey.setter
    def scriptpubkey(self, scriptpubkey: bytes):
        self._scriptpubkey = scriptpubkey
        self._address = _NEEDS_RECALC

    @property
    def address(self) -> Optional[str]:
        if self._address is _NEEDS_RECALC:
            self._address = get_address_from_output_script(self._scriptpubkey)
        return self._address

    def get_ui_address_str(self) -> str:
        addr = self.address
        if addr is not None:
            return addr
        return f"SCRIPT {self.scriptpubkey.hex()}"

    def __repr__(self):
        return f"<TxOutput script={self.scriptpubkey.hex()} address={self.address} value={self.value}>"

    def __eq__(self, other):
        if not isinstance(other, TxOutput):
            return False
        return self.scriptpubkey == other.scriptpubkey and self.value == other.value

    def __ne__(self, other):
        return not (self == other)

    def to_json(self):
        d = {
            'scriptpubkey': self.scriptpubkey.hex(),
            'address': self.address,
            'value_sats': self.value,
        }
        return d


class BIP143SharedTxDigestFields(NamedTuple):  # witness v0
    hashPrevouts: bytes
    hashSequence: bytes
    hashOutputs: bytes

    @classmethod
    def from_tx(cls, tx: 'PartialTransaction') -> 'BIP143SharedTxDigestFields':
        inputs = tx.inputs()
        outputs = tx.outputs()
        hashPrevouts = sha256d(b''.join(txin.prevout.serialize_to_network() for txin in inputs))
        hashSequence = sha256d(b''.join(
            int.to_bytes(txin.nsequence, length=4, byteorder="little", signed=False)
            for txin in inputs))
        hashOutputs = sha256d(b''.join(o.serialize_to_network() for o in outputs))
        return BIP143SharedTxDigestFields(
            hashPrevouts=hashPrevouts,
            hashSequence=hashSequence,
            hashOutputs=hashOutputs,
        )


class BIP341SharedTxDigestFields(NamedTuple):  # witness v1
    sha_prevouts: bytes
    sha_amounts: bytes
    sha_scriptpubkeys: bytes
    sha_sequences: bytes
    sha_outputs: bytes

    @classmethod
    def from_tx(cls, tx: 'PartialTransaction') -> 'BIP341SharedTxDigestFields':
        inputs = tx.inputs()
        outputs = tx.outputs()
        sha_prevouts = sha256(b''.join(txin.prevout.serialize_to_network() for txin in inputs))
        sha_amounts = sha256(b''.join(
            int.to_bytes(txin.value_sats(), length=8, byteorder="little", signed=False)
            for txin in inputs))
        sha_scriptpubkeys = sha256(b''.join(
            var_int(len(txin.scriptpubkey)) + txin.scriptpubkey
            for txin in inputs))
        sha_sequences = sha256(b''.join(
            int.to_bytes(txin.nsequence, length=4, byteorder="little", signed=False)
            for txin in inputs))
        sha_outputs = sha256(b''.join(o.serialize_to_network() for o in outputs))
        return BIP341SharedTxDigestFields(
            sha_prevouts=sha_prevouts,
            sha_amounts=sha_amounts,
            sha_scriptpubkeys=sha_scriptpubkeys,
            sha_sequences=sha_sequences,
            sha_outputs=sha_outputs,
        )


class SighashCache:

    def __init__(self):
        self._witver0 = None  # type: Optional[BIP143SharedTxDigestFields]
        self._witver1 = None  # type: Optional[BIP341SharedTxDigestFields]

    def get_witver0_data_for_tx(self, tx: 'PartialTransaction') -> BIP143SharedTxDigestFields:
        if self._witver0 is None:
            self._witver0 = BIP143SharedTxDigestFields.from_tx(tx)
        return self._witver0

    def get_witver1_data_for_tx(self, tx: 'PartialTransaction') -> BIP341SharedTxDigestFields:
        if self._witver1 is None:
            self._witver1 = BIP341SharedTxDigestFields.from_tx(tx)
        return self._witver1


class TxOutpoint(NamedTuple):
    txid: bytes  # endianness same as hex string displayed; reverse of tx serialization order
    out_idx: int

    @classmethod
    def from_str(cls, s: str) -> 'TxOutpoint':
        hash_str, idx_str = s.split(':')
        assert len(hash_str) == 64, f"{hash_str} should be a sha256 hash"
        return TxOutpoint(txid=bfh(hash_str),
                          out_idx=int(idx_str))

    def __str__(self) -> str:
        return f"""TxOutpoint("{self.to_str()}")"""

    def __repr__(self):
        return f"<{str(self)}>"

    def to_str(self) -> str:
        return f"{self.txid.hex()}:{self.out_idx}"

    def to_json(self):
        return [self.txid.hex(), self.out_idx]

    def serialize_to_network(self) -> bytes:
        return self.txid[::-1] + int.to_bytes(self.out_idx, length=4, byteorder="little", signed=False)

    def is_coinbase(self) -> bool:
        return self.txid == bytes(32)

    def short_name(self):
        return f"{self.txid.hex()[0:10]}:{self.out_idx}"


class TxInput:
    prevout: TxOutpoint
    script_sig: Optional[bytes]
    nsequence: int
    witness: Optional[bytes]
    _is_coinbase_output: bool

    def __init__(self, *,
                 prevout: TxOutpoint,
                 script_sig: bytes = None,
                 nsequence: int = 0xffffffff - 1,
                 witness: bytes = None,
                 is_coinbase_output: bool = False):
        self.prevout = prevout
        self.script_sig = script_sig
        self.nsequence = nsequence
        self.witness = witness
        self._is_coinbase_output = is_coinbase_output
        # blockchain fields
        self.block_height = None  # type: Optional[int]  # height at which the TXO is mined; None means unknown. not SPV-ed.
        self.block_txpos = None  # type: Optional[int]  # position of tx in block, if TXO is mined; otherwise None or -1
        self.spent_height = None  # type: Optional[int]  # height at which the TXO got spent
        self.spent_txid = None  # type: Optional[str]  # txid of the spender
        self._utxo = None  # type: Optional[Transaction]
        self.__scriptpubkey = None  # type: Optional[bytes]
        self.__address = None  # type: Optional[str]
        self.__value_sats = None  # type: Optional[int]

    @property
    def short_id(self):
        if self.block_txpos is not None and self.block_txpos >= 0:
            return ShortID.from_components(self.block_height, self.block_txpos, self.prevout.out_idx)
        else:
            return self.prevout.short_name()

    @property
    def utxo(self):
        return self._utxo

    @utxo.setter
    def utxo(self, tx: Optional['Transaction']):
        if tx is None:
            return
        # note that tx might be a PartialTransaction
        # serialize and de-serialize tx now. this might e.g. convert a complete PartialTx to a Tx
        tx = tx_from_any(str(tx))
        # 'utxo' field should not be a PSBT:
        if not tx.is_complete():
            return
        self.validate_data(utxo=tx)
        self._utxo = tx
        # update derived fields
        out_idx = self.prevout.out_idx
        self.__scriptpubkey = self._utxo.outputs()[out_idx].scriptpubkey
        self.__address = _NEEDS_RECALC
        self.__value_sats = self._utxo.outputs()[out_idx].value

    def validate_data(self, *, utxo: Optional['Transaction'] = None, **kwargs) -> None:
        utxo = utxo or self.utxo
        if utxo:
            if self.prevout.txid.hex() != utxo.txid():
                raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                  f"If a non-witness UTXO is provided, its hash must match the hash specified in the prevout")

    def is_coinbase_input(self) -> bool:
        """Whether this is the input of a coinbase tx."""
        return self.prevout.is_coinbase()

    def is_coinbase_output(self) -> bool:
        """Whether the coin being spent is an output of a coinbase tx.
        This matters for coin maturity (and pretty much only for that!).
        """
        return self._is_coinbase_output

    def value_sats(self) -> Optional[int]:
        return self.__value_sats

    @property
    def address(self) -> Optional[str]:
        if self.__address is _NEEDS_RECALC:
            self.__address = get_address_from_output_script(self.__scriptpubkey)
        return self.__address

    @property
    def scriptpubkey(self) -> Optional[bytes]:
        return self.__scriptpubkey

    def to_json(self):
        d = {
            'prevout_hash': self.prevout.txid.hex(),
            'prevout_n': self.prevout.out_idx,
            'coinbase': self.is_coinbase_output(),
            'nsequence': self.nsequence,
        }
        if self.script_sig is not None:
            d['scriptSig'] = self.script_sig.hex()
        if self.witness is not None:
            d['witness'] = self.witness.hex()
        return d

    def serialize_to_network(self, *, script_sig: bytes = None) -> bytes:
        if script_sig is None:
            script_sig = self.script_sig
        # Prev hash and index
        s = self.prevout.serialize_to_network()
        # Script length, script, sequence
        s += var_int(len(script_sig))
        s += script_sig
        s += int.to_bytes(self.nsequence, length=4, byteorder="little", signed=False)
        return s

    def witness_elements(self) -> Sequence[bytes]:
        if not self.witness:
            return []
        vds = BCDataStream()
        vds.write(self.witness)
        n = vds.read_compact_size()
        return list(vds.read_bytes(vds.read_compact_size()) for i in range(n))

    def is_segwit(self, *, guess_for_address=False) -> bool:
        if self.witness not in (b'\x00', b'', None):
            return True
        return False

    async def add_info_from_network(
            self,
            network: Optional['Network'],
            *,
            ignore_network_issues: bool = True,
            timeout=None,
    ) -> bool:
        """Returns True iff successful."""
        from .network import NetworkException
        async def fetch_from_network(txid) -> Optional[Transaction]:
            tx = None
            if network and network.has_internet_connection():
                try:
                    raw_tx = await network.get_transaction(txid, timeout=timeout)
                except NetworkException as e:
                    _logger.info(f'got network error getting input txn. err: {repr(e)}. txid: {txid}. '
                                 f'if you are intentionally offline, consider using the --offline flag')
                    if not ignore_network_issues:
                        raise e
                else:
                    tx = Transaction(raw_tx)
            if not tx and not ignore_network_issues:
                raise NetworkException('failed to get prev tx from network')
            return tx

        if self.utxo is None:
            self.utxo = await fetch_from_network(txid=self.prevout.txid.hex())
        return self.utxo is not None


class BCDataStream(object):
    """Workalike python implementation of Bitcoin's CDataStream class."""

    def __init__(self):
        self.input = None  # type: Optional[bytearray]
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, _bytes: Union[bytes, bytearray]):  # Initialize with string of _bytes
        assert isinstance(_bytes, (bytes, bytearray))
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

    def read_bytes(self, length: int) -> bytes:
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")
        assert length >= 0
        input_len = len(self.input)
        read_begin = self.read_cursor
        read_end = read_begin + length
        if 0 <= read_begin <= read_end <= input_len:
            result = self.input[read_begin:read_end]  # type: bytearray
            self.read_cursor += length
            return bytes(result)
        else:
            raise SerializationError('attempt to read past end of buffer')

    def write_bytes(self, _bytes: Union[bytes, bytearray], length: int):
        assert len(_bytes) == length, len(_bytes)
        self.write(_bytes)

    def can_read_more(self) -> bool:
        if not self.input:
            return False
        return self.read_cursor < len(self.input)

    def read_boolean(self) -> bool: return self.read_bytes(1) != b'\x00'
    def read_int16(self): return self._read_num('<h')
    def read_uint16(self): return self._read_num('<H')
    def read_int32(self): return self._read_num('<i')
    def read_uint32(self): return self._read_num('<I')
    def read_int64(self): return self._read_num('<q')
    def read_uint64(self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(b'\x01' if val else b'\x00')
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
        except IndexError as e:
            raise SerializationError("attempt to read past end of buffer") from e

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
        else:
            raise Exception(f"size {size} too large for compact_size")

    def _read_num(self, format):
        try:
            (i,) = struct.unpack_from(format, self.input, self.read_cursor)
            self.read_cursor += struct.calcsize(format)
        except Exception as e:
            raise SerializationError(e) from e
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


def script_GetOp(_bytes : bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                try: nSize = _bytes[i]
                except IndexError: raise MalformedBitcoinScript()
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                try: (nSize,) = struct.unpack_from('<H', _bytes, i)
                except struct.error: raise MalformedBitcoinScript()
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                try: (nSize,) = struct.unpack_from('<I', _bytes, i)
                except struct.error: raise MalformedBitcoinScript()
                i += 4
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


class OPPushDataGeneric:
    def __init__(self, pushlen: Callable=None):
        if pushlen is not None:
            self.check_data_len = pushlen

    @classmethod
    def check_data_len(cls, datalen: int) -> bool:
        # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        return opcodes.OP_PUSHDATA4 >= datalen >= 0

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
               or (isinstance(item, type) and issubclass(item, cls))


class OPGeneric:
    def __init__(self, matcher: Callable=None):
        if matcher is not None:
            self.matcher = matcher

    def match(self, op) -> bool:
        return self.matcher(op)

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
               or (isinstance(item, type) and issubclass(item, cls))

OPPushDataPubkey = OPPushDataGeneric(lambda x: x in (33, 65))
OP_ANYSEGWIT_VERSION = OPGeneric(lambda x: x in list(range(opcodes.OP_1, opcodes.OP_16 + 1)))

SCRIPTPUBKEY_TEMPLATE_P2PKH = [opcodes.OP_DUP, opcodes.OP_HASH160,
                               OPPushDataGeneric(lambda x: x == 20),
                               opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]
SCRIPTPUBKEY_TEMPLATE_P2SH = [opcodes.OP_HASH160, OPPushDataGeneric(lambda x: x == 20), opcodes.OP_EQUAL]
SCRIPTPUBKEY_TEMPLATE_WITNESS_V0 = [opcodes.OP_0, OPPushDataGeneric(lambda x: x in (20, 32))]
SCRIPTPUBKEY_TEMPLATE_P2WPKH = [opcodes.OP_0, OPPushDataGeneric(lambda x: x == 20)]
SCRIPTPUBKEY_TEMPLATE_P2WSH = [opcodes.OP_0, OPPushDataGeneric(lambda x: x == 32)]
SCRIPTPUBKEY_TEMPLATE_ANYSEGWIT = [OP_ANYSEGWIT_VERSION, OPPushDataGeneric(lambda x: x in list(range(2, 40 + 1)))]


def check_scriptpubkey_template_and_dust(scriptpubkey, amount: Optional[int]):
    if match_script_against_template(scriptpubkey, SCRIPTPUBKEY_TEMPLATE_P2PKH):
        dust_limit = bitcoin.DUST_LIMIT_P2PKH
    elif match_script_against_template(scriptpubkey, SCRIPTPUBKEY_TEMPLATE_P2SH):
        dust_limit = bitcoin.DUST_LIMIT_P2SH
    elif match_script_against_template(scriptpubkey, SCRIPTPUBKEY_TEMPLATE_P2WSH):
        dust_limit = bitcoin.DUST_LIMIT_P2WSH
    elif match_script_against_template(scriptpubkey, SCRIPTPUBKEY_TEMPLATE_P2WPKH):
        dust_limit = bitcoin.DUST_LIMIT_P2WPKH
    elif match_script_against_template(scriptpubkey, SCRIPTPUBKEY_TEMPLATE_ANYSEGWIT):
        dust_limit = bitcoin.DUST_LIMIT_UNKNOWN_SEGWIT
    else:
        raise Exception(f'scriptpubkey does not conform to any template: {scriptpubkey.hex()}')
    if amount < dust_limit:
        raise Exception(f'amount ({amount}) is below dust limit for scriptpubkey type ({dust_limit})')

def merge_duplicate_tx_outputs(outputs: Iterable['PartialTxOutput']) -> List['PartialTxOutput']:
    """Merges outputs that are paying to the same address by replacing them with a single larger output."""
    output_dict = {}
    for output in outputs:
        assert isinstance(output.value, int), "tx outputs with spend-max-like str cannot be merged"
        if output.scriptpubkey in output_dict:
            output_dict[output.scriptpubkey].value += output.value
        else:
            output_dict[output.scriptpubkey] = copy.copy(output)
    return list(output_dict.values())

def match_script_against_template(script, template, debug=False) -> bool:
    """Returns whether 'script' matches 'template'."""
    if script is None:
        return False
    # optionally decode script now:
    if isinstance(script, (bytes, bytearray)):
        try:
            script = [x for x in script_GetOp(script)]
        except MalformedBitcoinScript:
            if debug:
                _logger.debug(f"malformed script")
            return False
    if debug:
        _logger.debug(f"match script against template: {script}")
    if len(script) != len(template):
        if debug:
            _logger.debug(f"length mismatch {len(script)} != {len(template)}")
        return False
    for i in range(len(script)):
        template_item = template[i]
        script_item = script[i]
        if OPPushDataGeneric.is_instance(template_item) and template_item.check_data_len(script_item[0]):
            continue
        if OPGeneric.is_instance(template_item) and template_item.match(script_item[0]):
            continue
        if template_item != script_item[0]:
            if debug:
                _logger.debug(f"item mismatch at position {i}: {template_item} != {script_item[0]}")
            return False
    return True

def get_script_type_from_output_script(_bytes: bytes) -> Optional[str]:
    if _bytes is None:
        return None
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        return None
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2PKH):
        return 'p2pkh'
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2SH):
        return 'p2sh'
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2WPKH):
        return 'p2wpkh'
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2WSH):
        return 'p2wsh'
    return None

def get_address_from_output_script(_bytes: bytes, *, net=None) -> Optional[str]:
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        return None

    # p2pkh
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2PKH):
        return hash160_to_p2pkh(decoded[2][1], net=net)

    # p2sh
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2SH):
        return hash160_to_p2sh(decoded[1][1], net=net)

    # segwit address (version 0)
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_WITNESS_V0):
        return hash_to_segwit_addr(decoded[1][1], witver=0, net=net)

    # segwit address (version 1-16)
    future_witness_versions = list(range(opcodes.OP_1, opcodes.OP_16 + 1))
    for witver, opcode in enumerate(future_witness_versions, start=1):
        match = [opcode, OPPushDataGeneric(lambda x: 2 <= x <= 40)]
        if match_script_against_template(decoded, match):
            return hash_to_segwit_addr(decoded[1][1], witver=witver, net=net)

    return None


def parse_input(vds: BCDataStream) -> TxInput:
    prevout_hash = vds.read_bytes(32)[::-1]
    prevout_n = vds.read_uint32()
    prevout = TxOutpoint(txid=prevout_hash, out_idx=prevout_n)
    script_sig = vds.read_bytes(vds.read_compact_size())
    nsequence = vds.read_uint32()
    return TxInput(prevout=prevout, script_sig=script_sig, nsequence=nsequence)


def parse_witness(vds: BCDataStream, txin: TxInput) -> None:
    n = vds.read_compact_size()
    witness_elements = list(vds.read_bytes(vds.read_compact_size()) for i in range(n))
    txin.witness = construct_witness(witness_elements)


def parse_output(vds: BCDataStream) -> TxOutput:
    value = vds.read_int64()
    if value > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
        raise SerializationError('invalid output amount (too large)')
    if value < 0:
        raise SerializationError('invalid output amount (negative)')
    scriptpubkey = vds.read_bytes(vds.read_compact_size())
    return TxOutput(value=value, scriptpubkey=scriptpubkey)


# pay & redeem scripts

def multisig_script(public_keys: Sequence[str], m: int) -> bytes:
    n = len(public_keys)
    assert 1 <= m <= n <= 15, f'm {m}, n {n}'
    return construct_script([m, *public_keys, n, opcodes.OP_CHECKMULTISIG])




class Transaction:
    _cached_network_ser: Optional[str]

    def __str__(self):
        return self.serialize()

    def __init__(self, raw):
        if raw is None:
            self._cached_network_ser = None
        elif isinstance(raw, str):
            self._cached_network_ser = raw.strip() if raw else None
            assert is_hex_str(self._cached_network_ser)
        elif isinstance(raw, (bytes, bytearray)):
            self._cached_network_ser = raw.hex()
        else:
            raise Exception(f"cannot initialize transaction from {raw}")
        self._inputs = None  # type: List[TxInput]
        self._outputs = None  # type: List[TxOutput]
        self._locktime = 0
        self._version = 2

        self._cached_txid = None  # type: Optional[str]

    @property
    def locktime(self):
        self.deserialize()
        return self._locktime

    @locktime.setter
    def locktime(self, value: int):
        assert isinstance(value, int), f"locktime must be int, not {value!r}"
        self._locktime = value
        self.invalidate_ser_cache()

    @property
    def version(self):
        self.deserialize()
        return self._version

    @version.setter
    def version(self, value):
        self._version = value
        self.invalidate_ser_cache()

    def to_json(self) -> dict:
        d = {
            'version': self.version,
            'locktime': self.locktime,
            'inputs': [txin.to_json() for txin in self.inputs()],
            'outputs': [txout.to_json() for txout in self.outputs()],
        }
        return d

    def inputs(self) -> Sequence[TxInput]:
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self) -> Sequence[TxOutput]:
        if self._outputs is None:
            self.deserialize()
        return self._outputs

    def deserialize(self) -> None:
        if self._cached_network_ser is None:
            return
        if self._inputs is not None:
            return

        raw_bytes = bfh(self._cached_network_ser)
        vds = BCDataStream()
        vds.write(raw_bytes)
        self._version = vds.read_int32()
        n_vin = vds.read_compact_size()
        is_segwit = (n_vin == 0)
        if is_segwit:
            marker = vds.read_bytes(1)
            if marker != b'\x01':
                raise SerializationError('invalid txn marker byte: {}'.format(marker))
            n_vin = vds.read_compact_size()
        if n_vin < 1:
            raise SerializationError('tx needs to have at least 1 input')
        txins = [parse_input(vds) for i in range(n_vin)]
        n_vout = vds.read_compact_size()
        if n_vout < 1:
            raise SerializationError('tx needs to have at least 1 output')
        self._outputs = [parse_output(vds) for i in range(n_vout)]
        if is_segwit:
            for txin in txins:
                parse_witness(vds, txin)
        self._inputs = txins  # only expose field after witness is parsed, for sanity
        self._locktime = vds.read_uint32()
        if vds.can_read_more():
            raise SerializationError('extra junk at the end')

    @classmethod
    def serialize_witness(cls, txin: TxInput, *, estimate_size=False) -> bytes:
        if txin.witness is not None:
            return txin.witness
        if txin.is_coinbase_input():
            return b""
        assert isinstance(txin, PartialTxInput)

        if not txin.is_segwit():
            return construct_witness([])

        if estimate_size and txin.witness_sizehint is not None:
            return bytes(txin.witness_sizehint)

        dummy_desc = None
        if estimate_size:
            dummy_desc = create_dummy_descriptor_from_address(txin.address)
        if desc := (txin.script_descriptor or dummy_desc):
            sol = desc.satisfy(allow_dummy=estimate_size, sigdata=txin.sigs_ecdsa)
            if sol.witness is not None:
                return sol.witness
            return construct_witness([])
        raise UnknownTxinType("cannot construct witness")

    @classmethod
    def input_script(self, txin: TxInput, *, estimate_size=False) -> bytes:
        if txin.script_sig is not None:
            return txin.script_sig
        if txin.is_coinbase_input():
            return b""
        assert isinstance(txin, PartialTxInput)

        if txin.is_p2sh_segwit() and txin.redeem_script:
            return construct_script([txin.redeem_script])
        if txin.is_native_segwit():
            return b""

        dummy_desc = None
        if estimate_size:
            dummy_desc = create_dummy_descriptor_from_address(txin.address)
        if desc := (txin.script_descriptor or dummy_desc):
            if desc.is_segwit():
                if redeem_script := desc.expand().redeem_script:
                    return construct_script([redeem_script])
                return b""
            sol = desc.satisfy(allow_dummy=estimate_size, sigdata=txin.sigs_ecdsa)
            if sol.script_sig is not None:
                return sol.script_sig
            return b""
        raise UnknownTxinType("cannot construct scriptSig")

    @classmethod
    def get_preimage_script(cls, txin: 'PartialTxInput') -> bytes:
        if txin.witness_script:
            if opcodes.OP_CODESEPARATOR in [x[0] for x in script_GetOp(txin.witness_script)]:
                raise Exception('OP_CODESEPARATOR black magic is not supported')
            return txin.witness_script
        if not txin.is_segwit() and txin.redeem_script:
            if opcodes.OP_CODESEPARATOR in [x[0] for x in script_GetOp(txin.redeem_script)]:
                raise Exception('OP_CODESEPARATOR black magic is not supported')
            return txin.redeem_script

        if desc := txin.script_descriptor:
            sc = desc.expand()
            if script := sc.scriptcode_for_sighash:
                return script
            raise Exception(f"don't know scriptcode for descriptor: {desc.to_string()}")
        raise UnknownTxinType(f'cannot construct preimage_script')

    def is_segwit(self, *, guess_for_address=False):
        return any(txin.is_segwit(guess_for_address=guess_for_address)
                   for txin in self.inputs())

    def invalidate_ser_cache(self):
        self._cached_network_ser = None
        self._cached_txid = None

    def serialize(self) -> str:
        if not self._cached_network_ser:
            self._cached_network_ser = self.serialize_to_network(estimate_size=False, include_sigs=True)
        return self._cached_network_ser

    def serialize_as_bytes(self) -> bytes:
        return bfh(self.serialize())

    def serialize_to_network(self, *, estimate_size=False, include_sigs=True, force_legacy=False) -> str:
        """Serialize the transaction as used on the Bitcoin network, into hex.
        `include_sigs` signals whether to include scriptSigs and witnesses.
        `force_legacy` signals to use the pre-segwit format
        note: (not include_sigs) implies force_legacy
        """
        self.deserialize()
        nVersion = int.to_bytes(self.version, length=4, byteorder="little", signed=True).hex()
        nLocktime = int.to_bytes(self.locktime, length=4, byteorder="little", signed=False).hex()
        inputs = self.inputs()
        outputs = self.outputs()

        def create_script_sig(txin: TxInput) -> bytes:
            if include_sigs:
                script_sig = self.input_script(txin, estimate_size=estimate_size)
                return script_sig
            return b""
        txins = var_int(len(inputs)).hex() + ''.join(
            txin.serialize_to_network(script_sig=create_script_sig(txin)).hex()
            for txin in inputs)
        txouts = var_int(len(outputs)).hex() + ''.join(o.serialize_to_network().hex() for o in outputs)

        use_segwit_ser_for_estimate_size = estimate_size and self.is_segwit(guess_for_address=True)
        use_segwit_ser_for_actual_use = not estimate_size and self.is_segwit()
        use_segwit_ser = use_segwit_ser_for_estimate_size or use_segwit_ser_for_actual_use
        if include_sigs and not force_legacy and use_segwit_ser:
            marker = '00'
            flag = '01'
            witness = ''.join(self.serialize_witness(x, estimate_size=estimate_size).hex() for x in inputs)
            return nVersion + marker + flag + txins + txouts + witness + nLocktime
        else:
            return nVersion + txins + txouts + nLocktime

    def to_qr_data(self) -> Tuple[str, bool]:
        """Returns (serialized_tx, is_complete). The tx is serialized to be put inside a QR code. No side-effects.
        As space in a QR code is limited, some data might have to be omitted. This is signalled via is_complete=False.
        """
        is_complete = True
        tx = copy.deepcopy(self)  # make copy as we mutate tx
        if isinstance(tx, PartialTransaction):
            # this makes QR codes a lot smaller (or just possible in the first place!)
            # note: will not apply if all inputs are taproot, due to new sighash.
            tx.convert_all_utxos_to_witness_utxos()
            is_complete = False
        tx_bytes = tx.serialize_as_bytes()
        return base_encode(tx_bytes, base=43), is_complete

    def txid(self) -> Optional[str]:
        if self._cached_txid is None:
            self.deserialize()
            all_segwit = all(txin.is_segwit() for txin in self.inputs())
            if not all_segwit and not self.is_complete():
                return None
            try:
                ser = self.serialize_to_network(force_legacy=True)
            except UnknownTxinType:
                # we might not know how to construct scriptSig for some scripts
                return None
            self._cached_txid = sha256d(bfh(ser))[::-1].hex()
        return self._cached_txid

    def wtxid(self) -> Optional[str]:
        self.deserialize()
        if not self.is_complete():
            return None
        try:
            ser = self.serialize_to_network()
        except UnknownTxinType:
            # we might not know how to construct scriptSig/witness for some scripts
            return None
        return sha256d(bfh(ser))[::-1].hex()

    def add_info_from_wallet(self, wallet: 'Abstract_Wallet', **kwargs) -> None:
        # populate prev_txs
        for txin in self.inputs():
            wallet.add_input_info(txin)

    async def add_info_from_network(
        self,
        network: Optional['Network'],
        *,
        ignore_network_issues: bool = True,
        progress_cb: Callable[[TxinDataFetchProgress], None] = None,
        timeout=None,
    ) -> None:
        """note: it is recommended to call add_info_from_wallet first, as this can save some network requests"""
        if not self.is_missing_info_from_network():
            return
        if progress_cb is None:
            progress_cb = lambda *args, **kwargs: None
        num_tasks_done = 0
        num_tasks_total = 0
        has_errored = False
        has_finished = False
        async def add_info_to_txin(txin: TxInput):
            nonlocal num_tasks_done, has_errored
            progress_cb(TxinDataFetchProgress(num_tasks_done, num_tasks_total, has_errored, has_finished))
            success = await txin.add_info_from_network(
                network=network,
                ignore_network_issues=ignore_network_issues,
                timeout=timeout,
            )
            if success:
                num_tasks_done += 1
            else:
                has_errored = True
            progress_cb(TxinDataFetchProgress(num_tasks_done, num_tasks_total, has_errored, has_finished))
        # schedule a network task for each txin
        try:
            async with OldTaskGroup() as group:
                for txin in self.inputs():
                    if txin.utxo is None:
                        num_tasks_total += 1
                        await group.spawn(add_info_to_txin(txin=txin))
        except Exception as e:
            has_errored = True
            _logger.error(f"tx.add_info_from_network() got exc: {e!r}")
        finally:
            has_finished = True
            progress_cb(TxinDataFetchProgress(num_tasks_done, num_tasks_total, has_errored, has_finished))

    def is_missing_info_from_network(self) -> bool:
        return any(txin.utxo is None for txin in self.inputs())

    def add_info_from_wallet_and_network(
        self, *, wallet: 'Abstract_Wallet', show_error: Callable[[str], None],
    ) -> bool:
        """Returns whether successful.
        note: This is sort of a legacy hack... doing network requests in non-async code.
              Relatedly, this should *not* be called from the network thread.
        """
        # note side-effect: tx is being mutated
        from .network import NetworkException, Network
        self.add_info_from_wallet(wallet)
        try:
            if self.is_missing_info_from_network():
                Network.run_from_another_thread(
                    self.add_info_from_network(wallet.network, ignore_network_issues=False))
        except NetworkException as e:
            show_error(repr(e))
            return False
        return True

    def is_rbf_enabled(self) -> bool:
        """Whether the tx explicitly signals BIP-0125 replace-by-fee."""
        return any([txin.nsequence < 0xffffffff - 1 for txin in self.inputs()])

    def estimated_size(self) -> int:
        """Return an estimated virtual tx size in vbytes.
        BIP-0141 defines 'Virtual transaction size' to be weight/4 rounded up.
        This definition is only for humans, and has little meaning otherwise.
        If we wanted sub-byte precision, fee calculation should use transaction
        weights, but for simplicity we approximate that with (virtual_size)x4
        """
        weight = self.estimated_weight()
        return self.virtual_size_from_weight(weight)

    @classmethod
    def estimated_input_weight(cls, txin: TxInput, is_segwit_tx: bool) -> int:
        '''Return an estimate of serialized input weight in weight units.'''
        script_sig = cls.input_script(txin, estimate_size=True)
        input_size = len(txin.serialize_to_network(script_sig=script_sig))

        if txin.is_segwit(guess_for_address=True):
            witness_size = len(cls.serialize_witness(txin, estimate_size=True))
        else:
            witness_size = 1 if is_segwit_tx else 0

        return 4 * input_size + witness_size

    @classmethod
    def estimated_output_size_for_address(cls, address: str) -> int:
        """Return an estimate of serialized output size in bytes."""
        script = bitcoin.address_to_script(address)
        return cls.estimated_output_size_for_script(script)

    @classmethod
    def estimated_output_size_for_script(cls, script: bytes) -> int:
        """Return an estimate of serialized output size in bytes."""
        # 8 byte value + varint script len + script
        script_len = len(script)
        var_int_len = len(var_int(script_len))
        return 8 + var_int_len + script_len

    @classmethod
    def virtual_size_from_weight(cls, weight: int) -> int:
        return weight // 4 + (weight % 4 > 0)

    @classmethod
    def satperbyte_from_satperkw(cls, feerate_kw):
        """Converts feerate from sat/kw to sat/vbyte."""
        return feerate_kw * 4 / 1000

    def estimated_total_size(self):
        """Return an estimated total transaction size in bytes."""
        if not self.is_complete() or self._cached_network_ser is None:
            return len(self.serialize_to_network(estimate_size=True)) // 2
        else:
            return len(self._cached_network_ser) // 2  # ASCII hex string

    def estimated_witness_size(self):
        """Return an estimate of witness size in bytes."""
        estimate = not self.is_complete()
        if not self.is_segwit(guess_for_address=estimate):
            return 0
        inputs = self.inputs()
        witness = b"".join(self.serialize_witness(x, estimate_size=estimate) for x in inputs)
        witness_size = len(witness) + 2  # include marker and flag
        return witness_size

    def estimated_base_size(self):
        """Return an estimated base transaction size in bytes."""
        return self.estimated_total_size() - self.estimated_witness_size()

    def estimated_weight(self):
        """Return an estimate of transaction weight."""
        total_tx_size = self.estimated_total_size()
        base_tx_size = self.estimated_base_size()
        return 3 * base_tx_size + total_tx_size

    def is_complete(self) -> bool:
        return True

    def get_output_idxs_from_scriptpubkey(self, script: bytes) -> Set[int]:
        """Returns the set indices of outputs with given script."""
        assert isinstance(script, bytes)
        # build cache if there isn't one yet
        # note: can become stale and return incorrect data
        #       if the tx is modified later; that's out of scope.
        if not hasattr(self, '_script_to_output_idx'):
            d = defaultdict(set)
            for output_idx, o in enumerate(self.outputs()):
                o_script = o.scriptpubkey
                d[o_script].add(output_idx)
            self._script_to_output_idx = d
        return set(self._script_to_output_idx[script])  # copy

    def get_output_idxs_from_address(self, addr: str) -> Set[int]:
        script = bitcoin.address_to_script(addr)
        return self.get_output_idxs_from_scriptpubkey(script)

    def replace_output_address(self, old_address: str, new_address: str) -> None:
        idx = list(self.get_output_idxs_from_address(old_address))
        assert len(idx) == 1
        amount = self._outputs[idx[0]].value
        funding_output = PartialTxOutput.from_address_and_value(new_address, amount)
        old_output = PartialTxOutput.from_address_and_value(old_address, amount)
        self._outputs.remove(old_output)
        self.add_outputs([funding_output])
        delattr(self, '_script_to_output_idx')

    def get_change_outputs(self):
        return  [o for o in self._outputs if o.is_change]

    def has_dummy_output(self, dummy_addr: str) -> bool:
        return len(self.get_output_idxs_from_address(dummy_addr)) == 1

    def output_value_for_address(self, addr):
        # assumes exactly one output has that address
        for o in self.outputs():
            if o.address == addr:
                return o.value
        else:
            raise Exception('output not found', addr)

    def input_value(self) -> int:
        input_values = [txin.value_sats() for txin in self.inputs()]
        if any([val is None for val in input_values]):
            raise MissingTxInputAmount()
        return sum(input_values)

    def output_value(self) -> int:
        return sum(o.value for o in self.outputs())

    def get_fee(self) -> Optional[int]:
        try:
            return self.input_value() - self.output_value()
        except MissingTxInputAmount:
            return None

    def get_input_idx_that_spent_prevout(self, prevout: TxOutpoint) -> Optional[int]:
        # build cache if there isn't one yet
        # note: can become stale and return incorrect data
        #       if the tx is modified later; that's out of scope.
        if not hasattr(self, '_prevout_to_input_idx'):
            d = {}  # type: Dict[TxOutpoint, int]
            for i, txin in enumerate(self.inputs()):
                d[txin.prevout] = i
            self._prevout_to_input_idx = d
        idx = self._prevout_to_input_idx.get(prevout)
        if idx is not None:
            assert self.inputs()[idx].prevout == prevout
        return idx


def convert_raw_tx_to_hex(raw: Union[str, bytes]) -> str:
    """Sanitizes tx-describing input (hex/base43/base64) into
    raw tx hex string."""
    if not raw:
        raise ValueError("empty string")
    raw_unstripped = raw
    raw = raw.strip()
    # try hex
    try:
        return binascii.unhexlify(raw).hex()
    except Exception:
        pass
    # try base43
    try:
        return base_decode(raw, base=43).hex()
    except Exception:
        pass
    # try base64
    if raw[0:6] in ('cHNidP', b'cHNidP'):  # base64 psbt
        try:
            return base64.b64decode(raw).hex()
        except Exception:
            pass
    # raw bytes (do not strip whitespaces in this case)
    if isinstance(raw_unstripped, bytes):
        return raw_unstripped.hex()
    raise ValueError(f"failed to recognize transaction encoding for txt: {raw[:30]}...")


def tx_from_any(raw: Union[str, bytes], *,
                deserialize: bool = True) -> Union['PartialTransaction', 'Transaction']:
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    raw = convert_raw_tx_to_hex(raw)
    try:
        return PartialTransaction.from_raw_psbt(raw)
    except BadHeaderMagic:
        if raw[:10] == b'EPTF\xff'.hex():
            raise SerializationError("Partial transactions generated with old Electrum versions "
                                     "(< 4.0) are no longer supported. Please upgrade Electrum on "
                                     "the other machine where this transaction was created.")
    try:
        tx = Transaction(raw)
        if deserialize:
            tx.deserialize()
        return tx
    except Exception as e:
        raise SerializationError(f"Failed to recognise tx encoding, or to parse transaction. "
                                 f"raw: {raw[:30]}...") from e


class PSBTGlobalType(IntEnum):
    UNSIGNED_TX = 0
    XPUB = 1
    VERSION = 0xFB


class PSBTInputType(IntEnum):
    NON_WITNESS_UTXO = 0
    WITNESS_UTXO = 1
    PARTIAL_SIG = 2
    SIGHASH_TYPE = 3
    REDEEM_SCRIPT = 4
    WITNESS_SCRIPT = 5
    BIP32_DERIVATION = 6
    FINAL_SCRIPTSIG = 7
    FINAL_SCRIPTWITNESS = 8
    TAP_KEY_SIG = 0x13
    TAP_MERKLE_ROOT = 0x18
    SLIP19_OWNERSHIP_PROOF = 0x19


class PSBTOutputType(IntEnum):
    REDEEM_SCRIPT = 0
    WITNESS_SCRIPT = 1
    BIP32_DERIVATION = 2


# Serialization/deserialization tools
def deser_compact_size(f) -> Optional[int]:
    # note: ~inverse of bitcoin.var_int
    try:
        nit = f.read(1)[0]
    except IndexError:
        return None     # end of file

    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


class PSBTSection:

    def _populate_psbt_fields_from_fd(self, fd=None):
        if not fd: return

        while True:
            try:
                key_type, key, val = self.get_next_kv_from_fd(fd)
            except StopIteration:
                break
            self.parse_psbt_section_kv(key_type, key, val)

    @classmethod
    def get_next_kv_from_fd(cls, fd) -> Tuple[int, bytes, bytes]:
        key_size = deser_compact_size(fd)
        if key_size == 0:
            raise StopIteration()
        if key_size is None:
            raise UnexpectedEndOfStream()

        full_key = fd.read(key_size)
        key_type, key = cls.get_keytype_and_key_from_fullkey(full_key)

        val_size = deser_compact_size(fd)
        if val_size is None: raise UnexpectedEndOfStream()
        val = fd.read(val_size)

        return key_type, key, val

    @classmethod
    def create_psbt_writer(cls, fd):
        def wr(key_type: int, val: bytes, key: bytes = b''):
            full_key = cls.get_fullkey_from_keytype_and_key(key_type, key)
            fd.write(var_int(len(full_key)))  # key_size
            fd.write(full_key)  # key
            fd.write(var_int(len(val)))  # val_size
            fd.write(val)  # val
        return wr

    @classmethod
    def get_keytype_and_key_from_fullkey(cls, full_key: bytes) -> Tuple[int, bytes]:
        with io.BytesIO(full_key) as key_stream:
            key_type = deser_compact_size(key_stream)
            if key_type is None: raise UnexpectedEndOfStream()
            key = key_stream.read()
        return key_type, key

    @classmethod
    def get_fullkey_from_keytype_and_key(cls, key_type: int, key: bytes) -> bytes:
        key_type_bytes = var_int(key_type)
        return key_type_bytes + key

    def _serialize_psbt_section(self, fd):
        wr = self.create_psbt_writer(fd)
        self.serialize_psbt_section_kvs(wr)
        fd.write(b'\x00')  # section-separator

    def parse_psbt_section_kv(self, kt: int, key: bytes, val: bytes) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def serialize_psbt_section_kvs(self, wr) -> None:
        raise NotImplementedError()  # implemented by subclasses


class PartialTxInput(TxInput, PSBTSection):
    def __init__(self, *args, **kwargs):
        TxInput.__init__(self, *args, **kwargs)
        self._witness_utxo = None  # type: Optional[TxOutput]
        self.sigs_ecdsa = {}  # type: Dict[bytes, bytes]  # pubkey -> sig
        self.tap_key_sig = None  # type: Optional[bytes]  # sig for taproot key-path-spending
        self.sighash = None  # type: Optional[int]
        self.bip32_paths = {}  # type: Dict[bytes, Tuple[bytes, Sequence[int]]]  # pubkey -> (xpub_fingerprint, path)
        self.redeem_script = None  # type: Optional[bytes]
        self.witness_script = None  # type: Optional[bytes]
        self.tap_merkle_root = None  # type: Optional[bytes]
        self.slip_19_ownership_proof = None  # type: Optional[bytes]
        self._unknown = {}  # type: Dict[bytes, bytes]

        self._script_descriptor = None  # type: Optional[Descriptor]
        self.is_mine = False  # type: bool  # whether the wallet considers the input to be ismine
        self._trusted_value_sats = None  # type: Optional[int]
        self._trusted_address = None  # type: Optional[str]
        self._is_p2sh_segwit = None  # type: Optional[bool]  # None means unknown
        self._is_native_segwit = None  # type: Optional[bool]  # None means unknown
        self._is_taproot = None  # type: Optional[bool]  # None means unknown
        self.witness_sizehint = None  # type: Optional[int]  # byte size of serialized complete witness, for tx size est

    @property
    def witness_utxo(self):
        return self._witness_utxo

    @witness_utxo.setter
    def witness_utxo(self, value: Optional[TxOutput]):
        self.validate_data(witness_utxo=value)
        self._witness_utxo = value

    @property
    def pubkeys(self) -> Set[bytes]:
        if desc := self.script_descriptor:
            return desc.get_all_pubkeys()
        return set()

    @property
    def script_descriptor(self):
        return self._script_descriptor

    @script_descriptor.setter
    def script_descriptor(self, desc: Optional[Descriptor]):
        self._script_descriptor = desc
        if desc:
            if self.redeem_script is None:
                self.redeem_script = desc.expand().redeem_script
            if self.witness_script is None:
                self.witness_script = desc.expand().witness_script

    def to_json(self):
        d = super().to_json()
        d.update({
            'height': self.block_height,
            'value_sats': self.value_sats(),
            'address': self.address,
            'desc': self.script_descriptor.to_string() if self.script_descriptor else None,
            'utxo': str(self.utxo) if self.utxo else None,
            'witness_utxo': self.witness_utxo.serialize_to_network().hex() if self.witness_utxo else None,
            'sighash': self.sighash,
            'redeem_script': self.redeem_script.hex() if self.redeem_script else None,
            'witness_script': self.witness_script.hex() if self.witness_script else None,
            'sigs_ecdsa': {pubkey.hex(): sig.hex() for pubkey, sig in self.sigs_ecdsa.items()},
            'tap_key_sig': self.tap_key_sig.hex() if self.tap_key_sig else None,
            'tap_merkle_root': self.tap_merkle_root.hex() if self.tap_merkle_root else None,
            'bip32_paths': {pubkey.hex(): (xfp.hex(), bip32.convert_bip32_intpath_to_strpath(path))
                            for pubkey, (xfp, path) in self.bip32_paths.items()},
            'slip_19_ownership_proof': self.slip_19_ownership_proof.hex() if self.slip_19_ownership_proof else None,
            'unknown_psbt_fields': {key.hex(): val.hex() for key, val in self._unknown.items()},
        })
        return d

    @classmethod
    def from_txin(cls, txin: TxInput, *, strip_witness: bool = True) -> 'PartialTxInput':
        # FIXME: if strip_witness is True, res.is_segwit() will return False,
        # and res.estimated_size() will return an incorrect value. These methods
        # will return the correct values after we call add_input_info(). (see dscancel and bump_fee)
        # This is very fragile: the value returned by estimate_size() depends on the calling order.
        res = PartialTxInput(prevout=txin.prevout,
                             script_sig=None if strip_witness else txin.script_sig,
                             nsequence=txin.nsequence,
                             witness=None if strip_witness else txin.witness,
                             is_coinbase_output=txin.is_coinbase_output())
        res.utxo = txin.utxo
        return res

    def validate_data(
        self,
        *,
        for_signing=False,
        # allow passing provisional fields for 'self', before setting them:
        utxo: Optional[Transaction] = None,
        witness_utxo: Optional[TxOutput] = None,
    ) -> None:
        utxo = utxo or self.utxo
        witness_utxo = witness_utxo or self.witness_utxo
        if utxo:
            if self.prevout.txid.hex() != utxo.txid():
                raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                  f"If a non-witness UTXO is provided, its hash must match the hash specified in the prevout")
            if witness_utxo:
                if utxo.outputs()[self.prevout.out_idx] != witness_utxo:
                    raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                      f"If both non-witness UTXO and witness UTXO are provided, they must be consistent")
        # The following test is disabled, so we are willing to sign non-segwit inputs
        # without verifying the input amount. This means, given a maliciously modified PSBT,
        # for non-segwit inputs, we might end up burning coins as miner fees.
        if for_signing and False:
            if not self.is_segwit() and witness_utxo:
                raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                  f"If a witness UTXO is provided, no non-witness signature may be created")
        if self.redeem_script and self.address:
            addr = hash160_to_p2sh(hash_160(self.redeem_script))
            if self.address != addr:
                raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                  f"If a redeemScript is provided, the scriptPubKey must be for that redeemScript")
        if self.witness_script:
            if self.redeem_script:
                if self.redeem_script != bitcoin.p2wsh_nested_script(self.witness_script):
                    raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                      f"If a witnessScript is provided, the redeemScript must be for that witnessScript")
            elif self.address:
                if self.address != bitcoin.script_to_p2wsh(self.witness_script):
                    raise PSBTInputConsistencyFailure(f"PSBT input validation: "
                                                      f"If a witnessScript is provided, the scriptPubKey must be for that witnessScript")

    def parse_psbt_section_kv(self, kt, key, val):
        try:
            kt = PSBTInputType(kt)
        except ValueError:
            pass  # unknown type
        if DEBUG_PSBT_PARSING: print(f"{repr(kt)} {key.hex()} {val.hex()}")
        if kt == PSBTInputType.NON_WITNESS_UTXO:
            if self.utxo is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.utxo = Transaction(val)
            self.utxo.deserialize()
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.WITNESS_UTXO:
            if self.witness_utxo is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.witness_utxo = TxOutput.from_network_bytes(val)
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.PARTIAL_SIG:
            if key in self.sigs_ecdsa:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            if len(key) not in (33, 65):
                raise SerializationError(f"key for {repr(kt)} has unexpected length: {len(key)}")
            self.sigs_ecdsa[key] = val
        elif kt == PSBTInputType.TAP_KEY_SIG:
            if self.tap_key_sig is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            if len(val) not in (64, 65):
                raise SerializationError(f"value for {repr(kt)} has unexpected length: {len(val)}")
            self.tap_key_sig = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.TAP_MERKLE_ROOT:
            if self.tap_merkle_root is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            if len(val) != 32:
                raise SerializationError(f"value for {repr(kt)} has unexpected length: {len(val)}")
            self.tap_merkle_root = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.SIGHASH_TYPE:
            if self.sighash is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            if len(val) != 4:
                raise SerializationError(f"value for {repr(kt)} has unexpected length: {len(val)}")
            self.sighash = struct.unpack("<I", val)[0]
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.BIP32_DERIVATION:
            if key in self.bip32_paths:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            if len(key) not in (33, 65):
                raise SerializationError(f"key for {repr(kt)} has unexpected length: {len(key)}")
            self.bip32_paths[key] = unpack_bip32_root_fingerprint_and_int_path(val)
        elif kt == PSBTInputType.REDEEM_SCRIPT:
            if self.redeem_script is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.redeem_script = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.WITNESS_SCRIPT:
            if self.witness_script is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.witness_script = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.FINAL_SCRIPTSIG:
            if self.script_sig is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.script_sig = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.FINAL_SCRIPTWITNESS:
            if self.witness is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.witness = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTInputType.SLIP19_OWNERSHIP_PROOF:
            if self.slip_19_ownership_proof is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.slip_19_ownership_proof = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        else:
            full_key = self.get_fullkey_from_keytype_and_key(kt, key)
            if full_key in self._unknown:
                raise SerializationError(f'duplicate key. PSBT input key for unknown type: {full_key}')
            self._unknown[full_key] = val

    def serialize_psbt_section_kvs(self, wr):
        if self.witness_utxo:
            wr(PSBTInputType.WITNESS_UTXO, self.witness_utxo.serialize_to_network())
        if self.utxo:
            wr(PSBTInputType.NON_WITNESS_UTXO, bfh(self.utxo.serialize_to_network(include_sigs=True)))
        for pk, val in sorted(self.sigs_ecdsa.items()):
            wr(PSBTInputType.PARTIAL_SIG, val, pk)
        if self.tap_key_sig is not None:
            wr(PSBTInputType.TAP_KEY_SIG, self.tap_key_sig)
        if self.tap_merkle_root is not None:
            wr(PSBTInputType.TAP_MERKLE_ROOT, self.tap_merkle_root)
        if self.sighash is not None:
            wr(PSBTInputType.SIGHASH_TYPE, struct.pack('<I', self.sighash))
        if self.redeem_script is not None:
            wr(PSBTInputType.REDEEM_SCRIPT, self.redeem_script)
        if self.witness_script is not None:
            wr(PSBTInputType.WITNESS_SCRIPT, self.witness_script)
        for k in sorted(self.bip32_paths):
            packed_path = pack_bip32_root_fingerprint_and_int_path(*self.bip32_paths[k])
            wr(PSBTInputType.BIP32_DERIVATION, packed_path, k)
        if self.script_sig is not None:
            wr(PSBTInputType.FINAL_SCRIPTSIG, self.script_sig)
        if self.witness is not None:
            wr(PSBTInputType.FINAL_SCRIPTWITNESS, self.witness)
        if self.slip_19_ownership_proof:
            wr(PSBTInputType.SLIP19_OWNERSHIP_PROOF, self.slip_19_ownership_proof)
        for full_key, val in sorted(self._unknown.items()):
            key_type, key = self.get_keytype_and_key_from_fullkey(full_key)
            wr(key_type, val, key=key)

    def value_sats(self) -> Optional[int]:
        if (val := super().value_sats()) is not None:
            return val
        if self._trusted_value_sats is not None:
            return self._trusted_value_sats
        if self.witness_utxo:
            return self.witness_utxo.value
        return None

    @property
    def address(self) -> Optional[str]:
        if (addr := super().address) is not None:
            return addr
        if self._trusted_address is not None:
            return self._trusted_address
        if self.witness_utxo:
            return self.witness_utxo.address
        return None

    @property
    def scriptpubkey(self) -> Optional[bytes]:
        if (spk := super().scriptpubkey) is not None:
            return spk
        if self._trusted_address is not None:
            return bitcoin.address_to_script(self._trusted_address)
        if self.witness_utxo:
            return self.witness_utxo.scriptpubkey
        return None

    def is_complete(self) -> bool:
        if self.script_sig is not None and self.witness is not None:
            return True
        if self.is_coinbase_input():
            return True
        if self.script_sig is not None and not self.is_segwit():
            return True
        if desc := self.script_descriptor:
            try:
                desc.satisfy(allow_dummy=False, sigdata=self.sigs_ecdsa)
            except MissingSolutionPiece:
                pass
            else:
                return True
        return False

    def get_satisfaction_progress(self) -> Tuple[int, int]:
        if desc := self.script_descriptor:
            return desc.get_satisfaction_progress(sigdata=self.sigs_ecdsa)
        return 0, 0

    def finalize(self) -> None:
        def clear_fields_when_finalized():
            # BIP-174: "All other data except the UTXO and unknown fields in the
            #           input key-value map should be cleared from the PSBT"
            self.sigs_ecdsa = {}
            self.tap_key_sig = None
            self.tap_merkle_root = None
            self.sighash = None
            self.bip32_paths = {}
            self.redeem_script = None
            self.witness_script = None

        if self.script_sig is not None and self.witness is not None:
            clear_fields_when_finalized()
            return  # already finalized
        if self.is_complete():
            self.script_sig = Transaction.input_script(self)
            self.witness = Transaction.serialize_witness(self)
            clear_fields_when_finalized()

    def combine_with_other_txin(self, other_txin: 'TxInput') -> None:
        assert self.prevout == other_txin.prevout
        if other_txin.script_sig is not None:
            self.script_sig = other_txin.script_sig
        if other_txin.witness is not None:
            self.witness = other_txin.witness
        if isinstance(other_txin, PartialTxInput):
            if other_txin.witness_utxo:
                self.witness_utxo = other_txin.witness_utxo
            if other_txin.utxo:
                self.utxo = other_txin.utxo
            self.sigs_ecdsa.update(other_txin.sigs_ecdsa)
            if other_txin.sighash is not None:
                self.sighash = other_txin.sighash
            if other_txin.tap_key_sig is not None:
                self.tap_key_sig = other_txin.tap_key_sig
            if other_txin.tap_merkle_root is not None:
                self.tap_merkle_root = other_txin.tap_merkle_root
            self.bip32_paths.update(other_txin.bip32_paths)
            if other_txin.redeem_script is not None:
                self.redeem_script = other_txin.redeem_script
            if other_txin.witness_script is not None:
                self.witness_script = other_txin.witness_script
            self._unknown.update(other_txin._unknown)
        self.validate_data()
        # try to finalize now
        self.finalize()

    def convert_utxo_to_witness_utxo(self) -> None:
        if self.utxo:
            self._witness_utxo = self.utxo.outputs()[self.prevout.out_idx]
            self._utxo = None  # type: Optional[Transaction]

    def is_native_segwit(self) -> Optional[bool]:
        """Whether this input is native segwit (any witness version). None means inconclusive."""
        if self._is_native_segwit is None:
            if self.address:
                self._is_native_segwit = bitcoin.is_segwit_address(self.address)
        return self._is_native_segwit

    def is_p2sh_segwit(self) -> Optional[bool]:
        """Whether this input is p2sh-embedded-segwit. None means inconclusive."""
        if self._is_p2sh_segwit is None:
            def calc_if_p2sh_segwit_now():
                if not (self.address and self.redeem_script):
                    return None
                if self.address != bitcoin.hash160_to_p2sh(hash_160(self.redeem_script)):
                    # not p2sh address
                    return False
                try:
                    decoded = [x for x in script_GetOp(self.redeem_script)]
                except MalformedBitcoinScript:
                    decoded = None
                # witness version 0
                if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_WITNESS_V0):
                    return True
                # witness version 1-16
                future_witness_versions = list(range(opcodes.OP_1, opcodes.OP_16 + 1))
                for witver, opcode in enumerate(future_witness_versions, start=1):
                    match = [opcode, OPPushDataGeneric(lambda x: 2 <= x <= 40)]
                    if match_script_against_template(decoded, match):
                        return True
                return False

            self._is_p2sh_segwit = calc_if_p2sh_segwit_now()
        return self._is_p2sh_segwit

    def is_segwit(self, *, guess_for_address=False) -> bool:
        """Whether this input is segwit (any witness version)."""
        if super().is_segwit():
            return True
        if self.is_native_segwit() or self.is_p2sh_segwit():
            return True
        if self.is_native_segwit() is False and self.is_p2sh_segwit() is False:
            return False
        if self.witness_script:
            return True
        if desc := self.script_descriptor:
            return desc.is_segwit()
        if guess_for_address:
            dummy_desc = create_dummy_descriptor_from_address(self.address)
            return dummy_desc.is_segwit()
        return False  # can be false-negative

    def is_taproot(self) -> bool:
        if self._is_taproot is None:
            if self.address:
                self._is_taproot = bitcoin.is_taproot_address(self.address)
        if desc := self.script_descriptor:
            return desc.is_taproot()
        return self._is_taproot

    def already_has_some_signatures(self) -> bool:
        """Returns whether progress has been made towards completing this input."""
        return (self.sigs_ecdsa
                or self.tap_key_sig is not None
                or self.script_sig is not None
                or self.witness is not None)


class PartialTxOutput(TxOutput, PSBTSection):
    def __init__(self, *args, **kwargs):
        TxOutput.__init__(self, *args, **kwargs)
        self.redeem_script = None  # type: Optional[bytes]
        self.witness_script = None  # type: Optional[bytes]
        self.bip32_paths = {}  # type: Dict[bytes, Tuple[bytes, Sequence[int]]]  # pubkey -> (xpub_fingerprint, path)
        self._unknown = {}  # type: Dict[bytes, bytes]

        self._script_descriptor = None  # type: Optional[Descriptor]
        self.is_mine = False  # type: bool  # whether the wallet considers the output to be ismine
        self.is_change = False  # type: bool  # whether the wallet considers the output to be change

    @property
    def pubkeys(self) -> Set[bytes]:
        if desc := self.script_descriptor:
            return desc.get_all_pubkeys()
        return set()

    @property
    def script_descriptor(self):
        return self._script_descriptor

    @script_descriptor.setter
    def script_descriptor(self, desc: Optional[Descriptor]):
        self._script_descriptor = desc
        if desc:
            if self.redeem_script is None:
                self.redeem_script = desc.expand().redeem_script
            if self.witness_script is None:
                self.witness_script = desc.expand().witness_script

    def to_json(self):
        d = super().to_json()
        d.update({
            'desc': self.script_descriptor.to_string() if self.script_descriptor else None,
            'redeem_script': self.redeem_script.hex() if self.redeem_script else None,
            'witness_script': self.witness_script.hex() if self.witness_script else None,
            'bip32_paths': {pubkey.hex(): (xfp.hex(), bip32.convert_bip32_intpath_to_strpath(path))
                            for pubkey, (xfp, path) in self.bip32_paths.items()},
            'unknown_psbt_fields': {key.hex(): val.hex() for key, val in self._unknown.items()},
        })
        return d

    @classmethod
    def from_txout(cls, txout: TxOutput) -> 'PartialTxOutput':
        res = PartialTxOutput(scriptpubkey=txout.scriptpubkey,
                              value=txout.value)
        return res

    def parse_psbt_section_kv(self, kt, key, val):
        try:
            kt = PSBTOutputType(kt)
        except ValueError:
            pass  # unknown type
        if DEBUG_PSBT_PARSING: print(f"{repr(kt)} {key.hex()} {val.hex()}")
        if kt == PSBTOutputType.REDEEM_SCRIPT:
            if self.redeem_script is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.redeem_script = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTOutputType.WITNESS_SCRIPT:
            if self.witness_script is not None:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            self.witness_script = val
            if key: raise SerializationError(f"key for {repr(kt)} must be empty")
        elif kt == PSBTOutputType.BIP32_DERIVATION:
            if key in self.bip32_paths:
                raise SerializationError(f"duplicate key: {repr(kt)}")
            if len(key) not in (33, 65):
                raise SerializationError(f"key for {repr(kt)} has unexpected length: {len(key)}")
            self.bip32_paths[key] = unpack_bip32_root_fingerprint_and_int_path(val)
        else:
            full_key = self.get_fullkey_from_keytype_and_key(kt, key)
            if full_key in self._unknown:
                raise SerializationError(f'duplicate key. PSBT output key for unknown type: {full_key}')
            self._unknown[full_key] = val

    def serialize_psbt_section_kvs(self, wr):
        if self.redeem_script is not None:
            wr(PSBTOutputType.REDEEM_SCRIPT, self.redeem_script)
        if self.witness_script is not None:
            wr(PSBTOutputType.WITNESS_SCRIPT, self.witness_script)
        for k in sorted(self.bip32_paths):
            packed_path = pack_bip32_root_fingerprint_and_int_path(*self.bip32_paths[k])
            wr(PSBTOutputType.BIP32_DERIVATION, packed_path, k)
        for full_key, val in sorted(self._unknown.items()):
            key_type, key = self.get_keytype_and_key_from_fullkey(full_key)
            wr(key_type, val, key=key)

    def combine_with_other_txout(self, other_txout: 'TxOutput') -> None:
        assert self.scriptpubkey == other_txout.scriptpubkey
        if not isinstance(other_txout, PartialTxOutput):
            return
        if other_txout.redeem_script is not None:
            self.redeem_script = other_txout.redeem_script
        if other_txout.witness_script is not None:
            self.witness_script = other_txout.witness_script
        self.bip32_paths.update(other_txout.bip32_paths)
        self._unknown.update(other_txout._unknown)


class PartialTransaction(Transaction):

    def __init__(self):
        Transaction.__init__(self, None)
        self.xpubs = {}  # type: Dict[BIP32Node, Tuple[bytes, Sequence[int]]]  # intermediate bip32node -> (xfp, der_prefix)
        self._inputs = []  # type: List[PartialTxInput]
        self._outputs = []  # type: List[PartialTxOutput]
        self._unknown = {}  # type: Dict[bytes, bytes]
        self.rbf_merge_txid = None

    def to_json(self) -> dict:
        d = super().to_json()
        d.update({
            'xpubs': {bip32node.to_xpub(): (xfp.hex(), bip32.convert_bip32_intpath_to_strpath(path))
                      for bip32node, (xfp, path) in self.xpubs.items()},
            'unknown_psbt_fields': {key.hex(): val.hex() for key, val in self._unknown.items()},
        })
        return d

    @classmethod
    def from_tx(cls, tx: Transaction) -> 'PartialTransaction':
        assert tx
        res = cls()
        res._inputs = [PartialTxInput.from_txin(txin, strip_witness=True)
                       for txin in tx.inputs()]
        res._outputs = [PartialTxOutput.from_txout(txout) for txout in tx.outputs()]
        res.version = tx.version
        res.locktime = tx.locktime
        return res

    @classmethod
    def from_raw_psbt(cls, raw) -> 'PartialTransaction':
        # auto-detect and decode Base64 and Hex.
        if raw[0:10].lower() in (b'70736274ff', '70736274ff'):  # hex
            raw = bytes.fromhex(raw)
        elif raw[0:6] in (b'cHNidP', 'cHNidP'):  # base64
            raw = base64.b64decode(raw)
        if not isinstance(raw, (bytes, bytearray)) or raw[0:5] != b'psbt\xff':
            raise BadHeaderMagic("bad magic")

        tx = None  # type: Optional[PartialTransaction]

        # We parse the raw stream twice. The first pass is used to find the
        # PSBT_GLOBAL_UNSIGNED_TX key in the global section and set 'tx'.
        # The second pass does everything else.
        with io.BytesIO(raw[5:]) as fd:  # parsing "first pass"
            while True:
                try:
                    kt, key, val = PSBTSection.get_next_kv_from_fd(fd)
                except StopIteration:
                    break
                try:
                    kt = PSBTGlobalType(kt)
                except ValueError:
                    pass  # unknown type
                if kt == PSBTGlobalType.UNSIGNED_TX:
                    if tx is not None:
                        raise SerializationError(f"duplicate key: {repr(kt)}")
                    if key: raise SerializationError(f"key for {repr(kt)} must be empty")
                    unsigned_tx = Transaction(val.hex())
                    for txin in unsigned_tx.inputs():
                        if txin.script_sig or txin.witness:
                            raise SerializationError(f"PSBT {repr(kt)} must have empty scriptSigs and witnesses")
                    tx = PartialTransaction.from_tx(unsigned_tx)

        if tx is None:
            raise SerializationError(f"PSBT missing required global section PSBT_GLOBAL_UNSIGNED_TX")

        with io.BytesIO(raw[5:]) as fd:  # parsing "second pass"
            # global section
            while True:
                try:
                    kt, key, val = PSBTSection.get_next_kv_from_fd(fd)
                except StopIteration:
                    break
                try:
                    kt = PSBTGlobalType(kt)
                except ValueError:
                    pass  # unknown type
                if DEBUG_PSBT_PARSING: print(f"{repr(kt)} {key.hex()} {val.hex()}")
                if kt == PSBTGlobalType.UNSIGNED_TX:
                    pass  # already handled during "first" parsing pass
                elif kt == PSBTGlobalType.XPUB:
                    bip32node = BIP32Node.from_bytes(key)
                    if bip32node in tx.xpubs:
                        raise SerializationError(f"duplicate key: {repr(kt)}")
                    xfp, path = unpack_bip32_root_fingerprint_and_int_path(val)
                    if bip32node.depth != len(path):
                        raise SerializationError(f"PSBT global xpub has mismatching depth ({bip32node.depth}) "
                                                 f"and derivation prefix len ({len(path)})")
                    child_number_of_xpub = int.from_bytes(bip32node.child_number, 'big')
                    if not ((bip32node.depth == 0 and child_number_of_xpub == 0)
                            or (bip32node.depth != 0 and child_number_of_xpub == path[-1])):
                        raise SerializationError(f"PSBT global xpub has inconsistent child_number and derivation prefix")
                    tx.xpubs[bip32node] = xfp, path
                elif kt == PSBTGlobalType.VERSION:
                    if len(val) > 4:
                        raise SerializationError(f"value for {repr(kt)} has unexpected length: {len(val)} > 4")
                    psbt_version = int.from_bytes(val, byteorder='little', signed=False)
                    if psbt_version > 0:
                        raise SerializationError(f"Only PSBTs with version 0 are supported. Found version: {psbt_version}")
                    if key: raise SerializationError(f"key for {repr(kt)} must be empty")
                else:
                    full_key = PSBTSection.get_fullkey_from_keytype_and_key(kt, key)
                    if full_key in tx._unknown:
                        raise SerializationError(f'duplicate key. PSBT global key for unknown type: {full_key}')
                    tx._unknown[full_key] = val
            try:
                # inputs sections
                for txin in tx.inputs():
                    if DEBUG_PSBT_PARSING: print("-> new input starts")
                    txin._populate_psbt_fields_from_fd(fd)
                # outputs sections
                for txout in tx.outputs():
                    if DEBUG_PSBT_PARSING: print("-> new output starts")
                    txout._populate_psbt_fields_from_fd(fd)
            except UnexpectedEndOfStream:
                raise UnexpectedEndOfStream('Unexpected end of stream. Num input and output maps provided does not match unsigned tx.') from None

            if fd.read(1) != b'':
                raise SerializationError("extra junk at the end of PSBT")

        for txin in tx.inputs():
            txin.validate_data()

        return tx

    @classmethod
    def from_io(cls, inputs: Sequence[PartialTxInput], outputs: Sequence[PartialTxOutput], *,
                locktime: int = None, version: int = None, BIP69_sort: bool = True):
        self = cls()
        self._inputs = list(inputs)
        self._outputs = list(outputs)
        if locktime is not None:
            self.locktime = locktime
        if version is not None:
            self.version = version
        if BIP69_sort:
            self.BIP69_sort()
        return self

    def _serialize_psbt(self, fd) -> None:
        wr = PSBTSection.create_psbt_writer(fd)
        fd.write(b'psbt\xff')
        # global section
        wr(PSBTGlobalType.UNSIGNED_TX, bfh(self.serialize_to_network(include_sigs=False)))
        for bip32node, (xfp, path) in sorted(self.xpubs.items()):
            val = pack_bip32_root_fingerprint_and_int_path(xfp, path)
            wr(PSBTGlobalType.XPUB, val, key=bip32node.to_bytes())
        for full_key, val in sorted(self._unknown.items()):
            key_type, key = PSBTSection.get_keytype_and_key_from_fullkey(full_key)
            wr(key_type, val, key=key)
        fd.write(b'\x00')  # section-separator
        # input sections
        for inp in self._inputs:
            inp._serialize_psbt_section(fd)
        # output sections
        for outp in self._outputs:
            outp._serialize_psbt_section(fd)

    def finalize_psbt(self) -> None:
        for txin in self.inputs():
            txin.finalize()

    def combine_with_other_psbt(self, other_tx: 'Transaction') -> None:
        """Pulls in all data from other_tx we don't yet have (e.g. signatures).
        other_tx must be concerning the same unsigned tx.
        """
        if self.serialize_to_network(include_sigs=False) != other_tx.serialize_to_network(include_sigs=False):
            raise Exception('A Combiner must not combine two different PSBTs.')
        # BIP-174: "The resulting PSBT must contain all of the key-value pairs from each of the PSBTs.
        #           The Combiner must remove any duplicate key-value pairs, in accordance with the specification."
        # global section
        if isinstance(other_tx, PartialTransaction):
            self.xpubs.update(other_tx.xpubs)
            self._unknown.update(other_tx._unknown)
        # input sections
        for txin, other_txin in zip(self.inputs(), other_tx.inputs()):
            txin.combine_with_other_txin(other_txin)
        # output sections
        for txout, other_txout in zip(self.outputs(), other_tx.outputs()):
            txout.combine_with_other_txout(other_txout)
        self.invalidate_ser_cache()

    def join_with_other_psbt(self, other_tx: 'PartialTransaction', *, config: 'SimpleConfig') -> None:
        """Adds inputs and outputs from other_tx into this one."""
        if not isinstance(other_tx, PartialTransaction):
            raise Exception('Can only join partial transactions.')
        # make sure there are no duplicate prevouts
        prevouts = set()
        for txin in itertools.chain(self.inputs(), other_tx.inputs()):
            prevout_str = txin.prevout.to_str()
            if prevout_str in prevouts:
                raise Exception(f"Duplicate inputs! "
                                f"Transactions that spend the same prevout cannot be joined.")
            prevouts.add(prevout_str)
        # copy global PSBT section
        self.xpubs.update(other_tx.xpubs)
        self._unknown.update(other_tx._unknown)
        # copy and add inputs and outputs
        self.add_inputs(list(other_tx.inputs()))
        self.add_outputs(list(other_tx.outputs()), merge_duplicates=config.WALLET_MERGE_DUPLICATE_OUTPUTS)
        self.remove_signatures()
        self.invalidate_ser_cache()

    def inputs(self) -> Sequence[PartialTxInput]:
        return self._inputs

    def outputs(self) -> Sequence[PartialTxOutput]:
        return self._outputs

    def add_inputs(self, inputs: List[PartialTxInput]) -> None:
        self._inputs.extend(inputs)
        self.BIP69_sort(outputs=False)
        self.invalidate_ser_cache()

    def add_outputs(self, outputs: List[PartialTxOutput], *, merge_duplicates: bool = False) -> None:
        self._outputs.extend(outputs)
        if merge_duplicates:
            self._outputs = merge_duplicate_tx_outputs(self._outputs)
        self.BIP69_sort(inputs=False)
        self.invalidate_ser_cache()

    def set_rbf(self, rbf: bool) -> None:
        nSequence = 0xffffffff - (2 if rbf else 1)
        for txin in self.inputs():
            txin.nsequence = nSequence
        self.invalidate_ser_cache()

    def BIP69_sort(self, inputs=True, outputs=True):
        # NOTE: other parts of the code rely on these sorts being *stable* sorts
        if inputs:
            self._inputs.sort(key = lambda i: (i.prevout.txid, i.prevout.out_idx))
        if outputs:
            self._outputs.sort(key = lambda o: (o.value, o.scriptpubkey))
        self.invalidate_ser_cache()

    def serialize_preimage(
        self,
        txin_index: int,
        *,
        sighash_cache: SighashCache = None,
    ) -> bytes:
        nVersion = int.to_bytes(self.version, length=4, byteorder="little", signed=True)
        nLocktime = int.to_bytes(self.locktime, length=4, byteorder="little", signed=False)
        inputs = self.inputs()
        outputs = self.outputs()
        txin = inputs[txin_index]
        sighash = txin.sighash
        if sighash is None:
            sighash = Sighash.DEFAULT if txin.is_taproot() else Sighash.ALL
        if not Sighash.is_valid(sighash, is_taproot=txin.is_taproot()):
            raise Exception(f"SIGHASH_FLAG ({sighash}) not supported!")
        if sighash_cache is None:
            sighash_cache = SighashCache()
        if txin.is_segwit():
            if txin.is_taproot():
                scache = sighash_cache.get_witver1_data_for_tx(self)
                sighash_epoch = b"\x00"
                hash_type = int.to_bytes(sighash, length=1, byteorder="little", signed=False)
                # txdata
                preimage_txdata = bytearray()
                preimage_txdata += nVersion
                preimage_txdata += nLocktime
                if sighash & 0x80 != Sighash.ANYONECANPAY:
                    preimage_txdata += scache.sha_prevouts
                    preimage_txdata += scache.sha_amounts
                    preimage_txdata += scache.sha_scriptpubkeys
                    preimage_txdata += scache.sha_sequences
                if sighash & 3 not in (Sighash.NONE, Sighash.SINGLE):
                    preimage_txdata += scache.sha_outputs
                # inputdata
                preimage_inputdata = bytearray()
                spend_type = bytes([0])  # (ext_flag * 2) + annex_present
                preimage_inputdata += spend_type
                if sighash & 0x80 == Sighash.ANYONECANPAY:
                    preimage_inputdata += txin.prevout.serialize_to_network()
                    preimage_inputdata += int.to_bytes(txin.value_sats(), length=8, byteorder="little", signed=False)
                    preimage_inputdata += var_int(len(txin.scriptpubkey)) + txin.scriptpubkey
                    preimage_inputdata += int.to_bytes(txin.nsequence, length=4, byteorder="little", signed=False)
                else:
                    preimage_inputdata += int.to_bytes(txin_index, length=4, byteorder="little", signed=False)
                # TODO sha_annex
                # outputdata
                preimage_outputdata = bytearray()
                if sighash & 3 == Sighash.SINGLE:
                    try:
                        txout = outputs[txin_index]
                    except IndexError:
                        raise Exception("Using SIGHASH_SINGLE without a corresponding output") from None
                    preimage_outputdata += sha256(txout.serialize_to_network())
                return bytes(sighash_epoch + hash_type + preimage_txdata + preimage_inputdata + preimage_outputdata)
            else:  # segwit (witness v0)
                scache = sighash_cache.get_witver0_data_for_tx(self)
                if not (sighash & Sighash.ANYONECANPAY):
                    hashPrevouts = scache.hashPrevouts
                else:
                    hashPrevouts = bytes(32)
                if not (sighash & Sighash.ANYONECANPAY) and (sighash & 0x1f) != Sighash.SINGLE and (sighash & 0x1f) != Sighash.NONE:
                    hashSequence = scache.hashSequence
                else:
                    hashSequence = bytes(32)
                if (sighash & 0x1f) != Sighash.SINGLE and (sighash & 0x1f) != Sighash.NONE:
                    hashOutputs = scache.hashOutputs
                elif (sighash & 0x1f) == Sighash.SINGLE and txin_index < len(outputs):
                    hashOutputs = sha256d(outputs[txin_index].serialize_to_network())
                else:
                    hashOutputs = bytes(32)
                outpoint = txin.prevout.serialize_to_network()
                preimage_script = self.get_preimage_script(txin)
                scriptCode = var_int(len(preimage_script)) + preimage_script
                amount = int.to_bytes(txin.value_sats(), length=8, byteorder="little", signed=False)
                nSequence = int.to_bytes(txin.nsequence, length=4, byteorder="little", signed=False)
                nHashType = int.to_bytes(sighash, length=4, byteorder="little", signed=False)
                preimage = nVersion + hashPrevouts + hashSequence + outpoint + scriptCode + amount + nSequence + hashOutputs + nLocktime + nHashType
                return preimage
        else:  # legacy sighash (pre-segwit)
            if sighash != Sighash.ALL:
                raise Exception(f"SIGHASH_FLAG ({sighash}) not supported! (for legacy sighash)")
            preimage_script = self.get_preimage_script(txin)
            txins = var_int(len(inputs)) + b"".join(
                txin.serialize_to_network(script_sig=preimage_script if txin_index==k else b"")
                for k, txin in enumerate(inputs))
            txouts = var_int(len(outputs)) + b"".join(o.serialize_to_network() for o in outputs)
            nHashType = int.to_bytes(sighash, length=4, byteorder="little", signed=False)
            preimage = nVersion + txins + txouts + nLocktime + nHashType
            return preimage
        raise Exception("should not reach this")

    def sign(self, keypairs: Mapping[bytes, bytes]) -> None:
        # keypairs:  pubkey_bytes -> secret_bytes
        sighash_cache = SighashCache()
        for i, txin in enumerate(self.inputs()):
            for pubkey in txin.pubkeys:
                if txin.is_complete():
                    break
                if pubkey not in keypairs:
                    continue
                _logger.info(f"adding signature for {pubkey}. spending utxo {txin.prevout.to_str()}")
                sec = keypairs[pubkey]
                sig = self.sign_txin(i, sec, sighash_cache=sighash_cache)
                self.add_signature_to_txin(txin_idx=i, signing_pubkey=pubkey, sig=sig)

        _logger.debug(f"tx.sign() finished. is_complete={self.is_complete()}")
        self.invalidate_ser_cache()

    def sign_txin(
        self,
        txin_index: int,
        privkey_bytes: bytes,
        *,
        sighash_cache: SighashCache = None,
    ) -> bytes:
        txin = self.inputs()[txin_index]
        txin.validate_data(for_signing=True)
        pre_hash = self.serialize_preimage(txin_index, sighash_cache=sighash_cache)
        if txin.is_taproot():
            # note: privkey_bytes is the internal key
            merkle_root = txin.tap_merkle_root or bytes()
            output_privkey_bytes = taproot_tweak_seckey(privkey_bytes, merkle_root)
            output_privkey = ecc.ECPrivkey(output_privkey_bytes)
            msg_hash = bitcoin.bip340_tagged_hash(b"TapSighash", pre_hash)
            sig = output_privkey.schnorr_sign(msg_hash)
            sighash = txin.sighash if txin.sighash is not None else Sighash.DEFAULT
        else:
            privkey = ecc.ECPrivkey(privkey_bytes)
            msg_hash = sha256d(pre_hash)
            sig = privkey.ecdsa_sign(msg_hash, sigencode=ecc.ecdsa_der_sig_from_r_and_s)
            sighash = txin.sighash if txin.sighash is not None else Sighash.ALL
        return sig + Sighash.to_sigbytes(sighash)

    def is_complete(self) -> bool:
        return all([txin.is_complete() for txin in self.inputs()])

    def signature_count(self) -> Tuple[int, int]:
        nhave, nreq = 0, 0
        for txin in self.inputs():
            a, b = txin.get_satisfaction_progress()
            nhave += a
            nreq += b
        return nhave, nreq

    def serialize(self) -> str:
        """Returns PSBT as base64 text, or raw hex of network tx (if complete)."""
        self.finalize_psbt()
        if self.is_complete():
            return Transaction.serialize(self)
        return self._serialize_as_base64()

    def serialize_as_bytes(self, *, force_psbt: bool = False) -> bytes:
        """Returns PSBT as raw bytes, or raw bytes of network tx (if complete)."""
        self.finalize_psbt()
        if force_psbt or not self.is_complete():
            with io.BytesIO() as fd:
                self._serialize_psbt(fd)
                return fd.getvalue()
        else:
            return Transaction.serialize_as_bytes(self)

    def _serialize_as_base64(self) -> str:
        raw_bytes = self.serialize_as_bytes()
        return base64.b64encode(raw_bytes).decode('ascii')

    def update_signatures(self, signatures: Sequence[Union[bytes, None]]) -> None:
        """Add new signatures to a transaction

        `signatures` is expected to be a list of sigs with signatures[i]
        intended for self._inputs[i].
        This is used by the Trezor, KeepKey and Safe-T plugins.
        """
        if self.is_complete():
            return
        if len(self.inputs()) != len(signatures):
            raise Exception('expected {} signatures; got {}'.format(len(self.inputs()), len(signatures)))
        for i, txin in enumerate(self.inputs()):
            sig = signatures[i]
            if sig is None:
                continue
            if sig in list(txin.sigs_ecdsa.values()):
                continue
            msg_hash = sha256d(self.serialize_preimage(i))
            sig64 = ecc.ecdsa_sig64_from_der_sig(sig[:-1])
            for recid in range(4):
                try:
                    public_key = ecc.ECPubkey.from_ecdsa_sig64(sig64, recid, msg_hash)
                except ecc.InvalidECPointException:
                    # the point might not be on the curve for some recid values
                    continue
                pubkey_bytes = public_key.get_public_key_bytes(compressed=True)
                if pubkey_bytes in txin.pubkeys:
                    if not public_key.ecdsa_verify(sig64, msg_hash):
                        continue
                    _logger.info(f"adding sig: txin_idx={i}, signing_pubkey={pubkey_bytes.hex()}, sig={sig.hex()}")
                    self.add_signature_to_txin(txin_idx=i, signing_pubkey=pubkey_bytes, sig=sig)
                    break
        # redo raw
        self.invalidate_ser_cache()

    def add_signature_to_txin(self, *, txin_idx: int, signing_pubkey: bytes, sig: bytes) -> None:
        txin = self._inputs[txin_idx]
        txin.sigs_ecdsa[signing_pubkey] = sig
        # force re-serialization
        txin.script_sig = None
        txin.witness = None
        self.invalidate_ser_cache()

    def add_info_from_wallet(
            self,
            wallet: 'Abstract_Wallet',
            *,
            include_xpubs: bool = False,
    ) -> None:
        if self.is_complete():
            return
        # only include xpubs for multisig wallets; currently only they need it in practice
        # note: coldcard fw have a limitation that if they are included then all
        #       inputs are assumed to be multisig... https://github.com/spesmilo/electrum/pull/5440#issuecomment-549504761
        # note: trezor plugin needs xpubs included, if there are multisig inputs/change_outputs
        from .wallet import Multisig_Wallet
        if include_xpubs and isinstance(wallet, Multisig_Wallet):
            from .keystore import Xpub
            for ks in wallet.get_keystores():
                if isinstance(ks, Xpub):
                    fp_bytes, der_full = ks.get_fp_and_derivation_to_be_used_in_partial_tx(
                        der_suffix=[], only_der_suffix=False)
                    xpub = ks.get_xpub_to_be_used_in_partial_tx(only_der_suffix=False)
                    bip32node = BIP32Node.from_xkey(xpub)
                    self.xpubs[bip32node] = (fp_bytes, der_full)
        for txin in self.inputs():
            wallet.add_input_info(
                txin,
                only_der_suffix=False,
            )
        for txout in self.outputs():
            wallet.add_output_info(
                txout,
                only_der_suffix=False,
            )

    def remove_xpubs_and_bip32_paths(self) -> None:
        self.xpubs.clear()
        for txin in self.inputs():
            txin.bip32_paths.clear()
        for txout in self.outputs():
            txout.bip32_paths.clear()

    def prepare_for_export_for_coinjoin(self) -> None:
        """Removes all sensitive details."""
        # globals
        self.xpubs.clear()
        self._unknown.clear()
        # inputs
        for txin in self.inputs():
            txin.bip32_paths.clear()
        # outputs
        for txout in self.outputs():
            txout.redeem_script = None
            txout.witness_script = None
            txout.bip32_paths.clear()
            txout._unknown.clear()

    async def prepare_for_export_for_hardware_device(self, wallet: 'Abstract_Wallet') -> None:
        self.add_info_from_wallet(wallet, include_xpubs=True)
        await self.add_info_from_network(wallet.network)
        # log warning if PSBT_*_BIP32_DERIVATION fields cannot be filled with full path due to missing info
        from .keystore import Xpub
        def is_ks_missing_info(ks):
            return (isinstance(ks, Xpub) and (ks.get_root_fingerprint() is None
                                              or ks.get_derivation_prefix() is None))
        if any([is_ks_missing_info(ks) for ks in wallet.get_keystores()]):
            _logger.warning('PSBT was requested to be filled with full bip32 paths but '
                            'some keystores lacked either the derivation prefix or the root fingerprint')

    def convert_all_utxos_to_witness_utxos(self) -> None:
        """Replaces all NON-WITNESS-UTXOs with WITNESS-UTXOs.
        This will likely make an exported PSBT invalid spec-wise,
        but it makes e.g. QR codes significantly smaller.
        """
        for txin in self.inputs():
            txin.convert_utxo_to_witness_utxo()

    def remove_signatures(self):
        for txin in self.inputs():
            txin.sigs_ecdsa = {}
            txin.tap_key_sig = None
            txin.script_sig = None
            txin.witness = None
        assert not self.is_complete()
        self.invalidate_ser_cache()


def pack_bip32_root_fingerprint_and_int_path(xfp: bytes, path: Sequence[int]) -> bytes:
    if len(xfp) != 4:
        raise Exception(f'unexpected xfp length. xfp={xfp}')
    return xfp + b''.join(i.to_bytes(4, byteorder='little', signed=False) for i in path)


def unpack_bip32_root_fingerprint_and_int_path(path: bytes) -> Tuple[bytes, Sequence[int]]:
    if len(path) % 4 != 0:
        raise Exception(f'unexpected packed path length. path={path.hex()}')
    xfp = path[0:4]
    int_path = [int.from_bytes(b, byteorder='little', signed=False) for b in chunks(path[4:], 4)]
    return xfp, int_path
