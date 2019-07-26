##!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
Cash Accounts related classes and functions.

Note that this file also contains a unique class called `ScriptOutput` (which
inherits from address.py's own ScriptOutput), so always import this file
carefully if also importing address.py.
'''

import re
import requests
import threading
import queue
import random
import time
from collections import defaultdict, namedtuple
from typing import List, Tuple, Dict
from . import bitcoin
from . import util
from .address import Address, OpCodes, Script, ScriptError, UnknownAddress
from .address import ScriptOutput as ScriptOutputBase
from .transaction import BCDataStream, Transaction
from . import verifier
from . import blockchain
from . import caches

# 'cashacct:' URI scheme. Used by Crescent Cash and Electron Cash and
# other wallets in the future.
URI_SCHEME = 'cashacct'

# Cash Accounts protocol code prefix is 0x01010101
# See OP_RETURN prefix guideline: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/op_return-prefix-guideline.md
protocol_code = bytes.fromhex("01010101")

activation_height = 563720  # all cash acct registrations are invalid if they appear before this block height
height_modification = activation_height - 100  # compute the cashacct.number by subtracting this value from tx block height
collision_hash_length = 10  # DO NOT MODIFY -- this is hard-coded in spec

# This RE is used to accept/reject names
name_accept_re = re.compile(r'^[a-zA-Z0-9_]{1,99}$')
# Accept/reject collision_hash -- must be a number string of precisely length 10
collision_hash_accept_re = re.compile(f'^[0-9]{{{collision_hash_length}}}$')

# mapping of Address.kind -> cash account data types
_addr_kind_data_types = { Address.ADDR_P2PKH : 0x1, Address.ADDR_P2SH : 0x2 }
_unsupported_types = { 0x03, 0x04, 0x83, 0x84 }
# negative lengths here indicate advisory and not enforced.
_data_type_lengths = { 0x1 : 20, 0x2 : 20, 0x3 : 80, 0x4 : -66, 0x81 : 20, 0x82 : 20, 0x83 : 80, 0x84 : -66 }
_data_types_addr_kind = {
    0x1  : Address.ADDR_P2PKH,  0x2 : Address.ADDR_P2SH,
    0x81 : Address.ADDR_P2PKH, 0x82 : Address.ADDR_P2SH,  # FIXME: These should really map to SLP addresses, but this works too.
}
_preferred_types = { 0x1, 0x2 }  # these take precedence over 0x81, 0x82 in the case of multi registrations containing more than 1 type

assert set(_unsupported_types) | set(_data_types_addr_kind) == set(_data_type_lengths)

def _i2b(val): return bytes((val,))

class ArgumentError(ValueError):
    '''Raised by various CashAcct functions if the supplied args are bad or
    out of spec.'''

class ScriptOutput(ScriptOutputBase):
    '''A class to encapsulate a Cash Accounts script output. Use the __new__ or
    @classmethod factory methods to create instances. Suitable for including in
    a Transaction as an output.

    Note: This class is named ScriptOutput like its base. This is intentional
    and client code should import this file such that referring to this class
    is module-qualified, eg cashacct.ScriptOutput.

    Note2: that the Transaction class automatically deserializes TYPE_SCRIPT
    outputs to instances of this class if the script contents match the
    CashAccounts protocol (based on boolean result of protocol_match() below).
    See the address.ScriptOutput 'protocol' mechanism (in address.py).'''

    _protocol_prefix = _i2b(OpCodes.OP_RETURN) + _i2b(4) + protocol_code

    # Additional attributes outside of the base class tuple's 1 attribute
    attrs_extra = ( 'name', 'address', 'addresses', 'number', 'collision_hash', 'emoji' )

    @classmethod
    def _protocol_match_fast(cls, script_bytes):
        '''Returns true iff the `script_bytes` at least START with the correct
        protocol code. Useful for fast-matching script outputs and testing
        if they are potential CashAcct registrations.

        `script_bytes` should be the full script as a bytes-like-object,
        including the OP_RETURN byte prefix.'''
        return script_bytes.startswith(cls._protocol_prefix)

    @classmethod
    def protocol_match(cls, script_bytes):
        '''Returns true iff the `script_bytes` is a valid Cash Accounts
        registration script (has all the requisite fields, etc).'''
        try:
            res = cls.parse_script(script_bytes)
            return bool(res)
        except (ValueError, TypeError):
            return False

    @classmethod
    def is_valid(cls, script):
        '''Alias for protocol_match. Returns true if script is a valid CashAcct
        registration script.'''
        return cls.protocol_match(script)

    def __new__(cls, script, *, number=None, collision_hash=None, emoji=None):
        '''Instantiate from a script (or address.ScriptOutput) you wish to parse.
        Use number=, collision_hash=, emoji= kwargs if you also have that
        information and want to store it in this instance.

        The script will be parsed and self.name and self.address will be set
        regardless.  Raises ArgumentError on invalid script.

        Always has the following attributes defined (even if None):

                name, address, number, collision_hash, emoji
        '''
        if isinstance(script, cls) and not any((number, collision_hash, emoji)):
            # copy constructor work-alike
            number, collision_hash, emoji = script.number, script.collision_hash, script.emoji
        script = cls._ensure_script(script)
        self = super(__class__, cls).__new__(cls, script)
        self.name, self.address, self.addresses = self.parse_script(self.script)  # raises on error
        assert self.address in self.addresses
        self.number, self.collision_hash, self.emoji = None, None, None  # ensure attributes defined
        self.make_complete2(number, collision_hash, emoji=emoji)  # raises if number  bad and/or if collision_hash is bad, otherwise just sets attributes. None ok for args.
        return self

    def copy(self):
        ''' Creates a copy. '''
        return ScriptOutput(self)

    @staticmethod
    def _check_name_address(name, address, *, allow_unknown=False, addresses=None):
        '''Raises ArgumentError if either name or address are somehow invalid.'''
        if not isinstance(name, str) or not name_accept_re.match(name):
            raise ArgumentError('Invalid name specified: must be an alphanumeric ascii string of length 1-99', name)
        if name != name.encode('ascii', errors='ignore').decode('ascii', errors='ignore'):  # <-- ensure ascii.  Note that this test is perhaps superfluous but the mysteries of unicode and how re's deal with it elude me, so it's here just in case.
            raise ArgumentError('Name must be pure ascii', name)
        if addresses is None:
            addresses = [address]
        if address not in addresses:
            raise ArgumentError('Address not in address list', address, addresses)
        for address in addresses:
            allowed_classes = (Address, UnknownAddress) if allow_unknown else (Address,)
            if not isinstance(address, allowed_classes):
                raise ArgumentError(f'Address of type \'{allowed_classes}\' expected', address)
            if isinstance(address, Address) and address.kind not in _addr_kind_data_types:
                raise ArgumentError('Invalid or unsupported address type', address)
        return True

    @staticmethod
    def _check_number_collision_hash(number, collision_hash):
        '''Raises ArgumentError if either number or collision_hash aren't to spec.'''
        if number is not None:  # We don't raise on None
            if not isinstance(number, int) or number < 100:
                raise ArgumentError('Number must be an int >= 100')
        if collision_hash is not None:  # We don't raise on None
            if isinstance(collision_hash, int): collision_hash = str(collision_hash)  # grr.. it was an int
            if not isinstance(collision_hash, str) or not collision_hash_accept_re.match(collision_hash):
                raise ArgumentError('Collision hash must be a number string, right-padded with zeroes, of length 10')
        return number is not None and collision_hash is not None

    def is_complete(self, fast_check=False):
        '''Returns true iff we have the number and collision_hash data for this
        instance, as well as valid name and valid address.'''
        if fast_check:
            return self.name and self.address and self.number and self.collision_hash
        try:
            return self._check_name_address(self.name, self.address, allow_unknown=True, addresses=self.addresses) and self._check_number_collision_hash(self.number, self.collision_hash)
        except ArgumentError:
            return False

    def make_complete2(self, number, collision_hash, *, emoji=None):
        '''Make this ScriptOutput instance complete by filling in the number and
        collision_hash info. Raises ArgumentError on bad/out-of-spec args (None
        args are ok though, the cashacct just won't be complete).'''
        ok = self._check_number_collision_hash(number, collision_hash)
        self.number = number
        self.collision_hash = collision_hash
        self.emoji = emoji or self.emoji
        return ok

    def make_complete(self, block_height=None, block_hash=None, txid=None):
        '''Make this ScriptOutput instance complete by specifying block height,
        block_hash (hex string or bytes), and txid (hex string or bytes)'''
        ch = collision_hash(block_hash, txid) if block_hash and txid else None
        num = bh2num(block_height) if block_height is not None else None
        em = emoji(block_hash, txid) if ch else None
        return self.make_complete2(num, ch, emoji=em)

    def clear_completion(self):
        '''Make this ScriptOutput incomplete again.'''
        self.number = self.collision_hash = self.emoji = None

    def to_ui_string(self, ignored=True):
        ''' Overrides super to add cashaccount data '''
        s = super().to_ui_string(ignored)
        extra = []
        for a in __class__.attrs_extra:
            val = getattr(self, a, None)
            if val is not None:
                if a == "addresses":
                    # For the addresses list, we just show how many there are
                    # in the list. We do not support more than the primary
                    # address anyway. If list is 1 or empty, skip
                    a, val = "num_addresses", len(val)
                    if val < 2:
                        continue
                extra.append(f'{a}={val}')
        extra = ' '.join(extra)
        return f'{s} [CashAcct: {extra}]' if extra else f'{s} [CashAcct]'

    def block_height(self) -> int:
        ''' Convenience method to returns the block_height.
        Requires that this class have its 'number' attribute not None, otherwise
        returns 0. '''
        return self.number + height_modification if self.number else 0

    def __repr__(self):
        return f'<ScriptOutput (CashAcct) {self.__str__()}>'

    def __eq__(self, other):
        res = super().__eq__(other)
        if res and isinstance(other, __class__) and self is not other:
            # awkward.. we do a deep check if self and other are both this type
            for a in __class__.attrs_extra:
                res = res and getattr(self, a, None) == getattr(other, a, None)
                if not res:
                    break
        return res

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        l = [self.script]
        for name in __class__.attrs_extra:
            v = getattr(self, name, None)
            if isinstance(v, list):
                v = tuple(v)
            l.append(v)
        return hash(tuple(l))

    @staticmethod
    def _ensure_script(script):
        '''Returns script or script.script if script is a ScriptOutput instance.
        Raises if script is not bytes and/or not ScriptOutput.  Always returns
        a bytes-like-object.'''
        if isinstance(script, ScriptOutputBase):
            script = script.script
        script = _ensure_bytes(script, "Script")
        return script

    @classmethod
    def parse_script(cls, script):
        '''Parses `script`, which may be either a ScriptOutput class, or raw
        bytes data. Will raise various exceptions if it cannot parse.  Returns
        (name: str, address: Address) as a tuple. '''
        script = cls._ensure_script(script)
        # Check prefix, length, and that the 'type' byte is one we know about
        if not cls._protocol_match_fast(script) or len(script) < 30:
            raise ArgumentError('Not a valid CashAcct registration script')
        script_short = script
        try:
            script_short = script[len(cls._protocol_prefix):]  # take off the already-validated prefix
            ops = Script.get_ops(script_short)  # unpack ops
        except Exception as e:
            raise ArgumentError('Bad CashAcct script', script_short.hex()) from e
        # Check for extra garbage at the end, too few items and/or other nonsense
        if not ops or not len(ops) >= 2 or not all(len(op) == 2 and op[1] for op in ops):
            raise ArgumentError('CashAcct script parse error', ops)
        name_bytes = ops[0][1]
        try:
            name = name_bytes.decode('ascii')
        except UnicodeError as e:
            raise ArgumentError('CashAcct names must be ascii encoded', name_bytes) from e
        addresses = []
        addresses_preferred = []  # subset of above with types either 0x1 or 0x2, all valid Address instances (may be empty if registration contained no 0x1/0x2)
        try:
            # parse the list of payment data (more than 1), and try and grab
            # the first address we understand (type 1 or 2)
            for op in ops[1:]:
                def get_address(op):
                    type_byte = op[1][0]
                    hash160_bytes = op[1][1:]
                    req_len = _data_type_lengths.get(type_byte) or 0
                    strict = req_len >= 0
                    req_len = abs(req_len)
                    if type_byte in _data_types_addr_kind:
                        if len(hash160_bytes) != req_len:
                            if strict:
                                raise AssertionError('hash160 had wrong length')
                            else:
                                util.print_error(f"parse_script: type 0x{type_byte:02x} had length {len(hash160_bytes)} != expected length of {req_len}, will proceed anyway")
                        return Address(hash160_bytes, _data_types_addr_kind[type_byte]), type_byte
                    elif type_byte in _unsupported_types:
                        # unsupported type, just acknowledge this registration but
                        # mark the address as unknown
                        if len(hash160_bytes) != req_len:
                            msg = f"parse_script: unsupported type 0x{type_byte:02x} has unexpected length {len(hash160_bytes)}, expected {req_len}"
                            util.print_error(msg)
                            if strict:
                                raise AssertionError(msg)
                        return UnknownAddress(hash160_bytes), type_byte
                    else:
                        raise ValueError(f'unknown cash address type 0x{type_byte:02x}')
                # / get_address
                adr, type_byte = get_address(op)
                addresses.append(adr)
                if type_byte in _preferred_types and isinstance(adr, Address):
                    addresses_preferred.append(adr)
                del adr, type_byte  # defensive programming
            assert addresses
            maybes = [a for a in (addresses_preferred or addresses) if isinstance(a, Address)]
            address = (maybes and maybes[0]) or addresses[0]
        except Exception as e:
            # Paranoia -- this branch should never be reached at this point
            raise ArgumentError('Bad address or address could not be parsed') from e

        cls._check_name_address(name, address, addresses=addresses, allow_unknown=True)  # raises if invalid

        return name, address, addresses

    ############################################################################
    #                            FACTORY METHODS                               #
    ############################################################################
    @classmethod
    def create_registration(cls, name, address):
        '''Generate a CashAccounts registration script output for a given
        address. Raises ArgumentError (a ValueError subclass) if args are bad,
        otherwise returns an instance of this class.'''
        cls._check_name_address(name, address)
        # prepare payload
        # From: https://gitlab.com/cash-accounts/specification/blob/master/SPECIFICATION.md
        #
        # Sample payload (hex bytes) for registration of 'bv1' -> bitcoincash:qzgvpjawln2l8wfmsg2qwnnytcua02hy45vpdvrqu5
        # (This example is a real tx with txid: 4a2da2a69fba3ac07b7047dd17927a890091f13a9e89440a4cd4cfb4c009de1f)
        #
        # hex bytes:
        # 6a040101010103627631150190c0cbaefcd5f3b93b8214074e645e39d7aae4ad
        # | | |......|| |....|| | |......................................|
        # | | |......|| |....|| | ↳ hash160 of bitcoincash:qzgvpjawln2l8wfmsg2qwnnytcua02hy45vpdvrqu5
        # | | |......|| |....|| |
        # | | |......|| |....|| ↳ type (01 = p2pkh)
        # | | |......|| |....||
        # | | |......|| |....|↳ OP_PUSH(0x15 = 21)
        # | | |......|| |....|
        # | | |......|| ↳'bv1'
        # | | |......||
        # | | |......|↳OP_PUSH(3)
        # | | |......|
        # | | ↳protocol_code = 0x01010101
        # | |
        # | ↳OP_PUSH(4)
        # |
        # ↳OP_RETURN
        class MyBCDataStream(BCDataStream):
            def push_data(self, data):
                self.input = self.input or bytearray()
                self.input += Script.push_data(data)
        bcd = MyBCDataStream()
        bcd.write(cls._protocol_prefix)  # OP_RETURN -> 0x6a + 0x4 (pushdata 4 bytes) + 0x01010101 (protocol code)
        bcd.push_data(name.encode('ascii'))
        bcd.push_data(
            # type byte: 0x1 for ADDR_P2PKH, 0x2 for ADDR_P2SH
            _i2b(_addr_kind_data_types[address.kind])
            # 20 byte haash160
            + address.hash160
        )

        return cls(bytes(bcd.input))

    @classmethod
    def from_script(cls, script, *,
                    # these two optional args, if specified, take precedence
                    number=None, collision_hash=None,
                    # additionally these other args can be specified to
                    # have this class calculate number and collision_hash
                    # for you. Use either set of optional args but not both.
                    block_height=None,  # if set, self.number will be set. Cannot specify this & number
                    # Cannot specify these & collision_hash at the same time
                    block_hash=None, txid=None  # if block_hash and txid are set, .emoji will be set too on returned class (along with .collision_hash)
                    ):
        '''Create an instance from a `script`, which may be either a
        ScriptOutput class, or raw bytes data. Will raise various exceptions if
        it cannot parse and/or script or args are invalid.'''
        if block_height is not None:
            if number is not None:
                raise ArgumentError('Cannot specify both block_height and number')
            number = number_from_block_height(block_height)
        tup = (block_hash, txid)
        myemoji=None
        if any(tup):
            if not all(tup):
                raise ArgumentError('block_hash and txid must both be specified or not specified at all')
            if collision_hash is not None:
                raise ArgumentError('Cannot specify collision_hash, block_hash & txid together')
            collision_hash = chash(block_hash, txid)
            myemoji = emoji(block_hash, txid)
        return cls(script, number=number, collision_hash=collision_hash, emoji=myemoji)

    @classmethod
    def from_dict(cls, d: dict) -> object:
        ''' Create an isntance from a dict created by to_dict. '''
        return cls(d['script'],  # hex -> bytes will get auto-converted in c'tor
                   number=d.get('number'), collision_hash=d.get('collision_hash'),
                   emoji=d.get('emoji'))

    def to_dict(self) -> dict:
        assert self.script
        d = { 'script' : self.script.hex() }
        if self.number is not None: d['number'] = self.number
        if self.collision_hash is not None: d['collision_hash'] = self.collision_hash
        if self.emoji is not None: d['emoji'] = self.emoji
        return d

# register the above class with the ScriptOutput protocol system
ScriptOutputBase.protocol_classes.add(ScriptOutput)

# Helper Functions
def _ensure_bytes(arg, argname='Arg'):
    if isinstance(arg, str):
        try:
            arg = bytes.fromhex(arg)
        except ValueError as e:
            raise ArgumentError(f'{argname} could not be binhex decoded', arg) from e
    if not isinstance(arg, (bytes, bytearray)):
        raise ArgumentError(f'{argname} argument not a bytes-like-object', arg)
    if isinstance(arg, bytearray):
        arg = bytes(arg)  # ensure actual bytes so hash() works.
    return arg

def _collision_hash(block_hash, txid):
    ''' Returns the full sha256 collision hash as bytes given the hex strings
    and/or raw bytes as input. May raise ValueError or other. '''
    bh = _ensure_bytes(block_hash, 'block_hash')
    tx = _ensure_bytes(txid, 'txid')
    if not all( len(x) == 32 for x in (bh, tx) ):
        raise ArgumentError('Invalid arguments', block_hash, txid)
    return bitcoin.sha256(bh + tx)

def collision_hash(block_hash, txid):
    ''' May raise if block_hash and txid are not valid hex-encoded strings
    and/or raw bytes, otherwise returns the 0-padded collision hash string
    (always a str of length 10).'''
    ch = _collision_hash(block_hash, txid)[:4]
    ch = ''.join(reversed(str(int.from_bytes(ch, byteorder='big'))))  # convert int to string, reverse it
    ch += '0' * (10 - len(ch))  # pad with 0's at the end
    return ch

chash = collision_hash  # alias.

def emoji_index(block_hash, txid):
    ''' May raise. Otherwise returns an emoji index from 0 to 99. '''
    ch = _collision_hash(block_hash, txid)[-4:]
    return int.from_bytes(ch, byteorder='big') % 100

emoji_list = ( 128123, 128018, 128021, 128008, 128014, 128004, 128022, 128016,
               128042, 128024, 128000, 128007, 128063, 129415, 128019, 128039,
               129414, 129417, 128034, 128013, 128031, 128025, 128012, 129419,
               128029, 128030, 128375, 127803, 127794, 127796, 127797, 127809,
               127808, 127815, 127817, 127819, 127820, 127822, 127826, 127827,
               129373, 129381, 129365, 127805, 127798, 127812, 129472, 129370,
               129408, 127850, 127874, 127853, 127968, 128663, 128690, 9973,
               9992, 128641, 128640, 8986, 9728, 11088, 127752, 9730, 127880,
               127872, 9917, 9824, 9829, 9830, 9827, 128083, 128081, 127913,
               128276, 127925, 127908, 127911, 127928, 127930, 129345, 128269,
               128367, 128161, 128214, 9993, 128230, 9999, 128188, 128203,
               9986, 128273, 128274, 128296, 128295, 9878, 9775, 128681,
               128099, 127838 )

emoji_set = frozenset(chr(o) for o in emoji_list)

def emoji(block_hash, txid):
    ''' Returns the emoji character givern a block hash and txid. May raise.'''
    return chr(emoji_list[emoji_index(block_hash, txid)])

_emoji = emoji  # alias for internal use if names clash

def number_from_block_height(block_height):
    ''' Given a block height, returns the cash account 'number' (as int).
    This is simply the block height minus 563620. '''
    return int(block_height - height_modification)

def number_to_block_height(number):
    ''' Reciprocal of number_to_block_height '''
    return int(number + height_modification)

bh2num = number_from_block_height  # alias
num2bh = number_to_block_height  # alias

#### Lookup & Verification

class Info(namedtuple("Info", "name, address, number, collision_hash, emoji, txid")):
    @classmethod
    def from_script(cls, script, txid):
        ''' Converts a script to an Info object. Note that ideally the passed-in
        script.is_complete() should be True otherwise most of the fields of the
        returned Info object will be None.'''
        return cls(name=script.name,
                   address=script.address,
                   number=script.number,
                   collision_hash=script.collision_hash,
                   emoji=script.emoji,
                   txid=txid)

    def to_script(self):
        ''' Inverse of from_script, returns a (script, txid) tuple. '''
        script = ScriptOutput.create_registration(name=self.name, address=self.address)
        script.make_complete2(number=self.number, collision_hash=self.collision_hash,
                              emoji=self.emoji)
        return script, self.txid

    @classmethod
    def from_regtx(cls, regtx):
        return cls.from_script(regtx.script, regtx.txid)


servers = [
    "https://cashacct.imaginary.cash",  # Runs official 'cash-accounts' lookup server software
    "https://api.cashaccount.info",     # Runs official 'cash-accounts' lookup server software
    "https://cashacct.electroncash.dk", # Runs official 'cash-accounts' lookup server software
    "https://electrum.imaginary.cash"   # Runs alternative server software: https://gitlab.com/paOol/lookup-server
]

debug = False  # network debug setting. Set to True when developing to see more verbose information about network operations.
timeout = 12.5  # default timeout used in various network functions, in seconds.

def lookup(server, number, name=None, collision_prefix=None, timeout=timeout, exc=[], debug=debug) -> tuple:
    ''' Synchronous lookup, returns a tuple of:

            block_hash, List[ RegTx(txid, script) namedtuples ]

    or None on error. Note the .script in each returned RegTx will always have
    .is_complete() == True (has all fields filled-in from the lookup server).

    Optionally, pass a list as the `exc` parameter and the exception encountered
    will be returned to caller by appending to the list.

    Use `collision_prefix` and `name` to narrow the search, otherwise all
    results (if any) for a particular block (number) are returned.

    Name matching is case-insensitive.  Additionally, as of the time of this
    writing, collision_prefix without a specified name will always return no
    results from the lookup server. Also, name should be a complete name and not
    a substring.

    Note:
    Resulting tx's are not verified (in the SPV sense) by this function and
    further verification (SPV) is necessary before presenting any results to the
    user for the purposes of sending funds.'''
    url = f'{server}/lookup/{number}'
    if name:
        name = name.strip().lower()
        url += f'/{name}'
    if collision_prefix:
        collision_prefix = collision_prefix.strip()
        url += f'/{collision_prefix}'
    try:
        ret = []
        r = requests.get(url, allow_redirects=True, timeout=timeout) # will raise requests.exceptions.Timeout on timeout
        r.raise_for_status()
        d = r.json()
        if not isinstance(d, dict) or not d.get('results') or not isinstance(d.get('block'), int):
            raise RuntimeError('Unexpected response', r.text)
        res, block = d['results'], int(d['block'])
        bnumber = bh2num(block)
        if bnumber != number:
            raise RuntimeError('Bad response')
        if not isinstance(res, list) or number < 100:
            raise RuntimeError('Bad response')
        block_hash, header_prev = None, None
        unparseable = set()
        for d in res:
            txraw = d['transaction']
            header_hex = d['inclusion_proof'][:blockchain.HEADER_SIZE*2].lower()
            header_prev = header_prev or header_hex
            if len(header_hex)//2 != blockchain.HEADER_SIZE:
                raise AssertionError('Could not get header')
            if not block_hash:
                block_hash = blockchain.hash_header_hex(header_hex)
            elif header_prev != header_hex:
                raise AssertionError('Differing headers in results')
            tx = Transaction(txraw)
            txid = Transaction._txid(txraw)
            op_return_count = 0
            tx_regs = []  # there should be exactly 1 of these per tx, as per cash acount spec.. we reject tx's with more than 1 op_return
            for _typ, script, value in tx.outputs():
                if isinstance(script, ScriptOutputBase):
                    if script.is_opreturn():
                        op_return_count += 1
                    if isinstance(script, ScriptOutput):  # note ScriptOutput here is our subclass defined at the top of this file, not addess.ScriptOutput
                        script.make_complete(block_height=block, block_hash=block_hash, txid=txid)
                        tx_regs.append(CashAcct.RegTx(txid, script))
            if len(tx_regs) == 1 and op_return_count == 1:
                # we only accept tx's with exactly 1 OP_RETURN, as per the spec
                ret.extend(tx_regs)
            else:
                if debug:
                    util.print_error(f"lookup: {txid} had no valid registrations in it using server {server} (len(tx_regs)={len(tx_regs)} op_return_count={op_return_count})")
                unparseable.add(txid)
        if unparseable:
            util.print_error(f"lookup: Warning for block number {number}: got "
                             f"{len(res)} transactions from the server but "
                             f"unable to parse {len(unparseable)} of them."
                             " See if the Cash Accounts spec has changed!", unparseable)
        if debug:
            util.print_error(f"lookup: found {len(ret)} reg txs at block height {block} (number={number})")
        return block_hash, ret
    except Exception as e:
        if debug:
            util.print_error("lookup:", repr(e))
        if isinstance(exc, list):
            exc.append(e)

def lookup_asynch(server, number, success_cb, error_cb=None,
                  name=None, collision_prefix=None, timeout=timeout, debug=debug):
    ''' Like lookup() above, but spawns a thread and does its lookup
    asynchronously.

    success_cb - will be called on successful completion with a single arg:
                 a tuple of (block_hash, the results list).
    error_cb   - will be called on failure with a single arg: the exception
                 (guaranteed to be an Exception subclass).

    In either case one of the two callbacks will be called. It's ok for
    success_cb and error_cb to be the same function (in which case it should
    inspect the arg passed to it). Note that the callbacks are called in the
    context of the spawned thread, (So e.g. Qt GUI code using this function
    should not modify the GUI directly from the callbacks but instead should
    emit a Qt signal from within the callbacks to be delivered to the main
    thread as usual.) '''

    def thread_func():
        exc = []
        res = lookup(server=server, number=number, name=name, collision_prefix=collision_prefix, timeout=timeout, exc=exc, debug=debug)
        called = False
        if res is None:
            if callable(error_cb) and exc:
                error_cb(exc[-1])
                called = True
        else:
            success_cb(res)
            called = True
        if not called:
            # this should never happen
            util.print_error("WARNING: no callback called for ", threading.current_thread().name)
    t = threading.Thread(name=f"CashAcct lookup_asynch: {server} {number} ({name},{collision_prefix},{timeout})",
                         target=thread_func, daemon=True)
    t.start()

def lookup_asynch_all(number, success_cb, error_cb=None, name=None,
                      collision_prefix=None, timeout=timeout, debug=debug):
    ''' Like lookup_asynch above except it tries *all* the hard-coded servers
    from `servers` and if all fail, then calls the error_cb exactly once.
    If any succeed, calls success_cb exactly once.

    Note: in this function success_cb is called with TWO args:
      - first arg is the tuple of (block_hash, regtx-results-list)
      - the second arg is the 'server' that was successful (server string)

    One of the two callbacks are guaranteed to be called in either case.

    Callbacks are called in another thread context so GUI-facing code should
    be aware of that fact (see nodes for lookup_asynch above).  '''
    assert servers, "No servers hard-coded in cashacct.py. FIXME!"
    my_servers = servers.copy()
    random.shuffle(my_servers)
    N = len(my_servers)
    q = queue.Queue()
    lock = threading.Lock()
    n_ok, n_err = 0, 0
    def on_succ(res, server):
        nonlocal n_ok
        q.put(None)
        with lock:
            if debug: util.print_error("success", n_ok+n_err, server)
            if n_ok:
                return
            n_ok += 1
        success_cb(res, server)
    def on_err(exc, server):
        nonlocal n_err
        q.put(None)
        with lock:
            if debug: util.print_error("error", n_ok+n_err, server, exc)
            if n_ok:
                return
            n_err += 1
            if n_err < N:
                return
        if error_cb:
            error_cb(exc)
    def do_lookup_all_staggered():
        ''' Send req. out to all servers, staggering the requests every 200ms,
        and stopping early after the first success.  The goal here is to
        maximize the chance of successful results returned, with tolerance for
        some servers being unavailable, while also conserving on bandwidth a
        little bit and not unconditionally going out to ALL servers.'''
        t0 = time.time()
        for i, server in enumerate(my_servers):
            if debug: util.print_error("server:", server, i)
            lookup_asynch(server, number = number,
                          success_cb = lambda res, _server=server: on_succ(res, _server),
                          error_cb = lambda exc, _server=server: on_err(exc, _server),
                          name = name, collision_prefix = collision_prefix, timeout = timeout,
                          debug = debug)
            try:
                q.get(timeout=0.200)
                while True:
                    # Drain queue in case previous iteration's servers also
                    # wrote to it while we were sleeping, so that next iteration
                    # the queue is hopefully empty, to increase the chances
                    # we get to sleep.
                    q.get_nowait()
            except queue.Empty:
                pass
            with lock:
                if n_ok:  # check for success
                    if debug:
                        util.print_error(f"do_lookup_all_staggered: returning "
                                         f"early on server {i} of {len(my_servers)} after {(time.time()-t0)*1e3} msec")
                    return
    t = threading.Thread(daemon=True, target=do_lookup_all_staggered)
    t.start()

class ProcessedBlock:
    __slots__ = ( 'hash',  # str binhex block header hash
                  'height',  # int blockchain block height
                  'status_hash',  # str binhex computed value derived from Hash(hash + height + reg_txs..) see compute_status_hash
                  'reg_txs' )  # dict of txid -> RegTx(txid, script) namedtuple

    def __init__(self, *args, **kwargs):
        assert not args, "This class only takes kwargs"
        assert all(k in self.__slots__ for k in kwargs), "Unknown kwarg specified"
        for s in self.__slots__:
            setattr(self, s, kwargs.get(s))
        assert self.reg_txs is None or (isinstance(self.reg_txs, dict) and all(bytes.fromhex(k).hex() == bytes.fromhex(v.txid).hex() for k,v in self.reg_txs.items()))
        assert self.hash is None or (isinstance(self.hash, str) and bytes.fromhex(self.hash).hex())
        assert self.height is None or (isinstance(self.height, int) and self.height >= activation_height)
        self.status_hash or self.set_status_hash()  # tries to recompute if not provided
        assert self.status_hash is None or (isinstance(self.status_hash, str) and bytes.fromhex(self.status_hash))

    def __repr__(self):
        return ( f'<ProcessedBlock at 0x{id(self):x} hash={self.hash} height={self.height} status_hash={self.status_hash}'
                 + f' with {0 if not self.reg_txs else len(self.reg_txs)} registration(s)>')

    def set_status_hash(self) -> str:
        self.status_hash = self.compute_status_hash(self.hash, self.height, self.reg_txs)
        return self.status_hash

    def set_hash_from_raw_header_hex(self, rawhex : str) -> str:
        assert len(rawhex) >= blockchain.HEADER_SIZE * 2
        self.hash = blockchain.hash_header_hex(rawhex[:blockchain.HEADER_SIZE*2])
        return self.hash

    @staticmethod
    def compute_status_hash(hash_hex : str, height : int, reg_txs : dict) -> str:
        if hash_hex and isinstance(height, int) and isinstance(reg_txs, dict):
            ba = bytearray()
            ba.extend(int.to_bytes(height, length=4, byteorder='little'))
            ba.extend(bytes.fromhex(hash_hex))
            for txid in sorted(reg_txs.keys()):
                ba.extend(bytes.fromhex(txid))
            status_hash = bitcoin.hash_encode(bitcoin.Hash(ba))
            return status_hash

    def __eq__(self, other):
        if other is self: return True
        if isinstance(other, ProcessedBlock):
            return bool(self.hash == other.hash and self.height == other.height and (self.status_hash or self.set_status_hash()) == (other.status_hash or other.set_status_hash()))
        return False

    def __neq__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        l = []
        for name in self.__slots__:
            v = getattr(self, name, None)
            if isinstance(v, dict):
                # Python really needs a frozendict type. :)  This dict doesn't
                # mutate anyway once constructed, so this is safe.
                v = tuple(v.items())
            # uncomment below if we add a list to this class
            #elif isinstance(v, list):
            #    v = tuple(v)
            l.append(v)
        return hash(tuple(l))


class CashAcct(util.PrintError, verifier.SPVDelegate):
    ''' Class implementing cash account subsystem such as verification, etc. '''

    # info for a registration tx. may or may not be currently verified
    RegTx = namedtuple("RegTx", "txid, script")
    # info for a verified RegTx.  Invariant should be all VerifTx's have a
    # corrseponding RegTx but not necessarily vice-versa.
    VerifTx = namedtuple("VerifTx", "txid, block_height, block_hash")

    def __init__(self, wallet):
        assert wallet, "CashAcct cannot be instantiated without a wallet"
        self.wallet = wallet
        self.network = None
        self.verifier = None
        self.lock = threading.Lock()  # note, this lock is subordinate to wallet.lock and should always be taken AFTER wallet.lock and never before

        self._init_data()

        # below is used by method self.verify_block_asynch:
        self._blocks_in_flight = defaultdict(list)  # number (eg 100-based-modified height) -> List[tuple(success_cb, error_cb)]; guarded with lock

    def _init_data(self):
        self.wallet_reg_tx = dict() # dict of txid -> RegTx
        self.ext_reg_tx = dict() # dict of txid -> RegTx

        self.v_tx = dict() # dict of txid -> VerifTx
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid

        self.ext_unverif = dict()  # ephemeral (not saved) dict of txid -> block_height. This is however re-computed in load() (TODO: see if this should not be the case)

        self.ext_incomplete_tx = dict() # ephemeral (not saved) dict of txid -> RegTx (all regtx's are incomplete here)

        # minimal collision hash encodings cache. keyed off (name.lower(), number, collision_hash) -> '03' string or '' string, serialized to disk for good UX on startup.
        self.minimal_ch_cache = caches.ExpiringCache(name=f"{self.wallet.diagnostic_name()} - CashAcct minimal collision_hash cache")

        # Dict of block_height -> ProcessedBlock (not serialized to disk)
        self.processed_blocks = caches.ExpiringCache(name=f"{self.wallet.diagnostic_name()} - CashAcct processed block cache", maxlen=5000, timeout=3600.0)

    def diagnostic_name(self):
        return f'{self.wallet.diagnostic_name()}.{__class__.__name__}'

    def start(self, network):
        assert network, "CashAcct start requires a valid network instance"
        if not self.network:
            assert not self.verifier
            self.network = network
            # our own private verifier, we give it work via the delegate methods
            self.verifier = verifier.SPV(self.network, self)
            self.network.add_jobs([self.verifier])
            util.finalization_print_error(self.verifier)
            self.network.register_callback(self._fw_wallet_updated, ['wallet_updated'])

    def stop(self):
        if self.verifier:
            assert self.network
            self.network.unregister_callback(self._fw_wallet_updated)
            self.verifier.release()
            self.verifier = None
            self.network = None

    def fmt_info(self, info : Info, minimal_chash: str = None, emoji=False) -> str:
        ''' Given an Info object, returns a string of the form:

        name#123.1234;
        name2#100;
        name3#101.1234567890;

        If emoji=True, then we will append the emoji character like so:

        "NilacTheGrim#123.45; 🌶"

        (Note that the returned string will always end in a semicolon.)

        Will implicitly go out to network to cache the minimal_chash value
        if minimal_chash==None.. such that subsequent calls may return
        a shortened version once the minimal_chash is computed.'''
        name, number, chash = info.name, info.number, info.collision_hash
        if minimal_chash is None:
            minimal_chash = self.get_minimal_chash(name, number, chash)
        if minimal_chash: minimal_chash = '.' + minimal_chash
        emojipart = f' {info.emoji}' if emoji and info.emoji else ''
        return f"{name}#{number}{minimal_chash};{emojipart}"


    _number_re = re.compile(r'^[0-9]{3,}$')
    _collision_re = re.compile(r'^[0-9]{0,10}$')

    @staticmethod
    def strip_emoji(s : str) -> str:
        return ''.join(filter(lambda x: x not in emoji_set, s))

    @classmethod
    def parse_string(cls, s : str) -> tuple:
        ''' Returns a (name, number, collision_prefix) tuple on parse success
        of a string of the form: "name#100" or "name#100.12" or "name#100.123;"
        (trailing ; is ignored).

        Returns None on parse failure.

        Note:
            - number must always be >= 100 otherwise None is returned. e.g.
              mark#99 is bad but mark#100 is good.
            - collision_prefix must be empty or length <= 10 otherwise None is
              returned.  e.g. mark#100.01234567899 is too long but mark#100.0123456789 is ok

        Does not raise, merely returns None on all errors.'''
        s = s.strip()
        while s and s[-1] in emoji_set:
            s = s[:-1].strip() # strip trailing "<space><emoji>"
        while s.endswith(';'):
            s = s[:-1]  # strip trailing ;
        parts = s.split('#')
        if len(parts) != 2:
            return None
        name, therest = parts
        if name and name[0] in emoji_set:  # support a custom style string with "emoji name#number.123" as the format
            name = name[1:].strip()
        if not name_accept_re.match(name):
            return None
        parts = therest.split('.')
        if len(parts) == 1:
            number = parts[0]
            collision_prefix = ''
        elif len(parts) == 2:
            number, collision_prefix = parts
        else:
            return None
        if not cls._number_re.match(number):
            return None
        if not cls._collision_re.match(collision_prefix):
            return None
        try:
            number = int(number)
        except:
            return None
        if number < 100:
            return None
        return name, number, collision_prefix

    def resolve_verify(self, ca_string : str, timeout: float = timeout, exc: list = None) -> List[Tuple[Info, str]]:
        ''' Blocking resolver for Cash Account names. Given a ca_string of the
        form: name#number[.123], will verify the block it is on and do other
        magic. It will return a list of tuple of (Info, minimal_chash).

        This goes out to the network each time, so use it in GUI code that
        really needs to know verified CashAccount tx's (eg before sending funds),
        but not in advisory GUI code, since it can be slow (on the order of less
        than a second to several seconds depending on network speed).

        timeout is a timeout in seconds. If timer expires None is returned.

        It will return None on failure or nothing found.

        Optional arg `exc` is where to put the exception on network or other
        failure. '''
        tup = self.parse_string(ca_string)
        if not tup:
            return
        name, number, chash = tup
        specified_chash = chash or ''
        done = threading.Event()
        pb = None
        def done_cb(thing):
            nonlocal pb
            if isinstance(thing, ProcessedBlock) and thing.reg_txs:
                pb = thing
            elif isinstance(thing, Exception) and isinstance(exc, list):
                exc.append(thing)
            done.set()
        self.verify_block_asynch(number, success_cb=done_cb, error_cb=done_cb, timeout=timeout)
        if not done.wait(timeout=timeout) or not pb:
            return
        matches = list()
        found = None
        lname = name.lower()
        for txid, rtx in pb.reg_txs.items():
            rtx_lname = rtx.script.name.lower()
            if rtx_lname == lname:
                matches.append((txid, rtx_lname, rtx.script.collision_hash))

        if not matches:
            return # no match

        d = self._calc_minimal_chashes_for_sorted_lcased_tups(sorted(t[1:] for t in matches))

        ret = []
        empty_dict = dict()
        for txid, lname, chash in matches:
            min_chash = d.get(lname, empty_dict).get(chash, None)
            if min_chash is None:
                self.print_error(f"resolve_verify: WARNING! Internal Error! Did not find calculated minimal chash for {lname}.{chash}. FIXME!")
                min_chash = chash
            rtx = pb.reg_txs[txid]
            if rtx.script.collision_hash.startswith(specified_chash):
                info = Info.from_regtx(rtx)
                ret.append((info, min_chash))
        return ret or None


    def get_minimal_chash(self, name, number, collision_hash, *,
                          success_cb = None, skip_caches = False, only_cached = False) -> str:
        ''' Returns a string of the minimal collision hash for a given
        name, number, collision_hash combination. This initially will just
        return collision_hash, but will go out to the network and
        subsequent calls will return the cached results from the asynch. network
        lookup should it complete successfully. Note that cached results get
        saved to wallet storage, so over the course of the life of a wallet
        at least the GUI for the wallet's own addresses should contain correct
        results here.

        Client code can use the 'ca_updated_minimal_chash' network callback
        (see below) to be notified asynchronously when minimal_chash's are
        updated.

        Optionally client code can supply a success_cb callback function which
        will be passed 2 args:  (name, number, collision_hash), minimal_collision_hash
        Callback if specified is guaranteed to be called before or after this
        function returns, but it may be called in another thread.'''
        key = (name.lower(), number, collision_hash)
        def call_success_cb(min_ch):
            ''' Inform caller if they supplied a callback that the process is done. '''
            if success_cb: success_cb((name, number, collision_hash), min_ch)
        found, pb_cached = None, None
        if not skip_caches:
            with self.lock:
                found = self.minimal_ch_cache.get(key)
                if found is None:
                    # See if we have the block cached
                    pb_cached = self.processed_blocks.get(num2bh(number))
        if found is None and pb_cached is not None:
            # We didn't have the chash but we do have the block, use that
            # immediately without going out to network
            tup = self._calc_minimal_chash(name, collision_hash, pb_cached)
            if tup:
                found = tup[1]
                with self.lock:
                    # Cache result
                    self.minimal_ch_cache.put(key, found)
            # clean up after ourselves
            del tup
        if found is not None:
            call_success_cb(found)
            return found
        elif only_cached:
            call_success_cb(collision_hash)
            return collision_hash
        else:
            def do_lookup():
                t0 = time.time()
                def on_success(pb : ProcessedBlock):
                    minimal_chash = collision_hash  # start with worst-case, so finally block below has data no matter what happens..
                    try:
                        if bh2num(pb.height) != number:
                            self.print_error(f"get_minimal_chash: WARNING - Internal error. pb.height: {pb.height} != num2bh: {num2bh(number)}")
                            return
                        tup = self._calc_minimal_chash(name, collision_hash, pb)
                        if not tup:
                            # hmm. empty results.. or bad lookup. in either case,
                            # don't cache anything.
                            self.print_error("get_minimal_chash: no results found for", name, number, collision_hash)
                            return
                        rtx, minimal_chash = tup
                        with self.lock:
                            self.minimal_ch_cache.put(key, minimal_chash)
                        self.print_error(f"get_minimal_chash: network lookup completed in {time.time()-t0:1.2f} seconds")
                        network = self.network  # capture network obj to avoid race conditions with self.stop()
                        if network and rtx and minimal_chash != collision_hash:
                            network.trigger_callback('ca_updated_minimal_chash', self, Info.from_regtx(rtx), minimal_chash)
                    finally:
                        call_success_cb(minimal_chash)
                # /on_success
                self.verify_block_asynch(number=number, success_cb=on_success)
            if self.network:  # only do this if not 'offline'
                do_lookup()  # start the asynch lookup
            else:
                # no network, just call success_cb anyway with what we have so caller doesn't block on waiting for callback...
                call_success_cb(collision_hash)
            # Immediately return the long-form chash so we give the caller a
            # result immediately, even if it is not the final result.
            # The caller should subscribe to the ca_updated_minimal_chash
            # network signal to get final minimal_chash when it is ready.
            return collision_hash

    def get_cashaccounts(self, domain=None, inv=False) -> List[Info]:
        ''' Returns a list of Info objects for verified cash accounts in domain.
        Domain must be an iterable of addresses (either wallet or external).
        If domain is None, every verified cash account we know about is returned.

        If inv is True, then domain specifies addresses NOT to include
        in the results (i.e. eevery verified cash account we know about not in
        domain be returned). '''
        if domain is None:
            domain = self.v_by_addr if not inv else set()
        ret = []
        seen = set()
        with self.lock:
            if inv:
                domain = set(self.v_by_addr) - set(domain)
            for addr in domain:
                txids = self.v_by_addr.get(addr, set())
                for txid in txids:
                    script = self._find_script(txid)
                    if script and txid not in seen:
                        seen.add(txid)
                        ret.append(Info.from_script(script, txid))

        return ret

    def get_wallet_cashaccounts(self) -> List[Info]:
        ''' Convenience method, returns all the verified cash accounts we
        know about for wallet addresses only. '''
        return self.get_cashaccounts(domain=self.wallet.get_addresses())

    def get_external_cashaccounts(self) -> List[Info]:
        ''' Convenience method, retruns all the verified cash accounts we
        know about that are not for wallet addresses. '''
        return self.get_cashaccounts(domain=self.wallet.get_addresses(), inv=True)


    def load(self):
        ''' Note: loading should happen before threads are started, so no lock
        is needed.'''
        self._init_data()
        dd = self.wallet.storage.get('cash_accounts_data', {})
        wat_d = dd.get('wallet_reg_tx', {})
        eat_d = dd.get('ext_reg_tx', {})
        vtx_d = dd.get('verified_tx', {})
        min_enc_l = dd.get('minimal_ch_cache', [])

        seen_scripts = {}

        for txid, script_dict in wat_d.items():
            txid = txid.lower()
            script = ScriptOutput.from_dict(script_dict)
            if script.is_complete():
                # sanity check
                seen_scripts[txid] = script
            # Note we allow incomplete scripts in the wallet_reg_tx dict because
            # the user may close wallet and restart and then verifier will see
            # the tx as verified as it synchs, thus completing it.
            # This is safe since by default _find_script() only returns complete
            # scripts unless incomplete=True is specified.
            self.wallet_reg_tx[txid] = self.RegTx(txid, script)
        for txid, script_dict in eat_d.items():
            script = ScriptOutput.from_dict(script_dict)
            if script.is_complete() and txid not in seen_scripts:
                # sanity check
                seen_scripts[txid] = script
            # allow incomplete scripts to be loaded here too, in case
            # verification comes in later.
            self.ext_reg_tx[txid] = self.RegTx(txid, script)
        for txid, info in vtx_d.items():
            block_height, block_hash = info
            script = seen_scripts.get(txid)
            if script:
                self._add_vtx(self.VerifTx(txid, block_height, block_hash), script)
        for item in min_enc_l:
            value = item[-1]
            key = item[:-1]
            self.minimal_ch_cache.put(tuple(key), value)  # re-populate the cache

        # Re-enqueue previously unverified for verification.
        # they may come from either wallet or external source, but we
        # enqueue them with the private verifier here.
        # Note that verification failures will cause the tx's to get popped
        # and thus they shouldn't forever verify (see verification_failed et al).
        d = self.ext_reg_tx.copy()
        d.update(self.wallet_reg_tx)
        for txid, item in d.items():
            if txid not in self.v_tx and item.script.number is not None and item.script.number >= 100:
                self.ext_unverif[txid] = num2bh(item.script.number)

        # Note that 'wallet.load_transactions' will be called after this point
        # in the wallet c'tor and it will take care of removing wallet_reg_tx
        # and v_tx entries from self if it detects unreferenced transactions in
        # history (via the remove_transaction_hook callback).


    def save(self, write=False):
        '''
        FYI, current data model is:

        RegTx = namedtuple("RegTx", "txid, script")
        VerifTx = namedtuple("VerifTx", "txid, block_height, block_hash")

        self.wallet_reg_tx = dict() # dict of txid -> RegTx
        self.ext_reg_tx = dict() # dict of txid -> RegTx

        self.v_tx = dict() # dict of txid -> VerifTx
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid
        '''

        wat_d, eat_d, vtx_d = dict(), dict(), dict()
        min_enc_l = list()
        with self.lock:
            for txid, rtx in self.wallet_reg_tx.items():
                wat_d[txid] = rtx.script.to_dict()
            for txid, rtx in self.ext_reg_tx.items():
                eat_d[txid] = rtx.script.to_dict()
            for txid, vtx in self.v_tx.items():
                vtx_d[txid] = [vtx.block_height, vtx.block_hash]
            for key, tup in self.minimal_ch_cache.copy_dict().items():
                value = tup[-1]
                if value is None:
                    # we sometimes write 'None' to the cache to invalidate
                    # items but don't delete the entry.  Skip these.
                    continue
                min_enc_l.append([*key, value])

        data =  {
                    'wallet_reg_tx' : wat_d,
                    'ext_reg_tx'    : eat_d,
                    'verified_tx'   : vtx_d,
                    'minimal_ch_cache' : min_enc_l,
                }

        self.wallet.storage.put('cash_accounts_data', data)

        if write:
            self.wallet.storage.write()

    def get_verified(self, ca_name) -> Info:
        ''' Returns the Info object for ca_name of the form: Name#123.1234
        or None if not found in self.v_tx '''
        tup = self.parse_string(ca_name)
        if tup:
            name, num, cp = tup
            l = self.find_verified(name=name, number=num, collision_prefix=cp)
            if len(l) == 1:
                return l[0]

    def find_verified(self, name: str, number: int = None, collision_prefix: str = None) -> List[Info]:
        ''' Returns a list of Info objects for verified cash accounts matching
        lowercased name.  Optionally you can narrow the search by specifying
        number (int) and a collision_prefix (str of digits) '''
        ret = []
        with self.lock:
            name = name.lower()
            s = self.v_by_name.get(name, set())
            for txid in s:
                script = self._find_script(txid, False)
                if script:
                    if script.name.lower() != name:
                        self.print_error(f"find: FIXME -- v_by_name has inconsistent data for {txid}, name {name} != {script.name}")
                        continue
                    if not script.is_complete():
                        self.print_error(f"find: FIXME -- v_by_name has a script that is not 'complete' for {txid} name='{name}'")
                        continue
                    if number is not None and script.number != number:
                        continue
                    if collision_prefix is not None and not script.collision_hash.startswith(collision_prefix):
                        continue
                    ret.append(Info.from_script(script, txid))
        return ret

    def add_ext_tx(self, txid : str, script : ScriptOutput):
        ''' This will add txid to our ext_tx cache, and kick off verification,
        but only if it's not verified already and/or not in wallet_reg_tx. '''
        if not isinstance(script, ScriptOutput) or not script.is_complete():
            raise ArgumentError("Please pass an 'is_complete' script to add_ext_tx")
        with self.lock:
            if txid not in self.wallet_reg_tx:
                self.ext_reg_tx[txid] = self.RegTx(txid, script)
            if txid not in self.v_tx:
                self.ext_unverif[txid] = num2bh(script.number)

    def has_tx(self, txid: str) -> bool:
        ''' Returns true if we know about a complete tx, whether verified or not. '''
        with self.lock:
            return bool(self._find_script(txid, False))

    def is_verified(self, txid: str) -> bool:
        with self.lock:
            return txid in self.v_tx

    def add_ext_incomplete_tx(self, txid : str, block_height : int, script : ScriptOutput):
        if not isinstance(script, ScriptOutput) or not isinstance(block_height, (int, float)) or not txid or not isinstance(txid, str):
            raise ArgumentError("bad args to add_ext_incomplete_tx")
        script.number = bh2num(block_height)
        if script.number < 100:
            raise ArgumentError("bad block height")
        with self.lock:
            self.ext_incomplete_tx[txid] = self.RegTx(txid, script)
            self.ext_unverif[txid] = block_height


    @staticmethod
    def _do_verify_block_argchecks(network, number, exc=[], server='https://unknown'):
        if not isinstance(number, int) or number < 100:
            raise ArgumentError('number must be >= 100')
        if not isinstance(server, str) or not server:
            raise ArgumentError('bad server arg')
        if not isinstance(exc, list):
            raise ArgumentError('bad exc arg')
        if not network:
            exc.append(RuntimeError('no network'))
            return False
        return True

    def verify_block_asynch(self, number : int, success_cb=None, error_cb=None, timeout=timeout, debug=debug):
        ''' Tries all servers. Calls success_cb with the verified ProcessedBlock
        as the single argument on first successful retrieval of the block.
        Calls error_cb with the exc as the only argument on failure. Guaranteed
        to call 1 of the 2 callbacks in either case.  Callbacks are optional
        and won't be called if specified as None. '''
        network = self.network # capture network object in case it goes away while we are running
        exc = []
        if not self._do_verify_block_argchecks(network=network, number=number, exc=exc):
            if error_cb: error_cb((exc and exc[-1]) or RuntimeError('error'))
            return
        def on_error(exc):
            with self.lock:
                l = self._blocks_in_flight.pop(number, [])
            ct = 0
            for success_cb, error_cb in l:
                if error_cb:
                    error_cb(exc)
                    ct += 1
            if debug: self.print_error(f"verify_block_asynch: called {ct} error callbacks for #{number}")
        def on_success(res, server):
            pb = self._verify_block_inner(res, network, server, number, True, timeout, exc, debug=debug)
            if pb:
                with self.lock:
                    l = self._blocks_in_flight.pop(number, [])
                ct = 0
                for success_cb, error_cb in l:
                    if success_cb:
                        success_cb(pb)
                        ct += 1
                if debug: self.print_error(f"verify_block_asynch: called {ct} success callbacks for #{number}")
            else:
                on_error(exc[-1])
        with self.lock:
            l = self._blocks_in_flight[number]
            l.append((success_cb, error_cb))
            if len(l) == 1:
                if debug: self.print_error(f"verify_block_asynch: initiating new lookup_asynch_all on #{number}")
                lookup_asynch_all(number=number, success_cb=on_success, error_cb=on_error, timeout=timeout, debug=debug)
            else:
                if debug: self.print_error(f"verify_block_asynch: #{number} already in-flight, will just enqueue callbacks")

    def verify_block_synch(self, server : str, number : int, verify_txs=True, timeout=timeout, exc=[], debug=debug) -> ProcessedBlock:
        ''' Processes a whole block from the lookup server and returns it.
        Returns None on failure, and puts the Exception in the exc parameter.

        Note if this returns successfully, then all the tx's in the returned ProcessedBlock
        are guaranteed to have verified successfully. '''
        network = self.network  # just in case network goes away, capture it
        if not self._do_verify_block_argchecks(network=network, number=number, exc=exc, server=server):
            return
        res = lookup(server=server, number=number, timeout=timeout, exc=exc, debug=debug)
        if not res:
            return
        return self._verify_block_inner(res, network, server, number, verify_txs, timeout, exc, debug=debug)

    def _verify_block_inner(self, res, network, server, number, verify_txs, timeout, exc, debug=debug) -> ProcessedBlock:
        ''' Do not call this from the Network thread, as it actually relies on
        the network thread being another thread (it waits for callbacks from it
        to proceed).  Caller should NOT hold any locks. '''
        pb = ProcessedBlock(hash=res[0], height=num2bh(number), reg_txs={ r.txid : r for r in res[1] })
        if len(pb.reg_txs) == 0:
            self.print_error(f"Warning, received a block from server with number {number}"
                             "but we didn't recognize any tx's in it. "
                             "To the dev reading this: See if the Cash Account spec has changed!")
        # REORG or BAD SERVER CHECK
        def check_sanity_detect_reorg_etc():
            minimal_ch_removed = []
            with self.lock:
                pb_cached = self.processed_blocks.get(pb.height)
                if pb_cached and pb != pb_cached:
                    # Poor man's reorg detection below...
                    self.processed_blocks.put(pb.height, None)
                    self.print_error(f"Warning, retrieved block info from server {server} is {pb} which differs from cached version {pb_cached}! Reverifying!")
                    keys = set()  # (lname, number, collision_hash) tuples
                    chash_rtxs = dict()  # chash_key_tuple -> regtx
                    for txid in set(set(pb_cached.reg_txs or set()) | set(pb.reg_txs or set())):
                        self._rm_vtx(txid, rm_from_verifier=True)
                        script = self._find_script(txid, False)
                        if script:
                            k = (script.name.lower(), script.number, script.collision_hash)
                            keys.add(k)
                            rtx = pb.reg_txs.get(txid) or pb_cached.reg_txs.get(txid)
                            if rtx: chash_rtxs[k] = rtx
                    # invalidate minimal_chashes for block
                    for k in keys:
                        if self.minimal_ch_cache.get(k):
                            self.print_error("invalidated minimal_chash", k)
                            self.minimal_ch_cache.put(k, None)  # invalidate cache item
                            rtx = chash_rtxs.get(k)
                            if rtx:
                                minimal_ch_removed.append((Info.from_regtx(rtx), rtx.script.collision_hash))
                    verify_txs = True
            # finally, inform interested GUI code about the invalidations so that
            # it may re-enqueue some refreshes of the minimal collision hashes
            for info, long_chash in minimal_ch_removed:
                if debug:
                    self.print_error("triggering ca_updated_minimal_chash for", info, long_chash)
                network.trigger_callback('ca_updated_minimal_chash', self, info, long_chash)
        check_sanity_detect_reorg_etc()
        # /REORG or BAD SERVER CHECK
        def num_needed():
            with self.lock:
                return len(set(pb.reg_txs) - set(self.v_tx))
        if verify_txs and pb.reg_txs and num_needed():
            q = queue.Queue()
            class VFail(RuntimeWarning): pass
            def on_verified(event, *args):
                if not args or args[0] is not self:
                    # all the events we care about pass self as arg
                    return
                if event == 'ca_verified_tx':
                    if not num_needed():  # this implcititly checks if the tx's we care about are ready
                        q.put('done')
                elif event == 'ca_verification_failed' and args[1] in pb.reg_txs:
                    q.put(('failed', args[1], args[2]))
                    if args[2] == 'tx_not_found':
                        ctr = 0
                        with self.lock:
                            for txid in pb.reg_txs:
                                if txid not in self.v_tx:
                                    self._wipe_tx(txid, rm_from_verifier=True)
                                    ctr += 1
                        if ctr:
                            self.print_error(f"_verify_block_inner: Block number {number} from server {server} appears to be invalid on this chain: '{args[2]}' undid {ctr} verification requests")
            try:
                network.register_callback(on_verified, ['ca_verified_tx', 'ca_verification_failed'])
                for txid, regtx in pb.reg_txs.items():
                    self.add_ext_tx(txid, regtx.script)  # NB: this is a no-op if already verified and/or in wallet_reg_txs
                if num_needed():
                    thing = q.get(timeout=timeout)
                    if thing == 'done':
                        pass  # ok, success!
                    elif isinstance(thing, tuple) and thing[0] == 'failed':

                        raise VFail(thing[1], thing[2])
                    else:
                        self.print_error("INTERNAL ERROR: Got unknown thing from an internal queue in _verify_block_inner. FIXME!")
                        raise VFail("INTERNAL ERROR", "_verify_block_inner")
            except (queue.Empty, VFail) as e:
                if num_needed():
                    exc.append(e)
                    return
            finally:
                network.unregister_callback(on_verified)
        with self.lock:
            self.processed_blocks.put(pb.height, pb)
        return pb

    ############################
    # UI / Prefs / Convenience #
    ############################

    def get_address_default(self, infos : List[Info]) -> Info:
        ''' Returns the preferred Info object for a particular address from
        a given list. `infos' is a list of Info objects pertaining to a
        particular address (they should all pertain to said address, but this
        is not checked). '''
        if infos:
            last = infos[-1]
            d = self.wallet.storage.get('cash_accounts_address_defaults')
            if isinstance(d, dict) and isinstance(last.address, Address):  # sanity check, .address may not always be Address but may be UnknownAddress
                tup = d.get(last.address.to_storage_string())
                if isinstance(tup, (tuple, list)) and len(tup) == 3:
                    name, number, chash = tup
                    if isinstance(name, str) and isinstance(number, (int, float)) and isinstance(chash, str):
                        # find the matching one in the list
                        for info in infos:
                            if (name.lower(), number, chash) == (info.name.lower(), info.number, info.collision_hash):
                                return info
            # just return the latest one if no default specified
            return last

    def set_address_default(self, info : Info):
        ''' Set the default CashAccount for a particular address. Pass the Info
        object pertaining to the Cash Account / Address in question. '''
        if not isinstance(info.address, Address):
            self.print_error("Warning: Info object does not have an Address", info)
            return
        d = self.wallet.storage.get('cash_accounts_address_defaults', {})
        addr_str = info.address.to_storage_string()
        new_value = [info.name, info.number, info.collision_hash]
        d[addr_str] = new_value
        self.wallet.storage.put('cash_accounts_address_defaults', d)


    ###################
    # Private Methods #
    ###################

    @classmethod
    def _calc_minimal_chash(cls, name: str, collision_hash: str, pb : ProcessedBlock) -> Tuple[RegTx, str]:
        ''' returns None on failure, otherwise returns (RegTx, minimal_chash) tuple '''
        num_res = int(bool(pb.reg_txs) and len(pb.reg_txs))
        pb_num = bh2num(pb.height)
        if not num_res:
            util.print_error(f"_calc_minimal_chash: no results in block {pb_num}!")
            return
        lc_name = name.lower()
        d = cls._calc_minimal_chashes_for_block(pb, lc_name)
        minimal_chash = d.get(lc_name, {}).get(collision_hash, None)
        if minimal_chash is None:
            util.print_error(f"_calc_minimal_chash: WARNING INTERNAL ERROR: Could not find the minimal_chash for {pb_num} {lc_name}!")
            return
        found = None
        for rtx in pb.reg_txs.values():
            if lc_name == rtx.script.name.lower() and collision_hash == rtx.script.collision_hash:
                found = rtx
                break
        if not found:
            util.print_error(f"_calc_minimal_chash: WARNING INTERNAL ERROR: Could not find the minimal_chash for {pb_num} {lc_name}!")
            return
        if found.script.number != pb_num:
            util.print_error(f"_calc_minimal_chash: WARNING: script number differs from block number for block {pb_num} {lc_name} {found.txid}!")
        return found, minimal_chash

    @classmethod
    def _calc_minimal_chashes_for_block(cls, pb : ProcessedBlock, name: str = None) -> Dict[str, Dict[str, str]]:
        ''' Given a ProcessedBlock, returns a dict of:
            lc_name -> dict of collision_hash -> minimal_collision_hash.

            Optionally, pass a name to filter by name. '''
        if name is not None:
            name = name.lower()
            tups = sorted( (rtx.script.name.lower(), rtx.script.collision_hash)
                           for rtx in pb.reg_txs.values()
                           if rtx.script.name.lower() == name )
        else:
            tups = sorted( (rtx.script.name.lower(), rtx.script.collision_hash)
                           for rtx in pb.reg_txs.values() )
        # tups is now a sorted list of (name, collision_hash)
        return cls._calc_minimal_chashes_for_sorted_lcased_tups(tups)

    @staticmethod
    def _calc_minimal_chashes_for_sorted_lcased_tups(tups : List[Tuple[str,str]]) -> Dict[str, Dict[str, str]]:
        '''' Given a list of sorted tuples, with names already all lowercased,
        returns a dict of:

        lc_ name -> dict of collision_hash -> minimal_collision_hash '''
        ret = defaultdict(dict)

        N = collision_hash_length
        idxs = [0] * len(tups)
        for i in range(len(tups)-1):

            pnam, pch = tups[i]
            nam, ch = tups[i+1]

            j = 0
            if pnam == nam:
                while j < N and ch[:j] == pch[:j]:
                    j += 1
            idxs[i] = max(idxs[i], j)
            idxs[i+1] = max(idxs[i+1], j)

        for n, tupe in enumerate(tups):
            nam, ch = tupe
            ret[nam][ch] = ch[:idxs[n]]

        return ret


    def _fw_wallet_updated(self, evt, *args):
        ''' Our private verifier is done. Propagate updated signal to parent
        wallet so that the GUI will refresh. '''
        if evt == 'wallet_updated' and args and args[0] is self:
            self.print_error("forwarding 'wallet_updated' as parent wallet")
            self.network.trigger_callback('wallet_updated', self.wallet)

    def _find_script(self, txid, print_if_missing=True, *, incomplete=False, giveto=None):
        ''' lock should be held by caller '''
        maybes = (self.wallet_reg_tx.get(txid), self.ext_reg_tx.get(txid))
        item = None
        for maybe in maybes:
            if maybe and (not item or (not item.script.is_complete() and maybe.script.is_complete())):
                item = maybe
        del maybe, maybes
        if not item and incomplete:
            item = self.ext_incomplete_tx.get(txid)
        if item and not item.script.is_complete() and not incomplete:
            item = None # refuse to return an incomplete tx unless incomplete=True
        if item:
            # Note the giveto with incomplete=True is fragile and requires
            # a call to _add_verified_tx_common right after this
            # _find_script call.
            # Also note: we intentionally don't pop the ext_incomplete_tx
            # dict here as perhaps client code is maintaining a reference
            # and we want to update that reference later in add_verified_common.
            if giveto == 'e':
                self.wallet_reg_tx.pop(txid, None)
                self.ext_reg_tx[txid] = item
            elif giveto == 'w':
                self.ext_reg_tx.pop(txid, None)
                self.wallet_reg_tx[txid] = item
            return item.script
        if print_if_missing:
            self.print_error("_find_script: could not find script for txid", txid)

    def _add_vtx(self, vtx, script):
        ''' lock should be held by caller '''
        self.v_tx[vtx.txid] = vtx
        self.v_by_addr[script.address].add(vtx.txid)
        self.v_by_name[script.name.lower()].add(vtx.txid)

    def _rm_vtx(self, txid, *, force=False, rm_from_verifier=False):
        ''' lock should be held by caller '''
        vtx = self.v_tx.pop(txid, None)
        if not vtx:
            # was not relevant, abort early
            return
        assert txid == vtx.txid
        script = self._find_script(txid, print_if_missing=not force)  # will print_error if script not found
        if script:
            addr, name = script.address, script.name.lower()
            self.v_by_addr[addr].discard(txid)
            if not self.v_by_addr[addr]: self.v_by_addr.pop(addr, None)
            self.v_by_name[name].discard(txid)
            if not self.v_by_name[name]: self.v_by_name.pop(name, None)
        elif force:
            self.print_error("force remove v_tx", txid)
            empty = set()
            for a, s in self.v_by_addr.items():
                s.discard(txid)
                if not s:
                    empty.add(a)
            for a in empty:
                self.v_by_addr.pop(a, None)
            empty.clear()
            for n, s in self.v_by_name.items():
                s.discard(txid)
                if not s:
                    empty.add(n)
            for n in empty:
                self.v_by_name.pop(n, None)
        if rm_from_verifier:
            verifier = self.verifier
            if verifier:
                verifier.remove_spv_proof_for_tx(txid)

    def _wipe_tx(self, txid, rm_from_verifier=False):
        ''' called to completely forget a tx from all caches '''
        self._rm_vtx(txid, force=True, rm_from_verifier=rm_from_verifier)
        self.wallet_reg_tx.pop(txid, None)
        self.ext_reg_tx.pop(txid, None)
        self.ext_incomplete_tx.pop(txid, None)
        self.ext_unverif.pop(txid, None)

    def _add_verified_tx_common(self, script, txid, height, header):
        ''' caller must hold locks '''
        if not script or height < activation_height:
            # no-op or not relevant callback
            return

        block_hash = blockchain.hash_header(header)
        v = self.VerifTx(txid=txid, block_height=height, block_hash=block_hash)
        # update/completeify
        script.make_complete(block_height=v.block_height, block_hash=v.block_hash, txid=v.txid)
        rtx = self.ext_incomplete_tx.pop(txid, None)
        if rtx:
            # in case client code somewhere has a copy of this script ..
            # update it to 'complete' so GUI can reflect change.
            # (relevant to TxDialog class)
            rtx.script.make_complete(block_height=v.block_height, block_hash=v.block_hash, txid=v.txid)
            if txid not in self.ext_reg_tx and txid not in self.wallet_reg_tx:
                # save this is_complete RegTx to ext_reg_tx dict which gets saved to disk
                self.ext_reg_tx[txid] = rtx
        # register this tx as verified
        self._add_vtx(v, script)

    def _add_vtx_chk_height(self, txid, height_ts_pos_tup):
        ''' caller must hold locks '''
        height = height_ts_pos_tup[0]
        if not isinstance(height, (int, float)) or height < activation_height:
            self.print_error(f"Warning: Got a tx {txid} with height {height} < activation height {activation_height}!")
            self._wipe_tx(txid)
            return 0
        return int(height)

    #########################
    # Wallet hook callbacks #
    #########################
    def add_verified_tx_hook(self, txid: str, height_ts_pos_tup: tuple, header: dict):
        ''' Called by wallet when it itself got a verified tx from its own
        verifier.  We need to know about tx's that the parent wallet verified
        so we don't do the same work again. '''
        with self.lock:
            # Note: precondition here is that the tx exists in one of our RegTx
            # dicts, otherwise the tx is not relevant to us (contains no cash
            # account registrations). We need this check because we are called
            # a lot for every tx the wallet verifies.
            script = self._find_script(txid, False, giveto='w', incomplete=True)
            if not script:
                return

            self.print_error("verified internal:", txid, height_ts_pos_tup)

            height = self._add_vtx_chk_height(txid, height_ts_pos_tup)  # prints to print_error and wipes tx on error
            if not height:
                return

            self._add_verified_tx_common(script, txid, height, header)

        # this needs to be done without the lock held
        if self.network and script.is_complete():  # paranoia checks
            self.network.trigger_callback('ca_verified_tx', self, Info.from_script(script, txid))

    def verification_failed_hook(self, txid, reason):
        ''' Called by wallet when it receives a verification_failed callback
        from its verifier. We must check if the tx is relevant and if so,
        forwrd the information on with a callback '''
        with self.lock:
            script = self._find_script(txid, False, giveto='w', incomplete=True)
            if not script:
                # not relevant to us
                return
        if self.network:
            self.network.trigger_callback('ca_verification_failed', self, txid, reason)

    def undo_verifications_hook(self, txs: set):
        ''' Called by wallet when it itself got called to undo_verifictions by
        its verifier. We need to be told what set of tx_hash was undone. '''
        if not txs: return
        with self.lock:
            for txid in txs:
                self._rm_vtx(txid)  # this is safe as a no-op if txid was not relevant
                self._find_script(txid, False, giveto='w')
            # Since we have a chain reorg, invalidate the processed block and
            # minimal_ch_cache to force revalidation of our collision hashes.
            # FIXME: Do this more elegantly. This casts a pretty wide net.
            # NB: I believe assiging a new {} to .d is safer than d.clear()
            # in this case as the caches._ExpiringCacheMgr doesn't like it
            # when you remove items from the existing dict, but should run ok
            # if you just assign a new dict (it keeps a working reference as
            # it flushes the cache)... so assigning to .d is safer in this case.
            self.minimal_ch_cache.d = {}
            self.processed_blocks.d = {}

    def add_transaction_hook(self, txid: str, tx: object, out_n: int, script: ScriptOutput):
        ''' Called by wallet inside add_transaction (with wallet.lock held) to
        notify us about transactions that were added containing a cashacct
        scriptoutput. Note these tx's aren't yet in the verified set. '''
        assert isinstance(script, ScriptOutput)
        with self.lock:
            self.wallet_reg_tx[txid] = self.RegTx(txid=txid, script=script)
            self._find_script(txid, giveto='w')  # makes sure there is only 1 copy in wallet_reg_tx

    def remove_transaction_hook(self, txid: str):
        ''' Called by wallet inside remove_transaction (with wallet.lock held)
        to tell us about a transaction that was removed. '''
        with self.lock:
            self._rm_vtx(txid)
            self.wallet_reg_tx.pop(txid, None)

    def add_unverified_tx_hook(self, txid: str, block_height: int):
        ''' This is called by wallet when we expect a future subsequent
        verification to happen. So let's pop the vtx from our data structure
        in anticipation of a possible future verification coming in. '''
        with self.lock:
            self._rm_vtx(txid)
            self._find_script(txid, False, giveto='w', incomplete=True)

    def on_address_addition(self, address):
        ''' Called by wallet when a new address is added in imported wallet.'''

    def on_address_deletion(self, address):
        ''' Called by wallet when an existing address is deleted in imported wallet.'''

    def on_clear_history(self):
        ''' Called by wallet rebuild history mechanism to clear everything. '''
        with self.lock:
            self._init_data()

    def save_verified_tx_hook(self, write=False):
        self.save(write)

    # /Wallet hook callbacks

    #######################
    # SPVDelegate Methods #
    #######################
    def get_unverified_txs(self) -> dict:
        ''' Return a dict of tx_hash (hex encoded) -> height (int)'''
        with self.lock:
            return self.ext_unverif.copy()

    def add_verified_tx(self, tx_hash : str, height_ts_pos_tup : tuple, header : dict) -> None:
        ''' Called when a verification is successful.
        Params:
            #1 tx_hash - hex string
            #2 tuple of: (tx_height: int, timestamp: int, pos : int)
            #3 the header - dict. This can be subsequently serialized using
               blockchain.serialize_header if so desiered, or it can be ignored.
        '''
        self.print_error('verified external:', tx_hash, height_ts_pos_tup)

        with self.wallet.lock:  # thread safety, even though for 1-liners in CPython it hardly matters.
            # maintain invariant -- this is because pvt verifier can get kicked
            # off on .load() for any missing unverified tx (wallet or external)
            # so we have to determine here where to put the final tx should live
            giveto = 'w' if tx_hash in self.wallet.transactions else 'e'

        with self.lock:
            self.ext_unverif.pop(tx_hash, None)  # pop it off unconditionally

            height = self._add_vtx_chk_height(tx_hash, height_ts_pos_tup)  # prints to print_error and wipes tx on error
            if not height:
                return
            script = self._find_script(tx_hash, incomplete=True, giveto=giveto)
            # call back into the same codepath that registers tx's as verified, and completes them...
            self._add_verified_tx_common(script, tx_hash, height, header)

        # this needs to be done without the lock held
        if self.network and script and script.is_complete():  # paranoia checks
            self.network.trigger_callback('ca_verified_tx', self, Info.from_script(script, tx_hash))

    def is_up_to_date(self) -> bool:
        '''Return True to kick off network wallet_updated callback and
        save_verified_tx callback to us, only when nothing left to verify. '''
        return not self.ext_unverif

    def save_verified_tx(self, write : bool = False):
        ''' Save state. Called by ext verified when it's done. '''
        self.save(write)

    def undo_verifications(self, bchain : object, height : int) -> set:
        ''' Called when the blockchain has changed to tell the wallet to undo
        verifications when a reorg has happened. Returns a set of tx_hash. '''
        txs = set()
        with self.lock:
            for txid, vtx in self.v_tx.copy().items():
                if txid in self.wallet_reg_tx:
                    # wallet verifier will take care of this one
                    continue
                if vtx.block_height >= height:
                    header = bchain.read_header(vtx.block_height)
                    if not header or vtx.block_hash != blockchain.hash_header(header):
                        self._rm_vtx(txid)
                        self.ext_unverif[txid] = vtx.block_height  # re-enqueue for verification with private verifier...? TODO: how to detect tx's dropped out of new chain?
                        txs.add(txid)
        return txs

    def verification_failed(self, tx_hash, reason):
        ''' TODO.. figure out what to do here. Or with wallet verification in
        general in this error case. '''
        self.print_error(f"SPV failed for {tx_hash}, reason: '{reason}'")
        try:
            with self.lock:
                script = self._find_script(tx_hash)
                idx = self.verifier.failure_reasons.index(reason)
                if idx < 3 or not script or not script.is_complete():
                    # actual verification failure.. remove this tx
                    self.print_error("removing tx from ext_reg_tx cache")
                    self.ext_unverif.pop(tx_hash, None)
                    self.ext_reg_tx.pop(tx_hash, None)
                elif idx == 5:
                    # tx not found -- might be either we are testnet and lookup
                    # server was mainnet *OR* some other strangeness. Not sure
                    # what to do here, so we just wipe the tx from our caches
                    # because keeping it around will cause the client to DoS
                    # itself versus the ElectrumX server each time it connects.
                    self.print_error("tx appears to be completely unknown to server, wiping from cache")
                    self._wipe_tx(tx_hash)
                else:
                    # Note that the above ^ branch can also be reached due to a
                    # misbehaving server so .. not really sure what to do here.
                    # TODO: Determine best strategy for verification failures.
                    self.print_error("ignoring failure due misc. error response from server.. will try again next session")
        except ValueError:
            self.print_error(f"Cannot find '{reason}' in verifier reason list! FIXME!")
        if self.network:
            self.network.trigger_callback('ca_verification_failed', self, tx_hash, reason)

    # /SPVDelegate Methods

    ###############################################
    # Experimental Methods (stuff we may not use) #
    ###############################################

    def scan_servers_for_registrations(self, start=100, stop=None, progress_cb=None, error_cb=None, timeout=timeout,
                                       add_only_mine=True, debug=debug):
        ''' This is slow and not particularly useful.  Will maybe delete this
        code soon. I used it for testing to populate wallet.

        progress_cb is called with (progress : float, num_added : int, number : int) as args!
        error_cb is called with no arguments to indicate failure.

        Upon completion, either progress_cb(1.0 ..) will be called to indicate
        successful completion of the task.  Or, error_cb() will be called to
        indicate error abort (usually due to timeout).

        Returned object can be used to stop the process.  obj.stop() is the
        method.
        '''
        if not self.network:
            return
        cancel_evt = threading.Event()
        stop = num2bh(stop) if stop is not None else stop
        start = num2bh(max(start or 0, 100))
        def stop_height():
            return stop or self.wallet.get_local_height()+1
        def progress(h, added):
            if progress_cb:
                progress_cb(max((h-start)/(stop_height() - start), 0.0), added, bh2num(h))
        def thread_func():
            q = queue.Queue()
            h = start
            added = 0
            while self.network and not cancel_evt.is_set() and h < stop_height():
                num = bh2num(h)
                lookup_asynch_all(number=num,
                                  success_cb = lambda res,server: q.put(res),
                                  error_cb = q.put,
                                  timeout=timeout, debug=debug)
                try:
                    thing = q.get(timeout=timeout)
                    if isinstance(thing, Exception):
                        e = thing
                        if debug:
                            self.print_error(f"Height {h} got exception in lookup: {repr(e)}")
                    elif isinstance(thing, tuple):
                        block_hash, res = thing
                        for rtx in res:
                            if rtx.txid not in self.wallet_reg_tx and rtx.txid not in self.ext_reg_tx and (not add_only_mine or self.wallet.is_mine(rtx.script.address)):
                                self.add_ext_tx(rtx.txid, rtx.script)
                                added += 1
                    progress(h, added)
                except queue.Empty:
                    self.print_error("Could not complete request, timed out!")
                    if error_cb:
                        error_cb()
                    return
                h += 1
            progress(h, added)
        t = threading.Thread(daemon=True, target=thread_func)
        t.start()
        class ScanStopper(namedtuple("ScanStopper", "thread, event")):
            def is_alive(self):
                return self.thread.is_alive()
            def stop(self):
                if self.is_alive():
                    self.event.set()
                    self.thread.join()
        return ScanStopper(t, cancel_evt)
