#! /usr/bin/env python3
# This was forked from https://github.com/rustyrussell/lightning-payencode/tree/acc16ec13a3fa1dc16c07af6ec67c261bd8aff23

import re
import time
from hashlib import sha256
from binascii import hexlify
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Type

import random
import bitstring

from .bitcoin import hash160_to_b58_address, b58_address_to_hash160, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from .segwit_addr import bech32_encode, bech32_decode, CHARSET
from . import segwit_addr
from . import constants
from .constants import AbstractNet
from . import ecc
from .bitcoin import COIN

if TYPE_CHECKING:
    from .lnutil import LnFeatures


class LnInvoiceException(Exception): pass
class LnDecodeException(LnInvoiceException): pass
class LnEncodeException(LnInvoiceException): pass


# BOLT #11:
#
# A writer MUST encode `amount` as a positive decimal integer with no
# leading zeroes, SHOULD use the shortest representation possible.
def shorten_amount(amount):
    """ Given an amount in bitcoin, shorten it
    """
    # Convert to pico initially
    amount = int(amount * 10**12)
    units = ['p', 'n', 'u', 'm']
    for unit in units:
        if amount % 1000 == 0:
            amount //= 1000
        else:
            break
    else:
        unit = ''
    return str(amount) + unit

def unshorten_amount(amount) -> Decimal:
    """ Given a shortened amount, convert it into a decimal
    """
    # BOLT #11:
    # The following `multiplier` letters are defined:
    #
    #* `m` (milli): multiply by 0.001
    #* `u` (micro): multiply by 0.000001
    #* `n` (nano): multiply by 0.000000001
    #* `p` (pico): multiply by 0.000000000001
    units = {
        'p': 10**12,
        'n': 10**9,
        'u': 10**6,
        'm': 10**3,
    }
    unit = str(amount)[-1]
    # BOLT #11:
    # A reader SHOULD fail if `amount` contains a non-digit, or is followed by
    # anything except a `multiplier` in the table above.
    if not re.fullmatch("\\d+[pnum]?", str(amount)):
        raise LnDecodeException("Invalid amount '{}'".format(amount))

    if unit in units.keys():
        return Decimal(amount[:-1]) / units[unit]
    else:
        return Decimal(amount)

_INT_TO_BINSTR = {a: '0' * (5-len(bin(a)[2:])) + bin(a)[2:] for a in range(32)}

# Bech32 spits out array of 5-bit values.  Shim here.
def u5_to_bitarray(arr):
    b = ''.join(_INT_TO_BINSTR[a] for a in arr)
    return bitstring.BitArray(bin=b)

def bitarray_to_u5(barr):
    assert barr.len % 5 == 0
    ret = []
    s = bitstring.ConstBitStream(barr)
    while s.pos != s.len:
        ret.append(s.read(5).uint)
    return ret


def encode_fallback(fallback: str, net: Type[AbstractNet]):
    """ Encode all supported fallback addresses.
    """
    wver, wprog_ints = segwit_addr.decode_segwit_address(net.SEGWIT_HRP, fallback)
    if wver is not None:
        wprog = bytes(wprog_ints)
    else:
        addrtype, addr = b58_address_to_hash160(fallback)
        if addrtype == net.ADDRTYPE_P2PKH:
            wver = 17
        elif addrtype == net.ADDRTYPE_P2SH:
            wver = 18
        else:
            raise LnEncodeException(f"Unknown address type {addrtype} for {net}")
        wprog = addr
    return tagged('f', bitstring.pack("uint:5", wver) + wprog)


def parse_fallback(fallback, net: Type[AbstractNet]):
    wver = fallback[0:5].uint
    if wver == 17:
        addr = hash160_to_b58_address(fallback[5:].tobytes(), net.ADDRTYPE_P2PKH)
    elif wver == 18:
        addr = hash160_to_b58_address(fallback[5:].tobytes(), net.ADDRTYPE_P2SH)
    elif wver <= 16:
        witprog = fallback[5:]  # cut witver
        witprog = witprog[:len(witprog) // 8 * 8]  # can only be full bytes
        witprog = witprog.tobytes()
        addr = segwit_addr.encode_segwit_address(net.SEGWIT_HRP, wver, witprog)
    else:
        return None
    return addr


BOLT11_HRP_INV_DICT = {net.BOLT11_HRP: net for net in constants.NETS_LIST}


# Tagged field containing BitArray
def tagged(char, l):
    # Tagged fields need to be zero-padded to 5 bits.
    while l.len % 5 != 0:
        l.append('0b0')
    return bitstring.pack("uint:5, uint:5, uint:5",
                          CHARSET.find(char),
                          (l.len / 5) / 32, (l.len / 5) % 32) + l

# Tagged field containing bytes
def tagged_bytes(char, l):
    return tagged(char, bitstring.BitArray(l))

def trim_to_min_length(bits):
    """Ensures 'bits' have min number of leading zeroes.
    Assumes 'bits' is big-endian, and that it needs to be encoded in 5 bit blocks.
    """
    bits = bits[:]  # copy
    # make sure we can be split into 5 bit blocks
    while bits.len % 5 != 0:
        bits.prepend('0b0')
    # Get minimal length by trimming leading 5 bits at a time.
    while bits.startswith('0b00000'):
        if len(bits) == 5:
            break  # v == 0
        bits = bits[5:]
    return bits

# Discard trailing bits, convert to bytes.
def trim_to_bytes(barr):
    # Adds a byte if necessary.
    b = barr.tobytes()
    if barr.len % 8 != 0:
        return b[:-1]
    return b

# Try to pull out tagged data: returns tag, tagged data and remainder.
def pull_tagged(stream):
    tag = stream.read(5).uint
    length = stream.read(5).uint * 32 + stream.read(5).uint
    return (CHARSET[tag], stream.read(length * 5), stream)

def lnencode(addr: 'LnAddr', privkey) -> str:
    if addr.amount:
        amount = addr.net.BOLT11_HRP + shorten_amount(addr.amount)
    else:
        amount = addr.net.BOLT11_HRP if addr.net else ''

    hrp = 'ln' + amount

    # Start with the timestamp
    data = bitstring.pack('uint:35', addr.date)

    tags_set = set()

    # Payment hash
    data += tagged_bytes('p', addr.paymenthash)
    tags_set.add('p')

    if addr.payment_secret is not None:
        data += tagged_bytes('s', addr.payment_secret)
        tags_set.add('s')

    for k, v in addr.tags:

        # BOLT #11:
        #
        # A writer MUST NOT include more than one `d`, `h`, `n` or `x` fields,
        if k in ('d', 'h', 'n', 'x', 'p', 's'):
            if k in tags_set:
                raise LnEncodeException("Duplicate '{}' tag".format(k))

        if k == 'r':
            route = bitstring.BitArray()
            for step in v:
                pubkey, channel, feebase, feerate, cltv = step
                route.append(bitstring.BitArray(pubkey) + bitstring.BitArray(channel) + bitstring.pack('intbe:32', feebase) + bitstring.pack('intbe:32', feerate) + bitstring.pack('intbe:16', cltv))
            data += tagged('r', route)
        elif k == 't':
            pubkey, feebase, feerate, cltv = v
            route = bitstring.BitArray(pubkey) + bitstring.pack('intbe:32', feebase) + bitstring.pack('intbe:32', feerate) + bitstring.pack('intbe:16', cltv)
            data += tagged('t', route)
        elif k == 'f':
            if v is not None:
                data += encode_fallback(v, addr.net)
        elif k == 'd':
            # truncate to max length: 1024*5 bits = 639 bytes
            data += tagged_bytes('d', v.encode()[0:639])
        elif k == 'x':
            expirybits = bitstring.pack('intbe:64', v)
            expirybits = trim_to_min_length(expirybits)
            data += tagged('x', expirybits)
        elif k == 'h':
            data += tagged_bytes('h', sha256(v.encode('utf-8')).digest())
        elif k == 'n':
            data += tagged_bytes('n', v)
        elif k == 'c':
            finalcltvbits = bitstring.pack('intbe:64', v)
            finalcltvbits = trim_to_min_length(finalcltvbits)
            data += tagged('c', finalcltvbits)
        elif k == '9':
            if v == 0:
                continue
            feature_bits = bitstring.BitArray(uint=v, length=v.bit_length())
            feature_bits = trim_to_min_length(feature_bits)
            data += tagged('9', feature_bits)
        else:
            # FIXME: Support unknown tags?
            raise LnEncodeException("Unknown tag {}".format(k))

        tags_set.add(k)

    # BOLT #11:
    #
    # A writer MUST include either a `d` or `h` field, and MUST NOT include
    # both.
    if 'd' in tags_set and 'h' in tags_set:
        raise ValueError("Cannot include both 'd' and 'h'")
    if not 'd' in tags_set and not 'h' in tags_set:
        raise ValueError("Must include either 'd' or 'h'")

    # We actually sign the hrp, then data (padded to 8 bits with zeroes).
    msg = hrp.encode("ascii") + data.tobytes()
    privkey = ecc.ECPrivkey(privkey)
    sig = privkey.sign_message(msg, is_compressed=False, algo=lambda x:sha256(x).digest())
    recovery_flag = bytes([sig[0] - 27])
    sig = bytes(sig[1:]) + recovery_flag
    data += sig

    return bech32_encode(segwit_addr.Encoding.BECH32, hrp, bitarray_to_u5(data))


class LnAddr(object):
    def __init__(self, *, paymenthash: bytes = None, amount=None, net: Type[AbstractNet] = None, tags=None, date=None,
                 payment_secret: bytes = None):
        self.date = int(time.time()) if not date else int(date)
        self.tags = [] if not tags else tags
        self.unknown_tags = []
        self.paymenthash = paymenthash
        self.payment_secret = payment_secret
        self.signature = None
        self.pubkey = None
        self.net = constants.net if net is None else net  # type: Type[AbstractNet]
        self._amount = amount  # type: Optional[Decimal]  # in bitcoins
        self._min_final_cltv_expiry = 18

    @property
    def amount(self) -> Optional[Decimal]:
        return self._amount

    @amount.setter
    def amount(self, value):
        if not (isinstance(value, Decimal) or value is None):
            raise LnInvoiceException(f"amount must be Decimal or None, not {value!r}")
        if value is None:
            self._amount = None
            return
        assert isinstance(value, Decimal)
        if value.is_nan() or not (0 <= value <= TOTAL_COIN_SUPPLY_LIMIT_IN_BTC):
            raise LnInvoiceException(f"amount is out-of-bounds: {value!r} BTC")
        if value * 10**12 % 10:
            # max resolution is millisatoshi
            raise LnInvoiceException(f"Cannot encode {value!r}: too many decimal places")
        self._amount = value

    def get_amount_sat(self) -> Optional[Decimal]:
        # note that this has msat resolution potentially
        if self.amount is None:
            return None
        return self.amount * COIN

    def get_routing_info(self, tag):
        # note: tag will be 't' for trampoline
        r_tags = list(filter(lambda x: x[0] == tag, self.tags))
        # strip the tag type, it's implicitly 'r' now
        r_tags = list(map(lambda x: x[1], r_tags))
        # if there are multiple hints, we will use the first one that works,
        # from a random permutation
        random.shuffle(r_tags)
        return r_tags

    def get_amount_msat(self) -> Optional[int]:
        if self.amount is None:
            return None
        return int(self.amount * COIN * 1000)

    def get_features(self) -> 'LnFeatures':
        from .lnutil import LnFeatures
        return LnFeatures(self.get_tag('9') or 0)

    def __str__(self):
        return "LnAddr[{}, amount={}{} tags=[{}]]".format(
            hexlify(self.pubkey.serialize()).decode('utf-8') if self.pubkey else None,
            self.amount, self.net.BOLT11_HRP,
            ", ".join([k + '=' + str(v) for k, v in self.tags])
        )

    def get_min_final_cltv_expiry(self) -> int:
        return self._min_final_cltv_expiry

    def get_tag(self, tag):
        for k, v in self.tags:
            if k == tag:
                return v
        return None

    def get_description(self) -> str:
        return self.get_tag('d') or ''

    def get_fallback_address(self) -> str:
        return self.get_tag('f') or ''

    def get_expiry(self) -> int:
        exp = self.get_tag('x')
        if exp is None:
            exp = 3600
        return int(exp)

    def is_expired(self) -> bool:
        now = time.time()
        # BOLT-11 does not specify what expiration of '0' means.
        # we treat it as 0 seconds here (instead of never)
        return now > self.get_expiry() + self.date


class SerializableKey:
    def __init__(self, pubkey):
        self.pubkey = pubkey
    def serialize(self):
        return self.pubkey.get_public_key_bytes(True)

def lndecode(invoice: str, *, verbose=False, net=None) -> LnAddr:
    if net is None:
        net = constants.net
    decoded_bech32 = bech32_decode(invoice, ignore_long_length=True)
    hrp = decoded_bech32.hrp
    data = decoded_bech32.data
    if decoded_bech32.encoding is None:
        raise LnDecodeException("Bad bech32 checksum")
    if decoded_bech32.encoding != segwit_addr.Encoding.BECH32:
        raise LnDecodeException("Bad bech32 encoding: must be using vanilla BECH32")

    # BOLT #11:
    #
    # A reader MUST fail if it does not understand the `prefix`.
    if not hrp.startswith('ln'):
        raise LnDecodeException("Does not start with ln")

    if not hrp[2:].startswith(net.BOLT11_HRP):
        raise LnDecodeException(f"Wrong Lightning invoice HRP {hrp[2:]}, should be {net.BOLT11_HRP}")

    data = u5_to_bitarray(data)

    # Final signature 65 bytes, split it off.
    if len(data) < 65*8:
        raise LnDecodeException("Too short to contain signature")
    sigdecoded = data[-65*8:].tobytes()
    data = bitstring.ConstBitStream(data[:-65*8])

    addr = LnAddr()
    addr.pubkey = None

    m = re.search("[^\\d]+", hrp[2:])
    if m:
        addr.net = BOLT11_HRP_INV_DICT[m.group(0)]
        amountstr = hrp[2+m.end():]
        # BOLT #11:
        #
        # A reader SHOULD indicate if amount is unspecified, otherwise it MUST
        # multiply `amount` by the `multiplier` value (if any) to derive the
        # amount required for payment.
        if amountstr != '':
            addr.amount = unshorten_amount(amountstr)

    addr.date = data.read(35).uint

    while data.pos != data.len:
        tag, tagdata, data = pull_tagged(data)

        # BOLT #11:
        #
        # A reader MUST skip over unknown fields, an `f` field with unknown
        # `version`, or a `p`, `h`, or `n` field which does not have
        # `data_length` 52, 52, or 53 respectively.
        data_length = len(tagdata) / 5

        if tag == 'r':
            # BOLT #11:
            #
            # * `r` (3): `data_length` variable.  One or more entries
            # containing extra routing information for a private route;
            # there may be more than one `r` field, too.
            #    * `pubkey` (264 bits)
            #    * `short_channel_id` (64 bits)
            #    * `feebase` (32 bits, big-endian)
            #    * `feerate` (32 bits, big-endian)
            #    * `cltv_expiry_delta` (16 bits, big-endian)
            route=[]
            s = bitstring.ConstBitStream(tagdata)
            while s.pos + 264 + 64 + 32 + 32 + 16 < s.len:
                route.append((s.read(264).tobytes(),
                              s.read(64).tobytes(),
                              s.read(32).uintbe,
                              s.read(32).uintbe,
                              s.read(16).uintbe))
            addr.tags.append(('r',route))
        elif tag == 't':
            s = bitstring.ConstBitStream(tagdata)
            e = (s.read(264).tobytes(),
                 s.read(32).uintbe,
                 s.read(32).uintbe,
                 s.read(16).uintbe)
            addr.tags.append(('t', e))
        elif tag == 'f':
            fallback = parse_fallback(tagdata, addr.net)
            if fallback:
                addr.tags.append(('f', fallback))
            else:
                # Incorrect version.
                addr.unknown_tags.append((tag, tagdata))
                continue

        elif tag == 'd':
            addr.tags.append(('d', trim_to_bytes(tagdata).decode('utf-8')))

        elif tag == 'h':
            if data_length != 52:
                addr.unknown_tags.append((tag, tagdata))
                continue
            addr.tags.append(('h', trim_to_bytes(tagdata)))

        elif tag == 'x':
            addr.tags.append(('x', tagdata.uint))

        elif tag == 'p':
            if data_length != 52:
                addr.unknown_tags.append((tag, tagdata))
                continue
            addr.paymenthash = trim_to_bytes(tagdata)

        elif tag == 's':
            if data_length != 52:
                addr.unknown_tags.append((tag, tagdata))
                continue
            addr.payment_secret = trim_to_bytes(tagdata)

        elif tag == 'n':
            if data_length != 53:
                addr.unknown_tags.append((tag, tagdata))
                continue
            pubkeybytes = trim_to_bytes(tagdata)
            addr.pubkey = pubkeybytes

        elif tag == 'c':
            addr._min_final_cltv_expiry = tagdata.uint

        elif tag == '9':
            features = tagdata.uint
            addr.tags.append(('9', features))
            from .lnutil import validate_features
            validate_features(features)

        else:
            addr.unknown_tags.append((tag, tagdata))

    if verbose:
        print('hex of signature data (32 byte r, 32 byte s): {}'
              .format(hexlify(sigdecoded[0:64])))
        print('recovery flag: {}'.format(sigdecoded[64]))
        print('hex of data for signing: {}'
              .format(hexlify(hrp.encode("ascii") + data.tobytes())))
        print('SHA256 of above: {}'.format(sha256(hrp.encode("ascii") + data.tobytes()).hexdigest()))

    # BOLT #11:
    #
    # A reader MUST check that the `signature` is valid (see the `n` tagged
    # field specified below).
    addr.signature = sigdecoded[:65]
    hrp_hash = sha256(hrp.encode("ascii") + data.tobytes()).digest()
    if addr.pubkey: # Specified by `n`
        # BOLT #11:
        #
        # A reader MUST use the `n` field to validate the signature instead of
        # performing signature recovery if a valid `n` field is provided.
        if not ecc.ECPubkey(addr.pubkey).verify_message_hash(sigdecoded[:64], hrp_hash):
            raise LnDecodeException("bad signature")
        pubkey_copy = addr.pubkey
        class WrappedBytesKey:
            serialize = lambda: pubkey_copy
        addr.pubkey = WrappedBytesKey
    else: # Recover pubkey from signature.
        addr.pubkey = SerializableKey(ecc.ECPubkey.from_sig_string(sigdecoded[:64], sigdecoded[64], hrp_hash))

    return addr
