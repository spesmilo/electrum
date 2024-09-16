#! /usr/bin/env python3
# This was forked from https://github.com/rustyrussell/lightning-payencode/tree/acc16ec13a3fa1dc16c07af6ec67c261bd8aff23

import io
import re
import time
from hashlib import sha256
from binascii import hexlify
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Type, Dict, Any, Union, Sequence, List, Tuple
import random

from .bitcoin import hash160_to_b58_address, b58_address_to_hash160, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from .segwit_addr import bech32_encode, bech32_decode, CHARSET, CHARSET_INVERSE, convertbits
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


def encode_fallback_addr(fallback: str, net: Type[AbstractNet]) -> Sequence[int]:
    """Encode all supported fallback addresses."""
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
    data5 = convertbits(wprog, 8, 5)
    assert data5 is not None
    return tagged5('f', [wver] + list(data5))


def parse_fallback_addr(data5: Sequence[int], net: Type[AbstractNet]) -> Optional[str]:
    wver = data5[0]
    data8 = bytes(convertbits(data5[1:], 5, 8, False))
    if wver == 17:
        addr = hash160_to_b58_address(data8, net.ADDRTYPE_P2PKH)
    elif wver == 18:
        addr = hash160_to_b58_address(data8, net.ADDRTYPE_P2SH)
    elif wver <= 16:
        addr = segwit_addr.encode_segwit_address(net.SEGWIT_HRP, wver, data8)
    else:
        return None
    return addr


def tagged5(char: str, data5: Sequence[int]) -> Sequence[int]:
    assert len(data5) < (1 << 10)
    return [CHARSET_INVERSE[char], len(data5) >> 5, len(data5) & 31] + data5


def tagged8(char: str, data8: Sequence[int]) -> Sequence[int]:
    return tagged5(char, convertbits(data8, 8, 5))


def int_to_data5(val: int, *, bit_len: int = None) -> Sequence[int]:
    """Represent big-endian number with as many 0-31 values as it takes.
    If `bit_len` is set, use exactly bit_len//5 values (left-padded with zeroes).
    """
    if bit_len is not None:
        assert bit_len % 5 == 0, bit_len
        if val.bit_length() > bit_len:
            raise ValueError(f"{val=} too big for {bit_len=!r}")
    ret = []
    while val != 0:
        ret.append(val % 32)
        val //= 32
    if bit_len is not None:
        ret.extend([0] * (len(ret) - bit_len // 5))
    ret.reverse()
    return ret


def int_from_data5(data5: Sequence[int]) -> int:
    total = 0
    for v in data5:
        total = 32 * total + v
    return total


def pull_tagged(data5: bytearray) -> Tuple[str, Sequence[int]]:
    """Try to pull out tagged data: returns tag, tagged data. Mutates data in-place."""
    if len(data5) < 3:
        raise ValueError("Truncated field")
    length = data5[1] * 32 + data5[2]
    if length > len(data5) - 3:
        raise ValueError(
            "Truncated {} field: expected {} values".format(CHARSET[data5[0]], length))
    ret = (CHARSET[data5[0]], data5[3:3+length])
    del data5[:3 + length]    # much faster than: data5=data5[offset:]
    return ret


def lnencode(addr: 'LnAddr', privkey) -> str:
    if addr.amount:
        amount = addr.net.BOLT11_HRP + shorten_amount(addr.amount)
    else:
        amount = addr.net.BOLT11_HRP if addr.net else ''

    hrp = 'ln' + amount

    # Start with the timestamp
    data5 = int_to_data5(addr.date, bit_len=35)

    tags_set = set()

    # Payment hash
    assert addr.paymenthash is not None
    data5 += tagged8('p', addr.paymenthash)
    tags_set.add('p')

    if addr.payment_secret is not None:
        data5 += tagged8('s', addr.payment_secret)
        tags_set.add('s')

    for k, v in addr.tags:

        # BOLT #11:
        #
        # A writer MUST NOT include more than one `d`, `h`, `n` or `x` fields,
        if k in ('d', 'h', 'n', 'x', 'p', 's', '9'):
            if k in tags_set:
                raise LnEncodeException("Duplicate '{}' tag".format(k))

        if k == 'r':
            route = bytearray()
            for step in v:
                pubkey, scid, feebase, feerate, cltv = step
                route += pubkey
                route += scid
                route += int.to_bytes(feebase, length=4, byteorder="big", signed=False)
                route += int.to_bytes(feerate, length=4, byteorder="big", signed=False)
                route += int.to_bytes(cltv, length=2, byteorder="big", signed=False)
            data5 += tagged8('r', route)
        elif k == 't':
            pubkey, feebase, feerate, cltv = v
            route = bytearray()
            route += pubkey
            route += int.to_bytes(feebase, length=4, byteorder="big", signed=False)
            route += int.to_bytes(feerate, length=4, byteorder="big", signed=False)
            route += int.to_bytes(cltv, length=2, byteorder="big", signed=False)
            data5 += tagged8('t', route)
        elif k == 'f':
            if v is not None:
                data5 += encode_fallback_addr(v, addr.net)
        elif k == 'd':
            # truncate to max length: 1024*5 bits = 639 bytes
            data5 += tagged8('d', v.encode()[0:639])
        elif k == 'x':
            expirybits = int_to_data5(v)
            data5 += tagged5('x', expirybits)
        elif k == 'h':
            data5 += tagged8('h', sha256(v.encode('utf-8')).digest())
        elif k == 'n':
            data5 += tagged8('n', v)
        elif k == 'c':
            finalcltvbits = int_to_data5(v)
            data5 += tagged5('c', finalcltvbits)
        elif k == '9':
            if v == 0:
                continue
            feature_bits = int_to_data5(v)
            data5 += tagged5('9', feature_bits)
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
    if 'd' not in tags_set and 'h' not in tags_set:
        raise ValueError("Must include either 'd' or 'h'")

    # We actually sign the hrp, then data (padded to 8 bits with zeroes).
    msg = hrp.encode("ascii") + bytes(convertbits(data5, 5, 8))
    msg32 = sha256(msg).digest()
    privkey = ecc.ECPrivkey(privkey)
    sig = privkey.ecdsa_sign_recoverable(msg32, is_compressed=False)
    recovery_flag = bytes([sig[0] - 27])
    sig = bytes(sig[1:]) + recovery_flag
    sig = bytes(convertbits(sig, 8, 5, False))
    data5 += sig

    return bech32_encode(segwit_addr.Encoding.BECH32, hrp, data5)


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

    def validate_and_compare_features(self, myfeatures: 'LnFeatures') -> None:
        """Raises IncompatibleOrInsaneFeatures.

        note: these checks are not done by the parser (in lndecode), as then when we started requiring a new feature,
              old saved already paid invoices could no longer be parsed.
        """
        from .lnutil import validate_features, ln_compare_features
        invoice_features = self.get_features()
        validate_features(invoice_features)
        ln_compare_features(myfeatures.for_invoice(), invoice_features)

    def __str__(self):
        return "LnAddr[{}, amount={}{} tags=[{}]]".format(
            hexlify(self.pubkey.serialize()).decode('utf-8') if self.pubkey else None,
            self.amount, self.net.BOLT11_HRP,
            ", ".join([k + '=' + str(v) for k, v in self.tags])
        )

    def get_min_final_cltv_delta(self) -> int:
        cltv = self.get_tag('c')
        if cltv is None:
            return 18
        return int(cltv)

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

    def to_debug_json(self) -> Dict[str, Any]:
        d = {
            'pubkey': self.pubkey.serialize().hex(),
            'amount_BTC': str(self.amount),
            'rhash': self.paymenthash.hex(),
            'payment_secret': self.payment_secret.hex() if self.payment_secret else None,
            'description': self.get_description(),
            'exp': self.get_expiry(),
            'time': self.date,
            'min_final_cltv_delta': self.get_min_final_cltv_delta(),
            'features': self.get_features().get_names(),
            'tags': self.tags,
            'unknown_tags': self.unknown_tags,
        }
        if ln_routing_info := self.get_routing_info('r'):
            # show the last hop of routing hints. (our invoices only have one hop)
            d['r_tags'] = [str((a.hex(),b.hex(),c,d,e)) for a,b,c,d,e in ln_routing_info[-1]]
        return d


class SerializableKey:
    def __init__(self, pubkey):
        self.pubkey = pubkey
    def serialize(self):
        return self.pubkey.get_public_key_bytes(True)


def lndecode(invoice: str, *, verbose=False, net=None) -> LnAddr:
    """Parses a string into an LnAddr object.
    Can raise LnDecodeException or IncompatibleOrInsaneFeatures.
    """
    if net is None:
        net = constants.net
    decoded_bech32 = bech32_decode(invoice, ignore_long_length=True)
    hrp = decoded_bech32.hrp
    data5 = decoded_bech32.data  # "5" as in list of 5-bit integers
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

    # Final signature 65 bytes, split it off.
    if len(data5) < 65*8//5:
        raise LnDecodeException("Too short to contain signature")
    sigdecoded = bytes(convertbits(data5[-65*8//5:], 5, 8, False))
    data5 = data5[:-65*8//5]
    data5_remaining = bytearray(data5)  # note: bytearray is faster than list of ints

    addr = LnAddr()
    addr.pubkey = None
    addr.net = net

    amountstr = hrp[2+len(net.BOLT11_HRP):]
    # BOLT #11:
    #
    # A reader SHOULD indicate if amount is unspecified, otherwise it MUST
    # multiply `amount` by the `multiplier` value (if any) to derive the
    # amount required for payment.
    if amountstr != '':
        addr.amount = unshorten_amount(amountstr)

    addr.date = int_from_data5(data5_remaining[:7])
    data5_remaining = data5_remaining[7:]

    while data5_remaining:
        tag, tagdata = pull_tagged(data5_remaining)  # mutates arg

        # BOLT #11:
        #
        # A reader MUST skip over unknown fields, an `f` field with unknown
        # `version`, or a `p`, `h`, or `n` field which does not have
        # `data_length` 52, 52, or 53 respectively.
        data_length = len(tagdata)

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
            tagdata = convertbits(tagdata, 5, 8, False)
            if not tagdata:
                continue
            route = []
            with io.BytesIO(bytes(tagdata)) as s:
                while True:
                    pubkey = s.read(33)
                    scid = s.read(8)
                    feebase = s.read(4)
                    feerate = s.read(4)
                    cltv = s.read(2)
                    if len(cltv) != 2:
                        break  # EOF
                    feebase = int.from_bytes(feebase, byteorder="big")
                    feerate = int.from_bytes(feerate, byteorder="big")
                    cltv = int.from_bytes(cltv, byteorder="big")
                    route.append((pubkey, scid, feebase, feerate, cltv))
            if route:
                addr.tags.append(('r',route))
        elif tag == 't':
            tagdata = convertbits(tagdata, 5, 8, False)
            if not tagdata:
                continue
            route = []
            with io.BytesIO(bytes(tagdata)) as s:
                pubkey = s.read(33)
                feebase = s.read(4)
                feerate = s.read(4)
                cltv = s.read(2)
                if len(cltv) == 2:  # no EOF
                    feebase = int.from_bytes(feebase, byteorder="big")
                    feerate = int.from_bytes(feerate, byteorder="big")
                    cltv = int.from_bytes(cltv, byteorder="big")
                    route.append((pubkey, feebase, feerate, cltv))
            addr.tags.append(('t', route))
        elif tag == 'f':
            fallback = parse_fallback_addr(tagdata, addr.net)
            if fallback:
                addr.tags.append(('f', fallback))
            else:
                # Incorrect version.
                addr.unknown_tags.append((tag, tagdata))
                continue

        elif tag == 'd':
            addr.tags.append(('d', bytes(convertbits(tagdata, 5, 8, False)).decode('utf-8')))

        elif tag == 'h':
            if data_length != 52:
                addr.unknown_tags.append((tag, tagdata))
                continue
            addr.tags.append(('h', bytes(convertbits(tagdata, 5, 8, False))))

        elif tag == 'x':
            addr.tags.append(('x', int_from_data5(tagdata)))

        elif tag == 'p':
            if data_length != 52:
                addr.unknown_tags.append((tag, tagdata))
                continue
            addr.paymenthash = bytes(convertbits(tagdata, 5, 8, False))

        elif tag == 's':
            if data_length != 52:
                addr.unknown_tags.append((tag, tagdata))
                continue
            addr.payment_secret = bytes(convertbits(tagdata, 5, 8, False))

        elif tag == 'n':
            if data_length != 53:
                addr.unknown_tags.append((tag, tagdata))
                continue
            pubkeybytes = bytes(convertbits(tagdata, 5, 8, False))
            addr.pubkey = pubkeybytes

        elif tag == 'c':
            addr.tags.append(('c', int_from_data5(tagdata)))

        elif tag == '9':
            features = int_from_data5(tagdata)
            addr.tags.append(('9', features))
            # note: The features are not validated here in the parser,
            #       instead, validation is done just before we try paying the invoice (in lnworker._check_invoice).
            #       Context: invoice parsing happens when opening a wallet. If there was a backwards-incompatible
            #       change to a feature, and we raised, some existing wallets could not be opened. Such a change
            #       can happen to features not-yet-merged-to-BOLTs (e.g. trampoline feature bit was moved and reused).
        else:
            addr.unknown_tags.append((tag, tagdata))

    if verbose:
        print('hex of signature data (32 byte r, 32 byte s): {}'
              .format(hexlify(sigdecoded[0:64])))
        print('recovery flag: {}'.format(sigdecoded[64]))
        data8 = bytes(convertbits(data5, 5, 8, True))
        print('hex of data for signing: {}'
              .format(hexlify(hrp.encode("ascii") + data8)))
        print('SHA256 of above: {}'.format(sha256(hrp.encode("ascii") + data8).hexdigest()))

    # BOLT #11:
    #
    # A reader MUST check that the `signature` is valid (see the `n` tagged
    # field specified below).
    addr.signature = sigdecoded[:65]
    hrp_hash = sha256(hrp.encode("ascii") + bytes(convertbits(data5, 5, 8, True))).digest()
    if addr.pubkey: # Specified by `n`
        # BOLT #11:
        #
        # A reader MUST use the `n` field to validate the signature instead of
        # performing signature recovery if a valid `n` field is provided.
        if not ecc.ECPubkey(addr.pubkey).ecdsa_verify(sigdecoded[:64], hrp_hash):
            raise LnDecodeException("bad signature")
        pubkey_copy = addr.pubkey
        class WrappedBytesKey:
            serialize = lambda: pubkey_copy
        addr.pubkey = WrappedBytesKey
    else: # Recover pubkey from signature.
        addr.pubkey = SerializableKey(ecc.ECPubkey.from_ecdsa_sig64(sigdecoded[:64], sigdecoded[64], hrp_hash))

    return addr
