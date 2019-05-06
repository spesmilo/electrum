#! /usr/bin/env python3
# This was forked from https://github.com/rustyrussell/lightning-payencode/tree/acc16ec13a3fa1dc16c07af6ec67c261bd8aff23

import re
import time
from hashlib import sha256
from binascii import hexlify
from decimal import Decimal

import bitstring

from .bitcoin import hash160_to_b58_address, b58_address_to_hash160
from .segwit_addr import bech32_encode, bech32_decode, CHARSET
from . import constants
from . import ecc


# BOLT #11:
#
# A writer MUST encode `amount` as a positive decimal integer with no
# leading zeroes, SHOULD use the shortest representation possible.
def shorten_amount(amount):
    """ Given an amount in bitcoin, shorten it
    """
    # Convert to pico initially
    amount = int(amount * 10**12)
    units = ['p', 'n', 'u', 'm', '']
    for unit in units:
        if amount % 1000 == 0:
            amount //= 1000
        else:
            break
    return str(amount) + unit

def unshorten_amount(amount):
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
        raise ValueError("Invalid amount '{}'".format(amount))

    if unit in units.keys():
        return Decimal(amount[:-1]) / units[unit]
    else:
        return Decimal(amount)

# Bech32 spits out array of 5-bit values.  Shim here.
def u5_to_bitarray(arr):
    ret = bitstring.BitArray()
    for a in arr:
        ret += bitstring.pack("uint:5", a)
    return ret

def bitarray_to_u5(barr):
    assert barr.len % 5 == 0
    ret = []
    s = bitstring.ConstBitStream(barr)
    while s.pos != s.len:
        ret.append(s.read(5).uint)
    return ret

def encode_fallback(fallback, currency):
    """ Encode all supported fallback addresses.
    """
    if currency == 'bc' or currency == 'tb':
        fbhrp, witness = bech32_decode(fallback, ignore_long_length=True)
        if fbhrp:
            if fbhrp != currency:
                raise ValueError("Not a bech32 address for this currency")
            wver = witness[0]
            if wver > 16:
                raise ValueError("Invalid witness version {}".format(witness[0]))
            wprog = u5_to_bitarray(witness[1:])
        else:
            addrtype, addr = b58_address_to_hash160(fallback)
            if is_p2pkh(currency, addrtype):
                wver = 17
            elif is_p2sh(currency, addrtype):
                wver = 18
            else:
                raise ValueError("Unknown address type for {}".format(currency))
            wprog = addr
        return tagged('f', bitstring.pack("uint:5", wver) + wprog)
    else:
        raise NotImplementedError("Support for currency {} not implemented".format(currency))

def parse_fallback(fallback, currency):
    if currency == 'bc' or currency == 'tb':
        wver = fallback[0:5].uint
        if wver == 17:
            addr=hash160_to_b58_address(fallback[5:].tobytes(), base58_prefix_map[currency][0])
        elif wver == 18:
            addr=hash160_to_b58_address(fallback[5:].tobytes(), base58_prefix_map[currency][1])
        elif wver <= 16:
            addr=bech32_encode(currency, bitarray_to_u5(fallback))
        else:
            return None
    else:
        addr=fallback.tobytes()
    return addr


# Map of classical and witness address prefixes
base58_prefix_map = {
    'bc' : (0, 5),
    'tb' : (111, 196)
}

def is_p2pkh(currency, prefix):
    return prefix == base58_prefix_map[currency][0]

def is_p2sh(currency, prefix):
    return prefix == base58_prefix_map[currency][1]

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

def lnencode(addr, privkey):
    if addr.amount:
        amount = Decimal(str(addr.amount))
        # We can only send down to millisatoshi.
        if amount * 10**12 % 10:
            raise ValueError("Cannot encode {}: too many decimal places".format(
                addr.amount))

        amount = addr.currency + shorten_amount(amount)
    else:
        amount = addr.currency if addr.currency else ''

    hrp = 'ln' + amount

    # Start with the timestamp
    data = bitstring.pack('uint:35', addr.date)

    # Payment hash
    data += tagged_bytes('p', addr.paymenthash)
    tags_set = set()

    for k, v in addr.tags:

        # BOLT #11:
        #
        # A writer MUST NOT include more than one `d`, `h`, `n` or `x` fields,
        if k in ('d', 'h', 'n', 'x'):
            if k in tags_set:
                raise ValueError("Duplicate '{}' tag".format(k))

        if k == 'r':
            route = bitstring.BitArray()
            for step in v:
                pubkey, channel, feebase, feerate, cltv = step
                route.append(bitstring.BitArray(pubkey) + bitstring.BitArray(channel) + bitstring.pack('intbe:32', feebase) + bitstring.pack('intbe:32', feerate) + bitstring.pack('intbe:16', cltv))
            data += tagged('r', route)
        elif k == 'f':
            data += encode_fallback(v, addr.currency)
        elif k == 'd':
            data += tagged_bytes('d', v.encode())
        elif k == 'x':
            # Get minimal length by trimming leading 5 bits at a time.
            expirybits = bitstring.pack('intbe:64', v)[4:64]
            while expirybits.startswith('0b00000'):
                expirybits = expirybits[5:]
            data += tagged('x', expirybits)
        elif k == 'h':
            data += tagged_bytes('h', sha256(v.encode('utf-8')).digest())
        elif k == 'n':
            data += tagged_bytes('n', v)
        elif k == 'c':
            # Get minimal length by trimming leading 5 bits at a time.
            finalcltvbits = bitstring.pack('intbe:64', v)[4:64]
            while finalcltvbits.startswith('0b00000'):
                finalcltvbits = finalcltvbits[5:]
            data += tagged('c', finalcltvbits)
        else:
            # FIXME: Support unknown tags?
            raise ValueError("Unknown tag {}".format(k))

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

    return bech32_encode(hrp, bitarray_to_u5(data))

class LnAddr(object):
    def __init__(self, paymenthash=None, amount=None, currency=None, tags=None, date=None):
        self.date = int(time.time()) if not date else int(date)
        self.tags = [] if not tags else tags
        self.unknown_tags = []
        self.paymenthash=paymenthash
        self.signature = None
        self.pubkey = None
        self.currency = constants.net.SEGWIT_HRP if currency is None else currency
        self.amount = amount
        self._min_final_cltv_expiry = 9

    def __str__(self):
        return "LnAddr[{}, amount={}{} tags=[{}]]".format(
            hexlify(self.pubkey.serialize()).decode('utf-8') if self.pubkey else None,
            self.amount, self.currency,
            ", ".join([k + '=' + str(v) for k, v in self.tags])
        )

    def get_min_final_cltv_expiry(self) -> int:
        return self._min_final_cltv_expiry

    def get_description(self):
        description = ''
        for k,v in self.tags:
            if k == 'd':
                description = v
                break
        return description


def lndecode(a, verbose=False, expected_hrp=None):
    if expected_hrp is None:
        expected_hrp = constants.net.SEGWIT_HRP
    hrp, data = bech32_decode(a, ignore_long_length=True)
    if not hrp:
        raise ValueError("Bad bech32 checksum")

    # BOLT #11:
    #
    # A reader MUST fail if it does not understand the `prefix`.
    if not hrp.startswith('ln'):
        raise ValueError("Does not start with ln")

    if not hrp[2:].startswith(expected_hrp):
        raise ValueError("Wrong Lightning invoice HRP " + hrp[2:] + ", should be " + expected_hrp)

    data = u5_to_bitarray(data)

    # Final signature 65 bytes, split it off.
    if len(data) < 65*8:
        raise ValueError("Too short to contain signature")
    sigdecoded = data[-65*8:].tobytes()
    data = bitstring.ConstBitStream(data[:-65*8])

    addr = LnAddr()
    addr.pubkey = None

    m = re.search("[^\\d]+", hrp[2:])
    if m:
        addr.currency = m.group(0)
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
                              s.read(32).intbe,
                              s.read(32).intbe,
                              s.read(16).intbe))
            addr.tags.append(('r',route))
        elif tag == 'f':
            fallback = parse_fallback(tagdata, addr.currency)
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

        elif tag == 'n':
            if data_length != 53:
                addr.unknown_tags.append((tag, tagdata))
                continue
            pubkeybytes = trim_to_bytes(tagdata)
            addr.pubkey = pubkeybytes
        elif tag == 'c':
            addr._min_final_cltv_expiry = tagdata.int
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
        ecc.ECPubkey(addr.pubkey).verify_message_hash(sigdecoded[:64], hrp_hash)
        pubkey_copy = addr.pubkey
        class WrappedBytesKey:
            serialize = lambda: pubkey_copy
        addr.pubkey = WrappedBytesKey
    else: # Recover pubkey from signature.
        addr.pubkey = SerializableKey(ecc.ECPubkey.from_sig_string(sigdecoded[:64], sigdecoded[64], hrp_hash))

    return addr

class SerializableKey:
    def __init__(self, pubkey):
        self.pubkey = pubkey
    def serialize(self):
        return self.pubkey.get_public_key_bytes(True)

if __name__ == '__main__':
    # run using
    # python3 -m electrum.lnaddr <invoice> <expected hrp>
    # python3 -m electrum.lnaddr lntb1n1pdlcakepp5e7rn0knl0gm46qqp9eqdsza2c942d8pjqnwa5903n39zu28sgk3sdq423jhxapqv3hkuct5d9hkucqp2rzjqwyx8nu2hygyvgc02cwdtvuxe0lcxz06qt3lpsldzcdr46my5epmj9vk9sqqqlcqqqqqqqlgqqqqqqgqjqdhnmkgahfaynuhe9md8k49xhxuatnv6jckfmsjq8maxta2l0trh5sdrqlyjlwutdnpd5gwmdnyytsl9q0dj6g08jacvthtpeg383k0sq542rz2 tb1n
    import sys
    print(lndecode(sys.argv[1], expected_hrp=sys.argv[2]))
