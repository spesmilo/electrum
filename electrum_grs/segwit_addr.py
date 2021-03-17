
# Copyright (c) 2017 Pieter Wuille
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

"""Reference implementation for Bech32/Bech32m and segwit addresses."""

from enum import Enum
from typing import Tuple, Optional, Sequence, NamedTuple, List

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_INVERSE = {x: CHARSET.find(x) for x in CHARSET}

BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3


class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""
    BECH32 = 1
    BECH32M = 2


class DecodedBech32(NamedTuple):
    encoding: Optional[Encoding]
    hrp: Optional[str]
    data: Optional[Sequence[int]]  # 5-bit ints


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    check = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if check == BECH32_CONST:
        return Encoding.BECH32
    elif check == BECH32M_CONST:
        return Encoding.BECH32M
    else:
        return None


def bech32_create_checksum(encoding: Encoding, hrp: str, data: List[int]) -> List[int]:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if encoding == Encoding.BECH32M else BECH32_CONST
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(encoding: Encoding, hrp: str, data: List[int]) -> str:
    """Compute a Bech32 or Bech32m string given HRP and data values."""
    combined = data + bech32_create_checksum(encoding, hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def bech32_decode(bech: str, *, ignore_long_length=False) -> DecodedBech32:
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    bech_lower = bech.lower()
    if bech_lower != bech and bech.upper() != bech:
        return DecodedBech32(None, None, None)
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or (not ignore_long_length and len(bech) > 90):
        return DecodedBech32(None, None, None)
    # check that HRP only consists of sane ASCII chars
    if any(ord(x) < 33 or ord(x) > 126 for x in bech[:pos+1]):
        return DecodedBech32(None, None, None)
    bech = bech_lower
    hrp = bech[:pos]
    try:
        data = [_CHARSET_INVERSE[x] for x in bech[pos+1:]]
    except KeyError:
        return DecodedBech32(None, None, None)
    encoding = bech32_verify_checksum(hrp, data)
    if encoding is None:
        return DecodedBech32(None, None, None)
    return DecodedBech32(encoding=encoding, hrp=hrp, data=data[:-6])


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode_segwit_address(hrp: str, addr: Optional[str]) -> Tuple[Optional[int], Optional[Sequence[int]]]:
    """Decode a segwit address."""
    if addr is None:
        return (None, None)
    encoding, hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if (data[0] == 0 and encoding != Encoding.BECH32) or (data[0] != 0 and encoding != Encoding.BECH32M):
        return (None, None)
    return (data[0], decoded)


def encode_segwit_address(hrp: str, witver: int, witprog: bytes) -> Optional[str]:
    """Encode a segwit address."""
    encoding = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(encoding, hrp, [witver] + convertbits(witprog, 8, 5))
    if decode_segwit_address(hrp, ret) == (None, None):
        return None
    return ret
