# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2020 The Electron Cash Developers
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
import os

from collections import namedtuple
from typing import Optional, Union

from .util import print_error

def bits_to_target(bits: int) -> int:
    size = bits >> 24
    assert size <= 0x1d

    word = bits & 0x00ffffff
    assert 0x8000 <= word <= 0x7fffff

    if size <= 3:
        return word >> (8 * (3 - size))
    else:
        return word << (8 * (size - 3))

def _get_asert_activation_mtp():
    """ Returns 1605441600 (Nov 15, 2020 12:00:00 UTC) or whatever override may
    be set by the env variable ASERT_MTP """
    default_mtp = 1605441600  # Nov 15, 2020 12:00:00 UTC
    mtp = os.environ.get('ASERT_MTP', default_mtp)
    try: mtp = int(mtp)
    except: pass
    if not isinstance(mtp, int) or mtp <= 1510600000:
        print_error("Error: Environment variable ASERT_MTP ignored because it is invalid: {}".format(str(mtp)))
        mtp = default_mtp
    if mtp != default_mtp:
        print_error("ASERT_MTP of {} will be used".format(mtp))
    return mtp

class Anchor(namedtuple("Anchor", "height bits prev_time")):
    pass

class ASERTDaa:
    """ Parameters and methods for the ASERT DAA. Instances of these live in
    networks.TestNet, networks.MainNet as part of the chain params. """

    MTP_ACTIVATION_TIME = _get_asert_activation_mtp()  # Normally Nov. 15th, 2020 UTC 12:00:00

    IDEAL_BLOCK_TIME = 10 * 60  # 10 mins
    HALF_LIFE = 2 * 24 * 3600  # for mainnet, testnet has 3600 (1 hour) half-life
    # Integer implementation uses these for fixed point math
    RBITS = 16  # number of bits after the radix for fixed-point math
    RADIX = 1 << RBITS
    # POW Limit
    MAX_BITS = 0x1d00ffff

    MAX_TARGET = bits_to_target(MAX_BITS)

    anchor: Optional[Anchor] = None

    def __init__(self, is_testnet=False):
        if is_testnet:
            # From ASERT spec, testnet has 1 hour half-life
            self.HALF_LIFE = 3600

    @staticmethod
    def bits_to_target(bits: int) -> int:  return bits_to_target(bits)

    def target_to_bits(self, target: int) -> int:
        assert target > 0
        if target > self.MAX_TARGET:
            print_error('Warning: target went above maximum ({} > {})'.format(target, self.MAX_TARGET))
            target = self.MAX_TARGET
        size = (target.bit_length() + 7) // 8
        mask64 = 0xffffffffffffffff
        if size <= 3:
            compact = (target & mask64) << (8 * (3 - size))
        else:
            compact = (target >> (8 * (size - 3))) & mask64

        if compact & 0x00800000:
            compact >>= 8
            size += 1

        assert compact == (compact & 0x007fffff)
        assert size < 256
        return compact | size << 24

    @staticmethod
    def bits_to_work(bits: int) -> int:
        return (2 << 255) // (bits_to_target(bits) + 1)

    @staticmethod
    def target_to_hex(target: int) -> str:
        h = hex(target)[2:]
        return '0' * (64 - len(h)) + h

    def next_bits_aserti3_2d(self, anchor_bits: int, time_diff: Union[float, int], height_diff: int) -> int:
        """ Integer ASERTI algorithm, based on Jonathan Toomim's
        `next_bits_aserti` implementation in mining.py (see
        https://github.com/jtoomim/difficulty) """

        target = self.bits_to_target(anchor_bits)

        # Ultimately, we want to approximate the following ASERT formula, using
        # only integer (fixed-point) math:
        #     new_target = old_target * 2^((time_diff -
        #     IDEAL_BLOCK_TIME*(height_diff+1)) / HALF_LIFE)

        # First, we'll calculate the exponent, using floor division. The
        # assertion checks a type constraint of the C++ implementation which
        # uses a 64-bit signed integer for the exponent. If inputs violate that,
        # then the implementation will diverge.
        assert(abs(time_diff - self.IDEAL_BLOCK_TIME * (height_diff+1)) < (1<<(63-self.RBITS)))
        exponent = int(((time_diff - self.IDEAL_BLOCK_TIME*(height_diff+1)) * self.RADIX) / self.HALF_LIFE)

        # Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the (0, 1] interval.
        shifts = exponent >> self.RBITS
        exponent -= shifts * self.RADIX
        assert(exponent >= 0 and exponent < 65536)

        # Now we compute an approximated target * 2^(fractional part) * 65536
        # target * 2^x ~= target * (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3)
        target *= self.RADIX + ((195766423245049*exponent + 971821376*exponent**2 + 5127*exponent**3 + 2**47)>>(self.RBITS*3))

        # Next, we shift to multiply by 2^(integer part). Python doesn't allow
        # shifting by negative integers, so:
        if shifts < 0:
            target >>= -shifts
        else:
            target <<= shifts
        # Remove the 65536 multiplier we got earlier
        target >>= self.RBITS

        if target == 0:
            return self.target_to_bits(1)
        if target > self.MAX_TARGET:
            return self.MAX_BITS

        return self.target_to_bits(target)
