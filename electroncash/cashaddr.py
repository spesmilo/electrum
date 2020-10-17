# Copyright (c) 2017 Pieter Wuille
# Copyright (c) 2017 Shammah Chancellor, Neil Booth
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

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _polymod(values):
    """Internal function that computes the cashaddr checksum."""
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        if (c0 & 0x01):
            c ^= 0x98f2bc8e61
        if (c0 & 0x02):
            c ^= 0x79b76d99e2
        if (c0 & 0x04):
            c ^= 0xf33e5fb3c4
        if (c0 & 0x08):
            c ^= 0xae2eabe2a8
        if (c0 & 0x10):
            c ^= 0x1e4f43e470
    retval= c ^ 1
    return retval

def _prefix_expand(prefix):
    """Expand the prefix into values for checksum computation."""
    retval = bytearray(ord(x) & 0x1f for x in prefix)
    # Append null separator
    retval.append(0)
    return retval

def _create_checksum(prefix, data):
    """Compute the checksum values given prefix and data."""
    values = _prefix_expand(prefix) + data + bytes(8)
    polymod = _polymod(values)
    # Return the polymod expanded into eight 5-bit elements
    return bytes((polymod >> 5 * (7 - i)) & 31 for i in range(8))

def _convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = bytearray()
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value ) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)

    return ret

def _pack_addr_data(kind, addr_hash):
    """Pack addr data with version byte"""
    version_byte = kind << 3

    offset = 1
    encoded_size = 0
    if len(addr_hash) >= 40:
        offset = 2
        encoded_size |= 0x04
    encoded_size |= (len(addr_hash) - 20 * offset) // (4 * offset)

    # invalid size?
    if ((len(addr_hash) - 20 * offset) % (4 * offset) != 0
            or not 0 <= encoded_size <= 7):
        raise ValueError('invalid address hash size {}'.format(addr_hash))

    version_byte |= encoded_size

    data = bytes([version_byte]) + addr_hash
    return _convertbits(data, 8, 5, True)


def _decode_payload(addr):
    """Validate a cashaddr string.

    Throws CashAddr.Error if it is invalid, otherwise returns the
    triple

       (prefix,  payload)

    without the checksum.
    """
    lower = addr.lower()
    if lower != addr and addr.upper() != addr:
        raise ValueError('mixed case in address: {}'.format(addr))

    parts = lower.split(':', 1)
    if len(parts) != 2:
        raise ValueError("address missing ':' separator: {}".format(addr))

    prefix, payload = parts
    if not prefix:
        raise ValueError('address prefix is missing: {}'.format(addr))
    if not all(33 <= ord(x) <= 126 for x in prefix):
        raise ValueError('invalid address prefix: {}'.format(prefix))
    if not (8 <= len(payload) <= 124):
        raise ValueError('address payload has invalid length: {}'
                         .format(len(addr)))
    try:
        data = bytes(_CHARSET.find(x) for x in payload)
    except ValueError:
        raise ValueError('invalid characters in address: {}'
                            .format(payload))

    if _polymod(_prefix_expand(prefix) + data):
        raise ValueError('invalid checksum in address: {}'.format(addr))

    if lower != addr:
        prefix = prefix.upper()

    # Drop the 40 bit checksum
    return prefix, data[:-8]

#
# External Interface
#

PUBKEY_TYPE = 0
SCRIPT_TYPE = 1

def decode(address):
    '''Given a cashaddr address, return a triple

          (prefix, kind, hash)
    '''
    if not isinstance(address, str):
        raise TypeError('address must be a string')

    prefix, payload = _decode_payload(address)

    # Ensure there isn't extra padding
    extrabits = len(payload) * 5 % 8
    if extrabits >= 5:
        raise ValueError('excess padding in address {}'.format(address))

    # Ensure extrabits are zeros
    if payload[-1] & ((1 << extrabits) - 1):
        raise ValueError('non-zero padding in address {}'.format(address))

    decoded = _convertbits(payload, 5, 8, False)
    version = decoded[0]
    addr_hash = bytes(decoded[1:])
    size = (version & 0x03) * 4 + 20
    # Double the size, if the 3rd bit is on.
    if version & 0x04:
        size <<= 1
    if size != len(addr_hash):
        raise ValueError('address hash has length {} but expected {}'
                         .format(len(addr_hash), size))

    kind = version >> 3
    if kind not in (SCRIPT_TYPE, PUBKEY_TYPE):
        raise ValueError('unrecognised address type {}'.format(kind))

    return prefix, kind, addr_hash


def encode(prefix, kind, addr_hash):
    """Encode a cashaddr address without prefix and separator."""
    if not isinstance(prefix, str):
        raise TypeError('prefix must be a string')

    if not isinstance(addr_hash, (bytes, bytearray)):
        raise TypeError('addr_hash must be binary bytes')

    if kind not in (SCRIPT_TYPE, PUBKEY_TYPE):
        raise ValueError('unrecognised address type {}'.format(kind))

    payload = _pack_addr_data(kind, addr_hash)
    checksum = _create_checksum(prefix, payload)
    return ''.join([_CHARSET[d] for d in (payload + checksum)])


def encode_full(prefix, kind, addr_hash):
    """Encode a full cashaddr address, with prefix and separator."""
    return ':'.join([prefix, encode(prefix, kind, addr_hash)])
