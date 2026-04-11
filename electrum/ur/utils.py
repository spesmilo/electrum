#
# utils.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from .crc32 import crc32, crc32n

def crc32_bytes(buf):
    checksum = crc32n(buf)
    return checksum

def crc32_int(buf):
    return crc32(buf)

def data_to_hex(buf):
    return ''.join('{:02x}'.format(x) for x in buf)

def int_to_bytes(n):
    # return n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return n.to_bytes(4, 'big')

def bytes_to_int(buf):
    return int.from_bytes(buf, 'big')

def string_to_bytes(s):
    return bytes(s, 'utf8')

def is_ur_type(ch):
    if 'a' <= ch and ch <= 'z':
         return True
    if '0' <= ch and ch <= '9':
        return True
    if ch == '-':
        return True
    return False

def partition(s, n):
    return [s[i:i+n] for i in range(0, len(s), n)]

# Split the given sequence into two parts returned in a tuple
# The first entry in the tuple has the first `count` values.
# The second entry in the tuple has the remaining values.
def split(buf, count):
    return (buf[0:count], buf[count:])

def join_lists(lists):
    # return [y for x in lists for y in x]
    return sum(lists, [])

def join_bytes(list_of_ba):
    out = bytearray()
    for ba in list_of_ba:
        out.extend(ba)
    return out

def xor_into(target, source):
    count = len(target)
    assert(count == len(source)) # Must be the same length
    for i in range(count):
        target[i] ^= source[i]

def xor_with(a, b):
    target = a
    xor_into(target, b)
    return target

def take_first(s, count):
    return s[0:count]

def drop_first(s, count):
    return s[count:]
