#
# utils.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from typing import List, Tuple, Iterable, MutableSequence, AnyStr

from .crc32 import crc32, crc32n


def crc32_bytes(buf: bytes) -> bytes:
    checksum = crc32n(buf)
    return checksum


def crc32_int(buf: bytes) -> int:
    return crc32(buf)


def data_to_hex(buf: bytes) -> str:
    return ''.join('{:02x}'.format(x) for x in buf)


def int_to_bytes(n: int) -> bytes:
    # return n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return n.to_bytes(4, 'big')


def bytes_to_int(buf: bytes) -> int:
    return int.from_bytes(buf, 'big')


def string_to_bytes(s: str) -> bytes:
    return bytes(s, 'utf8')


def is_ur_type(ch: str) -> bool:
    if 'a' <= ch and ch <= 'z':
        return True
    if '0' <= ch and ch <= '9':
        return True
    if ch == '-':
        return True
    return False


def partition(s: AnyStr, n: int) -> List[AnyStr]:
    return [s[i:i+n] for i in range(0, len(s), n)]


# Split the given sequence into two parts returned in a tuple
# The first entry in the tuple has the first `count` values.
# The second entry in the tuple has the remaining values.
def split(buf: AnyStr, count: int) -> Tuple[AnyStr, AnyStr]:
    return (buf[0:count], buf[count:])


def join_lists(lists: List[list]) -> list:
    # return [y for x in lists for y in x]
    return sum(lists, [])


def join_bytes(list_of_ba: Iterable[bytes]) -> bytes:
    return b''.join(list_of_ba)


def xor_into(target: MutableSequence[int], source: bytes) -> None:
    count = len(target)
    assert count == len(source)  # Must be the same length
    for i in range(count):
        target[i] ^= source[i]


def xor_with(a: bytearray, b: bytes) -> bytearray:
    target = a
    xor_into(target, b)
    return target


def take_first(s: AnyStr, count: int) -> AnyStr:
    return s[0:count]


def drop_first(s: AnyStr, count: int) -> AnyStr:
    return s[count:]
