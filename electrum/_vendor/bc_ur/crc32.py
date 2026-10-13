#
# crc32.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from typing import Optional, List

from .constants import MAX_UINT32


def bit_length(n: int) -> int:
    return len(bin(abs(n))) - 2


TABLE: Optional[List[Optional[int]]] = None


def crc32(buf: bytes) -> int:
    # Lazily instantiate CRC table
    global TABLE
    if TABLE is None:
        TABLE = [None] * (256 * 4)

        for i in range(256):
            c = i
            for j in range(8):
                c = (c >> 1) if (c % 2 == 0) else (0xEDB88320 ^ (c >> 1))

            TABLE[i] = c

    crc = MAX_UINT32 & ~0
    for byte in buf:
        crc = (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]

    return MAX_UINT32 & ~crc


def crc32n(buf: bytes) -> bytes:
    n = crc32(buf)
    return n.to_bytes(4, 'big')
