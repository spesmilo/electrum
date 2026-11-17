#
# fountain_encoder.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

import math
from dataclasses import dataclass
from typing import Optional, List, Iterable

from ... import cbor
from .fountain_utils import choose_fragments
from .utils import crc32_int, xor_into
from .constants import MAX_UINT32


class InvalidHeader(Exception):
    pass


@dataclass(frozen=True)
class Part:
    MAX_SEQ_LEN = 10_000  # limit for untrusted input (QR codes)

    seq_num: int
    seq_len: int
    message_len: int
    checksum: int
    data: bytes

    def __post_init__(self) -> None:
        if not all(type(x) is int for x in (self.seq_num, self.seq_len, self.message_len, self.checksum)):
            raise InvalidHeader('header field is not an int')
        if type(self.data) is not bytes:
            raise InvalidHeader('data is not bytes')
        if not (1 <= self.seq_num <= MAX_UINT32 and 0 <= self.checksum <= MAX_UINT32):
            raise InvalidHeader('seq_num or checksum out of range')
        if not (1 <= self.seq_len <= self.MAX_SEQ_LEN and self.message_len >= 1 and len(self.data) >= 1):
            raise InvalidHeader('seq_len, message_len or fragment length out of range')
        # all fragments have the same length, the last one is padded
        if self.seq_len != -(-self.message_len // len(self.data)):
            raise InvalidHeader('seq_len does not match message_len and fragment length')

    @staticmethod
    def from_cbor(cbor_buf: bytes) -> 'Part':
        try:
            obj = cbor.loads(cbor_buf)
        except Exception as e:
            raise InvalidHeader('invalid CBOR') from e
        if not isinstance(obj, list) or len(obj) != 5:
            raise InvalidHeader('not an array of 5 elements')
        seq_num, seq_len, message_len, checksum, data = obj
        return Part(seq_num, seq_len, message_len, checksum, data)

    def to_cbor(self) -> bytes:
        return cbor.dumps([self.seq_num, self.seq_len, self.message_len, self.checksum, self.data])


class FountainEncoder:
    def __init__(self, message: bytes, max_fragment_len: int, first_seq_num: int = 0, min_fragment_len: int = 10) -> None:
        assert len(message) <= MAX_UINT32
        self.message_len = len(message)
        self.checksum = crc32_int(message)
        self.fragment_len = FountainEncoder.find_nominal_fragment_length(self.message_len, min_fragment_len, max_fragment_len)
        self.fragments = FountainEncoder.partition_message(message, self.fragment_len)
        self.seq_num = first_seq_num

    @staticmethod
    def find_nominal_fragment_length(message_len: int, min_fragment_len: int, max_fragment_len: int) -> int:
        assert message_len > 0
        assert min_fragment_len > 0
        assert max_fragment_len >= min_fragment_len
        max_fragment_count = message_len // min_fragment_len
        fragment_len: Optional[int] = None

        for fragment_count in range(1, max_fragment_count + 1):
            fragment_len = math.ceil(message_len / fragment_count)
            if fragment_len <= max_fragment_len:
                break

        assert fragment_len is not None
        return fragment_len

    @staticmethod
    def partition_message(message: bytes, fragment_len: int) -> List[bytes]:
        fragments = []
        for i in range(0, len(message), fragment_len):
            # the last fragment is padded with zeroes
            fragments.append(bytes(message[i:i + fragment_len]).ljust(fragment_len, b'\x00'))
        return fragments

    def seq_len(self) -> int:
        return len(self.fragments)

    # This becomes `true` when the minimum number of parts
    # to relay the complete message have been generated
    def is_complete(self) -> bool:
        return self.seq_num >= self.seq_len()

    # True if only a single part will be generated.
    def is_single_part(self) -> bool:
        return self.seq_len() == 1

    def next_part(self) -> Part:
        self.seq_num = (self.seq_num + 1) & MAX_UINT32  # wrap at period 2^32
        indexes = choose_fragments(self.seq_num, self.seq_len(), self.checksum)
        mixed = self.mix(indexes)
        data = bytes(mixed)
        return Part(self.seq_num, self.seq_len(), self.message_len, self.checksum, data)

    def mix(self, indexes: Iterable[int]) -> List[int]:
        result = [0] * self.fragment_len
        for index in indexes:
            xor_into(result, self.fragments[index])
        return result
