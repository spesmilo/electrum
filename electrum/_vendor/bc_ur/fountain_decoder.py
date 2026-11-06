#
# fountain_decoder.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from dataclasses import dataclass
from typing import Optional, Dict, Set, FrozenSet, Tuple, Union, Iterable

from .fountain_encoder import Part as FountainEncoderPart
from .fountain_utils import choose_fragments
from .utils import join_bytes, crc32_int, take_first


class InvalidPart(Exception):
    pass


class InvalidChecksum(Exception):
    pass


@dataclass(frozen=True)
class Part:
    indexes: FrozenSet[int]
    data: bytes

    @classmethod
    def from_encoder_part(cls, p: FountainEncoderPart) -> 'Part':
        return cls(frozenset(choose_fragments(p.seq_num, p.seq_len, p.checksum)), p.data)


class FountainDecoder:
    # Each part is the XOR of some fragments: a linear equation over GF(2). The equations are kept
    # in reduced row echelon form (Gauss-Jordan elimination), so that the message is decoded as soon
    # as the received parts determine it. The reference implementation instead only reduces parts by
    # parts with a subset of their fragments ("peeling"), which needs more parts for larger messages.

    def __init__(self) -> None:
        self.last_part_indexes: Optional[FrozenSet[int]] = None
        self.processed_parts_count = 0
        self.result: Union[None, bytes, Exception] = None
        self.expected_part_indexes: Optional[Set[int]] = None
        self.expected_fragment_len: Optional[int] = None
        self.expected_message_len: Optional[int] = None
        self.expected_checksum: Optional[int] = None
        # pivot fragment index -> (bitmask of fragment indexes, XOR of their data as int).
        # The bitmask contains no other pivot. There is at most one equation per fragment.
        self.equations: Dict[int, Tuple[int, int]] = {}

    def expected_part_count(self) -> int:
        assert self.expected_part_indexes is not None
        return len(self.expected_part_indexes)

    def independent_part_count(self) -> int:
        # the number of received parts that are not a combination of others,
        # the message is decoded once it reaches expected_part_count()
        return len(self.equations)

    def is_success(self) -> bool:
        return isinstance(self.result, bytes)

    def is_failure(self) -> bool:
        return isinstance(self.result, Exception)

    def is_complete(self) -> bool:
        return self.result is not None

    def result_message(self) -> bytes:
        assert isinstance(self.result, bytes)
        return self.result

    def result_error(self) -> Exception:
        assert isinstance(self.result, Exception)
        return self.result

    def estimated_percent_complete(self) -> float:
        if self.expected_part_indexes is None:
            return 0
        return self.independent_part_count() / self.expected_part_count()

    def receive_part(self, encoder_part: FountainEncoderPart) -> bool:
        # Don't process the part if we're already done
        if self.is_complete():
            return False

        # Don't continue if this part doesn't validate
        if not self.validate_part(encoder_part):
            return False

        p = Part.from_encoder_part(encoder_part)
        self.last_part_indexes = p.indexes
        self.add_equation(sum(1 << i for i in p.indexes), int.from_bytes(p.data, 'little'))

        # If we've received enough parts, each equation is now a single fragment
        if self.independent_part_count() == self.expected_part_count():
            assert self.expected_fragment_len is not None and self.expected_message_len is not None
            fragments = [self.equations[i][1].to_bytes(self.expected_fragment_len, 'little')
                         for i in range(self.expected_part_count())]
            message = self.join_fragments(fragments, self.expected_message_len)

            # Verify the message checksum and note success or failure
            checksum = crc32_int(message)
            if checksum == self.expected_checksum:
                self.result = message
            else:
                self.result = InvalidChecksum()

        # Keep track of how many parts we've processed
        self.processed_parts_count += 1

        return True

    # Join all the fragments of a message together, throwing away any padding
    @staticmethod
    def join_fragments(fragments: Iterable[bytes], message_len: int) -> bytes:
        message = join_bytes(fragments)
        return take_first(message, message_len)

    def add_equation(self, mask: int, data: int) -> None:
        # Eliminate the pivots of the stored equations from the new one
        for pivot, (m, d) in self.equations.items():
            if mask >> pivot & 1:
                mask ^= m
                data ^= d
        # If nothing is left, the part is a combination of the received ones (e.g. a duplicate)
        if mask == 0:
            return
        # Otherwise, it has a new pivot, which is eliminated from the stored equations
        pivot = (mask & -mask).bit_length() - 1
        for other, (m, d) in self.equations.items():
            if m >> pivot & 1:
                self.equations[other] = (m ^ mask, d ^ data)
        self.equations[pivot] = (mask, data)

    def validate_part(self, p: FountainEncoderPart) -> bool:
        # If this is the first part we've seen
        if self.expected_part_indexes is None:
            # Record the things that all the other parts we see will have to match to be valid.
            self.expected_part_indexes = set()
            for i in range(p.seq_len):
                self.expected_part_indexes.add(i)

            self.expected_message_len = p.message_len
            self.expected_checksum = p.checksum
            self.expected_fragment_len = len(p.data)
        else:
            # If this part's values don't match the first part's values, throw away the part
            if self.expected_part_count() != p.seq_len:
                return False
            if self.expected_message_len != p.message_len:
                return False
            if self.expected_checksum != p.checksum:
                return False
            if self.expected_fragment_len != len(p.data):
                return False

        # This part should be processed
        return True
