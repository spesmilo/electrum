#
# fountain_decoder.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from dataclasses import dataclass
from typing import Optional, List, Dict, Set, FrozenSet, Union, Iterable

from .fountain_encoder import Part as FountainEncoderPart
from .fountain_utils import choose_fragments, contains, is_strict_subset, set_difference
from .utils import join_bytes, crc32_int, xor_with, take_first


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

    def is_simple(self) -> bool:
        return len(self.indexes) == 1

    def index(self) -> int:
        # TODO: Not efficient
        return list(self.indexes)[0]


class FountainDecoder:
    def __init__(self) -> None:
        self.received_part_indexes: Set[int] = set()
        self.last_part_indexes: Optional[FrozenSet[int]] = None
        self.processed_parts_count = 0
        self.result: Union[None, bytes, Exception] = None
        self.expected_part_indexes: Optional[Set[int]] = None
        self.expected_fragment_len: Optional[int] = None
        self.expected_message_len: Optional[int] = None
        self.expected_checksum: Optional[int] = None
        self.simple_parts: Dict[FrozenSet[int], Part] = {}
        self.mixed_parts: Dict[FrozenSet[int], Part] = {}
        self.queued_parts: List[Part] = []

    def expected_part_count(self) -> int:
        assert self.expected_part_indexes is not None
        return len(self.expected_part_indexes)

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
        if self.is_complete():
            return 1
        if self.expected_part_indexes is None:
            return 0
        estimated_input_parts = self.expected_part_count() * 1.75
        return min(0.99, self.processed_parts_count / estimated_input_parts)

    def receive_part(self, encoder_part: FountainEncoderPart) -> bool:
        # Don't process the part if we're already done
        if self.is_complete():
            return False

        # Don't continue if this part doesn't validate
        if not self.validate_part(encoder_part):
            return False

        # Add this part to the queue
        p = Part.from_encoder_part(encoder_part)
        self.last_part_indexes = p.indexes
        self.enqueue(p)

        # Process the queue until we're done or the queue is empty
        while not self.is_complete() and len(self.queued_parts) != 0:
            self.process_queue_item()

        # Keep track of how many parts we've processed
        self.processed_parts_count += 1

        return True

    # Join all the fragments of a message together, throwing away any padding
    @staticmethod
    def join_fragments(fragments: Iterable[bytes], message_len: int) -> bytes:
        message = join_bytes(fragments)
        return take_first(message, message_len)

    def enqueue(self, p: Part) -> None:
        self.queued_parts.append(p)

    def process_queue_item(self) -> None:
        part = self.queued_parts.pop(0)

        if part.is_simple():
            self.process_simple_part(part)
        else:
            self.process_mixed_part(part)

    def reduce_mixed_by(self, p: Part) -> None:
        # Reduce all the current mixed parts by the given part
        reduced_parts = []
        for value in self.mixed_parts.values():
            reduced_parts.append(self.reduce_part_by_part(value, p))

        # Collect all the remaining mixed parts
        new_mixed = {}
        for reduced_part in reduced_parts:
            # If this reduced part is now simple
            if reduced_part.is_simple():
                # Add it to the queue
                self.enqueue(reduced_part)
            else:
                # Otherwise, add it to the dict of current mixed parts
                new_mixed[reduced_part.indexes] = reduced_part

        self.mixed_parts = new_mixed

    def reduce_part_by_part(self, a: Part, b: Part) -> Part:
        # If the fragments mixed into `b` are a strict (proper) subset of those in `a`...
        if is_strict_subset(b.indexes, a.indexes):
            # The new fragments in the revised part are `a` - `b`.
            new_indexes = set_difference(a.indexes, b.indexes)
            # The new data in the revised part are `a` XOR `b`
            new_data = xor_with(bytearray(a.data), b.data)
            return Part(new_indexes, new_data)
        else:
            # `a` is not reducable by `b`, so return a
            return a

    def process_simple_part(self, p: Part) -> None:
        # Don't process duplicate parts
        fragment_index = p.index()
        if contains(self.received_part_indexes, fragment_index):
            return

        # Record this part
        self.simple_parts[p.indexes] = p
        self.received_part_indexes.add(fragment_index)

        # If we've received all the parts
        if self.received_part_indexes == self.expected_part_indexes:
            # Reassemble the message from its fragments
            sorted_parts = []
            for value in self.simple_parts.values():
                sorted_parts.append(value)

            sorted_parts.sort(key=lambda a: a.index())

            fragments = []
            for part in sorted_parts:
                fragments.append(part.data)

            assert self.expected_message_len is not None
            message = self.join_fragments(fragments, self.expected_message_len)

            # Verify the message checksum and note success or failure
            checksum = crc32_int(message)
            if checksum == self.expected_checksum:
                self.result = bytes(message)
            else:
                self.result = InvalidChecksum()

        else:
            # Reduce all the mixed parts by this part
            self.reduce_mixed_by(p)

    def process_mixed_part(self, p: Part) -> None:
        # Don't process duplicate parts
        for r in self.mixed_parts.values():
            if r == p.indexes:
                return

        # Reduce this part by all the others
        p2 = p  # TODO: Does this need to make a copy of p?
        for r in self.simple_parts.values():
            p2 = self.reduce_part_by_part(p2, r)

        for r in self.mixed_parts.values():
            p2 = self.reduce_part_by_part(p2, r)

        # If the part is now simple
        if p2.is_simple():
            # Add it to the queue
            self.enqueue(p2)
        else:
            # Reduce all the mixed parts by this one
            self.reduce_mixed_by(p2)
            # Record this new mixed part
            self.mixed_parts[p2.indexes] = p2

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
