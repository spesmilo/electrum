#
# fountain_decoder.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from .fountain_utils import choose_fragments, contains, is_strict_subset, set_difference
from .utils import join_lists, join_bytes, crc32_int, xor_with, take_first

class InvalidPart(Exception):
    pass

class InvalidChecksum(Exception):
    pass

class FountainDecoder:
    class Part:
        def __init__(self, indexes, data):
            self.indexes = frozenset(indexes)
            self.data = data
        
        @classmethod
        def from_encoder_part(cls, p):
            return cls(choose_fragments(p.seq_num, p.seq_len, p.checksum), p.data[:])

        def indexes(self):
            return self.indexes

        def data(self):
            return self.data

        def is_simple(self):
            return len(self.indexes) == 1

        def index(self):
            # TODO: Not efficient
            return list(self.indexes)[0]

    # FountainDecoder
    def __init__(self):
        self.received_part_indexes = set()
        self.last_part_indexes = None
        self.processed_parts_count = 0
        self.result = None
        self.expected_part_indexes = None
        self.expected_fragment_len = None
        self.expected_message_len = None
        self.expected_checksum = None
        self.simple_parts = {}
        self.mixed_parts = {}
        self.queued_parts = []

    def expected_part_count(self):
        return len(self.expected_part_indexes)  # TODO: Handle None?

    def is_success(self):
        result = self.result
        return result if not isinstance(result, Exception) else False

    def is_failure(self):
        result = self.result
        return result if isinstance(result, Exception) else False

    def is_complete(self):
        return self.result != None

    def result_message(self):
        return self.result

    def result_error(self):
         return self.result

    def estimated_percent_complete(self):
        if self.is_complete():
            return 1
        if self.expected_part_indexes == None:
            return 0
        estimated_input_parts = self.expected_part_count() * .7
        return min(0.99, len(self.received_part_indexes) / estimated_input_parts)

    def receive_part(self, encoder_part):
        # Don't process the part if we're already done
        if self.is_complete():
            return False

        # Don't continue if this part doesn't validate
        if not self.validate_part(encoder_part):
            return False

        # Add this part to the queue
        p = FountainDecoder.Part.from_encoder_part(encoder_part)
        self.last_part_indexes = p.indexes
        self.enqueue(p)

        # Process the queue until we're done or the queue is empty
        while not self.is_complete() and len(self.queued_parts) != 0:
            self.process_queue_item()

        # Keep track of how many parts we've processed
        self.processed_parts_count += 1

        # self.print_part_end()

        return True

    # Join all the fragments of a message together, throwing away any padding
    @staticmethod
    def join_fragments(fragments, message_len):
        message = join_bytes(fragments)
        return take_first(message, message_len)

    def enqueue(self, p):
        self.queued_parts.append(p)

    def process_queue_item(self):
        part = self.queued_parts.pop(0)
        # self.print_part(part)

        if part.is_simple():
            self.process_simple_part(part)
        else:
            self.process_mixed_part(part)
        # self.print_state()

    def reduce_mixed_by(self, p):
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

    def reduce_part_by_part(self, a, b):
        # If the fragments mixed into `b` are a strict (proper) subset of those in `a`...
        if is_strict_subset(b.indexes, a.indexes):
            # The new fragments in the revised part are `a` - `b`.
            new_indexes = set_difference(a.indexes, b.indexes)
            # The new data in the revised part are `a` XOR `b`
            new_data = xor_with(bytearray(a.data), b.data)
            return self.Part(new_indexes, new_data)
        else:
            # `a` is not reducable by `b`, so return a
            return a

    def process_simple_part(self, p):
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

            message = self.join_fragments(fragments, self.expected_message_len)

            # Verify the message checksum and note success or failure
            checksum = crc32_int(message)
            if(checksum == self.expected_checksum):
                self.result = bytes(message)
            else:
                self.result = InvalidChecksum()

        else:
            # Reduce all the mixed parts by this part
            self.reduce_mixed_by(p)

    def process_mixed_part(self, p):
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

    def validate_part(self, p):
        # If this is the first part we've seen
        if self.expected_part_indexes == None:
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

    # debugging
    def indexes_to_string(self, indexes):
        i = list(indexes)
        i.sort()
        s = [str(j) for j in i]
        return '[{}]'.format(', '.join(s))

    def result_description(self):
        if self.result == None:
            return 'None'

        if self.is_success():
            return '{} bytes'.format(len(self.result))
        elif self.is_failure():
            return 'Exception: {}'.format(self.result)
        else:
            assert(False)

    def print_part(self, p):
        print('part indexes: {}'.format(self.indexes_to_string(p.indexes)))

    def print_part_end(self):
        expected = self.expected_part_count() if self.expected_part_indexes != None else 'None'
        percent = int(round(self.estimated_percent_complete() * 100))
        print("processed: {}, expected: {}, received: {}, percent: {}%".format(self.processed_parts_count, expected, len(self.received_part_indexes), percent))

    def print_state(self):
        parts = self.expected_part_count() if self.expected_part_indexes != None else 'None'
        received = self.indexes_to_string(self.received_part_indexes)
        mixed = []
        for indexes, p in self.mixed_parts.items():
            mixed.append(self.indexes_to_string(indexes))
        
        mixed_s = "[{}]".format(', '.join(mixed))
        queued = len(self.queued_parts)
        res = self.result_description()
        print('parts: {}, received: {}, mixed: {}, queued: {}, result: {}'.format(parts, received, mixed_s, queued, res))
