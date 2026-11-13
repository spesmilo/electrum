#
# ur_decoder.py
#
# Copyright (C) 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from typing import Optional, List, FrozenSet, Tuple, Union

from .ur import UR
from .fountain_encoder import Part as FountainEncoderPart
from .fountain_decoder import FountainDecoder
from .bytewords import Bytewords, Bytewords_Style_minimal
from .utils import drop_first, is_ur_type


class InvalidScheme(Exception):
    pass


class InvalidType(Exception):
    pass


class InvalidPathLength(Exception):
    pass


class InvalidSequenceComponent(Exception):
    pass


class URDecoder:
    def __init__(self) -> None:
        self.fountain_decoder = FountainDecoder()
        self.expected_type: Optional[str] = None
        self.result: Union[None, UR, Exception] = None

    @staticmethod
    def decode(str: str) -> UR:
        (type, components) = URDecoder.parse(str)
        if len(components) == 0:
            raise InvalidPathLength()

        body = components[0]
        return URDecoder.decode_by_type(type, body)

    @staticmethod
    def decode_by_type(type: str, body: str) -> UR:
        cbor = Bytewords.decode(Bytewords_Style_minimal, body)
        return UR(type, cbor)

    @staticmethod
    def parse(str: str) -> Tuple[str, List[str]]:
        # Don't consider case
        lowered = str.lower()

        # Validate URI scheme
        if not lowered.startswith('ur:'):
            raise InvalidScheme()

        path = drop_first(lowered, 3)

        # Split the remainder into path components
        components = path.split('/')

        # Make sure there are at least two path components
        if len(components) < 2:
            raise InvalidPathLength()

        # Validate the type
        type = components[0]
        if not is_ur_type(type):
            raise InvalidType()

        comps = components[1:]  # Don't include the ur type
        return (type, comps)

    @staticmethod
    def parse_sequence_component(str: str) -> Tuple[int, int]:
        try:
            comps = str.split('-')
            if len(comps) != 2:
                raise InvalidSequenceComponent()
            seq_num = int(comps[0])
            seq_len = int(comps[1])
            if seq_num < 1 or seq_len < 1:
                raise InvalidSequenceComponent()
            return (seq_num, seq_len)
        except ValueError:
            raise InvalidSequenceComponent()

    def validate_part(self, type: str) -> bool:
        if self.expected_type is None:
            if not is_ur_type(type):
                return False
            self.expected_type = type
            return True
        else:
            return type == self.expected_type

    def receive_part(self, str: str) -> bool:
        try:
            # Don't process the part if we're already done
            if self.result is not None:
                return False

            # Don't continue if this part doesn't validate
            (type, components) = URDecoder.parse(str)
            if not self.validate_part(type):
                return False

            # If this is a single-part UR then we're done
            if len(components) == 1:
                body = components[0]
                self.result = self.decode_by_type(type, body)
                return True

            # Multi-part URs must have two path components: seq/fragment
            if len(components) != 2:
                raise InvalidPathLength()
            seq = components[0]
            fragment = components[1]

            # Parse the sequence component and the fragment, and make sure they agree.
            (seq_num, seq_len) = URDecoder.parse_sequence_component(seq)
            cbor = Bytewords.decode(Bytewords_Style_minimal, fragment)
            part = FountainEncoderPart.from_cbor(cbor)
            if seq_num != part.seq_num or seq_len != part.seq_len:
                return False

            # Process the part
            if not self.fountain_decoder.receive_part(part):
                return False

            if self.fountain_decoder.is_success():
                self.result = UR(type, self.fountain_decoder.result_message())
            elif self.fountain_decoder.is_failure():
                self.result = self.fountain_decoder.result_error()

            return True
        except Exception:
            return False

    def expected_part_count(self) -> int:
        return self.fountain_decoder.expected_part_count()

    def independent_part_count(self) -> int:
        return self.fountain_decoder.independent_part_count()

    def last_part_indexes(self) -> Optional[FrozenSet[int]]:
        return self.fountain_decoder.last_part_indexes

    def processed_parts_count(self) -> int:
        return self.fountain_decoder.processed_parts_count

    def estimated_percent_complete(self) -> float:
        return self.fountain_decoder.estimated_percent_complete()

    def is_success(self) -> bool:
        return isinstance(self.result, UR)

    def is_failure(self) -> bool:
        return isinstance(self.result, Exception)

    def is_complete(self) -> bool:
        return self.result is not None

    def result_message(self) -> UR:
        assert isinstance(self.result, UR)
        return self.result

    def result_error(self) -> Exception:
        assert isinstance(self.result, Exception)
        return self.result
