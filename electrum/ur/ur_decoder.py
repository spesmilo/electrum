#
# ur_decoder.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from .ur import UR
from .fountain_encoder import FountainEncoder, Part as FountainEncoderPart
from .fountain_decoder import FountainDecoder
from .bytewords import *
from .utils import drop_first, is_ur_type

class InvalidScheme(Exception):
    pass

class InvalidType(Exception):
    pass

class InvalidPathLength(Exception):
    pass

class InvalidSequenceComponent(Exception):
    pass

class InvalidFragment(Exception):
    pass

class URDecoder:
    def __init__(self):
        self.fountain_decoder = FountainDecoder()
        self.expected_type = None
        self.result = None

    @staticmethod
    def decode(str):
        (type, components) = URDecoder.parse(str)
        if len(components) == 0:
            raise InvalidPathLength()

        body = components[0]
        return URDecoder.decode_by_type(type, body)

    @staticmethod
    def decode_by_type(type, body):
        cbor = Bytewords.decode(Bytewords_Style_minimal, body)
        return UR(type, cbor)

    @staticmethod
    def parse(str):
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

        comps = components[1:] # Don't include the ur type
        return (type, comps)

    @staticmethod
    def parse_sequence_component(str):
        try:
            comps = str.split('-')
            if len(comps) != 2:
                raise InvalidSequenceComponent()
            seq_num = int(comps[0])
            seq_len = int(comps[1])
            if seq_num < 1 or seq_len < 1:
                raise InvalidSequenceComponent()
            return (seq_num, seq_len)
        except:
            raise InvalidSequenceComponent()

    def validate_part(self, type):
        if self.expected_type == None:
            if not is_ur_type(type):
                return False
            self.expected_type = type
            return True
        else:
            return type == self.expected_type

    def receive_part(self, str):
        try:
            # Don't process the part if we're already done
            if self.result != None:
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
        except Exception as err:
            return False

    def expected_type(self):
       return self.expected_type

    def expected_part_count(self):
        return self.fountain_decoder.expected_part_count()

    def received_part_indexes(self):
        return self.fountain_decoder.received_part_indexes

    def last_part_indexes(self):
        return self.fountain_decoder.last_part_indexes

    def processed_parts_count(self):
        return self.fountain_decoder.processed_parts_count

    def estimated_percent_complete(self):
        return self.fountain_decoder.estimated_percent_complete()
        
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

    