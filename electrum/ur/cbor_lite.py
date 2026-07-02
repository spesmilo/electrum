#
# crc32.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

# From: https://bitbucket.org/isode/cbor-lite/raw/6c770624a97e3229e3f200be092c1b9c70a60ef1/include/cbor-lite/codec.h

# This file is part of CBOR-lite which is copyright Isode Limited
# and others and released under a MIT license. For details, see the
# COPYRIGHT.md file in the top-level folder of the CBOR-lite software
# distribution.

def bit_length(n):
    return len(bin(abs(n))) - 2


Flag_None = 0
Flag_Require_Minimal_Encoding = 1

Tag_Major_unsignedInteger = 0
Tag_Major_negativeInteger = 1 << 5
Tag_Major_byteString = 2 << 5
Tag_Major_textString = 3 << 5
Tag_Major_array = 4 << 5
Tag_Major_map = 5 << 5
Tag_Major_semantic = 6 << 5
Tag_Major_floatingPoint = 7 << 5
Tag_Major_simple = 7 << 5
Tag_Major_mask = 0xe0

Tag_Minor_length1 = 24
Tag_Minor_length2 = 25
Tag_Minor_length4 = 26
Tag_Minor_length8 = 27

Tag_Minor_false = 20
Tag_Minor_true = 21
Tag_Minor_null = 22
Tag_Minor_undefined = 23
Tag_Minor_half_float = 25
Tag_Minor_singleFloat = 26
Tag_Minor_doubleFloat = 27

Tag_Minor_dateTime = 0
Tag_Minor_epochDateTime = 1
Tag_Minor_positiveBignum = 2
Tag_Minor_negativeBignum = 3
Tag_Minor_decimalFraction = 4
Tag_Minor_bigFloat = 5
Tag_Minor_convertBase64Url = 21
Tag_Minor_convertBase64 = 22
Tag_Minor_convertBase16 = 23
Tag_Minor_cborEncodedData = 24
Tag_Minor_uri = 32
Tag_Minor_base64Url = 33
Tag_Minor_base64 = 34
Tag_Minor_regex = 35
Tag_Minor_mimeMessage = 36
Tag_Minor_selfDescribeCbor = 55799
Tag_Minor_mask = 0x1f
Tag_Undefined = Tag_Major_semantic + Tag_Minor_undefined


def get_byte_length(value):
    if value < 24:
        return 0
    
    return (bit_length(value) + 7) // 8

class CBOREncoder:
    def __init__(self):
        self.buf = bytearray()

    def get_bytes(self):
        return self.buf

    def encodeTagAndAdditional(self, tag, additional):
        self.buf.append(tag + additional)
        return 1

    def encodeTagAndValue(self, tag, value):
        length = get_byte_length(value)

        # 5-8 bytes required, use 8 bytes
        if length >= 5 and length <= 8:
            self.encodeTagAndAdditional(tag, Tag_Minor_length8)
            self.buf.append((value >> 56) & 0xff)
            self.buf.append((value >> 48) & 0xff)
            self.buf.append((value >> 40) & 0xff)
            self.buf.append((value >> 32) & 0xff)
            self.buf.append((value >> 24) & 0xff)
            self.buf.append((value >> 16) & 0xff)
            self.buf.append((value >> 8) & 0xff)
            self.buf.append(value & 0xff)

        # 3-4 bytes required, use 4 bytes
        elif length == 3 or length == 4:
            self.encodeTagAndAdditional(tag, Tag_Minor_length4)
            self.buf.append((value >> 24) & 0xff)
            self.buf.append((value >> 16) & 0xff)
            self.buf.append((value >> 8) & 0xff)
            self.buf.append(value & 0xff)

        elif length == 2:
            self.encodeTagAndAdditional(tag, Tag_Minor_length2)
            self.buf.append((value >> 8) & 0xff)
            self.buf.append(value & 0xff)

        elif length == 1:
            self.encodeTagAndAdditional(tag, Tag_Minor_length1)
            self.buf.append(value & 0xff)

        elif length == 0:
            self.encodeTagAndAdditional(tag, value)

        else:
            raise Exception("Unsupported byte length of {} for value in encodeTagAndValue()".format(length))

        encoded_size = 1 + length
        return encoded_size

    def encodeUnsigned(self, value):
        return self.encodeTagAndValue(Tag_Major_unsignedInteger, value)

    def encodeNegative(self, value):
        return self.encodeTagAndValue(Tag_Major_negativeInteger, value)

    def encodeInteger(self, value):
        if value >= 0:
            return self.encodeUnsigned(value)
        else:
            return self.encodeNegative(value)

    def encodeBool(self, value):
        return self.encodeTagAndValue(Tag_Major_simple, Tag_Minor_true if value else Tag_Minor_false)

    def encodeBytes(self, value):
        length = self.encodeTagAndValue(Tag_Major_byteString, len(value))
        self.buf += value
        return length + len(value)

    def encodeEncodedBytesPrefix(self, value):
        length = self.encodeTagAndValue(Tag_Major_semantic, Tag_Minor_cborEncodedData)
        return length + self.encodeTagAndAdditional

    def encodeEncodedBytes(self, value):
        length = self.encodeTagAndValue(Tag_Major_semantic, Tag_Minor_cborEncodedData)
        return length + self.encodeBytes(value)

    def encodeText(self, value):
        str_len = len(value)
        length = self.encodeTagAndValue(Tag_Major_textString, str_len)
        self.buf.append(bytes(value, 'utf8'))
        return length + str_len

    def encodeArraySize(self, value):
        return self.encodeTagAndValue(Tag_Major_array, value)

    def encodeMapSize(self, value):
        return self.encodeTagAndValue(Tag_Major_map, value)


class CBORDecoder:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def decodeTagAndAdditional(self, flags=Flag_None):
        if self.pos == len(self.buf):
            raise Exception("Not enough input")
        octet = self.buf[self.pos]
        self.pos += 1
        tag = octet & Tag_Major_mask
        additional = octet & Tag_Minor_mask
        return (tag, additional, 1)

    def decodeTagAndValue(self, flags):
        end = len(self.buf)

        if self.pos == end:
            raise Exception("Not enough input")        

        (tag, additional, length) = self.decodeTagAndAdditional(flags)
        if additional < Tag_Minor_length1:
            value = additional
            return (tag, value, length)

        value = 0
        if additional == Tag_Minor_length8:
            if end - self.pos < 8:
                raise Exception("Not enough input")            
            for shift in [56, 48, 40, 32, 24, 16, 8, 0]:
                value |= self.buf[self.pos] << shift
                self.pos += 1
            if ((flags & Flag_Require_Minimal_Encoding) and value == 0):
                raise Exception("Encoding not minimal")
            return (tag, value, self.pos)
        elif additional == Tag_Minor_length4:
            if end - self.pos < 4:
                raise Exception("Not enough input")            
            for shift in [24, 16, 8, 0]:
                value |= self.buf[self.pos] << shift
                self.pos += 1
            if ((flags & Flag_Require_Minimal_Encoding) and value == 0):
                raise Exception("Encoding not minimal")
            return (tag, value, self.pos)
        elif additional == Tag_Minor_length2:
            if end - self.pos < 2:
                raise Exception("Not enough input")            
            for shift in [8, 0]:
                value |= self.buf[self.pos] << shift
                self.pos += 1
            if ((flags & Flag_Require_Minimal_Encoding) and value == 0):
                raise Exception("Encoding not minimal")
            return (tag, value, self.pos)
        elif additional == Tag_Minor_length1:
            if end - self.pos < 1:
                raise Exception("Not enough input")            
            value |= self.buf[self.pos]
            self.pos += 1
            if ((flags & Flag_Require_Minimal_Encoding) and value == 0):
                raise Exception("Encoding not minimal")
            return (tag, value, self.pos)

        raise Exception("Bad additional value")

    def decodeUnsigned(self, flags=Flag_None):
        (tag, value, length) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_unsignedInteger:
            raise Exception("Expected Tag_Major_unsignedInteger ({}), but found {}".format(Tag_Major_unsignedInteger, tag))
        return (value, length)

    def decodeNegative(self, flags=Flag_None):
        (tag, value, length) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_negativeInteger:
            raise Exception("Expected Tag_Major_negativeInteger, but found {}".format(tag))
        return (value, length)

    def decodeInteger(self, flags=Flag_None):
        (tag, value, length) = self.decodeTagAndValue(flags)
        if tag == Tag_Major_unsignedInteger:
            return (value, length)
        elif tag == Tag_Major_negativeInteger:
            return (-1 - value, length)  # TODO: Check that this is the right way -- do we need to use struct.unpack()?

    def decodeBool(self, flags=Flag_None):
        (tag, value, length) = self.decodeTagAndValue(flags)
        if tag == Tag_Major_simple:
            if value == Tag_Minor_true:
                return (True, length)
            elif value == Tag_Minor_false:
                return (False, length)
            raise Exception("Not a Boolean")
        raise Exception("Not Simple/Boolean")

    def decodeBytes(self, flags=Flag_None):
        # First value is the length of the bytes that follow
        (tag, byte_length, size_length) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_byteString:
            raise Exception("Not a byteString")

        end = len(self.buf)
        if end - self.pos < byte_length:
            raise Exception("Not enough input")

        value = bytes(self.buf[self.pos : self.pos + byte_length])
        self.pos += byte_length
        return (value, size_length + byte_length)

    def decodeEncodedBytesPrefix(self, flags=Flag_None):
        (tag, value, length1) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_semantic or value != Tag_Minor_cborEncodedData:
            raise Exception("Not CBOR Encoded Data")

        (tag, value, length2) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_byteString:
            raise Exception("Not byteString")

        return (tag, value, length1 + length2)

    def decodeEncodedBytes(self, flags=Flag_None):
        (tag, minor_tag, tag_length) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_semantic or minor_tag != Tag_Minor_cborEncodedData:
            raise Exception("Not CBOR Encoded Data")

        (value, length) = self.decodeBytes(flags)
        return (value, tag_length + length)

    def decodeText(self, flags=Flag_None):
        # First value is the length of the bytes that follow
        (tag, byte_length, size_length) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_textString:
            raise Exception("Not a textString")

        end = len(self.buf)
        if end - self.pos < byte_length:
            raise Exception("Not enough input")

        value = bytes(self.buf[self.pos : self.pos + byte_length])
        self.pos += byte_length
        return (value, size_length + byte_length)

    def decodeArraySize(self, flags=Flag_None):
        (tag, value, length) = self.decodeTagAndValue(flags)

        if tag != Tag_Major_array:
            raise Exception("Expected Tag_Major_array, but found {}".format(tag))
        return (value, length)

    def decodeMapSize(self, flags=Flag_None):
        (tag, value, length) = self.decodeTagAndValue(flags)
        if tag != Tag_Major_mask:
            raise Exception("Expected Tag_Major_map, but found {}".format(tag))
        return (value, length)
