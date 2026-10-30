# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

"""Minimal CBOR (RFC 8949) encoder and decoder, as used by the Jade hardware wallet
and BC-UR (animated QR codes). Its API is a subset of the `cbor2` package.

Supported types: int (-2**64 <= i < 2**64), bytes, str, list, dict, bool, None
and CBORTag (tags are not interpreted). For encoding, also tuple and bytearray.

The decoder is meant for untrusted input. It rejects what we do not need:
indefinite-length items, floats, simple values other than false/true/null,
map keys other than int/str/bytes, duplicate map keys, and trailing data.
Nesting is limited to MAX_DEPTH, and memory use is bounded by the input length.
"""

import io
from dataclasses import dataclass
from typing import Any, BinaryIO


MAX_DEPTH = 64  # nesting levels of arrays, maps and tags
_READ_CHUNK = 65536  # declared lengths are untrusted: read large strings in chunks


class CBORError(ValueError):
    pass


class CBOREncodeError(CBORError):
    pass


class CBORDecodeError(CBORError):
    pass


class CBORDecodeEOF(CBORDecodeError, EOFError):
    pass


@dataclass
class CBORTag:
    tag: int
    value: Any


def dumps(obj: Any) -> bytes:
    out = bytearray()
    _encode(obj, out, 0)
    return bytes(out)


def _encode_head(out: bytearray, major_type: int, arg: int) -> None:
    if arg < 24:
        out.append(major_type << 5 | arg)
        return
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * size):
            out.append(major_type << 5 | info)
            out += arg.to_bytes(size, 'big')
            return
    raise CBOREncodeError('integer out of range')


def _encode(obj: Any, out: bytearray, depth: int) -> None:
    if obj is None:
        out.append(0xf6)
    elif isinstance(obj, bool):
        out.append(0xf5 if obj else 0xf4)
    elif isinstance(obj, int):
        if obj >= 0:
            _encode_head(out, 0, obj)
        else:
            _encode_head(out, 1, -1 - obj)
    elif isinstance(obj, (bytes, bytearray)):
        _encode_head(out, 2, len(obj))
        out += obj
    elif isinstance(obj, str):
        try:
            data = obj.encode('utf-8')
        except UnicodeEncodeError as e:  # lone surrogates
            raise CBOREncodeError('invalid string') from e
        _encode_head(out, 3, len(data))
        out += data
    elif isinstance(obj, (list, tuple, dict, CBORTag)):
        if depth >= MAX_DEPTH:
            raise CBOREncodeError('maximum nesting depth exceeded')
        if isinstance(obj, dict):
            _encode_head(out, 5, len(obj))
            for key, value in obj.items():
                if isinstance(key, bool) or not isinstance(key, (int, str, bytes)):
                    raise CBOREncodeError(f'unsupported map key type: {type(key).__name__}')
                _encode(key, out, depth + 1)
                _encode(value, out, depth + 1)
        elif isinstance(obj, CBORTag):
            if type(obj.tag) is not int or obj.tag < 0:
                raise CBOREncodeError('invalid tag')
            _encode_head(out, 6, obj.tag)
            _encode(obj.value, out, depth + 1)
        else:
            _encode_head(out, 4, len(obj))
            for item in obj:
                _encode(item, out, depth + 1)
    else:
        raise CBOREncodeError(f'cannot encode type: {type(obj).__name__}')


def loads(data: bytes) -> Any:
    """Decodes data, which must contain exactly one CBOR data item."""
    fp = io.BytesIO(data)
    obj = load(fp)
    if fp.read(1):
        raise CBORDecodeError('trailing data')
    return obj


def load(fp: BinaryIO) -> Any:
    """Decodes one CBOR data item from fp, without reading past its end.
    Raises CBORDecodeEOF (an EOFError) if fp.read(n) does not return n bytes.
    """
    return _Decoder(fp).decode(0)


class _Decoder:

    def __init__(self, fp: BinaryIO):
        self._fp = fp

    def read(self, n: int) -> bytes:
        if n > _READ_CHUNK:
            chunks = []
            for offset in range(0, n, _READ_CHUNK):
                chunks.append(self.read(min(_READ_CHUNK, n - offset)))
            return b''.join(chunks)
        data = self._fp.read(n)
        if len(data) != n:
            raise CBORDecodeEOF(f'unexpected end of data: wanted {n} bytes, got {len(data)}')
        return bytes(data)

    def decode(self, depth: int) -> Any:
        initial_byte = self.read(1)[0]
        major_type, info = initial_byte >> 5, initial_byte & 0x1f
        if major_type == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            raise CBORDecodeError(f'unsupported simple value or float: 0x{initial_byte:02x}')
        if info < 24:
            arg = info
        elif info < 28:
            arg = int.from_bytes(self.read(1 << (info - 24)), 'big')
        elif info == 31:
            raise CBORDecodeError('indefinite-length items are not supported')
        else:
            raise CBORDecodeError(f'reserved additional information: {info}')
        if major_type == 0:
            return arg
        if major_type == 1:
            return -1 - arg
        if major_type == 2:
            return self.read(arg)
        if major_type == 3:
            try:
                return self.read(arg).decode('utf-8')
            except UnicodeDecodeError as e:
                raise CBORDecodeError('invalid UTF-8 in text string') from e
        if depth >= MAX_DEPTH:
            raise CBORDecodeError('maximum nesting depth exceeded')
        # note: no preallocation for the declared number of items, each one needs at least one byte
        if major_type == 4:
            return [self.decode(depth + 1) for _ in range(arg)]
        if major_type == 5:
            result = {}
            for _ in range(arg):
                key = self.decode(depth + 1)
                if type(key) not in (int, str, bytes):
                    raise CBORDecodeError(f'unsupported map key type: {type(key).__name__}')
                if key in result:
                    raise CBORDecodeError('duplicate map key')
                result[key] = self.decode(depth + 1)
            return result
        return CBORTag(arg, self.decode(depth + 1))
