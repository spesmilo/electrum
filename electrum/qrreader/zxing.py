# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://opensource.org/licenses/mit-license.php

import ctypes
import os
import sys
from typing import List

from . import MissingLib
from .abstract_base import AbstractQrCodeReader, QrCodeResult
from ..logging import get_logger


_logger = get_logger(__name__)


class _Point(ctypes.Structure):
    _fields_ = [('x', ctypes.c_int), ('y', ctypes.c_int)]


class _Position(ctypes.Structure):
    _fields_ = [(corner, _Point) for corner in ('topLeft', 'topRight', 'bottomRight', 'bottomLeft')]


if sys.platform == 'darwin':
    LIBNAME = 'libZXing.dylib'
elif sys.platform == 'win32':
    LIBNAME = 'ZXing.dll'
else:
    LIBNAME = 'libZXing.so'


try:
    try:
        LIBZXING = ctypes.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), '..', LIBNAME))
    except OSError:
        LIBZXING = ctypes.cdll.LoadLibrary(LIBNAME)

    # ZXingC.h from the pinned zxing-cpp build. Owning pointers must remain
    # pointers (not c_char_p, which copies strings and loses the allocation).
    signatures = {
        'ZXing_ImageView_new_checked': (ctypes.c_void_p, [ctypes.c_void_p] + [ctypes.c_int] * 6),
        'ZXing_ImageView_delete': (None, [ctypes.c_void_p]),
        'ZXing_ReaderOptions_new': (ctypes.c_void_p, []),
        'ZXing_ReaderOptions_delete': (None, [ctypes.c_void_p]),
        'ZXing_ReaderOptions_setFormats': (None, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int]),
        'ZXing_BarcodeFormatFromString': (ctypes.c_int, [ctypes.c_char_p]),
        'ZXing_ReadBarcodes': (ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p]),
        'ZXing_Barcodes_size': (ctypes.c_int, [ctypes.c_void_p]),
        'ZXing_Barcodes_at': (ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_int]),
        'ZXing_Barcodes_delete': (None, [ctypes.c_void_p]),
        'ZXing_Barcode_bytes': (ctypes.c_void_p, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]),
        'ZXing_Barcode_position': (_Position, [ctypes.c_void_p]),
        'ZXing_LastErrorMsg': (ctypes.c_void_p, []),
        'ZXing_free': (None, [ctypes.c_void_p]),
    }
    for name, (restype, argtypes) in signatures.items():
        function = getattr(LIBZXING, name)
        function.restype = restype
        function.argtypes = argtypes
except (OSError, AttributeError):
    _logger.exception('Failed to load zxing-cpp C API')
    LIBZXING = None


class ZXingQrCodeReader(AbstractQrCodeReader):
    """Decode grayscale image buffers using zxing-cpp's C API."""

    def __init__(self):
        self._options = None
        if LIBZXING is None:
            raise MissingLib('zxing-cpp library with C API not found')
        self._lib = LIBZXING
        self._options = self._lib.ZXing_ReaderOptions_new()
        if not self._options:
            raise self._error()
        qr_format = ctypes.c_int(self._lib.ZXing_BarcodeFormatFromString(b'QRCode'))
        self._lib.ZXing_ReaderOptions_setFormats(self._options, ctypes.byref(qr_format), 1)

    def __del__(self):
        if self._options:
            self._lib.ZXing_ReaderOptions_delete(self._options)

    def _error(self) -> RuntimeError:
        message = self._lib.ZXing_LastErrorMsg()
        try:
            text = ctypes.string_at(message).decode('utf-8', errors='replace') if message else 'Unknown error'
            return RuntimeError(f'zxing-cpp: {text}')
        finally:
            self._lib.ZXing_free(message)

    def read_qr_code(self, buffer: ctypes.c_void_p, buffer_size: int,
                     rowlen_bytes: int, width: int, height: int, frame_id: int = -1) -> List[QrCodeResult]:
        # Reject invalid geometry before Python integers are narrowed to C ints.
        if not buffer or any(n <= 0 or n > 0x7fffffff for n in (buffer_size, rowlen_bytes, width, height)):
            raise ValueError('Invalid QR image buffer or dimensions')
        if rowlen_bytes < width or height * rowlen_bytes > buffer_size:
            raise ValueError('QR image buffer is too small for its dimensions and stride')

        image = self._lib.ZXing_ImageView_new_checked(
            buffer, buffer_size, width, height, 0x01000000, rowlen_bytes, 1,  # ZXing_ImageFormat_Lum
        )
        if not image:
            raise self._error()
        barcodes = None
        try:
            barcodes = self._lib.ZXing_ReadBarcodes(image, self._options)
            if not barcodes:
                raise self._error()
            results = []
            for i in range(self._lib.ZXing_Barcodes_size(barcodes)):
                barcode = self._lib.ZXing_Barcodes_at(barcodes, i)  # borrowed from barcodes
                length = ctypes.c_int()
                data = self._lib.ZXing_Barcode_bytes(barcode, ctypes.byref(length))
                try:
                    if not data:
                        raise MemoryError('zxing-cpp could not allocate the QR payload')
                    # Preserve the existing reader's UTF-8 payload semantics,
                    # including embedded NULs; do not use ZXing's display text.
                    text = ctypes.string_at(data, length.value).decode('utf-8')
                finally:
                    self._lib.ZXing_free(data)
                position = self._lib.ZXing_Barcode_position(barcode)
                points = [(getattr(position, corner).x, getattr(position, corner).y)
                          for corner, _type in _Position._fields_]
                center = (sum(x for x, y in points) // 4, sum(y for x, y in points) // 4)
                results.append(QrCodeResult(text, center, points))
            return results
        finally:
            self._lib.ZXing_Barcodes_delete(barcodes)
            self._lib.ZXing_ImageView_delete(image)
