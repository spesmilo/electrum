# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://opensource.org/licenses/mit-license.php

import ctypes
import os
import sys
from typing import List, Optional, Tuple

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

# Pin ZXING to a major version to prevent the API from silently changing
# e.g. when loading a system provided library or bumping the hash pin
ZXING_MAJOR_VERSION = 3


def _check_version(lib: ctypes.CDLL) -> str:
    """Returns the version of an API-compatible zxing-cpp, raises ValueError otherwise."""
    lib.ZXing_Version.restype = ctypes.c_char_p  # static string, not owned by the caller
    lib.ZXing_Version.argtypes = []
    version = (lib.ZXing_Version() or b'').decode('ascii', errors='replace')
    if version.split('.')[0] != str(ZXING_MAJOR_VERSION):
        raise ValueError(f'unsupported zxing-cpp version {version!r}, need {ZXING_MAJOR_VERSION}.x')
    return version


try:
    try:
        LIBZXING = ctypes.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), '..', LIBNAME))
    except OSError:
        # Fall back to a system-wide install, e.g. when running from source.
        LIBZXING = ctypes.cdll.LoadLibrary(LIBNAME)
    LIBZXING_VERSION = _check_version(LIBZXING)

    # ZXingC.h from the pinned zxing-cpp build. Owning pointers must remain
    # pointers (not c_char_p, which copies strings and loses the allocation).
    signatures = {
        'ZXing_ImageView_new_checked': (ctypes.c_void_p, [ctypes.c_void_p] + [ctypes.c_int] * 6),
        'ZXing_ImageView_crop': (None, [ctypes.c_void_p] + [ctypes.c_int] * 4),
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
except (OSError, AttributeError, ValueError):
    _logger.exception('Failed to load zxing-cpp C API')
    LIBZXING = LIBZXING_VERSION = None


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
        if qr_format.value == 0xffff:  # ZXing_BarcodeFormat_Invalid
            raise MissingLib('zxing-cpp does not support the QRCode barcode format')
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

    def read_qr_code(
        self,
        buffer: ctypes.c_void_p,
        buffer_size: int,
        rowlen_bytes: int,
        width: int,
        height: int,
        frame_id: int = -1,
        *,
        crop: Optional[Tuple[int, int, int, int]] = None,
    ) -> List[QrCodeResult]:
        # Reject invalid geometry before Python integers are narrowed to C ints.
        if not buffer or any(n <= 0 or n > 0x7fffffff for n in (buffer_size, rowlen_bytes, width, height)):
            raise ValueError('Invalid QR image buffer or dimensions')
        if rowlen_bytes < width or height * rowlen_bytes > buffer_size:
            raise ValueError('QR image buffer is too small for its dimensions and stride')
        if crop is not None:
            left, top, crop_width, crop_height = crop
            if not (0 <= left < width and 0 <= top < height
                    and 0 < crop_width <= width - left and 0 < crop_height <= height - top):
                raise ValueError('QR crop rectangle is not inside the image')

        image = self._lib.ZXing_ImageView_new_checked(
            buffer,
            buffer_size,
            width,
            height,
            0x01000000,  # ZXing_ImageFormat_Lum
            rowlen_bytes,
            1,
        )

        if not image:
            raise self._error()
        barcodes = None
        try:
            if crop is not None:
                self._lib.ZXing_ImageView_crop(image, left, top, crop_width, crop_height)
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
                    payload = ctypes.string_at(data, length.value)  # raw bytes, no charset conversion
                finally:
                    self._lib.ZXing_free(data)
                position = self._lib.ZXing_Barcode_position(barcode)
                points = [(getattr(position, corner).x, getattr(position, corner).y)
                          for corner, _type in _Position._fields_]
                center = (sum(x for x, _ in points) // 4, sum(y for _, y in points) // 4)
                results.append(QrCodeResult(payload, center, points))
            return results
        finally:
            self._lib.ZXing_Barcodes_delete(barcodes)
            self._lib.ZXing_ImageView_delete(image)
