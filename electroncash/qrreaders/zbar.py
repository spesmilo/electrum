#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import ctypes
import os
from typing import List
from enum import IntEnum

from . import MissingLib
from ..util import print_error, is_verbose, _

from .abstract_base import AbstractQrCodeReader, QrCodeResult

if sys.platform == 'darwin':
    LIBNAME = 'libzbar.0.dylib'
elif sys.platform in ('windows', 'win32'):
    LIBNAME = 'libzbar-0.dll'
else:
    LIBNAME = 'libzbar.so.0'

try:
    try:
        LIBZBAR = ctypes.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), '..', LIBNAME))
    except OSError as e:
        LIBZBAR = ctypes.cdll.LoadLibrary(LIBNAME)

    LIBZBAR.zbar_image_create.restype = ctypes.c_void_p
    LIBZBAR.zbar_image_scanner_create.restype = ctypes.c_void_p
    LIBZBAR.zbar_image_scanner_get_results.restype = ctypes.c_void_p
    LIBZBAR.zbar_symbol_set_first_symbol.restype = ctypes.c_void_p
    LIBZBAR.zbar_symbol_get_data.restype = ctypes.POINTER(ctypes.c_char_p)
    LIBZBAR.zbar_image_scanner_set_config.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    LIBZBAR.zbar_image_set_sequence.argtypes = [ctypes.c_void_p, ctypes.c_int]
    LIBZBAR.zbar_image_set_size.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    LIBZBAR.zbar_image_set_format.argtypes = [ctypes.c_void_p, ctypes.c_int]
    LIBZBAR.zbar_image_set_data.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    LIBZBAR.zbar_image_scanner_recycle_image.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    LIBZBAR.zbar_scan_image.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    LIBZBAR.zbar_image_scanner_get_results.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_symbol_set_first_symbol.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_symbol_get_data_length.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_symbol_get_data.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_symbol_get_loc_size.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_symbol_get_loc_x.argtypes = [ctypes.c_void_p, ctypes.c_int]
    LIBZBAR.zbar_symbol_get_loc_y.argtypes = [ctypes.c_void_p, ctypes.c_int]
    LIBZBAR.zbar_symbol_next.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_image_scanner_destroy.argtypes = [ctypes.c_void_p]
    LIBZBAR.zbar_image_destroy.argtypes = [ctypes.c_void_p]

    #if is_verbose:
        #LIBZBAR.zbar_set_verbosity(100)
except OSError:
    print_error(_("Failed to load zbar: {}").format(repr(sys.exc_info()[1])))
    LIBZBAR = None

FOURCC_Y800 = 0x30303859

@ctypes.CFUNCTYPE(None, ctypes.c_void_p)
def zbar_cleanup(image):
    """
    Do nothing, this is just so zbar doesn't try to manage our QImage buffers
    """

class ZbarSymbolType(IntEnum):
    """
    Supported symbol types, see zbar_symbol_type_e in zbar.h
    """
    EAN2 = 2
    EAN5 = 5
    EAN8 = 8
    UPCE = 9
    ISBN10 = 10
    UPCA = 12
    EAN13 = 13
    ISBN13 = 14
    COMPOSITE = 15
    I25 = 25
    DATABAR = 34
    DATABAR_EXP = 35
    CODABAR = 38
    CODE39 = 39
    PDF417 = 57
    QRCODE = 64
    SQCODE = 80
    CODE93 = 93
    CODE128 = 128

class ZbarConfig(IntEnum):
    """
    Supported configuration options, see zbar_config_e in zbar.h
    """
    ENABLE = 0

class ZbarQrCodeReader(AbstractQrCodeReader):
    """
    Reader that uses libzbar
    """

    def __init__(self):
        if not LIBZBAR:
            raise MissingLib('Zbar library not found')
        # Set up zbar
        self.zbar_scanner = LIBZBAR.zbar_image_scanner_create()
        self.zbar_image = LIBZBAR.zbar_image_create()

        # Disable all symbols
        for sym_type in ZbarSymbolType:
            LIBZBAR.zbar_image_scanner_set_config(self.zbar_scanner, sym_type, ZbarConfig.ENABLE, 0)

        # Enable only QR codes
        LIBZBAR.zbar_image_scanner_set_config(self.zbar_scanner, ZbarSymbolType.QRCODE,
                                              ZbarConfig.ENABLE, 1)

    def __del__(self):
        if LIBZBAR:
            LIBZBAR.zbar_image_scanner_destroy(self.zbar_scanner)
            LIBZBAR.zbar_image_destroy(self.zbar_image)

    def read_qr_code(self, buffer: ctypes.c_void_p, buffer_size: int,
                     rowlen_bytes: int,  # this param is ignored in this implementation
                     width: int, height: int, frame_id: int = -1) -> List[QrCodeResult]:
        LIBZBAR.zbar_image_set_sequence(self.zbar_image, frame_id)
        LIBZBAR.zbar_image_set_size(self.zbar_image, width, height)
        LIBZBAR.zbar_image_set_format(self.zbar_image, FOURCC_Y800)
        LIBZBAR.zbar_image_set_data(self.zbar_image, buffer, buffer_size, zbar_cleanup)
        LIBZBAR.zbar_image_scanner_recycle_image(self.zbar_scanner, self.zbar_image)
        LIBZBAR.zbar_scan_image(self.zbar_scanner, self.zbar_image)

        result_set = LIBZBAR.zbar_image_scanner_get_results(self.zbar_scanner)

        res = []
        symbol = LIBZBAR.zbar_symbol_set_first_symbol(result_set)
        while symbol:
            symbol_data_len = LIBZBAR.zbar_symbol_get_data_length(symbol)
            symbol_data_ptr = LIBZBAR.zbar_symbol_get_data(symbol)
            symbol_data_bytes = ctypes.string_at(symbol_data_ptr, symbol_data_len)
            symbol_data = symbol_data_bytes.decode('utf-8')

            symbol_loc = []
            symbol_loc_len = LIBZBAR.zbar_symbol_get_loc_size(symbol)
            for i in range(0, symbol_loc_len):
                # Normalize the coordinates into 0..1 range by dividing by width / height
                symbol_loc_x = LIBZBAR.zbar_symbol_get_loc_x(symbol, i)
                symbol_loc_y = LIBZBAR.zbar_symbol_get_loc_y(symbol, i)
                symbol_loc.append((symbol_loc_x, symbol_loc_y))

            # Find the center by getting the average values of the corners x and y coordinates
            symbol_loc_sum_x = sum([l[0] for l in symbol_loc])
            symbol_loc_sum_y = sum([l[1] for l in symbol_loc])
            symbol_loc_center = (int(symbol_loc_sum_x / symbol_loc_len), int(symbol_loc_sum_y / symbol_loc_len))

            res.append(QrCodeResult(symbol_data, symbol_loc_center, symbol_loc))

            symbol = LIBZBAR.zbar_symbol_next(symbol)

        return res
