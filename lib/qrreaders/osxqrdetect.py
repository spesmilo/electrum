#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2019 Calin Culianu <calin.culianu@gmail.com>
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
import os
import ctypes
from typing import List

if sys.platform != 'darwin':
    raise RuntimeError('osxqrdetect may only be used on macOS!')


from . import MissingLib
from ..util import print_error, is_verbose, _, PrintError

from .abstract_base import AbstractQrCodeReader, QrCodeResult

class DetectionResult(ctypes.Structure):
    '''
     struct DetectionResult {
        double topLeftX, topLeftY; ///< note these are in pixels, despite being a double
        double width, height; ///< pixels
        char str[4096]; ///< detection result is UTF8 encoded, always NUL terminated
    };
    '''
    _fields_ = [
        ('topLeftX', ctypes.c_double),
        ('topLeftY', ctypes.c_double),
        ('width', ctypes.c_double),
        ('height', ctypes.c_double),
        ('str', ctypes.c_char * 4096)
    ]

class OSXQRDetect(AbstractQrCodeReader, PrintError):
    LIBNAME = 'libosxqrdetect.dylib'
    LIB = None

    @classmethod
    def _init_func_args(cls):
        assert cls.LIB
        cls.LIB.context_create.restype = ctypes.c_void_p
        cls.LIB.context_create.argtypes = [ctypes.c_int]
        cls.LIB.context_destroy.restype = ctypes.c_int  # it's actually void, but is ignored
        cls.LIB.context_destroy.argtypes = [ctypes.c_void_p]
        '''
        // img must be 8-bit grayscale. returns 1 on success, 0 on no detection. If 1, detectionResult is valid.
        extern int detect_qr(void *context, ///< pointer obtained by calling context_create()
                             const void *img, ///< pointer to img buffer
                             int width, int height, ///< x,y size in pixels
                             int rowsize_bytes, ///< row length in bytes (should be >= width)
                             struct DetectionResult *detectionResult);
        '''
        cls.LIB.detect_qr.restype = ctypes.c_int
        cls.LIB.detect_qr.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_void_p,  # img buffer
            ctypes.c_int, ctypes.c_int,  # Width, Height pix
            ctypes.c_int,  # rowsize bytes
            ctypes.POINTER(DetectionResult)
        ]
        print_error('[OSXQRDetect] Lib initialized:', cls.LIB)

    def __init__(self):
        cls = type(self)
        self.ctx = None
        try:
            if not cls.LIB:
                import electroncash
                root_ec_dir = os.path.abspath(os.path.join(electroncash.__path__[0], '..'))
                lib_dir = os.path.join(root_ec_dir, "contrib", "osx", "OSXQRDetect", "build", "Release")
                cls.LIB = ctypes.cdll.LoadLibrary(os.path.join(lib_dir, self.LIBNAME))
                cls._init_func_args()
        except OSError as e:
            raise MissingLib from e
        self.ctx = cls.LIB.context_create(int(is_verbose))
        assert self.ctx
        self.print_error("Context created", self.ctx)

    def __del__(self):
        if self.ctx:
            cls = type(self)
            if not cls.LIB:
                self.print_error("WARNING: No LIB but have ctx!  FIXME")
                return
            cls.LIB.context_destroy(self.ctx)
            self.print_error("context destroyed", self.ctx)
            self.ctx = None

    def read_qr_code(self, buffer: ctypes.c_void_p, buffer_size: int,
                     rowlen_bytes : int,
                     width: int, height: int, frame_id: int = -1) -> List[QrCodeResult]:
        """
        Reads a QR code from an image buffer in Y800 / GREY format.
        Returns a list of detected QR codes which includes their data and positions.
        """
        cls = type(self)
        assert self.ctx and cls.LIB
        res = DetectionResult()
        retval = cls.LIB.detect_qr(self.ctx, buffer, width, height, rowlen_bytes, res)
        retList = []
        if retval:
            self.print_error("Got", res.width, res.height, res.str)
            qrstring = res.str.decode('utf-8')
            res.topLeftY = height - res.topLeftY - res.height  # flip vertically as y=0 in this coordinate space and in OSX coordinate space are flipped
            center = (int(res.topLeftX+res.width/2), int(res.topLeftY+res.height/2))
            pts = [
                (int(res.topLeftX), int(res.topLeftY)),
                (int(res.topLeftX + res.width), int(res.topLeftY)),
                (int(res.topLeftX + res.width), int(res.topLeftY + res.height)),
                (int(res.topLeftX), int(res.topLeftY + res.height)),
            ]
            retList += [
                QrCodeResult(qrstring, center, pts)
            ]
        return retList
