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

import ctypes
from typing import List, Tuple
from abc import ABC, abstractmethod

QrCodePoint = Tuple[int, int]
QrCodePointList = List[QrCodePoint]

class QrCodeResult():
    """
    A detected QR code.
    """
    def __init__(self, data: str, center: QrCodePoint, points: QrCodePointList):
        self.data: str = data
        self.center: QrCodePoint = center
        self.points: QrCodePointList = points

    def __str__(self) -> str:
        return 'data: {} center: {} points: {}'.format(self.data, self.center, self.points)

    def __hash__(self):
        return hash(self.data)

    def __eq__(self, other):
        return self.data == other.data

    def __ne__(self, other):
        return not self == other

class AbstractQrCodeReader(ABC):
    """
    Abstract base class for QR code readers.
    """
    @abstractmethod
    def read_qr_code(self, buffer: ctypes.c_void_p, buffer_size: int,
                     width: int, height: int, frame_id: int = -1) -> List[QrCodeResult]:
        """
        Reads a QR code from an image buffer in Y800 / GREY format.
        Returns a list of detected QR codes which includes their data and positions.
        """
