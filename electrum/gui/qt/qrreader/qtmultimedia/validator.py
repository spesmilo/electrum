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

from typing import List, Dict

from PyQt6.QtGui import QColor

from electrum.qrreader import QrCodeResult


class QrReaderValidatorResult():
    """
    Result of a QR code validator
    """

    def __init__(self):
        self.accepted: bool = False

        self.simple_result : str | None = None

        self.result_colors: Dict[QrCodeResult, QColor] = {}
        self.result_messages: Dict[QrCodeResult, str] = {}


class QrReaderValidator:
    """
    Accepts the first QR code containing text that is detected.
    """

    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        res = QrReaderValidatorResult()
        for result in results:
            try:
                res.simple_result = result.data.decode('utf-8')
            except UnicodeDecodeError:
                continue  # not text, keep scanning
            res.accepted = True
            break
        return res
