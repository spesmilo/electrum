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
from PyQt6.QtCore import Qt

from electrum.bcur import URScanCollector, is_multipart_ur
from electrum.qrreader import QrCodeResult

from electrum.gui.qt.util import QColorLerp


class QrReaderValidatorResult():
    """
    Result of a QR code validator
    """

    def __init__(self):
        self.accepted: bool = False

        self.simple_result : str | None = None

        # The video overlay only shows the results that have a message
        self.result_colors: Dict[QrCodeResult, QColor] = {}
        self.result_messages: Dict[QrCodeResult, str] = {}


class QrReaderValidator:
    """
    Accepts the first QR code containing text that is detected. The parts of animated QR codes
    (multi-part BC-UR) are collected until all have been scanned, and are labelled with the progress,
    colorized from red to green.
    """

    START_COLOR: QColor = QColor(Qt.GlobalColor.red)
    DONE_COLOR: QColor = QColor(Qt.GlobalColor.green)

    def __init__(self):
        self.ur_collector = URScanCollector()

    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        res = QrReaderValidatorResult()
        texts: Dict[QrCodeResult, str] = {}
        for result in results:
            try:
                texts[result] = result.data.decode('utf-8')
            except UnicodeDecodeError:
                continue  # not text, keep scanning
        if (data := self.ur_collector.add_frame(list(texts.values()))) is not None:
            res.accepted = True
            res.simple_result = data
            return res
        if progress := self.ur_collector.progress:
            received, total = progress
            color = QColorLerp(self.START_COLOR, self.DONE_COLOR, received / total)
            for result, text in texts.items():
                if is_multipart_ur(text):
                    res.result_colors[result] = color
                    res.result_messages[result] = f'{received}/{total}'
        return res
