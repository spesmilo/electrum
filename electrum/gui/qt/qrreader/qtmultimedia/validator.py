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

from typing import List, Dict, Callable, Any
from abc import ABC, abstractmethod

from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt

from electrum.i18n import _
from electrum.qrreader import QrCodeResult

from electrum.gui.qt.util import ColorScheme, QColorLerp


class QrReaderValidatorResult():
    """
    Result of a QR code validator
    """

    def __init__(self):
        self.accepted: bool = False

        self.message: str = None
        self.message_color: QColor = None

        self.simple_result : str = None

        self.result_usable: Dict[QrCodeResult, bool] = {}
        self.result_colors: Dict[QrCodeResult, QColor] = {}
        self.result_messages: Dict[QrCodeResult, str] = {}

        self.selected_results: List[QrCodeResult] = []


class AbstractQrReaderValidator(ABC):
    """
    Abstract base class for QR code result validators.
    """

    @abstractmethod
    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        """
        Checks a list of QR code results for usable codes.
        """

class QrReaderValidatorCounting(AbstractQrReaderValidator):
    """
    This QR code result validator doesn't directly accept any results but maintains a dictionary
    of detection counts in `result_counts`.
    """

    result_counts: Dict[QrCodeResult, int] = {}

    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        res = QrReaderValidatorResult()

        for result in results:
            # Increment the detection count
            if result not in self.result_counts:
                self.result_counts[result] = 0
            self.result_counts[result] += 1

        # Search for missing results, iterate over a copy because the loop might modify the dict
        for result in self.result_counts.copy():
            # Count down missing results
            if result in results:
                continue
            self.result_counts[result] -= 2
            # When the count goes to zero, remove
            if self.result_counts[result] < 1:
                del self.result_counts[result]

        return res

class QrReaderValidatorColorizing(QrReaderValidatorCounting):
    """
    This QR code result validator doesn't directly accept any results but colorizes the results
    based on the counts maintained by `QrReaderValidatorCounting`.
    """

    WEAK_COLOR: QColor = QColor(Qt.GlobalColor.red)
    STRONG_COLOR: QColor = QColor(Qt.GlobalColor.green)

    strong_count: int = 10

    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        res = super().validate_results(results)

        # Colorize the QR code results by their detection counts
        for result in results:
            # Enforce strong_count as upper limit
            self.result_counts[result] = min(self.result_counts[result], self.strong_count)

            # Interpolate between WEAK_COLOR and STRONG_COLOR based on count / strong_count
            lerp_factor = (self.result_counts[result] - 1) / self.strong_count
            lerped_color = QColorLerp(self.WEAK_COLOR, self.STRONG_COLOR, lerp_factor)
            res.result_colors[result] = lerped_color

        return res

class QrReaderValidatorStrong(QrReaderValidatorColorizing):
    """
    This QR code result validator doesn't directly accept any results but passes every strong
    detection in the return values `selected_results`.
    """

    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        res = super().validate_results(results)

        for result in results:
            if self.result_counts[result] >= self.strong_count:
                res.selected_results.append(result)
                break

        return res

class QrReaderValidatorCounted(QrReaderValidatorStrong):
    """
    This QR code result validator accepts a result as soon as there is at least `minimum` and at
    most `maximum` QR code(s) with strong detection.
    """

    def __init__(self, minimum: int = 1, maximum: int = 1):
        super().__init__()
        self.minimum = minimum
        self.maximum = maximum

    def validate_results(self, results: List[QrCodeResult]) -> QrReaderValidatorResult:
        res = super().validate_results(results)

        num_results = len(res.selected_results)
        if num_results < self.minimum:
            if num_results > 0:
                res.message = _('Too few QR codes detected.')
                res.message_color = ColorScheme.RED.as_color()
        elif num_results > self.maximum:
            res.message = _('Too many QR codes detected.')
            res.message_color = ColorScheme.RED.as_color()
        else:
            res.accepted = True
            res.simple_result = (results and results[0].data) or ''  # hack added by calin just to take the first one

        return res
