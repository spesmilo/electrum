# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2020 Axel Gembe <derago@gmail.com>
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

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QIntValidator, QValidator
from PyQt5.QtWidgets import QLineEdit

import warnings

class PortValidator(QIntValidator):
    ''' A generic IP port validator.  Accepts any number in the range [1,65535]
    by default. '''
    stateChanged = pyqtSignal(QValidator.State)
    def __init__(self, parent, minimum=1, accept_zero=False):
        super().__init__(0, 65535, parent)
        if not isinstance(parent, QLineEdit):
            warnings.warn(RuntimeWarning('PortValidator must be passed a QLineEdit parent'))
        self.minimum = minimum
        self.accept_zero = accept_zero
        self.stateChanged.connect(self.setRedBorder)

    def validate(self, inputStr: str, pos: int) -> QValidator.State:
        res = list(super().validate(inputStr, pos))
        if res[0] == QValidator.Acceptable:
            try:
                value = int(inputStr)
                if value < self.minimum and (not self.accept_zero or value != 0):
                    res[0] = QValidator.Intermediate
            except (ValueError, TypeError):
                res[0] = QValidator.Invalid
        self.stateChanged.emit(res[0])
        return tuple(res)

    def setRedBorder(self, state):
        parent = self.parent()
        if isinstance(parent, QLineEdit):
            if state == QValidator.Acceptable:
                parent.setStyleSheet('')
            else:
                parent.setStyleSheet('QLineEdit { border: 1px solid red }')

class UserPortValidator(PortValidator):
    """
    Checks that a given port is either a high port (from 1024 to 65535) or zero.
    Additionally provides a callback for when the validation state changes.
    """
    def __init__(self, parent, accept_zero=False):
        super().__init__(parent, 1024, accept_zero)
