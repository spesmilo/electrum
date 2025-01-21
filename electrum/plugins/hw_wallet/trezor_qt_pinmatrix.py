# from https://github.com/trezor/trezor-firmware/blob/3f1d2059ca140788dab8726778f05cedbea20bc4/python/src/trezorlib/qt/pinmatrix.py
#
# This file is part of the Trezor project.
#
# Copyright (C) 2012-2022 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import math
from typing import Any

from PyQt6.QtCore import QRegularExpression, Qt
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)



class PinButton(QPushButton):
    def __init__(self, password: QLineEdit, encoded_value: int) -> None:
        super(PinButton, self).__init__("?")
        self.password = password
        self.encoded_value = encoded_value

        self.clicked.connect(self._pressed)

    def _pressed(self) -> None:
        self.password.setText(self.password.text() + str(self.encoded_value))
        self.password.setFocus()


class PinMatrixWidget(QWidget):
    """
    Displays widget with nine blank buttons and password box.
    Encodes button clicks into sequence of numbers for passing
    into PinAck messages of Trezor.

    show_strength=True may be useful for entering new PIN
    """

    def __init__(self, show_strength: bool = True, parent: Any = None) -> None:
        super(PinMatrixWidget, self).__init__(parent)

        self.password = QLineEdit()
        self.password.setValidator(QRegularExpressionValidator(QRegularExpression("[1-9]+"), None))
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        self.password.textChanged.connect(self._password_changed)

        self.strength = QLabel()
        self.strength.setMinimumWidth(75)
        self.strength.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._set_strength(0)

        grid = QGridLayout()
        grid.setSpacing(0)
        for y in range(3)[::-1]:
            for x in range(3):
                button = PinButton(self.password, x + y * 3 + 1)
                button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
                button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
                grid.addWidget(button, 3 - y, x)

        hbox = QHBoxLayout()
        hbox.addWidget(self.password)
        if show_strength:
            hbox.addWidget(self.strength)

        vbox = QVBoxLayout()
        vbox.addLayout(grid)
        vbox.addLayout(hbox)
        self.setLayout(vbox)

    def _set_strength(self, strength: float) -> None:
        if strength < 3000:
            self.strength.setText("weak")
            self.strength.setStyleSheet("QLabel { color : #d00; }")
        elif strength < 60000:
            self.strength.setText("fine")
            self.strength.setStyleSheet("QLabel { color : #db0; }")
        elif strength < 360000:
            self.strength.setText("strong")
            self.strength.setStyleSheet("QLabel { color : #0a0; }")
        else:
            self.strength.setText("ULTIMATE")
            self.strength.setStyleSheet("QLabel { color : #000; font-weight: bold;}")

    def _password_changed(self, password: Any) -> None:
        self._set_strength(self.get_strength())

    def get_strength(self) -> float:
        digits = len(set(str(self.password.text())))
        strength = math.factorial(9) / math.factorial(9 - digits)
        return strength

    def get_value(self) -> str:
        return self.password.text()
