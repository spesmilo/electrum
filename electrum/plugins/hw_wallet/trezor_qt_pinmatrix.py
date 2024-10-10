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
import sys
from typing import Any

try:
    from PyQt5.QtCore import QT_VERSION_STR, QRegExp, Qt
    from PyQt5.QtGui import QRegExpValidator
    from PyQt5.QtWidgets import (
        QApplication,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QSizePolicy,
        QVBoxLayout,
        QWidget,
    )
except Exception:
    from PyQt4.QtCore import QT_VERSION_STR, SIGNAL, QObject, QRegExp, Qt  # noqa: I
    from PyQt4.QtGui import (  # noqa: I
        QApplication,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QRegExpValidator,
        QSizePolicy,
        QVBoxLayout,
        QWidget,
    )


class PinButton(QPushButton):
    def __init__(self, password: QLineEdit, encoded_value: int) -> None:
        super(PinButton, self).__init__("?")
        self.password = password
        self.encoded_value = encoded_value

        if QT_VERSION_STR >= "5":
            self.clicked.connect(self._pressed)
        elif QT_VERSION_STR >= "4":
            QObject.connect(self, SIGNAL("clicked()"), self._pressed)
        else:
            raise RuntimeError("Unsupported Qt version")

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
        self.password.setValidator(QRegExpValidator(QRegExp("[1-9]+"), None))
        self.password.setEchoMode(QLineEdit.Password)

        if QT_VERSION_STR >= "5":
            self.password.textChanged.connect(self._password_changed)
        elif QT_VERSION_STR >= "4":
            QObject.connect(
                self.password, SIGNAL("textChanged(QString)"), self._password_changed
            )
        else:
            raise RuntimeError("Unsupported Qt version")

        self.strength = QLabel()
        self.strength.setMinimumWidth(75)
        self.strength.setAlignment(Qt.AlignCenter)
        self._set_strength(0)

        grid = QGridLayout()
        grid.setSpacing(0)
        for y in range(3)[::-1]:
            for x in range(3):
                button = PinButton(self.password, x + y * 3 + 1)
                button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                button.setFocusPolicy(Qt.NoFocus)
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


if __name__ == "__main__":
    """
    Demo application showing PinMatrix widget in action
    """
    app = QApplication(sys.argv)

    matrix = PinMatrixWidget()

    def clicked() -> None:
        print("PinMatrix value is", matrix.get_value())
        print("Possible button combinations:", matrix.get_strength())
        sys.exit()

    ok = QPushButton("OK")
    if QT_VERSION_STR >= "5":
        ok.clicked.connect(clicked)
    elif QT_VERSION_STR >= "4":
        QObject.connect(ok, SIGNAL("clicked()"), clicked)
    else:
        raise RuntimeError("Unsupported Qt version")

    vbox = QVBoxLayout()
    vbox.addWidget(matrix)
    vbox.addWidget(ok)

    w = QWidget()
    w.setLayout(vbox)
    w.move(100, 100)
    w.show()

    app.exec_()
