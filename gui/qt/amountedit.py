# -*- coding: utf-8 -*-

from decimal import Decimal

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import (QLineEdit, QStyle, QStyleOptionFrame)

from electrum_ltc.util import (format_satoshis_plain, decimal_point_to_base_unit_name,
                               FEERATE_PRECISION, quantize_feerate)


class MyLineEdit(QLineEdit):
    frozen = pyqtSignal()

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setFrame(not b)
        self.frozen.emit()

class AmountEdit(MyLineEdit):
    shortcut = pyqtSignal()

    def __init__(self, base_unit, is_int=False, parent=None):
        QLineEdit.__init__(self, parent)
        # This seems sufficient for hundred-BTC amounts with 8 decimals
        self.setFixedWidth(140)
        self.base_unit = base_unit
        self.textChanged.connect(self.numbify)
        self.is_int = is_int
        self.is_shortcut = False
        self.help_palette = QPalette()
        self.extra_precision = 0

    def decimal_point(self):
        return 8

    def max_precision(self):
        return self.decimal_point() + self.extra_precision

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.shortcut.emit()
            return
        pos = self.cursorPosition()
        chars = '0123456789'
        if not self.is_int: chars +='.'
        s = ''.join([i for i in text if i in chars])
        if not self.is_int:
            if '.' in s:
                p = s.find('.')
                s = s.replace('.','')
                s = s[:p] + '.' + s[p:p+self.max_precision()]
        self.setText(s)
        # setText sets Modified to False.  Instead we want to remember
        # if updates were because of user modification.
        self.setModified(self.hasFocus())
        self.setCursorPosition(pos)

    def paintEvent(self, event):
        QLineEdit.paintEvent(self, event)
        if self.base_unit:
            panel = QStyleOptionFrame()
            self.initStyleOption(panel)
            textRect = self.style().subElementRect(QStyle.SE_LineEditContents, panel, self)
            textRect.adjust(2, 0, -10, 0)
            painter = QPainter(self)
            painter.setPen(self.help_palette.brush(QPalette.Disabled, QPalette.Text).color())
            painter.drawText(textRect, Qt.AlignRight | Qt.AlignVCenter, self.base_unit())

    def get_amount(self):
        try:
            return (int if self.is_int else Decimal)(str(self.text()))
        except:
            return None

    def setAmount(self, x):
        self.setText("%d"%x)


class BTCAmountEdit(AmountEdit):

    def __init__(self, decimal_point, is_int=False, parent=None):
        AmountEdit.__init__(self, self._base_unit, is_int, parent)
        self.decimal_point = decimal_point

    def _base_unit(self):
        return decimal_point_to_base_unit_name(self.decimal_point())

    def get_amount(self):
        try:
            x = Decimal(str(self.text()))
        except:
            return None
        # scale it to max allowed precision, make it an int
        power = pow(10, self.max_precision())
        max_prec_amount = int(power * x)
        # if the max precision is simply what unit conversion allows, just return
        if self.max_precision() == self.decimal_point():
            return max_prec_amount
        # otherwise, scale it back to the expected unit
        amount = Decimal(max_prec_amount) / pow(10, self.max_precision()-self.decimal_point())
        return Decimal(amount) if not self.is_int else int(amount)

    def setAmount(self, amount):
        if amount is None:
            self.setText(" ") # Space forces repaint in case units changed
        else:
            self.setText(format_satoshis_plain(amount, self.decimal_point()))


class FeerateEdit(BTCAmountEdit):

    def __init__(self, decimal_point, is_int=False, parent=None):
        super().__init__(decimal_point, is_int, parent)
        self.extra_precision = FEERATE_PRECISION

    def _base_unit(self):
        return 'sat/byte'

    def get_amount(self):
        sat_per_byte_amount = BTCAmountEdit.get_amount(self)
        return quantize_feerate(sat_per_byte_amount)

    def setAmount(self, amount):
        amount = quantize_feerate(amount)
        super().setAmount(amount)
