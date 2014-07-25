# -*- coding: utf-8 -*-

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from qsdn import QSDNNumericValidator
from qsdn import QSDNConverter
from decimal import Decimal

class MyLineEdit(QLineEdit):
    frozen = pyqtSignal()

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setFrame(not b)
        self.frozen.emit()

class AmountEdit(MyLineEdit):

    def __init__(self, base_unit, is_int = False, parent=None):
        QLineEdit.__init__(self, parent)
        self.base_unit = base_unit
        self.is_int = is_int
        self.is_shortcut = False
        self.help_palette = QPalette()

    def decimal_point(self):
        return 8

    def set_shortcut(self):
	self.is_shortcut = True

    def paintEvent(self, event):
        QLineEdit.paintEvent(self, event)
        if self.base_unit:
            panel = QStyleOptionFrameV2()
            self.initStyleOption(panel)
            textRect = self.style().subElementRect(QStyle.SE_LineEditContents, panel, self)
            textRect.adjust(2, 0, -10, 0)
            painter = QPainter(self)
            painter.setPen(self.help_palette.brush(QPalette.Disabled, QPalette.Text).color())
            painter.drawText(textRect, Qt.AlignRight | Qt.AlignVCenter, self.base_unit())



class BTCAmountEdit(AmountEdit):

    def __init__(self, decimal_point, is_int = False, parent=None, add_ws = False):
        AmountEdit.__init__(self, self._base_unit, is_int, parent)
        self.decimal_point = decimal_point
        self.converter = QSDNConverter()
        self.setValidator(QSDNNumericValidator(16 - self.decimal_point(), self.decimal_point(), add_ws))
        self.connect(self.validator(), SIGNAL('bang()'), self.set_shortcut)

    def _base_unit(self):
        p = self.decimal_point()
        assert p in [2, 5, 8]
        if p == 8:
            return 'BTC'
        if p == 5:
            return 'mBTC'
        if p == 2:
            return 'bits'
        raise Exception('Unknown base unit')

    def get_amount(self):
        (x, ok) = self.converter.toDecimal(self.text())
        if ok == False:
            return None
        p = pow(Decimal(10), Decimal(self.decimal_point()))
        return int( p * x )

    def setAmount(self, amount):
        if amount is None:
            self.setText("")
            return

        p = pow(10, self.decimal_point())
        x = amount / Decimal(p)
        self.setText(self.converter.toString(x))

