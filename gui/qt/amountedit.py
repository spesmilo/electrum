# -*- coding: utf-8 -*-

from PyQt4.QtCore import *
from PyQt4.QtGui import *

from decimal import Decimal

class MyLineEdit(QLineEdit):

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setFrame(not b)

class AmountEdit(MyLineEdit):

    def __init__(self, base_unit, is_int = False, parent=None):
        QLineEdit.__init__(self, parent)
        self.base_unit = base_unit
        self.textChanged.connect(self.numbify)
        self.is_int = is_int
        self.is_shortcut = False
        self.help_palette = QPalette()

    def numbify(self):
        text = unicode(self.text()).strip()
        if text == '!':
            self.is_shortcut = True
        pos = self.cursorPosition()
        chars = '0123456789'
        if not self.is_int: chars +='.'
        s = ''.join([i for i in text if i in chars])
        if not self.is_int:
            if '.' in s:
                p = s.find('.')
                s = s.replace('.','')
                s = s[:p] + '.' + s[p:p+8]
        self.setText(s)
        self.setCursorPosition(pos)

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

    def __init__(self, decimal_point, is_int = False, parent=None):
        AmountEdit.__init__(self, self._base_unit, is_int, parent)
        self.decimal_point = decimal_point

    def _base_unit(self):
        p = self.decimal_point()
        assert p in [5,8]
        return "BTC" if p == 8 else "mBTC"

    def get_amount(self):
        try:
            x = Decimal(str(self.text()))
        except:
            return None
        p = pow(10, self.decimal_point())
        return int( p * x )

    def setAmount(self, amount):
        p = pow(10, self.decimal_point())
        x = amount / Decimal(p)
        self.setText(str(x))

