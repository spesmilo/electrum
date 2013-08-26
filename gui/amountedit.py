# -*- coding: utf-8 -*-

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from comma_separated import *
from decimal import Decimal

class BangDoubleValidator(CryptoCurrencyValidator):
    def __init__(self):
        CryptoCurrencyValidator.__init__(self, 8, 8)
    def validate(self, s, pos):
    	if (str(s)).strip() == '!':
    		return QValidator.Acceptable, pos
    	else:
    		return CryptoCurrencyValidator.validate(self, s, pos)


class AmountEdit(QLineEdit):

    def __init__(self, text_getter, is_int = False, parent=None):
        QLineEdit.__init__(self, parent)
        self.text_getter = text_getter
        self.textChanged.connect(self.numbify)
        self.is_int = is_int
        self.is_shortcut = False
        self.locale = MyQLocale(QLocale.system())
    	self.setValidator(BangDoubleValidator())


    def paintEvent(self, event):
        QLineEdit.paintEvent(self, event)
        if self.text_getter:
             panel = QStyleOptionFrameV2()
             self.initStyleOption(panel)
             textRect = self.style().subElementRect(QStyle.SE_LineEditContents, panel, self)
             textRect.adjust(2, 0, -10, 0)
             painter = QPainter(self)
             painter.setPen(self.palette().brush(QPalette.Disabled, QPalette.Text).color())
             painter.drawText(textRect, Qt.AlignRight | Qt.AlignVCenter, self.text_getter())


    def numbify(self):
        if self.text == '!':
            self.is_shortcut = True
        
    def value(self):
    	    status, value = self.locale.toDecimal(QLineEdit.text(self, 10), 10)
    	    if status == False:
    	    	    raise
    	    return value
    	    
    def setValue(self, d):
    	    assert(d.__class__ == Decimal or d.__class__ == int or d.__class__ == long)
    	    d = Decimal(d)
    	    text = self.locale.toString(d)
    	    QLineEdit.setText(self, text)
