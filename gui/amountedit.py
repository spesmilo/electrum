# -*- coding: utf-8 -*-

from PyQt4.QtCore import *
from PyQt4.QtGui import *


class AmountEdit(QLineEdit):

    def __init__(self, text_getter, is_int = False, parent=None):
        QLineEdit.__init__(self, parent)
        self.text_getter = text_getter
        self.textChanged.connect(self.numbify)
        self.is_int = is_int
        self.is_shortcut = False


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
