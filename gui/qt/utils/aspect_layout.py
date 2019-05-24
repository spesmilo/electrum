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

from typing import List

from PyQt5.QtWidgets import QLayout, QWidget, QLayoutItem
from PyQt5.QtCore import Qt, QSize, QRect, QPoint

class FixedAspectRatioLayout(QLayout):
    def __init__(self, parent: QWidget = None, aspect_ratio: float = 1.0):
        super().__init__(parent)
        self.aspect_ratio = aspect_ratio
        self.items: List[QLayoutItem] = []

    def set_aspect_ratio(self, aspect_ratio: float = 1.0):
        self.aspect_ratio = aspect_ratio
        self.update()

    def addItem(self, item: QLayoutItem):
        self.items.append(item)

    def count(self) -> int:
        return len(self.items)

    def itemAt(self, index: int) -> QLayoutItem:
        if index >= len(self.items):
            return None
        return self.items[index]

    def takeAt(self, index: int) -> QLayoutItem:
        if index >= len(self.items):
            return None
        return self.items.pop(index)

    def _get_contents_margins_size(self) -> QSize:
        margins = self.contentsMargins()
        return QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def setGeometry(self, rect: QRect):
        super().setGeometry(rect)
        if not self.items:
            return

        contents = self.contentsRect()
        if contents.height() > 0:
            c_aratio = contents.width() / contents.height()
        else:
            c_aratio = 1
        s_aratio = self.aspect_ratio
        item_rect = QRect(QPoint(0, 0), QSize(
            contents.width() if c_aratio < s_aratio else contents.height() * s_aratio,
            contents.height() if c_aratio > s_aratio else contents.width() / s_aratio
        ))

        content_margins = self.contentsMargins()
        free_space = contents.size() - item_rect.size()

        for item in self.items:
            if free_space.width() > 0 and not item.alignment() & Qt.AlignLeft:
                if item.alignment() & Qt.AlignRight:
                    item_rect.moveRight(contents.width() + content_margins.right())
                else:
                    item_rect.moveLeft(content_margins.left() + (free_space.width() / 2))
            else:
                item_rect.moveLeft(content_margins.left())

            if free_space.height() > 0 and not item.alignment() & Qt.AlignTop:
                if item.alignment() & Qt.AlignBottom:
                    item_rect.moveBottom(contents.height() + content_margins.bottom())
                else:
                    item_rect.moveTop(content_margins.top() + (free_space.height() / 2))
            else:
                item_rect.moveTop(content_margins.top())

            item.widget().setGeometry(item_rect)

    def sizeHint(self) -> QSize:
        result = QSize()
        for item in self.items:
            result = result.expandedTo(item.sizeHint())
        return self._get_contents_margins_size() + result

    def minimumSize(self) -> QSize:
        result = QSize()
        for item in self.items:
            result = result.expandedTo(item.minimumSize())
        return self._get_contents_margins_size() + result

    def expandingDirections(self) -> Qt.Orientations:
        return Qt.Horizontal | Qt.Vertical
