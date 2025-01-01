#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
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

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (QVBoxLayout, QCheckBox, QHBoxLayout, QLineEdit,
                             QLabel, QCompleter, QDialog, QStyledItemDelegate,
                             QScrollArea, QWidget, QPushButton, QGridLayout, QToolButton)
from PyQt6.QtCore import QRect, QEventLoop, Qt, pyqtSignal
from PyQt6.QtGui import QPalette, QPen, QPainter, QPixmap


from electrum.i18n import _

from .util import Buttons, CloseButton, WindowModalDialog, ColorScheme, font_height, AmountLabel

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet


# Todo:
#  show lightning funds that are not usable
#  pie chart mouse interactive, to prepare a swap

COLOR_CONFIRMED = Qt.GlobalColor.green
COLOR_UNCONFIRMED = Qt.GlobalColor.red
COLOR_UNMATURED = Qt.GlobalColor.magenta
COLOR_FROZEN = ColorScheme.BLUE.as_color(True)
COLOR_LIGHTNING = Qt.GlobalColor.yellow
COLOR_FROZEN_LIGHTNING = Qt.GlobalColor.cyan

class PieChartObject:

    def paintEvent(self, event):
        pen = QPen(Qt.GlobalColor.gray, 1, Qt.PenStyle.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.RenderHint.Antialiasing)
        qp.setBrush(Qt.GlobalColor.gray)
        total = sum([x[2] for x in self._list])
        if total == 0:
            return
        alpha = 0
        s = 0
        for name, color, amount in self._list:
            qp.setBrush(color)
            if amount == 0:
                continue
            elif amount == total:
                qp.drawEllipse(self.R)
            else:
                delta = int(16 * 360 * amount/total)
                qp.drawPie(self.R, alpha, delta)
                alpha += delta
        qp.end()

class PieChartWidget(QWidget, PieChartObject):

    def __init__(self, size, l):
        QWidget.__init__(self)
        self.size = size
        self.R = QRect(0, 0, self.size, self.size)
        self.setGeometry(self.R)
        self.setMinimumWidth(self.size)
        self.setMaximumWidth(self.size)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
        self._list = l # list[ (name, color, amount)]
        self.update()

    def update_list(self, l):
        self._list = l
        self.update()


class BalanceToolButton(QToolButton, PieChartObject):

    def __init__(self):
        QToolButton.__init__(self)
        self._list = []
        self._update_size()

    def update_list(self, l):
        self._list = l
        self.update()

    def setText(self, text):
        # this is a hack
        QToolButton.setText(self, '       ' + text)

    def paintEvent(self, event):
        QToolButton.paintEvent(self, event)
        PieChartObject.paintEvent(self, event)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._update_size()

    def _update_size(self):
        size = round(font_height(self) * 1.1)
        self.R = QRect(6, 3, size, size)


class LegendWidget(QWidget):
    size = 20

    def __init__(self, color):
        QWidget.__init__(self)
        self.color = color
        self.R = QRect(0, 0, self.size, int(self.size*0.75))
        self.setGeometry(self.R)
        self.setMinimumWidth(self.size)
        self.setMaximumWidth(self.size)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)

    def paintEvent(self, event):
        pen = QPen(Qt.GlobalColor.gray, 1, Qt.PenStyle.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.RenderHint.Antialiasing)
        qp.setBrush(self.color)
        qp.drawRect(self.R)
        qp.end()


class BalanceDialog(WindowModalDialog):

    def __init__(self, parent: 'ElectrumWindow', *, wallet: 'Abstract_Wallet'):

        WindowModalDialog.__init__(self, parent, _("Wallet Balance"))
        self.wallet = wallet
        self.config = parent.config
        self.fx = parent.fx

        confirmed, unconfirmed, unmatured, frozen, lightning, f_lightning = self.wallet.get_balances_for_piechart()

        frozen_str =  self.config.format_amount_and_units(frozen)
        confirmed_str =  self.config.format_amount_and_units(confirmed)
        unconfirmed_str =  self.config.format_amount_and_units(unconfirmed)
        unmatured_str =  self.config.format_amount_and_units(unmatured)
        lightning_str =  self.config.format_amount_and_units(lightning)
        f_lightning_str =  self.config.format_amount_and_units(f_lightning)

        frozen_fiat_str = self.fx.format_amount_and_units(frozen) if self.fx else ''
        confirmed_fiat_str = self.fx.format_amount_and_units(confirmed) if self.fx else ''
        unconfirmed_fiat_str = self.fx.format_amount_and_units(unconfirmed) if self.fx else ''
        unmatured_fiat_str = self.fx.format_amount_and_units(unmatured) if self.fx else ''
        lightning_fiat_str = self.fx.format_amount_and_units(lightning) if self.fx else ''
        f_lightning_fiat_str = self.fx.format_amount_and_units(f_lightning) if self.fx else ''

        piechart = PieChartWidget(
            max(120, 9 * font_height()),
            [
                (_('Frozen'), COLOR_FROZEN, frozen),
                (_('Unmatured'), COLOR_UNMATURED, unmatured),
                (_('Unconfirmed'), COLOR_UNCONFIRMED, unconfirmed),
                (_('On-chain'), COLOR_CONFIRMED, confirmed),
                (_('Lightning'), COLOR_LIGHTNING, lightning),
                (_('Lightning frozen'), COLOR_FROZEN_LIGHTNING, f_lightning),
            ]
        )

        vbox = QVBoxLayout()
        vbox.addWidget(piechart)
        grid = QGridLayout()
        #grid.addWidget(QLabel(_("Onchain") + ':'), 0, 1)
        #grid.addWidget(QLabel(onchain_str), 0, 2, alignment=Qt.AlignmentFlag.AlignRight)
        #grid.addWidget(QLabel(onchain_fiat_str), 0, 3, alignment=Qt.AlignmentFlag.AlignRight)

        if frozen:
            grid.addWidget(LegendWidget(COLOR_FROZEN), 0, 0)
            grid.addWidget(QLabel(_("Frozen") + ':'), 0, 1)
            grid.addWidget(AmountLabel(frozen_str), 0, 2, alignment=Qt.AlignmentFlag.AlignRight)
            grid.addWidget(AmountLabel(frozen_fiat_str), 0, 3, alignment=Qt.AlignmentFlag.AlignRight)
        if unconfirmed:
            grid.addWidget(LegendWidget(COLOR_UNCONFIRMED), 2, 0)
            grid.addWidget(QLabel(_("Unconfirmed") + ':'), 2, 1)
            grid.addWidget(AmountLabel(unconfirmed_str), 2, 2, alignment=Qt.AlignmentFlag.AlignRight)
            grid.addWidget(AmountLabel(unconfirmed_fiat_str), 2, 3, alignment=Qt.AlignmentFlag.AlignRight)
        if unmatured:
            grid.addWidget(LegendWidget(COLOR_UNMATURED), 3, 0)
            grid.addWidget(QLabel(_("Unmatured") + ':'), 3, 1)
            grid.addWidget(AmountLabel(unmatured_str), 3, 2, alignment=Qt.AlignmentFlag.AlignRight)
            grid.addWidget(AmountLabel(unmatured_fiat_str), 3, 3, alignment=Qt.AlignmentFlag.AlignRight)
        if confirmed:
            grid.addWidget(LegendWidget(COLOR_CONFIRMED), 1, 0)
            grid.addWidget(QLabel(_("On-chain") + ':'), 1, 1)
            grid.addWidget(AmountLabel(confirmed_str), 1, 2, alignment=Qt.AlignmentFlag.AlignRight)
            grid.addWidget(AmountLabel(confirmed_fiat_str), 1, 3, alignment=Qt.AlignmentFlag.AlignRight)
        if lightning:
            grid.addWidget(LegendWidget(COLOR_LIGHTNING), 4, 0)
            grid.addWidget(QLabel(_("Lightning") + ':'), 4, 1)
            grid.addWidget(AmountLabel(lightning_str), 4, 2, alignment=Qt.AlignmentFlag.AlignRight)
            grid.addWidget(AmountLabel(lightning_fiat_str), 4, 3, alignment=Qt.AlignmentFlag.AlignRight)
        if f_lightning:
            grid.addWidget(LegendWidget(COLOR_FROZEN_LIGHTNING), 5, 0)
            grid.addWidget(QLabel(_("Lightning (frozen)") + ':'), 5, 1)
            grid.addWidget(AmountLabel(f_lightning_str), 5, 2, alignment=Qt.AlignmentFlag.AlignRight)
            grid.addWidget(AmountLabel(f_lightning_fiat_str), 5, 3, alignment=Qt.AlignmentFlag.AlignRight)

        vbox.addLayout(grid)
        vbox.addStretch(1)
        btn_close = CloseButton(self)
        btns = Buttons(btn_close)
        vbox.addLayout(btns)
        self.setLayout(vbox)

    def run(self):
        self.exec()
