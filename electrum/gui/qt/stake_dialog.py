#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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


from PyQt5.QtCore import QSize, Qt
from PyQt5.QtWidgets import (QGridLayout, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QWidget, QToolButton)

from electrum.i18n import _

from .util import read_QIcon


class CustomButton(QPushButton):
    def __init__(self, text, func=None, icon=None):
        QPushButton.__init__(self, text)
        super().__init__()
        self.setText(text)
        if icon is not None:
            self.setIcon(icon)
        self.clicked.connect(self.on_press)
        self.func = func
        self.setIconSize(QSize(20, 20))

    def on_press(self, checked=False):
        """Drops the unwanted PyQt5 "checked" argument"""
        self.func()


    def key_press_event(self, e):
        if e.key() in [Qt.Key_Return, Qt.Key_Enter]:
            self.func()


def create(self):

    self.receive_grid = grid = QGridLayout()

    from .stake_create_dialog import CreateStaking
    self.create_stake_dialog = CreateStaking(parent=None, title=_('Create Staking'))

    self.stake_button = CustomButton(text=_('Stake'), func=self.create_stake_dialog, icon=read_QIcon("electrum.png"))

    self.claim_rewords_button = CustomButton(text=_('Claim Rewords'))

    self.staking_header = buttons = QHBoxLayout()
    buttons.addStretch(1)
    buttons.addWidget(self.stake_button)
    buttons.addWidget(self.claim_rewords_button)
    grid.addLayout(buttons, 4, 3, 1, 2)

    self.receive_requests_label = QLabel(_('Staking History'))

    from .staking_list import StakingList
    self.staking_list = StakingList(self)

    # layout
    vbox_g = QVBoxLayout()
    vbox_g.addLayout(grid)
    vbox_g.addStretch()
    hbox = QHBoxLayout()
    hbox.addLayout(vbox_g)
    hbox.addStretch()

    w = QWidget()
    w.searchable_list = self.staking_list
    vbox = QVBoxLayout(w)
    vbox.addLayout(hbox)

    vbox.addStretch(1)
    vbox.addWidget(self.receive_requests_label)
    vbox.addWidget(self.staking_list)
    vbox.setStretchFactor(self.staking_list, 1000)

    return w

