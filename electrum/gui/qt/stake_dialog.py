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
from PyQt5.QtWidgets import (QGridLayout, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QWidget, QToolButton,
                             QTextBrowser)
from PyQt5 import QtCore, QtGui
from electrum.i18n import _
from .terms_and_conditions_mixin import load_terms_and_conditions

from .util import read_QIcon, WindowModalDialog, OkButton


class CustomButton(QPushButton):
    def __init__(self, text, trigger=None, icon=None):
        QPushButton.__init__(self, text)
        super().__init__()
        self.setText(text)
        if icon is not None:
            self.setIcon(icon)
        self.clicked.connect(self.on_press)
        self.func = trigger
        self.setIconSize(QSize(20, 20))

    def on_press(self, checked=False):
        """Drops the unwanted PyQt5 "checked" argument"""
        self.func()

    def key_press_event(self, e):
        if e.key() in [Qt.Key_Return, Qt.Key_Enter]:
            self.func()


def staking_dialog(window):

    window.receive_grid = grid = QGridLayout()

    from .create_new_stake_window import CreateNewStakingWindow
    window.create_stake_dialog = CreateNewStakingWindow(window)

    window.stake_button = CustomButton(text=_('Stake'), trigger=window.create_stake_dialog, icon=read_QIcon("electrum.png"))

    window.claim_rewords_button = CustomButton(text=_('Claim Rewords'))

    window.staking_header = buttons = QHBoxLayout()
    buttons.addStretch(1)
    buttons.addWidget(window.stake_button)
    buttons.addWidget(window.claim_rewords_button)
    grid.addLayout(buttons, 4, 3, 1, 2)

    window.receive_requests_label = QLabel(_('Staking History'))

    from .staking_list import StakingList
    window.staking_list = StakingList(window)

    font = QtGui.QFont()
    font.setUnderline(True)
    window.terms_button = QPushButton()
    window.terms_button.setFont(font)
    window.terms_button.setText(_("Terms & Conditions"))
    window.terms_button.setMaximumSize(QtCore.QSize(140, 16777215))
    window.terms_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
    window.terms_button.setStyleSheet("border: none;")
    window.terms_button.setAutoDefault(True)
    window.terms_button.clicked.connect(terms_and_conditions_view)

    vbox_g = QVBoxLayout()
    vbox_g.addLayout(grid)
    vbox_g.addStretch()
    hbox = QHBoxLayout()
    hbox.addLayout(vbox_g)
    hbox.addStretch()

    w = QWidget()
    w.searchable_list = window.staking_list
    vbox = QVBoxLayout(w)
    vbox.addLayout(hbox)

    vbox.addStretch(1)
    vbox.addWidget(window.receive_requests_label)
    vbox.addWidget(window.staking_list)
    vbox.addWidget(window.terms_button)
    vbox.setStretchFactor(window.staking_list, 1000)

    return w


def terms_and_conditions_view():
    terms = load_terms_and_conditions(config={})
    dialog = WindowModalDialog(None, _('Terms & Conditions'))
    # size and icon position the same like in install wizard
    dialog.setMinimumSize(600, 400)
    main_vbox = QVBoxLayout(dialog)
    logo_vbox = QVBoxLayout()
    logo_vbox.addStretch(1)
    logo_hbox = QHBoxLayout()
    logo_hbox.addLayout(logo_vbox)
    logo_hbox.addSpacing(5)
    vbox = QVBoxLayout()
    text_browser = QTextBrowser()
    text_browser.setReadOnly(True)
    text_browser.setOpenExternalLinks(True)
    text_browser.setHtml(terms)
    vbox.addWidget(text_browser)
    footer = QHBoxLayout()
    footer.addStretch(1)
    footer.addWidget(OkButton(dialog))
    vbox.addLayout(footer)
    logo_hbox.addLayout(vbox)
    main_vbox.addLayout(logo_hbox)
    dialog.exec_()
