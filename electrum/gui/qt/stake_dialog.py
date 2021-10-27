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
# NONINFINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QCursor, QFont
from PyQt5.QtWidgets import (
    QGridLayout,
    QLabel,
    QPushButton,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
    QTextBrowser,
)

from electrum.i18n import _
from .create_new_stake_window import CreateNewStakingWindow
from .staking_detail_tx_window import CompletedMultiClaimedStakeDialog
from .terms_and_conditions_mixin import load_terms_and_conditions
from .util import read_QIcon, WindowModalDialog, OkButton
from ...stake import stake_api
from .staking_list import staking_list


def refresh_stake_dialog_window(window):
    """
    Call this function to refresh stake dialog window
    TODO
    """
    current_staking_data = stake_api.get_detailed_stakes_data_for_addresses(
        addresses=window.wallet.get_addresses()
    )
    current_height = window.wallet.get_local_height()

    staking_list.insert_data(
        table_data={
            'Type': [get_verbal_type_name(stack_data=data) for data in current_staking_data],
            'Start Date': [data['timestamp'] for data in current_staking_data],
            'Amount': [data['staking_amount'] for data in current_staking_data],
            'Staking Period': [data['staking_period'] for data in current_staking_data],
            'Deposit Height': [data['deposit_height'] for data in current_staking_data],
            'Blocks Left': [get_block_left(data, current_height) for data in current_staking_data],
            'tx_hash': [data['tx_hash'] for data in current_staking_data],
        },
        context_menu_kwargs={'window': window, },
    )


def get_verbal_type_name(stack_data):
    if not stack_data['fulfilled'] and not stack_data['paid_out']:
        return 'Staked'
    if stack_data['fulfilled'] and stack_data['paid_out']:
        return 'Unstaked'
    elif stack_data['fulfilled']:
        return 'Completed'


def get_block_left(data, current_height):
    blocks_left = (data['deposit_height'] + data['staking_period']) - current_height
    if blocks_left > 0:
        return blocks_left
    else:
        return 0


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

    def on_press(self):
        """Drops the unwanted PyQt5 "checked" argument"""
        self.func()

    def key_press_event(self, e):
        if e.key() in [Qt.Key_Return, Qt.Key_Enter]:
            self.func()


def staking_dialog(window):
    window.receive_grid = grid = QGridLayout()
    window.create_stake_dialog = CreateNewStakingWindow(window)

    window.stake_button = CustomButton(
        text=_('Stake'), trigger=window.create_stake_dialog, icon=read_QIcon("electrum.png")
    )
    window.tx_detail_dialog = None
    window.claim_rewords_button = CustomButton(text=_('Claim Rewords'), trigger=None)

    window.staking_header = buttons = QHBoxLayout()
    buttons.addStretch(1)
    buttons.addWidget(window.stake_button)
    buttons.addWidget(window.claim_rewords_button)
    grid.addLayout(buttons, 4, 3, 1, 2)

    window.receive_requests_label = QLabel(_('Staking History'))

    window.staking_list = staking_list

    font = QFont()
    font.setUnderline(True)
    window.terms_button = QPushButton()
    window.terms_button.setFont(font)
    window.terms_button.setText(_("Terms & Conditions"))
    window.terms_button.setMaximumSize(QSize(140, 16777215))
    window.terms_button.setCursor(QCursor(Qt.PointingHandCursor))
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
    vbox = QVBoxLayout(w)
    vbox.addLayout(hbox)

    vbox.addStretch(1)
    vbox.addWidget(window.receive_requests_label)
    vbox.addWidget(window.staking_list)
    vbox.addWidget(window.terms_button)
    vbox.setStretchFactor(window.staking_list, 1000)

    refresh_stake_dialog_window(window=window)

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
