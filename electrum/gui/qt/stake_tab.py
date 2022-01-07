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
from decimal import Decimal

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
    QSpacerItem,
    QSizePolicy
)

from electrum.i18n import _
from .create_new_stake_window import CreateNewStakingWindow
from .staking.utils import get_all_stake_amount, get_sum_available_rewards
from .staking_detail_tx_window import CompletedMultiClaimedStakeDialog, ClaimReward
from .terms_and_conditions_mixin import load_terms_and_conditions
from .util import read_QIcon, WindowModalDialog, OkButton
from ... import bitcoin
from ...bitcoin import COIN
from ...transaction import PartialTxOutput
from ...util import bfh


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


class StakingTabQWidget(QWidget):

    def __init__(self, parent, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent = parent
        self.password = None
        self.top_h_label = QHBoxLayout()
        self.create_stake_dialog = CreateNewStakingWindow(self.parent)

        self.stake_button = CustomButton(
            text=_('Stake'),
            trigger=self.create_stake_dialog,
            icon=read_QIcon("electrum.png"),
        )
        self.tx_detail_dialog = None
        self.claim_rewards_button = CustomButton(text=_('Claim Rewards'), trigger=self.claim_rewards)
        self.claim_rewards_button.setEnabled(False)

        self.stake_balance_label = QLabel()
        self.stake_balance_label.setAlignment(Qt.AlignRight | Qt.AlignRight)

        self.staking_header = buttons = QHBoxLayout()
        buttons.addWidget(self.stake_button)
        buttons.addWidget(self.claim_rewards_button)

        verticalSpacer = QSpacerItem(400, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.top_h_label.addLayout(buttons)
        self.top_h_label.addItem(verticalSpacer)
        self.top_h_label.addWidget(self.stake_balance_label)

        font = QFont()
        font.setUnderline(True)
        self.terms_button = QPushButton()
        self.terms_button.setFont(font)
        self.terms_button.setText(_("Terms & Conditions"))
        self.terms_button.setMaximumSize(QSize(140, 16777215))
        self.terms_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.terms_button.setStyleSheet("border: none;")
        self.terms_button.setAutoDefault(True)
        self.terms_button.clicked.connect(terms_and_conditions_view)

        vbox = QVBoxLayout(self)

        vbox.addStretch(1)
        vbox.addLayout(self.top_h_label)

        vbox.addWidget(self.parent.staking_list)

        vbox.addWidget(self.terms_button)
        vbox.setStretchFactor(self.parent.staking_list, 1000)

    def update(self):
        value = get_all_stake_amount(self.parent.wallet)
        available_rewards = get_sum_available_rewards(self.parent.wallet)
        if available_rewards > Decimal('0.0'):
            self.claim_rewards_button.setEnabled(True)
        else:
            self.claim_rewards_button.setDisabled(True)

        self.stake_balance_label.setText(f'Staked balance: {value:.8f} ELCASH')

    def claim_rewards(self):
        password_required = self.parent.wallet.has_keystore_encryption()
        if password_required:
            self.password = None
            def got_valid_password(password):
                self.password = password
            unstake_dialog = ClaimReward(self, got_valid_password)
            unstake_dialog.finished.connect(self.claim_rewards_unlocked)
            unstake_dialog.show()
        else:
            self.claim_rewards_unlocked()

    def claim_rewards_unlocked(self):
        staking_txs = self.parent.wallet.db.get_stakes(fulfilled=True, paid_out=False)
        tx = self.parent.wallet.make_unsigned_claim_stake_transaction(staking_txs.keys())

        def sign_done(success):
            if success:
                self.parent.broadcast_or_show(tx)

        self.parent.sign_tx_with_password(tx, callback=sign_done, password=self.password)

# def staking_tab(self):
#     widget = QWidget()
#
#     return widget


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
