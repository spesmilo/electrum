#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

from typing import Callable, Optional, List

import qrcode
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QWidget, QFrame, QAction,
                             QMenu)
from qrcode import exceptions

from electrum.i18n import _
from electrum.transaction import Transaction
from ..util import (MessageBoxMixin, read_QIcon, Buttons, ColorScheme, ButtonsLineEdit)


class BaseStakingTxDialog(QDialog, MessageBoxMixin):
    def __call__(self, *args, **kwargs):
        self.open()

    def __init__(self, parent, tx=None):
        # We want to be a top-level window
        QDialog.__init__(self, parent=parent)
        self.tx = tx  # type: Optional[Transaction]
        self.main_window = parent
        self.config = parent.config
        self.wallet = parent.wallet

        self.setMinimumWidth(950)
        self.psbt_only_widgets = []  # type: List[QWidget]

        self.vbox = vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))

        hbox_hash_explorer = QHBoxLayout()
        tx_hash = '0957fdfb1b7e9467fdef6d1951f5d6a7809d428846e06e5d7193ce3d7c0a022f'  # hash in qr code and label
        self.tx_hash_e = ButtonsLineEdit()
        self.tx_hash_e.setText(tx_hash)
        self.tx_hash_e.setFixedHeight(35)
        qr_show = lambda: parent.show_qrcode(str(tx_hash), 'Transaction ID', parent=self)
        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.tx_hash_e.addButton(qr_icon, qr_show, _("Show as QR code"))
        self.tx_hash_e.setReadOnly(True)
        hbox_hash_explorer.addWidget(self.tx_hash_e)

        self.explorer_button = QPushButton()
        self.explorer_button.setText(_("View in explorer"))
        self.explorer_button.clicked.connect(self.on_push_explorer_button)
        hbox_hash_explorer.addWidget(self.explorer_button)

        vbox.addLayout(hbox_hash_explorer)
        vbox.addSpacing(10)

    def add_export_actions_to_menu(self, menu: QMenu, *, gettx: Callable[[], Transaction] = None) -> None:
        if gettx is None:
            gettx = lambda: None

        action = QAction(_("Copy to clipboard"), self)
        action.triggered.connect(lambda: self.copy_to_clipboard(tx=gettx()))
        menu.addAction(action)

        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        action = QAction(read_QIcon(qr_icon), _("Show as QR code"), self)
        action.triggered.connect(lambda: self.show_qr(tx=gettx()))
        menu.addAction(action)

        action = QAction(_("Export to file"), self)
        action.triggered.connect(lambda: self.export_to_file(tx=gettx()))
        menu.addAction(action)

    def show_qr(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        qr_data = tx.to_qr_data()
        try:
            self.main_window.show_qrcode(qr_data, 'Transaction', parent=self)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Transaction is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + repr(e))

    def on_push_explorer_button(self):
        url = QUrl("https://explorer.electriccash.global/")
        QDesktopServices.openUrl(url)


class StakedDialog(BaseStakingTxDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.insert_data(self.vbox)
        self.add_buttons()

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel('Stake')
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_period = QHBoxLayout()
        period_lab = QLabel('Staking period:')
        period_lab_data = QLabel('90 Days')
        hbox_period.addWidget(period_lab)
        hbox_period.addWidget(period_lab_data)
        vbox_left.addLayout(hbox_period)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel('2021-01-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Blocks:')
        blocks_lab_data = QLabel('99 / 12960')
        hbox_blocks.addWidget(blocks_lab)
        hbox_blocks.addWidget(blocks_lab_data)
        vbox_left.addLayout(hbox_blocks)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()

        hbox_reword = QHBoxLayout()
        reword_lab = QLabel("<b>" + _("Guaranteed rewards:") + "</b>")
        hbox_reword.addWidget(reword_lab)
        vbox_right.addLayout(hbox_reword)

        hbox_gp = QHBoxLayout()
        gp_lab = QLabel(_("Governance Power:"))
        hbox_gp.addWidget(gp_lab)
        gp_lab_data = QLabel(_("123 GP"))
        hbox_gp.addWidget(gp_lab_data)
        vbox_right.addLayout(hbox_gp)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Daily free transaction limit:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("200000 bytes"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        hbox_rh = QHBoxLayout()
        rh_lab = QLabel("<b>" + _("Predicted rewards:") + "</b>")
        hbox_rh.addWidget(rh_lab)
        vbox_right.addLayout(hbox_rh)

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Estimated payout:"))
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_("0.000000003 ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)
        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.unstake_button = QPushButton(_("Unstake"))
        self.close_button = QPushButton(_("Close"))

        # Action buttons (right side)
        self.buttons = [self.unstake_button, self.close_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


class CompletedReadyToClaimStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.insert_data(self.vbox)
        self.add_buttons()

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel('Stake')
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_period = QHBoxLayout()
        period_lab = QLabel('Staking period:')
        period_lab_data = QLabel('90 Days')
        hbox_period.addWidget(period_lab)
        hbox_period.addWidget(period_lab_data)
        vbox_left.addLayout(hbox_period)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel('2021-01-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('End date:')
        start_date_lab_data = QLabel('2021-10-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Blocks:')
        blocks_lab_data = QLabel('12960 / 12960')
        hbox_blocks.addWidget(blocks_lab)
        hbox_blocks.addWidget(blocks_lab_data)
        vbox_left.addLayout(hbox_blocks)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()

        hbox_reword = QHBoxLayout()
        reword_lab = QLabel("<b>" + _("Rewards:") + "</b>")
        hbox_reword.addWidget(reword_lab)
        vbox_right.addLayout(hbox_reword)

        hbox_gp = QHBoxLayout()
        gp_lab = QLabel(_("Governance Power:"))
        hbox_gp.addWidget(gp_lab)
        gp_lab_data = QLabel(_("123 GP"))
        hbox_gp.addWidget(gp_lab_data)
        vbox_right.addLayout(hbox_gp)

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Payout:"))
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_("0.000000003 ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)

        hbox_rh = QHBoxLayout()
        rh_lab = QLabel("<b>" + _("Rewards history:") + "</b>")
        hbox_rh.addWidget(rh_lab)
        vbox_right.addLayout(hbox_rh)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Daily free transaction limit:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("200000 bytes"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.claim_reword_button = QPushButton(_("Claim Reward"))
        self.explorer_button = QPushButton(_("Close"))

        self.buttons = [self.claim_reword_button, self.explorer_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


class CompletedMultiClaimedStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.insert_data(self.vbox)
        self.add_buttons()

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel('Stake')
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel('2021-01-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('End date:')
        start_date_lab_data = QLabel('2021-10-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Block time:')
        blocks_lab_data = QLabel('15:11')
        hbox_blocks.addWidget(blocks_lab)
        hbox_blocks.addWidget(blocks_lab_data)
        vbox_left.addLayout(hbox_blocks)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Payout") + ':')
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_("0.000000003 ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Number od tx:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("3"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))

        # Action buttons (right side)
        self.buttons = [self.close_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


class CompletedSingleClaimedStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.insert_data(self.vbox)
        self.add_buttons()

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel('Stake')
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel('2021-01-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('End date:')
        start_date_lab_data = QLabel('2021-10-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Block time:')
        blocks_lab_data = QLabel('15:11')
        hbox_blocks.addWidget(blocks_lab)
        hbox_blocks.addWidget(blocks_lab_data)
        vbox_left.addLayout(hbox_blocks)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Payout") + ':')
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_("0.000000003 ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Number od tx:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("3"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))
        self.restake_button = QPushButton(_("Restake"))

        # Action buttons (right side)
        self.buttons = [self.restake_button, self.close_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


class UnstakedMultiStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.insert_data(self.vbox)
        self.add_buttons()

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel('Stake')
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel('2021-01-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('End date:')
        start_date_lab_data = QLabel('2021-10-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Payout") + ':')
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_("0.000000003 ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Block time:')
        blocks_lab_data = QLabel('15:11')
        hbox_blocks.addWidget(blocks_lab)
        hbox_blocks.addWidget(blocks_lab_data)
        vbox_right.addLayout(hbox_blocks)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Number od tx:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("-3"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Penalty:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("-3.001 ELCASH"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))

        # Action buttons (right side)
        self.buttons = [self.close_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


class UnstakedSingleStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.insert_data(self.vbox)
        self.add_buttons()

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel('Stake')
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel('2021-01-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('End date:')
        start_date_lab_data = QLabel('2021-10-01')
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Payout") + ':')
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_("0.000000003 ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Block time:')
        blocks_lab_data = QLabel('15:11')
        hbox_blocks.addWidget(blocks_lab)
        hbox_blocks.addWidget(blocks_lab_data)
        vbox_right.addLayout(hbox_blocks)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Number od tx:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("-3"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Penalty:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("-3.001 ELCASH"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))
        self.restake_button = QPushButton(_("Restake"))

        # Action buttons (right side)
        self.buttons = [self.restake_button, self.close_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)
