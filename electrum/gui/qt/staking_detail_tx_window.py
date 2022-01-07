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
import datetime
from decimal import Decimal
from typing import Callable, Optional, List

import qrcode
from PyQt5.QtCore import Qt, QUrl, QSize
from PyQt5.QtGui import QDesktopServices, QFont
from PyQt5.QtWidgets import (QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QWidget, QFrame, QAction,
                             QMenu, QGridLayout, QSizePolicy, QSpacerItem)
from qrcode import exceptions

from electrum import bitcoin
from electrum.bitcoin import COIN
from electrum.i18n import _
from electrum.transaction import Transaction, PartialTxOutput
from electrum.gui.qt.create_new_stake_window import CreateNewStakingWindow, CreateNewStakingFinish
from electrum.gui.qt.util import (MessageBoxMixin, read_QIcon, Buttons, ColorScheme, ButtonsLineEdit, WindowModalDialog,
                                  PasswordLineEdit)

from electrum.common.widgets import CustomTableWidget
from electrum.common.services import CustomTableWidgetController
from electrum.util import InvalidPassword, bfh


class TxList(CustomTableWidget):
    pass


def refresh_stake_dialog_window(data):
    """
    Call this function to refresh
    """

    tx_list.insert_data(
        table_data={
            'Tx ID': ['aaaaaaa'],
            'Staked Amount': '2',
            'Payout': '2',
            'GP': '1',
            'Daily Tx Limit': '1',
        },
    )


tx_list = TxList(
    starting_empty_cells=1,
    column_names=['Tx ID', 'Staked Amount', 'Payout', 'GP', 'Daily Tx Limit'],
    resize_column=0
)

tx_list_controller = CustomTableWidgetController(table_widget=tx_list)


class BaseStakingTxDialog(QDialog, MessageBoxMixin):
    def __call__(self, *args, **kwargs):
        self.open()

    def __init__(self, parent, data, detail_tx):
        # We want to be a top-level window
        QDialog.__init__(self, parent=parent)
        self.data = data
        self.detail_tx = detail_tx
        self.main_window = parent
        self.config = parent.config
        self.wallet = parent.wallet

        self.setMinimumWidth(1100)
        self.psbt_only_widgets = []  # type: List[QWidget]

        self.vbox = vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))

        hbox_hash_explorer = QHBoxLayout()
        tx_hash = detail_tx['txid']
        self.tx_hash_e = ButtonsLineEdit()
        self.tx_hash_e.setText(tx_hash)
        self.tx_hash_e.setFixedHeight(35)
        qr_show = lambda: self.main_window.show_qrcode(str(tx_hash), 'Transaction ID', parent=self)
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

# trwajacy stake
class StakedDialog(BaseStakingTxDialog):

    def __init__(self, parent, data, detail_tx):
        super().__init__(parent, data, detail_tx)
        self.insert_data(self.vbox)
        self.add_buttons()
        self.password = None

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
        start_date_lab_data = QLabel('2021 - 12 -12 ')
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
        self.unstake_button.setVisible(True)
        self.unstake_button.clicked.connect(self.on_push_unstake)
        self.close_button = QPushButton(_("Close"))
        self.close_button.setVisible(True)
        self.close_button.clicked.connect(self.on_push_close)


        # Action buttons (right side)
        self.buttons = [self.unstake_button, self.close_button]
        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)

    def on_push_unstake(self):
        password_required = self.wallet.has_keystore_encryption()
        if password_required:
            self.password = None
            def got_valid_password(password):
                self.password = password
            unstake_dialog = UnstakeDialog(self, got_valid_password)
            unstake_dialog.finished.connect(self.unstake)
            unstake_dialog.show()
        else:
            self.unstake()

    def unstake(self):
        tx = self.wallet.make_unsigned_unstake_transaction(self.detail_tx['txid'])
        if not tx:
            #TODO: probably show some error message indicating that transaction could not be created? (no inputs found most likely)
            return

        def sign_done(success):
            if success:
                self.parent().parent.broadcast_or_show(tx)

        self.parent().parent.sign_tx_with_password(tx, callback=sign_done, password=self.password)

        finish_dialog = CreateNewStakingFinish(parent=self, transaction_id=tx.txid())
        finish_dialog.finished.connect(self.on_push_close)
        finish_dialog.show()

    def on_push_close(self):
        self.close()


# stake gotowy do zebrania
class CompletedReadyToClaimStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent, data, detail_tx):
        super().__init__(parent, data, detail_tx)
        self.data = data
        self.detail_tx = detail_tx
        self.main_window = parent
        self.insert_data(self.vbox)
        self.add_buttons()
        self.password = None

    def insert_data(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()

        hbox_status = QHBoxLayout()
        status_lab = QLabel('Status:')
        status_lab_data = QLabel(_('Completed'))
        hbox_status.addWidget(status_lab)
        hbox_status.addWidget(status_lab_data)
        vbox_left.addLayout(hbox_status)

        hbox_period = QHBoxLayout()
        period_lab = QLabel('Staking period:')
        period_lab_data = QLabel(f"{self.data.staking_info.staking_period/144} Days")
        hbox_period.addWidget(period_lab)
        hbox_period.addWidget(period_lab_data)
        vbox_left.addLayout(hbox_period)

        hbox_start_date = QHBoxLayout()
        start_date_lab = QLabel('Start date:')
        start_date_lab_data = QLabel(self.detail_tx['date'].strftime("%m/%d/%Y"))
        hbox_start_date.addWidget(start_date_lab)
        hbox_start_date.addWidget(start_date_lab_data)
        vbox_left.addLayout(hbox_start_date)
        hbox_end_date = QHBoxLayout()
        end_date_lab = QLabel('End date:')
        finish_height = self.data.staking_info.deposit_height + self.data.staking_info.staking_period
        block_header = self.wallet.network.run_from_another_thread(self.wallet.network.get_block_header(finish_height, 'catchup'))
        end_date = datetime.datetime.fromtimestamp(block_header['timestamp']).strftime("%Y-%m-%d")
        end_date_lab_data = QLabel(end_date)
        hbox_end_date.addWidget(end_date_lab)
        hbox_end_date.addWidget(end_date_lab_data)

        vbox_left.addLayout(hbox_end_date)

        hbox_blocks = QHBoxLayout()
        blocks_lab = QLabel('Blocks:')
        blocks_lab_data = QLabel(
            f"{self.data.staking_info.staking_period}/"
            f"{self.data.staking_info.staking_period}"
        )

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
        gp_lab_data = QLabel(_("????"))
        hbox_gp.addWidget(gp_lab_data)
        vbox_right.addLayout(hbox_gp)

        hbox_payout = QHBoxLayout()
        p_lab = QLabel(_("Payout:"))
        hbox_payout.addWidget(p_lab)
        p_lab_data = QLabel(_(f"{self.data.staking_info.accumulated_reward+self.data.staking_info.staking_amount} ELCASH"))
        hbox_payout.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_payout)

        hbox_rh = QHBoxLayout()
        rh_lab = QLabel("<b>" + _("Rewards history:") + "</b>")
        hbox_rh.addWidget(rh_lab)
        vbox_right.addLayout(hbox_rh)

        hbox_fee = QHBoxLayout()
        p_lab = QLabel(_("Daily free transaction limit:"))
        hbox_fee.addWidget(p_lab)
        p_lab_data = QLabel(_("????"))
        hbox_fee.addWidget(p_lab_data)
        vbox_right.addLayout(hbox_fee)

        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        # todo: dodac tabele Michała

    def add_buttons(self):
        self.claim_reword_button = QPushButton(_("Claim Reward"))
        self.claim_reword_button.clicked.connect(self.on_push_claim)

        self.close_button = QPushButton(_("Close"))
        self.close_button.clicked.connect(self.on_push_close)


        self.buttons = [self.claim_reword_button, self.close_button]

        for b in self.buttons:
            b.setVisible(True)

        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)

    def on_push_claim(self):
        password_required = self.wallet.has_keystore_encryption()
        if password_required:
            self.password = None
            def got_valid_password(password):
                self.password = password
            unstake_dialog = ClaimReward(self, got_valid_password)
            unstake_dialog.finished.connect(self.claim_reward)
            unstake_dialog.show()
        else:
            self.claim_reward()


    def on_push_close(self):
        self.close()

    def claim_reward(self):
        tx = self.wallet.make_unsigned_claim_stake_transaction([self.detail_tx['txid']])
        if not tx:
            #TODO: probably show some error message indicating that transaction could not be created? (no inputs found most likely)
            return

        def sign_done(success):
            if success:
                self.parent().parent.broadcast_or_show(tx)

        self.parent().parent.sign_tx_with_password(tx, callback=sign_done, password=self.password)

        finish_dialog = CreateNewStakingFinish(parent=self, transaction_id=tx.txid())
        finish_dialog.finished.connect(self.on_push_close)
        finish_dialog.show()

# zebrany multi stake
class CompletedMultiClaimedStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent, data, detail_tx):
        self.data = data
        self.detail_tx = detail_tx
        self.main_window = parent
        self.tx_table = tx_list
        super().__init__(parent, data, detail_tx)
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

        vbox.addStretch(1)
        vbox.addWidget(self.tx_table)
        refresh_stake_dialog_window(data=[])

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))
        self.setVisible(True)

        # Action buttons (right side)
        self.buttons = [self.close_button]
        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


# zebrany single stake
class CompletedSingleClaimedStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent, data, detail_tx):
        self.data = data
        self.detail_tx = detail_tx
        self.main_window = parent
        self.tx_table = tx_list
        super().__init__(parent, data, detail_tx)
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

        vbox.addStretch(1)
        vbox.addWidget(self.tx_table)
        refresh_stake_dialog_window(data=[])

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))
        self.close_button.setVisible(True)
        self.restake_button = QPushButton(_("Restake"))
        self.restake_button.setVisible(True)
        self.restake_button.clicked.connect(self.on_push_restake)

        # Action buttons (right side)
        self.buttons = [self.restake_button, self.close_button]
        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)

    def on_push_restake(self):
        self.restake_window = CreateNewStakingWindow(self, default_amount=10, default_period=99)
        self.restake_window.show()


# zerwany multi stake
class UnstakedMultiStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent, data, detail_tx):
        self.data = data
        self.detail_tx = detail_tx
        self.main_window = parent
        self.tx_table = tx_list
        super().__init__(parent, data, detail_tx)
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
        vbox.addStretch(1)
        vbox.addWidget(self.tx_table)
        refresh_stake_dialog_window(data=[])

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))
        self.close_button.setVisible(True)

        # Action buttons (right side)
        self.buttons = [self.close_button]
        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


# zerwany single stake
class UnstakedSingleStakeDialog(BaseStakingTxDialog):

    def __init__(self, parent, data, detail_tx):
        self.data = data
        self.detail_tx = detail_tx
        self.main_window = parent
        self.tx_table = tx_list
        super().__init__(parent, data, detail_tx)
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
        vbox.addStretch(1)
        vbox.addWidget(self.tx_table)
        refresh_stake_dialog_window(data=[])

    def add_buttons(self):
        self.close_button = QPushButton(_("Close"))
        self.close_button.setVisible(True)
        self.restake_button = QPushButton(_("Restake"))
        self.restake_button.setVisible(True)

        # Action buttons (right side)
        self.buttons = [self.restake_button, self.close_button]
        self.hbox = hbox = QHBoxLayout()

        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        self.vbox.addLayout(hbox)


class UnstakeDialog(WindowModalDialog):

    def __call__(self, *args, **kwargs):
        self.show()

    def __init__(self, parent, success_callback):
        super().__init__(parent)
        self.success_callback = success_callback
        self.parent = parent
        self.wallet = parent.wallet
        self.setEnabled(True)
        self.setMinimumSize(QSize(420, 300))
        self.setMaximumSize(QSize(420, 300))
        self.setWindowTitle("Create New Stake")
        self.main_box = QVBoxLayout(self)

        self.title = QLabel()
        self.setup_txt()

        self.data_grid_box = QGridLayout()
        self.payout_label_2 = QLabel()

        self.amount_label = QLabel()
        self.period_label = QLabel()

        self.password_layout = QHBoxLayout()
        self.password_label = QLabel()
        self.password_lineEdit = PasswordLineEdit()
        self.password_error_label = QLabel()
        self.setup_password_label()

        self.text_tabel = QLabel()
        self.button_layout = QHBoxLayout()
        self.cancel_button = QPushButton()
        self.send_button = QPushButton()
        self.setup_buttons()

    def setup_txt(self):
        self.title.setText(_("Are you sure?"))
        size_policy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Maximum)
        size_policy.setHorizontalStretch(0)
        size_policy.setVerticalStretch(0)
        size_policy.setHeightForWidth(self.title.sizePolicy().hasHeightForWidth())
        self.title.setSizePolicy(size_policy)
        self.title.setMaximumSize(QSize(600, 35))
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.title.setFont(font)
        self.title.setAlignment(Qt.AlignCenter)
        self.main_box.addWidget(self.title)

        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_2 = QLabel()
        self.label_2.setText(
            _("If you unstake this transaction earlier, you will be charged 3% as penality,"
              " and you will lose your daily fee"))
        self.label_2.setWordWrap(True)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_4 = QLabel()
        self.label_4.setText(_("Total unstaked amount:"))
        self.horizontalLayout.addWidget(self.label_4)
        self.label_3 = QLabel()
        self.label_3.setText(_("2.00000000 ELCASH"))
        self.horizontalLayout.addWidget(self.label_3)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.verticalLayout.addLayout(self.verticalLayout_2)
        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_5 = QLabel()
        self.label_5.setText(_("Penality:"))
        self.horizontalLayout_2.addWidget(self.label_5)
        self.label_6 = QLabel()
        self.label_6.setText(_("2.00000000 ELCASH"))
        self.horizontalLayout_2.addWidget(self.label_6)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.main_box.addLayout(self.verticalLayout)


    def setup_password_label(self):
        self.password_label.setText(_("Password:"))
        self.password_label.setMaximumSize(QSize(16777215, 40))
        self.password_layout.addWidget(self.password_label)
        self.password_lineEdit.setText("")
        self.password_layout.addWidget(self.password_lineEdit)
        self.main_box.addLayout(self.password_layout)
        self.password_error_label.setText(_("incorrect password"))
        self.password_error_label.setStyleSheet('color: red')
        self.main_box.addWidget(self.password_error_label)
        self.password_error_label.hide()

    def setup_buttons(self):
        self.text_tabel.setText(_("Click Send to proceed"))
        self.main_box.addWidget(self.text_tabel)
        spacer_item = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.button_layout.addItem(spacer_item)
        self.cancel_button.setText(_("Cancel"))
        self.cancel_button.clicked.connect(self.on_push_cancel_button)
        self.button_layout.addWidget(self.cancel_button)
        self.send_button.setText(_("Send"))
        self.send_button.clicked.connect(self.on_push_send_window)
        self.button_layout.addWidget(self.send_button)
        self.main_box.addLayout(self.button_layout)

    def on_push_cancel_button(self):
        self.close()

    def on_push_send_window(self):
        password = self.password_lineEdit.text() or None
        if not password:
            return
        try:
            self.wallet.check_password(password)
        except InvalidPassword:
            self.password_error_label.show()
            self.password_lineEdit.setStyleSheet("background-color: red;")
            return

        self.success_callback(password)
        self.close()


class ClaimReward(WindowModalDialog):

    def __call__(self, *args, **kwargs):
        self.show()

    def __init__(self, parent, success_callback):
        super().__init__(parent)
        self.success_callback = success_callback
        self.parent = parent
        self.wallet = parent.wallet
        self.setEnabled(True)
        self.setMinimumSize(QSize(420, 200))
        self.setMaximumSize(QSize(420, 200))
        self.setWindowTitle("Claim reward")
        self.main_box = QVBoxLayout(self)

        self.title = QLabel()
        self.setup_txt()

        self.data_grid_box = QGridLayout()
        self.payout_label_2 = QLabel()

        self.amount_label = QLabel()
        self.period_label = QLabel()

        self.password_layout = QHBoxLayout()
        self.password_label = QLabel()
        self.password_lineEdit = PasswordLineEdit()
        self.password_error_label = QLabel()
        self.setup_password_label()

        self.text_tabel = QLabel()
        self.button_layout = QHBoxLayout()
        self.cancel_button = QPushButton()
        self.send_button = QPushButton()
        self.setup_buttons()

    def setup_txt(self):
        self.title.setText(_("Enter your password to proceed"))
        size_policy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Maximum)
        size_policy.setHorizontalStretch(0)
        size_policy.setVerticalStretch(0)
        size_policy.setHeightForWidth(self.title.sizePolicy().hasHeightForWidth())
        self.title.setSizePolicy(size_policy)
        self.title.setMaximumSize(QSize(600, 35))
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.title.setFont(font)
        self.title.setAlignment(Qt.AlignCenter)
        self.main_box.addWidget(self.title)

    def setup_password_label(self):
        self.password_label.setText(_("Password:"))
        self.password_label.setMaximumSize(QSize(16777215, 40))
        self.password_layout.addWidget(self.password_label)
        self.password_lineEdit.setText("")
        self.password_layout.addWidget(self.password_lineEdit)
        self.main_box.addLayout(self.password_layout)
        self.password_error_label.setText(_("incorrect password"))
        self.password_error_label.setStyleSheet('color: red')
        self.main_box.addWidget(self.password_error_label)
        self.password_error_label.hide()

    def setup_buttons(self):
        self.text_tabel.setText(_("Click Send to proceed"))
        self.main_box.addWidget(self.text_tabel)
        spacer_item = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.button_layout.addItem(spacer_item)
        self.cancel_button.setText(_("Cancel"))
        self.cancel_button.clicked.connect(self.on_push_cancel_button)
        self.button_layout.addWidget(self.cancel_button)
        self.send_button.setText(_("Send"))
        self.send_button.clicked.connect(self.on_push_send_window)
        self.button_layout.addWidget(self.send_button)
        self.main_box.addLayout(self.button_layout)

    def on_push_cancel_button(self):
        self.close()

    def on_push_send_window(self):
        password = self.password_lineEdit.text() or None
        if password is None:
            return
        try:
            self.wallet.check_password(password)
        except Exception:
            self.password_error_label.show()
            self.password_lineEdit.setStyleSheet("background-color: red;")
            return

        self.success_callback(password)
        self.close()

