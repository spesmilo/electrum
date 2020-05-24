from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QMenu, QHBoxLayout, QLabel, QVBoxLayout, QGridLayout, QLineEdit,
                             QPushButton, QAbstractItemView, QComboBox)
from PyQt5.QtGui import QFont, QStandardItem, QBrush

from electrum.util import bh2u, NotEnoughFunds, NoDynamicFeeEstimates
from electrum.i18n import _
from electrum.lnchannel import AbstractChannel, PeerState
from electrum.wallet import Abstract_Wallet
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id, LN_MAX_FUNDING_SAT
from electrum.lnworker import LNWallet

from .util import (MyTreeView, WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, WaitingDialog, MONOSPACE_FONT, ColorScheme)
from .amountedit import BTCAmountEdit, FreezableLineEdit


import asyncio
from .util import read_QIcon


class SwapDialog(WindowModalDialog):

    def __init__(self, window):
        WindowModalDialog.__init__(self, window, _('Submarine Swap'))
        self.window = window
        self.swap_manager = self.window.wallet.lnworker.swap_manager
        self.network = window.network
        self.normal_fee = 0
        self.lockup_fee = 0
        self.claim_fee = 0
        self.percentage = 0
        vbox = QVBoxLayout(self)
        self.send_amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.recv_amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.send_button = QPushButton('')
        self.recv_button = QPushButton('')
        self.is_reverse = False
        self.toggle_direction()
        self.send_amount_e.follows = False
        self.recv_amount_e.follows = False
        self.send_button.clicked.connect(self.toggle_direction)
        self.recv_button.clicked.connect(self.toggle_direction)
        self.send_amount_e.textChanged.connect(self.on_send_edited)
        self.recv_amount_e.textChanged.connect(self.on_recv_edited)
        h = QGridLayout()
        h.addWidget(QLabel(_('You send')+':'), 2, 0)
        h.addWidget(self.send_amount_e, 2, 1)
        h.addWidget(self.send_button, 2, 2)
        h.addWidget(QLabel(_('You receive')+':'), 3, 0)
        h.addWidget(self.recv_amount_e, 3, 1)
        h.addWidget(self.recv_button, 3, 2)
        self.normal_fee_label = QLabel()
        self.lockup_fee_label = QLabel()
        self.claim_fee_label = QLabel()
        h.addWidget(self.normal_fee_label, 4, 0, 1, 2)
        h.addWidget(self.lockup_fee_label, 5, 0, 1, 2)
        h.addWidget(self.claim_fee_label, 6, 0, 1, 2)
        vbox.addLayout(h)
        ok_button = OkButton(self)
        ok_button.setDefault(True)
        vbox.addLayout(Buttons(CancelButton(self), ok_button))
        # todo: add a fee slider for the claim tx

    def toggle_direction(self):
        self.is_reverse = not self.is_reverse
        self.send_button.setIcon(read_QIcon("lightning.png" if self.is_reverse else "bitcoin.png"))
        self.recv_button.setIcon(read_QIcon("lightning.png" if not self.is_reverse else "bitcoin.png"))

    def on_send_edited(self):
        if self.send_amount_e.follows:
            return
        amount = self.send_amount_e.get_amount()
        self.recv_amount_e.follows = True
        self.recv_amount_e.setAmount(self.get_recv_amount(amount))
        self.recv_amount_e.follows = False

    def on_recv_edited(self):
        if self.recv_amount_e.follows:
            return
        amount = self.recv_amount_e.get_amount()
        self.send_amount_e.follows = True
        self.send_amount_e.setAmount(self.get_send_amount(amount))
        self.send_amount_e.follows = False

    def get_pairs(self):
        fut = asyncio.run_coroutine_threadsafe(self.swap_manager.get_pairs(), self.network.asyncio_loop)
        pairs = fut.result()
        print(pairs)
        fees = pairs['pairs']['BTC/BTC']['fees']
        self.percentage = fees['percentage']
        self.normal_fee = fees['minerFees']['baseAsset']['normal']
        self.lockup_fee = fees['minerFees']['baseAsset']['reverse']['lockup']
        self.claim_fee = fees['minerFees']['baseAsset']['reverse']['claim']
        self.normal_fee_label.setText(f'normal fee: {self.normal_fee}')
        self.lockup_fee_label.setText(f'lockup fee: {self.lockup_fee}')
        self.claim_fee_label.setText(f'claim fee: {self.claim_fee}')

    def get_recv_amount(self, send_amount):
        if send_amount is None:
            return
        x = send_amount * (100 - self.percentage) / 100
        if self.is_reverse:
            x -= self.lockup_fee
            x -= self.claim_fee
        else:
            x -= self.normal_fee
        return x

    def get_send_amount(self, recv_amount):
        if not recv_amount:
            return
        x = recv_amount * (100 + self.percentage) / 100
        if self.is_reverse:
            x += self.lockup_fee
            x += self.claim_fee
        else:
            x += self.normal_fee
        return x

    def run(self):
        self.get_pairs()
        if not self.exec_():
            return
        if self.is_reverse:
            amount_sat = self.send_amount_e.get_amount()
            coro = self.swap_manager.reverse_swap(amount_sat)
        else:
            amount_sat = self.recv_amount_e.get_amount()
            password = self.window.protect(lambda x: x, [])
            coro = self.swap_manager.normal_swap(amount_sat, password)
        asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
