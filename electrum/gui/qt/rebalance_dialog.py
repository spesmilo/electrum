from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton

from electrum.i18n import _
from electrum.lnchannel import Channel

from .util import WindowModalDialog, Buttons, OkButton, CancelButton, WWLabel
from .amountedit import BTCAmountEdit

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class RebalanceDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow', chan1: Channel, chan2: Channel, amount_sat):
        WindowModalDialog.__init__(self, window, _("Rebalance channels"))
        self.window = window
        self.wallet = window.wallet
        self.chan1 = chan1
        self.chan2 = chan2
        vbox = QVBoxLayout(self)
        vbox.addWidget(WWLabel(_('Rebalance your channels in order to increase your sending or receiving capacity') + ':'))
        grid = QGridLayout()
        self.amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.amount_e.setAmount(amount_sat)
        self.amount_e.textChanged.connect(self.on_amount)
        self.rev_button = QPushButton(u'\U000021c4')
        self.rev_button.clicked.connect(self.on_reverse)
        self.max_button = QPushButton('Max')
        self.max_button.clicked.connect(self.on_max)
        self.label1 = QLabel('')
        self.label2 = QLabel('')
        self.ok_button = OkButton(self)
        self.ok_button.setEnabled(False)
        grid.addWidget(QLabel(_("From channel")), 0, 0)
        grid.addWidget(self.label1, 0, 1)
        grid.addWidget(QLabel(_("To channel")), 1, 0)
        grid.addWidget(self.label2, 1, 1)
        grid.addWidget(QLabel(_("Amount")), 2, 0)
        grid.addWidget(self.amount_e, 2, 1)
        grid.addWidget(self.max_button, 2, 2)
        grid.addWidget(self.rev_button, 0, 2)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))
        self.update()

    def on_reverse(self, x):
        a, b = self.chan1, self.chan2
        self.chan1, self.chan2 = b, a
        self.amount_e.setAmount(None)
        self.update()

    def on_amount(self, x):
        self.update()

    def on_max(self, x):
        n_sat = self.wallet.lnworker.num_sats_can_rebalance(self.chan1, self.chan2)
        self.amount_e.setAmount(n_sat)

    def update(self):
        self.label1.setText(self.chan1.short_id_for_GUI())
        self.label2.setText(self.chan2.short_id_for_GUI())
        amount_sat = self.amount_e.get_amount()
        b = bool(amount_sat) and self.wallet.lnworker.num_sats_can_rebalance(self.chan1, self.chan2) >= amount_sat
        self.ok_button.setEnabled(b)

    def run(self):
        if not self.exec():
            return
        amount_msat = self.amount_e.get_amount() * 1000
        coro = self.wallet.lnworker.rebalance_channels(self.chan1, self.chan2, amount_msat=amount_msat)
        self.window.run_coroutine_from_thread(coro, _('Rebalancing channels'))
        self.window.receive_tab.update_current_request()  # this will gray out the button
