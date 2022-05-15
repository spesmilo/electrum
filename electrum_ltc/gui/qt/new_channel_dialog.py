from typing import TYPE_CHECKING, Optional

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QComboBox, QLineEdit

from electrum_ltc.i18n import _
from electrum_ltc.transaction import PartialTxOutput, PartialTransaction
from electrum_ltc.lnutil import LN_MAX_FUNDING_SAT
from electrum_ltc.lnworker import hardcoded_trampoline_nodes
from electrum_ltc import ecc
from electrum_ltc.util import NotEnoughFunds, NoDynamicFeeEstimates


from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, ColorScheme, WWLabel, read_QIcon, IconLabel)
from .amountedit import BTCAmountEdit


if TYPE_CHECKING:
    from .main_window import ElectrumWindow



class NewChannelDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow', amount_sat: Optional[int] = None):
        WindowModalDialog.__init__(self, window, _('Open Channel'))
        self.window = window
        self.network = window.network
        self.config = window.config
        self.lnworker = self.window.wallet.lnworker
        self.trampolines = hardcoded_trampoline_nodes()
        self.trampoline_names = list(self.trampolines.keys())
        vbox = QVBoxLayout(self)
        if self.network.channel_db:
            vbox.addWidget(QLabel(_('Enter Remote Node ID or connection string or invoice')))
            self.remote_nodeid = QLineEdit()
            self.remote_nodeid.setMinimumWidth(700)
            self.suggest_button = QPushButton(self, text=_('Suggest Peer'))
            self.suggest_button.clicked.connect(self.on_suggest)
        else:
            vbox.addWidget(QLabel(_('Choose a trampoline node to open a channel with')))
            self.trampoline_combo = QComboBox()
            self.trampoline_combo.addItems(self.trampoline_names)
            self.trampoline_combo.setCurrentIndex(1)
        self.amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.amount_e.setAmount(amount_sat)
        self.max_button = EnterButton(_("Max"), self.spend_max)
        self.max_button.setFixedWidth(100)
        self.max_button.setCheckable(True)
        self.clear_button = QPushButton(self, text=_('Clear'))
        self.clear_button.clicked.connect(self.on_clear)
        self.clear_button.setFixedWidth(100)
        h = QGridLayout()
        if self.network.channel_db:
            h.addWidget(QLabel(_('Remote Node ID')), 0, 0)
            h.addWidget(self.remote_nodeid, 0, 1, 1, 4)
            h.addWidget(self.suggest_button, 0, 5)
        else:
            h.addWidget(QLabel(_('Trampoline')), 0, 0)
            h.addWidget(self.trampoline_combo, 0, 1, 1, 4)
        h.addWidget(QLabel('Amount'), 2, 0)
        h.addWidget(self.amount_e, 2, 1)
        h.addWidget(self.max_button, 2, 2)
        h.addWidget(self.clear_button, 2, 3)
        vbox.addLayout(h)
        vbox.addStretch()
        ok_button = OkButton(self)
        ok_button.setDefault(True)
        vbox.addLayout(Buttons(CancelButton(self), ok_button))

    def on_suggest(self):
        self.network.start_gossip()
        nodeid = self.lnworker.suggest_peer().hex() or ''
        if not nodeid:
            self.remote_nodeid.setText("")
            self.remote_nodeid.setPlaceholderText(
                "Please wait until the graph is synchronized to 30%, and then try again.")
        else:
            self.remote_nodeid.setText(nodeid)
        self.remote_nodeid.repaint()  # macOS hack for #6269

    def on_clear(self):
        self.amount_e.setText('')
        self.amount_e.setFrozen(False)
        self.amount_e.repaint()  # macOS hack for #6269
        if self.network.channel_db:
            self.remote_nodeid.setText('')
            self.remote_nodeid.repaint()  # macOS hack for #6269
        self.max_button.setChecked(False)
        self.max_button.repaint()  # macOS hack for #6269

    def spend_max(self):
        self.amount_e.setFrozen(self.max_button.isChecked())
        if not self.max_button.isChecked():
            return
        dummy_nodeid = ecc.GENERATOR.get_public_key_bytes(compressed=True)
        make_tx = self.window.mktx_for_open_channel(funding_sat='!', node_id=dummy_nodeid)
        try:
            tx = make_tx(None)
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            self.max_button.setChecked(False)
            self.amount_e.setFrozen(False)
            self.main_window.show_error(str(e))
            return
        amount = tx.output_value()
        amount = min(amount, LN_MAX_FUNDING_SAT)
        self.amount_e.setAmount(amount)

    def run(self):
        if not self.exec_():
            return
        if self.max_button.isChecked() and self.amount_e.get_amount() < LN_MAX_FUNDING_SAT:
            # if 'max' enabled and amount is strictly less than max allowed,
            # that means we have fewer coins than max allowed, and hence we can
            # spend all coins
            funding_sat = '!'
        else:
            funding_sat = self.amount_e.get_amount()
        if self.network.channel_db:
            connect_str = str(self.remote_nodeid.text()).strip()
        else:
            name = self.trampoline_names[self.trampoline_combo.currentIndex()]
            connect_str = str(self.trampolines[name])
        if not connect_str or not funding_sat:
            return
        self.window.open_channel(connect_str, funding_sat, 0)
        return True
