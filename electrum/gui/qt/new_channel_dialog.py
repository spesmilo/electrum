from typing import TYPE_CHECKING, Optional

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QComboBox, QLineEdit, QSpacerItem, QWidget, QHBoxLayout

from electrum.i18n import _
from electrum.transaction import PartialTxOutput, PartialTransaction
from electrum.lnutil import MIN_FUNDING_SAT
from electrum.lnworker import hardcoded_trampoline_nodes
from electrum import ecc
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates

from electrum.gui import messages
from . import util
from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, ColorScheme, WWLabel, read_QIcon, IconLabel,
                   char_width_in_lineedit)
from .amountedit import BTCAmountEdit
from .my_treeview import create_toolbar_with_menu

if TYPE_CHECKING:
    from .main_window import ElectrumWindow



class NewChannelDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow', amount_sat: Optional[int] = None, min_amount_sat: Optional[int] = None):
        WindowModalDialog.__init__(self, window, _('Open Channel'))
        self.window = window
        self.network = window.network
        self.config = window.config
        self.lnworker = self.window.wallet.lnworker
        self.trampolines = hardcoded_trampoline_nodes()
        self.trampoline_names = list(self.trampolines.keys())
        self.min_amount_sat = min_amount_sat or MIN_FUNDING_SAT
        vbox = QVBoxLayout(self)
        toolbar, menu = create_toolbar_with_menu(self.config, '')
        menu.addConfig(
            self.config.cv.LIGHTNING_USE_RECOVERABLE_CHANNELS,
            checked=self.lnworker.has_recoverable_channels(),
        ).setEnabled(self.lnworker.can_have_recoverable_channels())
        vbox.addLayout(toolbar)
        msg = _('Choose a remote node and an amount to fund the channel.')
        msg += '\n' + _('Minimum required amount: {}').format(self.window.format_amount_and_units(self.min_amount_sat))
        vbox.addWidget(WWLabel(msg))
        if self.network.channel_db:
            vbox.addWidget(QLabel(_('Enter Remote Node ID or connection string or invoice')))
            self.remote_nodeid = QLineEdit()
            self.remote_nodeid.setMinimumWidth(700)
            self.suggest_button = QPushButton(self, text=_('Suggest Peer'))
            self.suggest_button.clicked.connect(self.on_suggest)
        else:
            self.trampoline_combo = QComboBox()
            self.trampoline_combo.addItems(self.trampoline_names)
            self.trampoline_combo.setCurrentIndex(1)
        self.amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.amount_e.setAmount(amount_sat)

        btn_width = 10 * char_width_in_lineedit()
        self.min_button = EnterButton(_("Min"), self.spend_min)
        self.min_button.setEnabled(bool(self.min_amount_sat))
        self.min_button.setFixedWidth(btn_width)
        self.max_button = EnterButton(_("Max"), self.spend_max)
        self.max_button.setFixedWidth(btn_width)
        self.max_button.setCheckable(True)
        self.clear_button = QPushButton(self, text=_('Clear'))
        self.clear_button.clicked.connect(self.on_clear)
        self.clear_button.setFixedWidth(btn_width)
        h = QGridLayout()
        if self.network.channel_db:
            h.addWidget(QLabel(_('Remote Node ID')), 0, 0)
            h.addWidget(self.remote_nodeid, 0, 1, 1, 4)
            h.addWidget(self.suggest_button, 0, 5)
        else:
            h.addWidget(QLabel(_('Remote Node')), 0, 0)
            h.addWidget(self.trampoline_combo, 0, 1, 1, 4)
        h.addWidget(QLabel('Amount'), 2, 0)

        amt_hbox = QHBoxLayout()
        amt_hbox.setContentsMargins(0, 0, 0, 0)
        amt_hbox.addWidget(self.amount_e)
        amt_hbox.addWidget(self.min_button)
        amt_hbox.addWidget(self.max_button)
        amt_hbox.addWidget(self.clear_button)
        amt_hbox.addStretch()
        h.addLayout(amt_hbox, 2, 1, 1, 4)

        vbox.addLayout(h)
        vbox.addStretch()
        ok_button = OkButton(self)
        ok_button.setDefault(True)
        vbox.addLayout(Buttons(CancelButton(self), ok_button))

    def on_suggest(self):
        self.network.start_gossip()
        nodeid = (self.lnworker.suggest_peer() or b"").hex()
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

    def spend_min(self):
        self.max_button.setChecked(False)
        self.amount_e.setAmount(self.min_amount_sat)

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
            self.window.show_error(str(e))
            return
        amount = tx.output_value()
        amount = min(amount, self.config.LIGHTNING_MAX_FUNDING_SAT)
        self.amount_e.setAmount(amount)

    def run(self):
        if not self.exec():
            return
        if self.max_button.isChecked() and self.amount_e.get_amount() < self.config.LIGHTNING_MAX_FUNDING_SAT:
            # if 'max' enabled and amount is strictly less than max allowed,
            # that means we have fewer coins than max allowed, and hence we can
            # spend all coins
            funding_sat = '!'
        else:
            funding_sat = self.amount_e.get_amount()
        if not funding_sat:
            return
        if funding_sat != '!':
            if self.min_amount_sat and funding_sat < self.min_amount_sat:
                self.window.show_error(_('Amount too low'))
                return
        if self.network.channel_db:
            connect_str = str(self.remote_nodeid.text()).strip()
        else:
            name = self.trampoline_names[self.trampoline_combo.currentIndex()]
            connect_str = str(self.trampolines[name])
        if not connect_str:
            return
        self.window.open_channel(connect_str, funding_sat, 0)
        return True
