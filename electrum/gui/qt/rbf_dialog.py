# Copyright (C) 2021 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import TYPE_CHECKING

from PyQt5.QtWidgets import (QCheckBox, QLabel, QVBoxLayout, QGridLayout, QWidget,
                             QPushButton, QHBoxLayout, QComboBox)

from .amountedit import FeerateEdit
from .fee_slider import FeeSlider, FeeComboBox
from .util import (ColorScheme, WindowModalDialog, Buttons,
                   OkButton, WWLabel, CancelButton)

from electrum.i18n import _
from electrum.transaction import PartialTransaction
from electrum.wallet import CannotBumpFee

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class _BaseRBFDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str,
            title: str):

        WindowModalDialog.__init__(self, main_window, title=title)
        self.window = main_window
        self.wallet = main_window.wallet
        self.tx = tx
        self.new_tx = None
        assert txid
        self.txid = txid
        self.message = ''

        fee = tx.get_fee()
        assert fee is not None
        tx_size = tx.estimated_size()
        self.old_fee_rate = old_fee_rate = fee / tx_size  # sat/vbyte
        vbox = QVBoxLayout(self)
        vbox.addWidget(WWLabel(self.help_text))
        vbox.addStretch(1)

        self.ok_button = OkButton(self)
        self.message_label = QLabel('')
        self.feerate_e = FeerateEdit(lambda: 0)
        self.feerate_e.setAmount(max(old_fee_rate * 1.5, old_fee_rate + 1))
        self.feerate_e.textChanged.connect(self.update)

        def on_slider(dyn, pos, fee_rate):
            fee_slider.activate()
            if fee_rate is not None:
                self.feerate_e.setAmount(fee_rate / 1000)

        fee_slider = FeeSlider(self.window, self.window.config, on_slider)
        fee_combo = FeeComboBox(fee_slider)
        fee_slider.deactivate()
        self.feerate_e.textEdited.connect(fee_slider.deactivate)

        grid = QGridLayout()

        self.method_label = QLabel(_('Method') + ':')
        self.method_combo = QComboBox()
        self.method_combo.addItems([_('Preserve payment'), _('Decrease payment')])
        self.method_combo.currentIndexChanged.connect(self.update)
        grid.addWidget(self.method_label, 0, 0)
        grid.addWidget(self.method_combo, 0, 1)

        grid.addWidget(QLabel(_('Current fee') + ':'), 1, 0)
        grid.addWidget(QLabel(self.window.format_amount_and_units(fee)), 1, 1)
        grid.addWidget(QLabel(_('Current fee rate') + ':'), 2, 0)
        grid.addWidget(QLabel(self.window.format_fee_rate(1000 * old_fee_rate)), 2, 1)

        grid.addWidget(QLabel(_('New fee rate') + ':'), 3, 0)
        grid.addWidget(self.feerate_e, 3, 1)
        grid.addWidget(fee_slider, 3, 2)
        grid.addWidget(fee_combo, 3, 3)
        grid.addWidget(self.message_label, 5, 0, 1, 3)

        vbox.addLayout(grid)
        vbox.addStretch(1)
        btns_hbox = QHBoxLayout()
        btns_hbox.addStretch(1)
        btns_hbox.addWidget(CancelButton(self))
        btns_hbox.addWidget(self.ok_button)
        vbox.addLayout(btns_hbox)

        new_fee_rate = old_fee_rate + max(1, old_fee_rate // 20)
        self.feerate_e.setAmount(new_fee_rate)
        self._update_tx(new_fee_rate)
        self._update_message()
        # give focus to fee slider
        fee_slider.activate()
        fee_slider.setFocus()
        # are we paying max?
        invoices = self.wallet.get_relevant_invoices_for_tx(txid)
        if len(invoices) == 1 and len(invoices[0].outputs) == 1:
            if invoices[0].outputs[0].value == '!':
                self.set_decrease_payment()

    def is_decrease_payment(self):
        return self.method_combo.currentIndex() == 1

    def set_decrease_payment(self):
        self.method_combo.setCurrentIndex(1)

    def rbf_func(self, fee_rate) -> PartialTransaction:
        raise NotImplementedError()  # implemented by subclasses

    def run(self) -> None:
        if not self.exec_():
            return
        self.new_tx.set_rbf(True)
        tx_label = self.wallet.get_label_for_txid(self.txid)
        self.window.show_transaction(self.new_tx, tx_desc=tx_label)
        # TODO maybe save tx_label as label for new tx??

    def update(self):
        fee_rate = self.feerate_e.get_amount()
        self._update_tx(fee_rate)
        self._update_message()

    def _update_tx(self, fee_rate):
        if fee_rate is None:
            self.new_tx = None
            self.message = ''
        elif fee_rate <= self.old_fee_rate:
            self.new_tx = None
            self.message = _("The new fee rate needs to be higher than the old fee rate.")
        else:
            try:
                self.new_tx = self.rbf_func(fee_rate)
            except CannotBumpFee as e:
                self.new_tx = None
                self.message = str(e)
        if not self.new_tx:
            return
        delta = self.new_tx.get_fee() - self.tx.get_fee()
        if not self.is_decrease_payment():
            self.message = _("You will pay {} more.").format(self.window.format_amount_and_units(delta))
        else:
            self.message = _("The recipient will receive {} less.").format(self.window.format_amount_and_units(delta))

    def _update_message(self):
        enabled = bool(self.new_tx)
        self.ok_button.setEnabled(enabled)
        if enabled:
            style = ColorScheme.BLUE.as_stylesheet()
        else:
            style = ColorScheme.RED.as_stylesheet()
        self.message_label.setStyleSheet(style)
        self.message_label.setText(self.message)


class BumpFeeDialog(_BaseRBFDialog):

    help_text = _("Increase your transaction's fee to improve its position in mempool.")

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str):
        _BaseRBFDialog.__init__(
            self,
            main_window=main_window,
            tx=tx,
            txid=txid,
            title=_('Bump Fee'))

    def rbf_func(self, fee_rate):
        return self.wallet.bump_fee(
            tx=self.tx,
            txid=self.txid,
            new_fee_rate=fee_rate,
            coins=self.window.get_coins(),
            decrease_payment=self.is_decrease_payment())


class DSCancelDialog(_BaseRBFDialog):

    help_text = _(
        "Cancel an unconfirmed transaction by replacing it with "
        "a higher-fee transaction that spends back to your wallet.")

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str):
        _BaseRBFDialog.__init__(
            self,
            main_window=main_window,
            tx=tx,
            txid=txid,
            title=_('Cancel transaction'))
        self.method_label.setVisible(False)
        self.method_combo.setVisible(False)

    def rbf_func(self, fee_rate):
        return self.wallet.dscancel(tx=self.tx, new_fee_rate=fee_rate)
