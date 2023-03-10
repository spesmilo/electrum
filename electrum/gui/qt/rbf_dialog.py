# Copyright (C) 2021 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt
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


from .confirm_tx_dialog import ConfirmTxDialog, TxEditor, TxSizeLabel, HelpLabel

class _BaseRBFDialog(TxEditor):

    def __init__(
            self,
            *,
            main_window: 'ElectrumWindow',
            tx: PartialTransaction,
            txid: str,
            title: str):

        self.wallet = main_window.wallet
        self.old_tx = tx
        assert txid
        self.old_txid = txid
        self.message = ''

        self.old_fee = self.old_tx.get_fee()
        self.old_tx_size = tx.estimated_size()
        self.old_fee_rate = old_fee_rate = self.old_fee / self.old_tx_size  # sat/vbyte

        TxEditor.__init__(
            self,
            window=main_window,
            title=title,
            make_tx=self.rbf_func)

        new_fee_rate = self.old_fee_rate + max(1, self.old_fee_rate // 20)
        self.feerate_e.setAmount(new_fee_rate)
        self.update()
        self.fee_slider.deactivate()
        # are we paying max?
        invoices = self.wallet.get_relevant_invoices_for_tx(txid)
        if len(invoices) == 1 and len(invoices[0].outputs) == 1:
            if invoices[0].outputs[0].value == '!':
                self.set_decrease_payment()
        # do not decrease payment if it is a swap
        if self.wallet.get_swap_by_funding_tx(self.old_tx):
            self.method_combo.setEnabled(False)

    def create_grid(self):
        self.method_label = QLabel(_('Method') + ':')
        self.method_combo = QComboBox()
        self.method_combo.addItems([_('Preserve payment'), _('Decrease payment')])
        self.method_combo.currentIndexChanged.connect(self.trigger_update)
        self.method_combo.setFocusPolicy(Qt.NoFocus)
        old_size_label = TxSizeLabel()
        old_size_label.setAlignment(Qt.AlignCenter)
        old_size_label.setAmount(self.old_tx_size)
        old_size_label.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
        current_fee_hbox = QHBoxLayout()
        current_fee_hbox.addWidget(QLabel(self.main_window.format_fee_rate(1000 * self.old_fee_rate)))
        current_fee_hbox.addWidget(old_size_label)
        current_fee_hbox.addWidget(QLabel(self.main_window.format_amount_and_units(self.old_fee)))
        current_fee_hbox.addStretch()
        grid = QGridLayout()
        grid.addWidget(self.method_label, 0, 0)
        grid.addWidget(self.method_combo, 0, 1)
        grid.addWidget(QLabel(_('Current fee') + ':'), 1, 0)
        grid.addLayout(current_fee_hbox, 1, 1, 1, 3)
        grid.addWidget(QLabel(_('New fee') + ':'), 2, 0)
        grid.addLayout(self.fee_hbox, 2, 1, 1, 3)
        grid.addWidget(HelpLabel(_("Fee target") + ": ", self.fee_combo.help_msg), 4, 0)
        grid.addLayout(self.fee_target_hbox, 4, 1, 1, 3)
        grid.setColumnStretch(4, 1)
        # locktime
        grid.addWidget(self.locktime_label, 5, 0)
        grid.addWidget(self.locktime_e, 5, 1, 1, 2)
        return grid

    def is_decrease_payment(self):
        return self.method_combo.currentIndex() == 1

    def set_decrease_payment(self):
        self.method_combo.setCurrentIndex(1)

    def run(self) -> None:
        if not self.exec_():
            return
        if self.is_preview:
            self.main_window.show_transaction(self.tx)
            return
        def sign_done(success):
            if success:
                self.main_window.broadcast_or_show(self.tx)
        self.main_window.sign_tx(
            self.tx,
            callback=sign_done,
            external_keypairs={})

    def update_tx(self):
        fee_rate = self.feerate_e.get_amount()
        if fee_rate is None:
            self.tx = None
            self.error = _('No fee rate')
        elif fee_rate <= self.old_fee_rate:
            self.tx = None
            self.error = _("The new fee rate needs to be higher than the old fee rate.")
        else:
            try:
                self.tx = self.make_tx(fee_rate)
            except CannotBumpFee as e:
                self.tx = None
                self.error = str(e)

    def get_messages(self):
        messages = super().get_messages()
        if not self.tx:
            return
        delta = self.tx.get_fee() - self.old_tx.get_fee()
        if not self.is_decrease_payment():
            msg = _("You will pay {} more.").format(self.main_window.format_amount_and_units(delta))
        else:
            msg = _("The recipient will receive {} less.").format(self.main_window.format_amount_and_units(delta))
        messages.insert(0, msg)
        return messages


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

    def rbf_func(self, fee_rate, *, confirmed_only=False):
        return self.wallet.bump_fee(
            tx=self.old_tx,
            txid=self.old_txid,
            new_fee_rate=fee_rate,
            coins=self.main_window.get_coins(nonlocal_only=True, confirmed_only=confirmed_only),
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

    def rbf_func(self, fee_rate, *, confirmed_only=False):
        return self.wallet.dscancel(tx=self.old_tx, new_fee_rate=fee_rate)
