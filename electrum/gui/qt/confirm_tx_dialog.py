#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (2019) The Electrum Developers
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

from decimal import Decimal
from typing import TYPE_CHECKING, Optional, Union

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QGridLayout, QPushButton, QLineEdit

from electrum.i18n import _
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.plugin import run_hook
from electrum.transaction import Transaction, PartialTransaction
from electrum.wallet import InternalAddressCorruption

from .util import (WindowModalDialog, ColorScheme, HelpLabel, Buttons, CancelButton,
                   BlockingWaitingDialog, PasswordLineEdit, WWLabel)

from .fee_slider import FeeSlider, FeeComboBox

if TYPE_CHECKING:
    from .main_window import ElectrumWindow



class TxEditor:

    def __init__(self, *, window: 'ElectrumWindow', make_tx,
                 output_value: Union[int, str] = None, is_sweep: bool):
        self.main_window = window
        self.make_tx = make_tx
        self.output_value = output_value
        self.tx = None  # type: Optional[PartialTransaction]
        self.config = window.config
        self.wallet = window.wallet
        self.not_enough_funds = False
        self.no_dynfee_estimates = False
        self.needs_update = False
        self.password_required = self.wallet.has_keystore_encryption() and not is_sweep
        self.main_window.gui_object.timer.timeout.connect(self.timer_actions)

    def timer_actions(self):
        if self.needs_update:
            self.update_tx()
            self.update()
            self.needs_update = False

    def stop_editor_updates(self):
        self.main_window.gui_object.timer.timeout.disconnect(self.timer_actions)

    def fee_slider_callback(self, dyn, pos, fee_rate):
        if dyn:
            if self.config.use_mempool_fees():
                self.config.set_key('depth_level', pos, False)
            else:
                self.config.set_key('fee_level', pos, False)
        else:
            self.config.set_key('fee_per_kb', fee_rate, False)
        self.needs_update = True

    def get_fee_estimator(self):
        return None

    def update_tx(self, *, fallback_to_zero_fee: bool = False):
        fee_estimator = self.get_fee_estimator()
        try:
            self.tx = self.make_tx(fee_estimator)
            self.not_enough_funds = False
            self.no_dynfee_estimates = False
        except NotEnoughFunds:
            self.not_enough_funds = True
            self.tx = None
            if fallback_to_zero_fee:
                try:
                    self.tx = self.make_tx(0)
                except BaseException:
                    return
            else:
                return
        except NoDynamicFeeEstimates:
            self.no_dynfee_estimates = True
            self.tx = None
            try:
                self.tx = self.make_tx(0)
            except NotEnoughFunds:
                self.not_enough_funds = True
                return
            except BaseException:
                return
        except InternalAddressCorruption as e:
            self.tx = None
            self.main_window.show_error(str(e))
            raise
        use_rbf = bool(self.config.get('use_rbf', True))
        self.tx.set_rbf(use_rbf)

    def have_enough_funds_assuming_zero_fees(self) -> bool:
        try:
            tx = self.make_tx(0)
        except NotEnoughFunds:
            return False
        else:
            return True




class ConfirmTxDialog(TxEditor, WindowModalDialog):
    # set fee and return password (after pw check)

    def __init__(self, *, window: 'ElectrumWindow', make_tx, output_value: Union[int, str], is_sweep: bool):

        TxEditor.__init__(self, window=window, make_tx=make_tx, output_value=output_value, is_sweep=is_sweep)
        WindowModalDialog.__init__(self, window, _("Confirm Transaction"))
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        grid = QGridLayout()
        vbox.addLayout(grid)

        msg = (_('The amount to be received by the recipient.') + ' '
               + _('Fees are paid by the sender.'))
        self.amount_label = QLabel('')
        self.amount_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        grid.addWidget(HelpLabel(_("Amount to be sent") + ": ", msg), 0, 0)
        grid.addWidget(self.amount_label, 0, 1)

        msg = _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
              + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
              + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')
        self.fee_label = QLabel('')
        self.fee_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        grid.addWidget(HelpLabel(_("Mining fee") + ": ", msg), 1, 0)
        grid.addWidget(self.fee_label, 1, 1)

        self.extra_fee_label = QLabel(_("Additional fees") + ": ")
        self.extra_fee_label.setVisible(False)
        self.extra_fee_value = QLabel('')
        self.extra_fee_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.extra_fee_value.setVisible(False)
        grid.addWidget(self.extra_fee_label, 2, 0)
        grid.addWidget(self.extra_fee_value, 2, 1)

        self.fee_slider = FeeSlider(self, self.config, self.fee_slider_callback)
        self.fee_combo = FeeComboBox(self.fee_slider)
        grid.addWidget(HelpLabel(_("Fee rate") + ": ", self.fee_combo.help_msg), 5, 0)
        grid.addWidget(self.fee_slider, 5, 1)
        grid.addWidget(self.fee_combo, 5, 2)

        self.message_label = WWLabel(self.default_message())
        grid.addWidget(self.message_label, 6, 0, 1, -1)
        self.pw_label = QLabel(_('Password'))
        self.pw_label.setVisible(self.password_required)
        self.pw = PasswordLineEdit()
        self.pw.setVisible(self.password_required)
        grid.addWidget(self.pw_label, 8, 0)
        grid.addWidget(self.pw, 8, 1, 1, -1)
        self.preview_button = QPushButton(_('Advanced'))
        self.preview_button.clicked.connect(self.on_preview)
        grid.addWidget(self.preview_button, 0, 2)
        self.send_button = QPushButton(_('Send'))
        self.send_button.clicked.connect(self.on_send)
        self.send_button.setDefault(True)
        vbox.addLayout(Buttons(CancelButton(self), self.send_button))
        BlockingWaitingDialog(window, _("Preparing transaction..."), self.update_tx)
        self.update()
        self.is_send = False

    def default_message(self):
        return _('Enter your password to proceed') if self.password_required else _('Click Send to proceed')

    def on_preview(self):
        self.accept()

    def run(self):
        cancelled = not self.exec_()
        password = self.pw.text() or None
        self.stop_editor_updates()
        self.deleteLater()  # see #3956
        return cancelled, self.is_send, password, self.tx

    def on_send(self):
        password = self.pw.text() or None
        if self.password_required:
            if password is None:
                self.main_window.show_error(_("Password required"), parent=self)
                return
            try:
                self.wallet.check_password(password)
            except Exception as e:
                self.main_window.show_error(str(e), parent=self)
                return
        self.is_send = True
        self.accept()

    def toggle_send_button(self, enable: bool, *, message: str = None):
        if message is None:
            self.message_label.setStyleSheet(None)
            self.message_label.setText(self.default_message())
        else:
            self.message_label.setStyleSheet(ColorScheme.RED.as_stylesheet())
            self.message_label.setText(message)
        self.pw.setEnabled(enable)
        self.send_button.setEnabled(enable)

    def _update_amount_label(self):
        tx = self.tx
        if self.output_value == '!':
            if tx:
                amount = tx.output_value()
                amount_str = self.main_window.format_amount_and_units(amount)
            else:
                amount_str = "max"
        else:
            amount = self.output_value
            amount_str = self.main_window.format_amount_and_units(amount)
        self.amount_label.setText(amount_str)

    def update(self):
        tx = self.tx
        self._update_amount_label()

        if self.not_enough_funds:
            text = self.main_window.send_tab.get_text_not_enough_funds_mentioning_frozen()
            self.toggle_send_button(False, message=text)
            return

        if not tx:
            return

        fee = tx.get_fee()
        assert fee is not None
        self.fee_label.setText(self.main_window.format_amount_and_units(fee))
        x_fee = run_hook('get_tx_extra_fee', self.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            self.extra_fee_label.setVisible(True)
            self.extra_fee_value.setVisible(True)
            self.extra_fee_value.setText(self.main_window.format_amount_and_units(x_fee_amount))

        amount = tx.output_value() if self.output_value == '!' else self.output_value
        tx_size = tx.estimated_size()
        fee_warning_tuple = self.wallet.get_tx_fee_warning(
            invoice_amt=amount, tx_size=tx_size, fee=fee)
        if fee_warning_tuple:
            allow_send, long_warning, short_warning = fee_warning_tuple
            self.toggle_send_button(allow_send, message=long_warning)
        else:
            self.toggle_send_button(True)
