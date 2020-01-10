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

from typing import TYPE_CHECKING, Optional, Union

from PyQt5.QtWidgets import  QVBoxLayout, QLabel, QGridLayout, QPushButton, QLineEdit

from electrum.i18n import _
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.plugin import run_hook
from electrum.transaction import Transaction, PartialTransaction
from electrum.simple_config import FEERATE_WARNING_HIGH_FEE
from electrum.wallet import InternalAddressCorruption

from .util import WindowModalDialog, ColorScheme, HelpLabel, Buttons, CancelButton, BlockingWaitingDialog

from .fee_slider import FeeSlider

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

    def update_tx(self):
        fee_estimator = self.get_fee_estimator()
        try:
            self.tx = self.make_tx(fee_estimator)
            self.not_enough_funds = False
            self.no_dynfee_estimates = False
        except NotEnoughFunds:
            self.not_enough_funds = True
            self.tx = None
            return
        except NoDynamicFeeEstimates:
            self.no_dynfee_estimates = True
            self.tx = None
            try:
                self.tx = self.make_tx(0)
            except BaseException:
                return
        except InternalAddressCorruption as e:
            self.tx = None
            self.main_window.show_error(str(e))
            raise
        use_rbf = bool(self.config.get('use_rbf', True))
        if use_rbf:
            self.tx.set_rbf(True)






class ConfirmTxDialog(TxEditor, WindowModalDialog):
    # set fee and return password (after pw check)

    def __init__(self, *, window: 'ElectrumWindow', make_tx, output_value: Union[int, str], is_sweep: bool):

        TxEditor.__init__(self, window=window, make_tx=make_tx, output_value=output_value, is_sweep=is_sweep)
        WindowModalDialog.__init__(self, window, _("Confirm Transaction"))
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        grid = QGridLayout()
        vbox.addLayout(grid)
        self.amount_label = QLabel('')
        grid.addWidget(QLabel(_("Amount to be sent") + ": "), 0, 0)
        grid.addWidget(self.amount_label, 0, 1)

        msg = _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
              + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
              + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')
        self.fee_label = QLabel('')
        grid.addWidget(HelpLabel(_("Mining fee") + ": ", msg), 1, 0)
        grid.addWidget(self.fee_label, 1, 1)

        self.extra_fee_label = QLabel(_("Additional fees") + ": ")
        self.extra_fee_label.setVisible(False)
        self.extra_fee_value = QLabel('')
        self.extra_fee_value.setVisible(False)
        grid.addWidget(self.extra_fee_label, 2, 0)
        grid.addWidget(self.extra_fee_value, 2, 1)

        self.fee_slider = FeeSlider(self, self.config, self.fee_slider_callback)
        grid.addWidget(self.fee_slider, 5, 1)

        self.message_label = QLabel(self.default_message())
        grid.addWidget(self.message_label, 6, 0, 1, -1)
        self.pw_label = QLabel(_('Password'))
        self.pw_label.setVisible(self.password_required)
        self.pw = QLineEdit()
        self.pw.setEchoMode(2)
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
        return cancelled, self.is_send, password, self.tx

    def on_send(self):
        password = self.pw.text() or None
        if self.password_required:
            if password is None:
                return
            try:
                self.wallet.check_password(password)
            except Exception as e:
                self.main_window.show_error(str(e), parent=self)
                return
        self.is_send = True
        self.accept()

    def disable(self, reason):
        self.message_label.setStyleSheet(ColorScheme.RED.as_stylesheet())
        self.message_label.setText(reason)
        self.pw.setEnabled(False)
        self.send_button.setEnabled(False)

    def enable(self):
        self.message_label.setStyleSheet(None)
        self.message_label.setText(self.default_message())
        self.pw.setEnabled(True)
        self.send_button.setEnabled(True)

    def update(self):
        tx = self.tx
        amount = tx.output_value() if self.output_value == '!' else self.output_value
        self.amount_label.setText(self.main_window.format_amount_and_units(amount))

        if self.not_enough_funds:
            text = _("Not enough funds")
            c, u, x = self.wallet.get_frozen_balance()
            if c+u+x:
                text += " ({} {} {})".format(
                    self.main_window.format_amount(c + u + x).strip(), self.main_window.base_unit(), _("are frozen")
                )
            self.disable(text)
            return

        if not tx:
            return

        fee = tx.get_fee()
        self.fee_label.setText(self.main_window.format_amount_and_units(fee))
        x_fee = run_hook('get_tx_extra_fee', self.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            self.extra_fee_label.setVisible(True)
            self.extra_fee_value.setVisible(True)
            self.extra_fee_value.setText(self.main_window.format_amount_and_units(x_fee_amount))

        feerate_warning = FEERATE_WARNING_HIGH_FEE
        low_fee = fee < self.wallet.relayfee() * tx.estimated_size() / 1000
        high_fee = fee > feerate_warning * tx.estimated_size() / 1000
        if low_fee:
            msg = '\n'.join([
                _("This transaction requires a higher fee, or it will not be propagated by your current server"),
                _("Try to raise your transaction fee, or use a server with a lower relay fee.")
            ])
            self.disable(msg)
        elif high_fee:
            self.disable(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))
        else:
            self.enable()
