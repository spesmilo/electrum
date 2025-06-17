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
from functools import partial
from typing import TYPE_CHECKING, Optional, Union, Callable

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QLabel, QGridLayout, QPushButton, QToolButton, QMenu, QComboBox

from electrum.i18n import _
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.util import quantize_feerate
from electrum.plugin import run_hook
from electrum.transaction import Transaction, PartialTransaction
from electrum.wallet import InternalAddressCorruption
from electrum.bitcoin import DummyAddress
from electrum.fee_policy import FeePolicy, FixedFeePolicy, FeeMethod

from .util import (WindowModalDialog, ColorScheme, HelpLabel, Buttons, CancelButton,
                   WWLabel, read_QIcon)
from .transaction_dialog import TxSizeLabel, TxFiatLabel, TxInOutWidget
from .fee_slider import FeeSlider, FeeComboBox
from .amountedit import FeerateEdit, BTCAmountEdit
from .locktimeedit import LockTimeEdit
from .my_treeview import QMenuWithConfig

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class TxEditor(WindowModalDialog):

    def __init__(
            self, *, title='',
            window: 'ElectrumWindow',
            make_tx,
            output_value: Union[int, str],
            allow_preview=True,
            batching_candidates=None,
    ):

        WindowModalDialog.__init__(self, window, title=title)
        self.main_window = window
        self.make_tx = make_tx
        self.output_value = output_value
        self.tx = None  # type: Optional[PartialTransaction]
        self.messages = []
        self.error = ''   # set by side effect

        self.config = window.config
        self.network = window.network
        self.fee_policy = FeePolicy(self.config.FEE_POLICY)
        self.wallet = window.wallet
        self.feerounding_sats = 0
        self.not_enough_funds = False
        self.no_dynfee_estimates = False
        self.needs_update = False
        # preview is disabled for lightning channel funding
        self.allow_preview = allow_preview
        self.is_preview = False
        self._base_tx = None # for batching
        self.batching_candidates = batching_candidates

        self.locktime_e = LockTimeEdit(self)
        self.locktime_e.valueEdited.connect(self.trigger_update)
        self.locktime_label = QLabel(_("LockTime") + ": ")
        self.io_widget = TxInOutWidget(self.main_window, self.wallet)
        self.create_fee_controls()

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        top = self.create_top_bar(self.help_text)
        grid = self.create_grid()

        vbox.addLayout(top)
        vbox.addLayout(grid)
        vbox.addWidget(self.io_widget)
        self.message_label = WWLabel('')
        self.message_label.setMinimumHeight(70)
        vbox.addWidget(self.message_label)

        buttons = self.create_buttons_bar()
        vbox.addStretch(1)
        vbox.addLayout(buttons)

        self.set_io_visible()
        self.set_fee_edit_visible()
        self.set_locktime_visible()
        self.update_fee_target()
        self.resize(self.layout().sizeHint())

        self.main_window.gui_object.timer.timeout.connect(self.timer_actions)

    def is_batching(self) -> bool:
        return self._base_tx is not None

    def timer_actions(self):
        if self.needs_update:
            self.update()
            self.needs_update = False

    def update(self):
        self.update_tx()
        self.set_locktime()
        self._update_widgets()

    def stop_editor_updates(self):
        self.main_window.gui_object.timer.timeout.disconnect(self.timer_actions)

    def update_tx(self, *, fallback_to_zero_fee: bool = False):
        # expected to set self.tx, self.message and self.error
        raise NotImplementedError()

    def update_fee_target(self):
        text = self.fee_slider.fee_policy.get_target_text()
        self.fee_target.setText(text)
        # self.fee_target.setVisible(self.fee_slider.fee_policy.use_dynamic_estimates) # hide in static mode

    def update_feerate_label(self):
        self.feerate_label.setText(self.feerate_e.text() + ' ' + self.feerate_e.base_unit())

    def create_fee_controls(self):

        self.fee_label = QLabel('')
        self.fee_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.size_label = TxSizeLabel()
        self.size_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.size_label.setAmount(0)
        self.size_label.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())

        self.feerate_label = QLabel('')
        self.feerate_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.fiat_fee_label = TxFiatLabel()
        self.fiat_fee_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.fiat_fee_label.setAmount(0)
        self.fiat_fee_label.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())

        self.feerate_e = FeerateEdit(lambda: 0)
        self.feerate_e.textEdited.connect(partial(self.on_fee_or_feerate, self.feerate_e, False))
        self.feerate_e.editingFinished.connect(partial(self.on_fee_or_feerate, self.feerate_e, True))
        self.update_feerate_label()

        self.fee_e = BTCAmountEdit(self.main_window.get_decimal_point)
        self.fee_e.textEdited.connect(partial(self.on_fee_or_feerate, self.fee_e, False))
        self.fee_e.editingFinished.connect(partial(self.on_fee_or_feerate, self.fee_e, True))

        self.feerate_e.setFixedWidth(150)
        self.fee_e.setFixedWidth(150)

        if self.fee_policy.method != FeeMethod.FIXED:
            self.feerate_e.setAmount(self.fee_policy.fee_per_byte(self.network))
        else:
            self.fee_e.setAmount(self.fee_policy.value)

        self.fee_e.textChanged.connect(self.entry_changed)
        self.feerate_e.textChanged.connect(self.entry_changed)

        self.fee_target = QLabel('')
        self.fee_slider = FeeSlider(parent=self, network=self.network, fee_policy=self.fee_policy, callback=self.fee_slider_callback)
        self.fee_combo = FeeComboBox(self.fee_slider)
        self.fee_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        def feerounding_onclick():
            text = (self.feerounding_text() + '\n\n' +
                    _('To somewhat protect your privacy, Electrum tries to create change with similar precision to other outputs.') + ' ' +
                    _('At most 100 satoshis might be lost due to this rounding.') + ' ' +
                    _("You can disable this setting in '{}'.").format(_('Preferences')) + '\n' +
                    _('Also, dust is not kept as change, but added to the fee.')  + '\n' +
                    _('Also, when batching RBF transactions, BIP 125 imposes a lower bound on the fee.'))
            self.show_message(title=_('Fee rounding'), msg=text)

        self.feerounding_icon = QToolButton()
        self.feerounding_icon.setStyleSheet("background-color: rgba(255, 255, 255, 0); ")
        self.feerounding_icon.setAutoRaise(True)
        self.feerounding_icon.clicked.connect(feerounding_onclick)
        self.set_feerounding_visibility(False)

        self.fee_hbox = fee_hbox = QHBoxLayout()
        fee_hbox.addWidget(self.feerate_e)
        fee_hbox.addWidget(self.feerate_label)
        fee_hbox.addWidget(self.size_label)
        fee_hbox.addWidget(self.fee_e)
        fee_hbox.addWidget(self.fee_label)
        fee_hbox.addWidget(self.fiat_fee_label)
        fee_hbox.addWidget(self.feerounding_icon)
        fee_hbox.addStretch()

        self.fee_target_hbox = fee_target_hbox = QHBoxLayout()
        fee_target_hbox.addWidget(self.fee_target)
        fee_target_hbox.addWidget(self.fee_slider)
        fee_target_hbox.addWidget(self.fee_combo)
        fee_target_hbox.addStretch()

        # set feerate_label to same size as feerate_e
        self.feerate_label.setFixedSize(self.feerate_e.sizeHint())
        self.fee_label.setFixedSize(self.fee_e.sizeHint())
        self.fee_slider.setFixedWidth(200)
        self.fee_target.setFixedSize(self.feerate_e.sizeHint())

    def trigger_update(self):
        # set tx to None so that the ok button is disabled while we compute the new tx
        self.tx = None
        self.messages = []
        self.error = ''
        self._update_widgets()
        self.needs_update = True

    def fee_slider_callback(self, fee_rate):
        if self.fee_policy.method == FeeMethod.FIXED:
            return
        self.config.FEE_POLICY = self.fee_policy.get_descriptor()
        self.fee_slider.activate()
        if fee_rate:
            fee_rate = Decimal(fee_rate)
            self.feerate_e.setAmount(quantize_feerate(fee_rate / 1000))
        else:
            self.feerate_e.setAmount(None)
        self.fee_e.setModified(False)
        self.update_fee_target()
        self.update_feerate_label()
        self.trigger_update()

    def on_fee_or_feerate(self, edit_changed, editing_finished):
        edit_other = self.feerate_e if edit_changed == self.fee_e else self.fee_e
        if editing_finished:
            if edit_changed.get_amount() is None:
                # This is so that when the user blanks the fee and moves on,
                # we go back to auto-calculate mode and put a fee back.
                edit_changed.setModified(False)
        else:
            # edit_changed was edited just now, so make sure we will
            # freeze the correct fee setting (this)
            edit_other.setModified(False)
            self.fee_slider.deactivate()
            # do not call trigger_update on editing_finished,
            # because that event is emitted when we press OK
            self.trigger_update()

    def is_send_fee_frozen(self) -> bool:
        return self.fee_e.isVisible() and self.fee_e.isModified() \
               and (bool(self.fee_e.text()) or self.fee_e.hasFocus())

    def is_send_feerate_frozen(self) -> bool:
        return self.feerate_e.isVisible() and self.feerate_e.isModified() \
               and (bool(self.feerate_e.text()) or self.feerate_e.hasFocus())

    def feerounding_text(self):
        return (_('Additional {} satoshis are going to be added.').format(self.feerounding_sats))

    def set_feerounding_visibility(self, b:bool):
        # we do not use setVisible because it affects the layout
        self.feerounding_icon.setIcon(read_QIcon('info.png') if b else QIcon())
        self.feerounding_icon.setEnabled(b)

    def get_fee_policy(self):
        feerate = self.feerate_e.get_amount()
        fee_amount = self.fee_e.get_amount()
        if self.is_send_fee_frozen() and fee_amount is not None:
            fee_policy = FixedFeePolicy(fee_amount)
        elif self.is_send_feerate_frozen() and feerate is not None:
            feerate_per_kb = int(feerate * 1000)
            fee_policy = FeePolicy(f'static:{feerate_per_kb}')
        else:
            fee_policy = self.fee_slider.get_policy()
        return fee_policy

    def entry_changed(self):
        # blue color denotes auto-filled values
        text = ""
        fee_color = ColorScheme.DEFAULT
        feerate_color = ColorScheme.DEFAULT
        if self.not_enough_funds:
            fee_color = ColorScheme.RED
            feerate_color = ColorScheme.RED
        elif self.fee_e.isModified():
            feerate_color = ColorScheme.BLUE
        elif self.feerate_e.isModified():
            fee_color = ColorScheme.BLUE
        else:
            fee_color = ColorScheme.BLUE
            feerate_color = ColorScheme.BLUE
        self.fee_e.setStyleSheet(fee_color.as_stylesheet())
        self.feerate_e.setStyleSheet(feerate_color.as_stylesheet())
        #
        self.needs_update = True

    def update_fee_fields(self):
        freeze_fee = self.is_send_fee_frozen()
        freeze_feerate = self.is_send_feerate_frozen()
        tx = self.tx
        if self.no_dynfee_estimates and tx:
            size = tx.estimated_size()
            self.size_label.setAmount(size)
            #self.size_e.setAmount(size)
        if self.not_enough_funds or self.no_dynfee_estimates:
            if not freeze_fee:
                self.fee_e.setAmount(None)
            if not freeze_feerate:
                self.feerate_e.setAmount(None)
            self.set_feerounding_visibility(False)
            return

        assert tx is not None
        size = tx.estimated_size()
        fee = tx.get_fee()

        #self.size_e.setAmount(size)
        self.size_label.setAmount(size)
        fiat_fee = self.main_window.format_fiat_and_units(fee)
        self.fiat_fee_label.setAmount(fiat_fee)

        # Displayed fee/fee_rate values are set according to user input.
        # Due to rounding or dropping dust in CoinChooser,
        # actual fees often differ somewhat.
        if freeze_feerate or self.fee_slider.is_active():
            displayed_feerate = self.feerate_e.get_amount()
            if displayed_feerate is not None:
                displayed_feerate = quantize_feerate(displayed_feerate)
            elif self.fee_slider.is_active():
                # fallback to actual fee
                displayed_feerate = quantize_feerate(fee / size) if fee is not None else None
                self.feerate_e.setAmount(displayed_feerate)
            displayed_fee = round(displayed_feerate * size) if displayed_feerate is not None else None
            self.fee_e.setAmount(displayed_fee)
        else:
            if freeze_fee:
                displayed_fee = self.fee_e.get_amount()
            else:
                # fallback to actual fee if nothing is frozen
                displayed_fee = fee
                self.fee_e.setAmount(displayed_fee)
            displayed_fee = displayed_fee if displayed_fee else 0
            displayed_feerate = quantize_feerate(displayed_fee / size) if displayed_fee is not None else None
            self.feerate_e.setAmount(displayed_feerate)

        # set fee rounding icon to empty if there is no rounding
        feerounding = (fee - displayed_fee) if (fee and displayed_fee is not None) else 0
        self.feerounding_sats = int(feerounding)
        self.feerounding_icon.setToolTip(self.feerounding_text())
        self.set_feerounding_visibility(abs(feerounding) >= 1)
        # feerate_label needs to be updated from feerate_e
        self.update_feerate_label()

    def create_buttons_bar(self):
        self.preview_button = QPushButton(_('Preview'))
        self.preview_button.clicked.connect(self.on_preview)
        self.preview_button.setVisible(self.allow_preview)
        self.ok_button = QPushButton(_('OK'))
        self.ok_button.clicked.connect(self.on_send)
        self.ok_button.setDefault(True)
        buttons = Buttons(CancelButton(self), self.preview_button, self.ok_button)

        if self.batching_candidates is not None and len(self.batching_candidates) > 0:
            batching_combo = QComboBox()
            batching_combo.addItems([_('Do not batch')] + [_('Batch with') + ' ' + tx.txid()[0:10] for tx in self.batching_candidates])
            buttons.insertWidget(0, batching_combo)
            def on_batching_combo(x):
                self._base_tx = self.batching_candidates[x - 1] if x > 0 else None
                self.trigger_update()
            batching_combo.currentIndexChanged.connect(on_batching_combo)
        return buttons

    def create_top_bar(self, text):
        self.pref_menu = QMenuWithConfig(self.config)

        def cb():
            self.set_io_visible()
            self.resize_to_fit_content()
        self.pref_menu.addConfig(self.config.cv.GUI_QT_TX_EDITOR_SHOW_IO, callback=cb)
        def cb():
            self.set_fee_edit_visible()
            self.resize_to_fit_content()
        self.pref_menu.addConfig(self.config.cv.GUI_QT_TX_EDITOR_SHOW_FEE_DETAILS, callback=cb)
        def cb():
            self.set_locktime_visible()
            self.resize_to_fit_content()
        self.pref_menu.addConfig(self.config.cv.GUI_QT_TX_EDITOR_SHOW_LOCKTIME, callback=cb)
        self.pref_menu.addSeparator()
        self.pref_menu.addConfig(self.config.cv.WALLET_SEND_CHANGE_TO_LIGHTNING, callback=self.trigger_update)
        self.pref_menu.addToggle(
            _('Use change addresses'),
            self.toggle_use_change,
            default_state=self.wallet.use_change,
            tooltip=_('Using change addresses makes it more difficult for other people to track your transactions.'))
        self.use_multi_change_menu = self.pref_menu.addToggle(
            _('Use multiple change addresses'),
            self.toggle_multiple_change,
            default_state=self.wallet.multiple_change,
            tooltip='\n'.join([
                _('In some cases, use up to 3 change addresses in order to break '
                  'up large coin amounts and obfuscate the recipient address.'),
                _('This may result in higher transactions fees.')
            ]))
        self.use_multi_change_menu.setEnabled(self.wallet.use_change)
        # fixme: some of these options (WALLET_SEND_CHANGE_TO_LIGHTNING, WALLET_MERGE_DUPLICATE_OUTPUTS)
        # only make sense when we create a new tx, and should not be visible/enabled in rbf dialog
        self.pref_menu.addConfig(self.config.cv.WALLET_MERGE_DUPLICATE_OUTPUTS, callback=self.trigger_update)
        self.pref_menu.addConfig(self.config.cv.WALLET_SPEND_CONFIRMED_ONLY, callback=self.trigger_update)
        self.pref_menu.addConfig(self.config.cv.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING, callback=self.trigger_update)
        self.pref_button = QToolButton()
        self.pref_button.setIcon(read_QIcon("preferences.png"))
        self.pref_button.setMenu(self.pref_menu)
        self.pref_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.pref_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(text))
        hbox.addStretch()
        hbox.addWidget(self.pref_button)
        return hbox

    def resize_to_fit_content(self):
        # fixme: calling resize once is not enough...
        size = self.layout().sizeHint()
        self.resize(size)
        self.resize(size)

    def toggle_use_change(self):
        self.wallet.use_change = not self.wallet.use_change
        self.wallet.db.put('use_change', self.wallet.use_change)
        self.use_multi_change_menu.setEnabled(self.wallet.use_change)
        self.trigger_update()

    def toggle_multiple_change(self):
        self.wallet.multiple_change = not self.wallet.multiple_change
        self.wallet.db.put('multiple_change', self.wallet.multiple_change)
        self.trigger_update()

    def set_io_visible(self):
        self.io_widget.setVisible(self.config.GUI_QT_TX_EDITOR_SHOW_IO)

    def set_fee_edit_visible(self):
        b = self.config.GUI_QT_TX_EDITOR_SHOW_FEE_DETAILS
        detailed = [self.feerounding_icon, self.feerate_e, self.fee_e]
        basic = [self.fee_label, self.feerate_label]
        # first hide, then show
        for w in (basic if b else detailed):
            w.hide()
        for w in (detailed if b else basic):
            w.show()

    def set_locktime_visible(self):
        b = self.config.GUI_QT_TX_EDITOR_SHOW_LOCKTIME
        for w in [
                self.locktime_e,
                self.locktime_label]:
            w.setVisible(b)

    def run(self):
        cancelled = not self.exec()
        self.stop_editor_updates()
        self.deleteLater()  # see #3956
        return self.tx if not cancelled else None

    def on_send(self):
        self.accept()

    def on_preview(self):
        self.is_preview = True
        self.accept()

    def _update_widgets(self):
        # side effect: self.error
        self._update_amount_label()
        if self.not_enough_funds:
            self.error = _('Not enough funds.')
            confirmed_only = self.config.WALLET_SPEND_CONFIRMED_ONLY
            if confirmed_only and self.can_pay_assuming_zero_fees(confirmed_only=False):
                self.error += ' ' + _('Change your settings to allow spending unconfirmed coins.')
            elif self.can_pay_assuming_zero_fees(confirmed_only=confirmed_only):
                self.error += ' ' + _('You need to set a lower fee.')
            elif frozen_bal := self.wallet.get_frozen_balance_str():
                self.error = self.wallet.get_text_not_enough_funds_mentioning_frozen(
                    for_amount=self.output_value,
                    hint=_('Can be unfrozen in the Addresses or in the Coins tab')
                )
        if not self.tx:
            if self.not_enough_funds:
                self.io_widget.update(None)
            self.set_feerounding_visibility(False)
            self.messages = [_('Preparing transaction...')]
        else:
            self.messages = self.get_messages()
            self.update_fee_fields()
            if self.locktime_e.get_locktime() is None:
                self.locktime_e.set_locktime(self.tx.locktime)
            self.io_widget.update(self.tx)
            self.fee_label.setText(self.main_window.config.format_amount_and_units(self.tx.get_fee()))
            self._update_extra_fees()

        self._update_send_button()
        self._update_message()

    def get_messages(self):
        # side effect: self.error
        messages = []
        fee = self.tx.get_fee()
        assert fee is not None
        amount = self.tx.output_value() if self.output_value == '!' else self.output_value
        tx_size = self.tx.estimated_size()
        fee_warning_tuple = self.wallet.get_tx_fee_warning(
            invoice_amt=amount, tx_size=tx_size, fee=fee, txid=self.tx.txid())
        if fee_warning_tuple:
            allow_send, long_warning, short_warning = fee_warning_tuple
            if not allow_send:
                self.error = long_warning
            else:
                messages.append(long_warning)
        if self.no_dynfee_estimates:
            self.error = _('Fee estimates not available. Please set a fixed fee or feerate.')
        if self.tx.get_dummy_output(DummyAddress.SWAP):
            messages.append(_('This transaction will send funds to a submarine swap.'))
        # warn if spending unconf
        if any((txin.block_height is not None and txin.block_height<=0) for txin in self.tx.inputs()):
            messages.append(_('This transaction will spend unconfirmed coins.'))
        # warn if a reserve utxo was added
        if reserve_sats := sum(txo.value for txo in self.tx.outputs() if txo.is_utxo_reserve):
            reserve_str = self.main_window.config.format_amount_and_units(reserve_sats)
            messages.append(_('Could not spend max: a security reserve of {} was kept for your Lightning channels.').format(reserve_str))
        # warn if we merge from mempool
        if self.is_batching():
            messages.append(_('This payment will be merged with another existing transaction.'))
        # warn if we use multiple change outputs
        num_change = sum(int(o.is_change) for o in self.tx.outputs())
        num_ismine = sum(int(o.is_mine) for o in self.tx.outputs())
        if num_change > 1:
            messages.append(_('This transaction has {} change outputs.'.format(num_change)))
        # warn if there is no ismine output, as it might be problematic to RBF the tx later.
        # (though RBF is still possible by adding new inputs, if the wallet has more utxos)
        if num_ismine == 0:
            messages.append(_('Make sure you pay enough mining fees; you will not be able to bump the fee later.'))

        # TODO: warn if we send change back to input address
        return messages

    def set_locktime(self):
        if not self.tx:
            return
        locktime = self.locktime_e.get_locktime()
        if locktime is not None:
            self.tx.locktime = locktime

    def _update_amount_label(self):
        pass

    def _update_extra_fees(self):
        pass

    def _update_message(self):
        style = ColorScheme.RED if self.error else ColorScheme.BLUE
        message_str = '\n'.join(self.messages) if self.messages else ''
        self.message_label.setStyleSheet(style.as_stylesheet())
        self.message_label.setText(self.error or message_str)

    def _update_send_button(self):
        enabled = bool(self.tx) and not self.error
        self.preview_button.setEnabled(enabled)
        self.ok_button.setEnabled(enabled)

    def can_pay_assuming_zero_fees(self, confirmed_only: bool) -> bool:
        raise NotImplementedError


class ConfirmTxDialog(TxEditor):
    help_text = ''  #_('Set the mining fee of your transaction')

    def __init__(self, *, window: 'ElectrumWindow', make_tx, output_value: Union[int, str], allow_preview=True, batching_candidates=None):

        TxEditor.__init__(
            self,
            window=window,
            make_tx=make_tx,
            output_value=output_value,
            title=_("New Transaction"), # todo: adapt title for channel funding tx, swaps
            allow_preview=allow_preview, # false for channel funding
            batching_candidates=batching_candidates,
        )
        self.trigger_update()

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

    def update_tx(self, *, fallback_to_zero_fee: bool = False):
        fee_policy = self.get_fee_policy()
        confirmed_only = self.config.WALLET_SPEND_CONFIRMED_ONLY
        base_tx = self._base_tx
        try:
            self.tx = self.make_tx(fee_policy, confirmed_only=confirmed_only, base_tx=base_tx)
            self.not_enough_funds = False
            self.no_dynfee_estimates = False
        except NotEnoughFunds:
            self.not_enough_funds = True
            self.tx = None
            if fallback_to_zero_fee:
                try:
                    self.tx = self.make_tx(FixedFeePolicy(0), confirmed_only=confirmed_only, base_tx=base_tx)
                except BaseException:
                    return
            else:
                return
        except NoDynamicFeeEstimates:
            # is this still needed?
            self.no_dynfee_estimates = True
            self.tx = None
            try:
                self.tx = self.make_tx(FixedFeePolicy(0), confirmed_only=confirmed_only, base_tx=base_tx)
            except NotEnoughFunds:
                self.not_enough_funds = True
                return
            except BaseException:
                return
        except InternalAddressCorruption as e:
            self.tx = None
            self.main_window.show_error(str(e))
            raise
        self.tx.set_rbf(True)

    def can_pay_assuming_zero_fees(self, confirmed_only: bool) -> bool:
        # called in send_tab.py
        try:
            tx = self.make_tx(FixedFeePolicy(0), confirmed_only=confirmed_only, base_tx=None)
        except NotEnoughFunds:
            return False
        else:
            return True

    def create_grid(self):
        grid = QGridLayout()
        msg = (_('The amount to be received by the recipient.') + ' '
               + _('Fees are paid by the sender.'))
        self.amount_label = QLabel('')
        self.amount_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        grid.addWidget(HelpLabel(_("Amount to be sent") + ": ", msg), 0, 0)
        grid.addWidget(self.amount_label, 0, 1)

        msg = _('Bitcoin transactions are in general not free. A transaction fee is paid by the sender of the funds.') + '\n\n'\
              + _('The amount of fee can be decided freely by the sender. However, transactions with low fees take more time to be processed.') + '\n\n'\
              + _('A suggested fee is automatically added to this field. You may override it. The suggested fee increases with the size of the transaction.')

        grid.addWidget(HelpLabel(_("Mining Fee") + ": ", msg), 1, 0)
        grid.addLayout(self.fee_hbox, 1, 1, 1, 3)

        grid.addWidget(HelpLabel(_("Fee policy") + ": ", self.fee_combo.help_msg), 3, 0)
        grid.addLayout(self.fee_target_hbox, 3, 1, 1, 3)

        grid.setColumnStretch(4, 1)

        # extra fee
        self.extra_fee_label = QLabel(_("Additional fees") + ": ")
        self.extra_fee_label.setVisible(False)
        self.extra_fee_value = QLabel('')
        self.extra_fee_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.extra_fee_value.setVisible(False)
        grid.addWidget(self.extra_fee_label, 5, 0)
        grid.addWidget(self.extra_fee_value, 5, 1)

        # locktime editor
        grid.addWidget(self.locktime_label, 6, 0)
        grid.addWidget(self.locktime_e, 6, 1, 1, 2)

        return grid

    def _update_extra_fees(self):
        x_fee = run_hook('get_tx_extra_fee', self.wallet, self.tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            self.extra_fee_label.setVisible(True)
            self.extra_fee_value.setVisible(True)
            self.extra_fee_value.setText(self.main_window.format_amount_and_units(x_fee_amount))
