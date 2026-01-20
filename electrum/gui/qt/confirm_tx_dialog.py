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

import asyncio
from decimal import Decimal
from functools import partial
from typing import TYPE_CHECKING, Optional, Union
from concurrent.futures import Future
from enum import Enum, auto

from PyQt6.QtCore import Qt, QTimer, pyqtSlot, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (QHBoxLayout, QVBoxLayout, QLabel, QGridLayout, QPushButton, QToolButton,
                             QComboBox, QTabWidget, QWidget, QStackedWidget)

from electrum.i18n import _
from electrum.util import (UserCancelled, quantize_feerate, profiler, NotEnoughFunds, NoDynamicFeeEstimates,
                           get_asyncio_loop, wait_for2, UserFacingException)
from electrum.plugin import run_hook
from electrum.transaction import PartialTransaction, PartialTxOutput
from electrum.wallet import InternalAddressCorruption
from electrum.bitcoin import DummyAddress
from electrum.fee_policy import FeePolicy, FixedFeePolicy, FeeMethod
from electrum.logging import Logger
from electrum.submarine_swaps import NostrTransport, HttpTransport, SwapServerTransport, SwapServerError
from electrum.gui.messages import MSG_SUBMARINE_PAYMENT_HELP_TEXT

from .util import (WindowModalDialog, ColorScheme, HelpLabel, Buttons, CancelButton, WWLabel,
                   read_QIcon, qt_event_listener, QtEventListener, IconLabel,
                   HelpButton, RunCoroutineDialog)
from .transaction_dialog import TxSizeLabel, TxFiatLabel, TxInOutWidget
from .fee_slider import FeeSlider, FeeComboBox
from .amountedit import FeerateEdit, BTCAmountEdit
from .locktimeedit import LockTimeEdit
from .my_treeview import QMenuWithConfig
from .swap_dialog import SwapProvidersButton

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class TxEditorContext(Enum):
    """
    Context for which the TxEditor gets launched.
    Allows to enable/disable certain features.
    """
    PAYMENT = auto()
    CHANNEL_FUNDING = auto()


class TxEditor(WindowModalDialog, QtEventListener, Logger):

    swap_availability_changed = pyqtSignal()

    def __init__(
            self, *, title='',
            window: 'ElectrumWindow',
            make_tx,
            output_value: Union[int, str],
            payee_outputs: Optional[list[PartialTxOutput]] = None,
            context: TxEditorContext = TxEditorContext.PAYMENT,
            batching_candidates=None,
    ):

        WindowModalDialog.__init__(self, window, title=title)
        Logger.__init__(self)
        self.main_window = window
        self.make_tx = make_tx
        self.output_value = output_value
        # used only for submarine payments as they construct tx independently of make_tx
        self.payee_outputs = payee_outputs
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
        self.context = context
        self.is_preview = False
        self._base_tx = None # for batching
        self.batching_candidates = batching_candidates

        self.swap_manager = self.wallet.lnworker.swap_manager if self.wallet.has_lightning() else None
        self.swap_transport = None  # type: Optional[SwapServerTransport]
        self.swap_availability_changed.connect(self.on_swap_availability_changed, Qt.ConnectionType.QueuedConnection)
        self.ongoing_swap_transport_connection_attempt = None  # type: Optional[Future]
        self.did_swap = False  # used to clear the PI on send tab

        self.locktime_e = LockTimeEdit(self)
        self.locktime_e.valueEdited.connect(self.trigger_update)
        self.locktime_label = QLabel(_("LockTime") + ": ")
        self.io_widget = TxInOutWidget(self.main_window, self.wallet)
        self.create_fee_controls()

        onchain_vbox = QVBoxLayout()
        onchain_top = self.create_top_bar(self.help_text)
        onchain_grid = self.create_grid()
        onchain_vbox.addLayout(onchain_top)
        onchain_vbox.addLayout(onchain_grid)
        onchain_vbox.addWidget(self.io_widget)
        self.message_label = WWLabel('')
        self.message_label.setMinimumHeight(70)
        onchain_vbox.addWidget(self.message_label)

        onchain_buttons = self.create_buttons_bar()
        onchain_vbox.addStretch(1)
        onchain_vbox.addLayout(onchain_buttons)

        # onchain tab is the main tab and the content is also shown if tabs are disabled
        self.onchain_tab = QWidget()
        self.onchain_tab.setContentsMargins(0,0,0,0)
        self.onchain_tab.setLayout(onchain_vbox)

        # optional submarine payment tab, the tab is only shown if the option is enabled
        self.submarine_payment_tab = self.create_submarine_payment_tab()

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabBarAutoHide(True)  # hides the tab bar if there is only one tab
        self.tab_widget.setContentsMargins(0, 0, 0, 0)
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(self.tab_widget)
        self.main_layout.setContentsMargins(6, 6, 6, 6)  # reduce outermost margins a bit
        self.setLayout(self.main_layout)

        self.set_io_visible()
        self.set_fee_edit_visible()
        self.set_locktime_visible()
        self.update_fee_target()
        self.update_tab_visibility()
        self.resize_to_fit_content()

        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.setSingleShot(False)
        self.timer.timeout.connect(self.timer_actions)
        self.timer.start()
        self.register_callbacks()
        # debug_widget_layouts(self)  # enable to show red lines around all elements

    def accept(self):
        self._cleanup()
        super().accept()

    def reject(self):
        self._cleanup()
        super().reject()

    def closeEvent(self, event):
        self._cleanup()
        super().closeEvent(event)

    def _cleanup(self):
        self.unregister_callbacks()
        if self.ongoing_swap_transport_connection_attempt:
            self.ongoing_swap_transport_connection_attempt.cancel()
        if isinstance(self.swap_transport, NostrTransport):
            asyncio.run_coroutine_threadsafe(self.swap_transport.stop(), get_asyncio_loop())
        self.swap_transport = None  # HTTPTransport doesn't need to be closed

    def on_tab_changed(self, index):
        if self.tab_widget.widget(index) == self.submarine_payment_tab:
            self.prepare_swap_transport()
            self.update_submarine_payment_tab()
        else:
            self.update()

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
        self.timer.stop()

    def update_tx(self, *, fallback_to_zero_fee: bool = False):
        # expected to set self.tx, self.message and self.error
        raise NotImplementedError()

    def create_grid(self) -> QGridLayout:
        raise NotImplementedError()

    @property
    def help_text(self) -> str:
        raise NotImplementedError()

    def update_fee_target(self):
        if self.fee_slider.is_active():
            text = self.fee_policy.get_target_text()
        else:
            text = ""
        self.fee_target.setText(text)

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

    def update_tab_visibility(self):
        """Update self.tab_widget to show all tabs that are enabled."""
        # first remove all tabs
        while self.tab_widget.count() > 0:
            self.tab_widget.removeTab(0)

        # always show onchain payment tab
        self.tab_widget.addTab(self.onchain_tab, _('Onchain Transaction'))

        allow_swaps = self.context == TxEditorContext.PAYMENT and self.payee_outputs and self.swap_manager
        if self.config.WALLET_ENABLE_SUBMARINE_PAYMENTS and allow_swaps:
            i = self.tab_widget.addTab(self.submarine_payment_tab, _('Submarine Payment'))
            tooltip = self.config.cv.WALLET_ENABLE_SUBMARINE_PAYMENTS.get_long_desc()
            if len(self.payee_outputs) > 1:
                self.tab_widget.setTabEnabled(i, False)
                tooltip = _("Submarine Payments don't support multiple outputs (Pay-to-many).")
            elif self.payee_outputs[0].value == '!':
                self.tab_widget.setTabEnabled(i, False)
                self.submarine_payment_tab.setEnabled(False)
                tooltip = _("Submarine Payments don't support 'Max' value spends.")
            self.tab_widget.tabBar().setTabToolTip(i, tooltip)

        # enable document mode if there is only one tab to hide the frame
        self.tab_widget.setDocumentMode(self.tab_widget.count() < 2)
        self.resize_to_fit_content()

    def trigger_update(self):
        # set tx to None so that the ok button is disabled while we compute the new tx
        self.tx = None
        self.messages = []
        self.error = ''
        self._update_widgets()
        self.needs_update = True

    def fee_slider_callback(self, fee_rate):
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
            fee_policy = FeePolicy(f'feerate:{feerate_per_kb}')
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
            if displayed_feerate is not None:
                displayed_fee = FeePolicy.estimate_fee_for_feerate(fee_per_kb=displayed_feerate * 1000, size=size)
            else:
                displayed_fee = None
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
        self.update_fee_target()

    def create_buttons_bar(self):
        self.change_to_ln_swap_providers_button = SwapProvidersButton(lambda: self.swap_transport, self.config, self.main_window)
        self.preview_button = QPushButton(_('Preview'))
        self.preview_button.clicked.connect(self.on_preview)
        self.preview_button.setVisible(self.context != TxEditorContext.CHANNEL_FUNDING)
        self.ok_button = QPushButton(_('OK'))
        self.ok_button.clicked.connect(self.on_send)
        self.ok_button.setDefault(True)
        buttons = Buttons(CancelButton(self), self.preview_button, self.ok_button)
        buttons.insertWidget(0, self.change_to_ln_swap_providers_button)

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
        can_have_lightning = self.wallet.can_have_lightning()
        send_ch_to_ln = self.pref_menu.addConfig(
            self.config.cv.WALLET_SEND_CHANGE_TO_LIGHTNING,
            callback=lambda: (self.prepare_swap_transport(), self.trigger_update()),  # type: ignore
            checked=False if not can_have_lightning else None,
        )
        sub_payments = self.pref_menu.addConfig(
            self.config.cv.WALLET_ENABLE_SUBMARINE_PAYMENTS,
            callback=self.update_tab_visibility,
            checked=False if not can_have_lightning else None,
        )
        if not can_have_lightning:  # disable the buttons and override tooltip
            ln_unavailable_msg = _("Not available for this wallet.") \
                                 + "\n" + _("Requires a wallet with Lightning network support.")
            for ln_conf in (send_ch_to_ln, sub_payments):
                ln_conf.setEnabled(False)
                ln_conf.setToolTip(ln_unavailable_msg)
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
        self.pref_button.setText(_('Tools'))
        self.pref_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.pref_button.setMenu(self.pref_menu)
        self.pref_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.pref_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(text))
        hbox.addStretch()
        hbox.addWidget(self.pref_button)
        return hbox

    @profiler(min_threshold=0.02)
    def resize_to_fit_content(self):
        # update all geometries so the updated size hints are used for size adjustment
        for widget in self.findChildren(QWidget):
            widget.updateGeometry()
        self.adjustSize()

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
        if self.config.WALLET_SEND_CHANGE_TO_LIGHTNING:
            # if disabled but submarine payments are enabled we only connect once the other tab gets opened
            self.prepare_swap_transport()
        cancelled = not self.exec()
        self.stop_editor_updates()
        self.deleteLater()  # see #3956
        return self.tx if not cancelled else None

    def on_send(self):
        if self.tx and self.tx.get_dummy_output(DummyAddress.SWAP):
            if not self.request_forward_swap():
                return
        self.accept()

    def on_preview(self):
        assert not self.tx.get_dummy_output(DummyAddress.SWAP), "no preview when sending change to ln"
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

        if self.config.WALLET_SEND_CHANGE_TO_LIGHTNING:
            self.change_to_ln_swap_providers_button.setVisible(True)
            self.change_to_ln_swap_providers_button.fetching = bool(self.ongoing_swap_transport_connection_attempt)
            self.change_to_ln_swap_providers_button.update()
        else:
            self.change_to_ln_swap_providers_button.setVisible(False)

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
        if dummy_output := self.tx.get_dummy_output(DummyAddress.SWAP):
            swap_msg = _('Will send change to lightning')
            swap_fee_msg = "."
            if self.swap_manager and self.swap_manager.is_initialized.is_set() and isinstance(dummy_output.value, int):
                ln_amount_we_recv = self.swap_manager.get_recv_amount(send_amount=dummy_output.value, is_reverse=False)
                if ln_amount_we_recv:
                    swap_fees = dummy_output.value - ln_amount_we_recv
                    swap_fee_msg = " [" + _("Swap fees:") + " " + self.main_window.format_amount_and_units(swap_fees) + "]."
            messages.append(swap_msg + swap_fee_msg)
        elif self.config.WALLET_SEND_CHANGE_TO_LIGHTNING \
                and not self.ongoing_swap_transport_connection_attempt \
                and self.tx.has_change():
            swap_msg = _('Will not send change to Lightning')
            swap_msg_reason = None
            change_amount = sum(c.value for c in self.tx.get_change_outputs() if isinstance(c.value, int))
            if not self.wallet.has_lightning():
                swap_msg_reason = _('Lightning is not enabled.')
            elif change_amount > int(self.wallet.lnworker.num_sats_can_receive()):
                swap_msg_reason = _("Your channels cannot receive this amount.")
            elif self.wallet.lnworker.swap_manager.is_initialized.is_set():
                min_amount = self.wallet.lnworker.swap_manager.get_min_amount()
                max_amount = self.wallet.lnworker.swap_manager.get_provider_max_reverse_amount()
                if change_amount < min_amount:
                    swap_msg_reason = _("Below the swap providers minimum value of {}.").format(
                        self.main_window.format_amount_and_units(min_amount)
                    )
                else:
                    swap_msg_reason = _('Change amount exceeds the swap providers maximum value of {}.').format(
                        self.main_window.format_amount_and_units(max_amount)
                    )
            messages.append(swap_msg + (f": {swap_msg_reason}" if swap_msg_reason else '.'))
        elif self.ongoing_swap_transport_connection_attempt:
            messages.append(_("Fetching submarine swap providers..."))
        # warn if spending unconf
        if any((txin.block_height is not None and txin.block_height<=0) for txin in self.tx.inputs()):
            messages.append(_('This transaction will spend unconfirmed coins.'))
        # warn if a reserve utxo was added
        if reserve_sats := self.wallet.tx_keeps_ln_utxo_reserve(self.tx, gui_spend_max=bool(self.output_value == '!')):
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
        # disable preview button when sending change to lightning to prevent the user from saving or
        # exporting the transaction and broadcasting it later somehow.
        send_change_to_ln = self.tx and self.tx.get_dummy_output(DummyAddress.SWAP)
        enabled = bool(self.tx) and not self.error
        self.preview_button.setEnabled(enabled and not send_change_to_ln)
        self.preview_button.setToolTip(_("Can't show preview when sending change to lightning") if send_change_to_ln else "")
        self.ok_button.setEnabled(enabled)

    def can_pay_assuming_zero_fees(self, confirmed_only: bool) -> bool:
        raise NotImplementedError

    ### --- Shared functionality for submarine swaps (change to ln and submarine payments) ---
    def prepare_swap_transport(self):
        if not self.swap_manager:
            return  # no swaps possible, lightning disabled
        if self.swap_transport is not None and self.swap_transport.is_connected.is_set():
            # we already have a connected transport, no need to create a new one
            return
        if self.ongoing_swap_transport_connection_attempt:
            # another task is currently trying to connect
            return

        # there should only be a connected transport.
        # a useless transport should get cleaned up and not stored.
        assert self.swap_transport is None, "swap transport wasn't cleaned up properly"

        new_swap_transport = self.main_window.create_sm_transport()
        if not new_swap_transport:
            # user declined to enable Nostr and has no http server configured
            self.swap_availability_changed.emit()
            return

        async def _initialize_transport(transport):
            try:
                if isinstance(transport, NostrTransport):
                    asyncio.create_task(transport.main_loop())
                else:
                    assert isinstance(transport, HttpTransport)
                    asyncio.create_task(transport.get_pairs_just_once())
                if not await self.wait_for_swap_transport(transport):
                    return
                self.swap_transport = transport
            except Exception:
                self.logger.exception("failed to create swap transport")
            finally:
                self.ongoing_swap_transport_connection_attempt = None
                self.swap_availability_changed.emit()

        # this task will get cancelled if the TxEditor gets closed
        self.ongoing_swap_transport_connection_attempt = asyncio.run_coroutine_threadsafe(
            _initialize_transport(new_swap_transport),
            get_asyncio_loop(),
        )

    async def wait_for_swap_transport(self, new_swap_transport: Union[HttpTransport, NostrTransport]) -> bool:
        """
        Wait until we found the announcement event of the configured swap server.
        If it is not found but the relay connection is established return True anyway,
        the user will then need to select a different swap server.
        """
        timeout = new_swap_transport.connect_timeout + 1
        try:
            # swap_manager.is_initialized gets set once we got pairs of the configured swap server
            await wait_for2(self.swap_manager.is_initialized.wait(), timeout)
        except asyncio.TimeoutError:
            self.logger.debug(f"swap transport initialization timed out after {timeout} sec")

        if self.swap_manager.is_initialized.is_set():
            return True

        # timed out above
        if self.config.SWAPSERVER_URL:
            # http swapserver didn't return pairs
            self.logger.error(f"couldn't request pairs from {self.config.SWAPSERVER_URL=}")
            return False
        elif new_swap_transport.is_connected.is_set():
            assert isinstance(new_swap_transport, NostrTransport)
            # couldn't find announcement of configured swapserver, maybe it is gone.
            # update_submarine_payment_tab will tell the user to select a different swap server.
            return True

        # we couldn't even connect to the relays, this transport is useless. maybe network issues.
        return False

    @qt_event_listener
    def on_event_swap_provider_changed(self):
        self.swap_availability_changed.emit()

    @qt_event_listener
    def on_event_channel(self, wallet, _channel):
        # useful e.g. if the user quickly opens the tab after startup before the channels are initialized
        if wallet == self.wallet and self.swap_manager and self.swap_manager.is_initialized.is_set():
            self.swap_availability_changed.emit()

    @qt_event_listener
    def on_event_swap_offers_changed(self, _):
        self.change_to_ln_swap_providers_button.update()
        self.submarine_payment_provider_button.update()
        if self.ongoing_swap_transport_connection_attempt:
            return
        self.swap_availability_changed.emit()

    @pyqtSlot()
    def on_swap_availability_changed(self):
        # uses a signal/slot to update the gui so we can schedule an update from the asyncio thread
        if self.tab_widget.currentWidget() == self.submarine_payment_tab:
            self.update_submarine_payment_tab()
        else:
            self.update()

    ### --- Functionality for reverse submarine swaps to external address ---
    def create_submarine_payment_tab(self) -> QWidget:
        """Returns widget for submarine payment functionality to be added as tab"""
        tab_widget = QWidget()
        vbox = QVBoxLayout(tab_widget)

        # stack two views, a warning view and the regular one. The warning view is shown if
        # the swap cannot be performed, e.g. due to missing liquidity.
        self.submarine_stacked_widget = QStackedWidget()

        # Normal layout page
        normal_page = QWidget()
        h = QGridLayout(normal_page)
        help_button = HelpButton(MSG_SUBMARINE_PAYMENT_HELP_TEXT)
        self.submarine_lightning_send_amount_label = QLabel()
        self.submarine_onchain_send_amount_label = QLabel()
        self.submarine_claim_mining_fee_label = QLabel()
        self.submarine_server_fee_label = QLabel()
        self.submarine_we_send_label = IconLabel(text=_('You send')+':')
        self.submarine_we_send_label.setIcon(read_QIcon('lightning.png'))
        self.submarine_they_receive_label = IconLabel(text=_('They receive')+':')
        self.submarine_they_receive_label.setIcon(read_QIcon('bitcoin.png'))
        # column 0 (labels)
        h.addWidget(self.submarine_we_send_label, 0, 0)
        h.addWidget(self.submarine_they_receive_label, 1, 0)
        h.addWidget(QLabel(_('Swap fee')+':'), 2, 0)
        h.addWidget(QLabel(_('Mining fee')+':'), 3, 0)
        # column 1 (spacing)
        h.setColumnStretch(1, 1)
        # column 2 (amounts)
        h.addWidget(self.submarine_lightning_send_amount_label, 0, 2)
        h.addWidget(self.submarine_onchain_send_amount_label, 1, 2)
        h.addWidget(self.submarine_server_fee_label, 2, 2, 1, 2)
        h.addWidget(self.submarine_claim_mining_fee_label, 3, 2, 1, 2)
        # column 3 (spacing)
        h.setColumnStretch(3, 1)
        # column 4 (help button)
        h.addWidget(help_button, 0, 4)

        # Warning layout page
        warning_page = QWidget()
        warning_layout = QVBoxLayout(warning_page)
        self.submarine_warning_label = QLabel('')
        warning_layout.addWidget(self.submarine_warning_label)

        self.submarine_stacked_widget.addWidget(normal_page)
        self.submarine_stacked_widget.addWidget(warning_page)

        vbox.addWidget(self.submarine_stacked_widget)
        vbox.addStretch(1)

        self.submarine_payment_provider_button = SwapProvidersButton(lambda: self.swap_transport, self.config, self.main_window)

        self.submarine_ok_button = QPushButton(_('OK'))
        self.submarine_ok_button.setDefault(True)
        self.submarine_ok_button.setEnabled(False)
        # pay button must not self.accept() as this triggers closing the transport
        self.submarine_ok_button.clicked.connect(self.start_submarine_payment)

        buttons = Buttons(CancelButton(self), self.submarine_ok_button)
        buttons.insertWidget(0, self.submarine_payment_provider_button)
        vbox.addLayout(buttons)

        return tab_widget

    def show_swap_transport_connection_message(self):
        self.submarine_stacked_widget.setCurrentIndex(1)
        self.submarine_warning_label.setText(_("Connecting, please wait..."))
        self.submarine_ok_button.setEnabled(False)

    def start_submarine_payment(self):
        assert self.payee_outputs and len(self.payee_outputs) == 1
        payee_output = self.payee_outputs[0]

        assert self.expected_onchain_amount_sat is not None
        assert self.lightning_send_amount_sat is not None
        assert self.last_server_mining_fee_sat is not None
        assert self.swap_transport.is_connected.is_set()
        assert self.swap_manager.is_initialized.is_set()

        self.tx = None  # prevent broadcasting
        self.submarine_ok_button.setEnabled(False)
        coro = self.swap_manager.reverse_swap(
            transport=self.swap_transport,
            lightning_amount_sat=self.lightning_send_amount_sat,
            expected_onchain_amount_sat=self.expected_onchain_amount_sat,
            prepayment_sat=2 * self.last_server_mining_fee_sat,
            claim_to_output=payee_output,
        )
        try:
            funding_txid = self.main_window.run_coroutine_dialog(coro, _('Initiating Submarine Payment...'))
        except Exception as e:
            self.close()
            self.main_window.show_error(_("Submarine Payment failed:") + "\n" + str(e))
            return
        self.did_swap = True
        # accepting closes the swap transport, so it needs to happen after the swap
        self.accept()
        self.main_window.on_swap_result(funding_txid, is_reverse=True)

    def update_submarine_payment_tab(self):
        assert self.tab_widget.currentWidget() == self.submarine_payment_tab
        assert self.payee_outputs, "Opened submarine payment tab without outputs?"
        assert len(self.payee_outputs) == \
               len([o for o in self.payee_outputs if not o.is_change and not isinstance(o.value, str)])
        f = self.main_window.format_amount_and_units
        self.logger.debug(f"TxEditor updating submarine payment tab")

        if not self.swap_manager:
            self.set_submarine_payment_tab_warning(_("Enable Lightning in the 'Channels' tab to use Submarine Swaps."))
            return
        if not self.swap_manager.is_initialized.is_set() \
                and self.ongoing_swap_transport_connection_attempt:
            self.show_swap_transport_connection_message()
            return
        if not self.swap_transport:
            # couldn't connect to nostr relays or http server didn't respond
            self.set_submarine_payment_tab_warning(_("Submarine swap provider unavailable."))
            return

        # Update the swapserver selection button text
        self.submarine_payment_provider_button.update()

        if not self.swap_manager.is_initialized.is_set():
            # connected to nostr relays but couldn't find swapserver announcement
            assert isinstance(self.swap_transport, NostrTransport), "HTTPTransport shouldn't get set if it cannot fetch pairs"
            assert self.swap_transport.is_connected.is_set(), "closed transport wasn't cleaned up"
            if self.config.SWAPSERVER_NPUB:
                msg = _("Couldn't connect to your swap provider. Please select a different provider.")
            else:
                msg = _('Please select a submarine swap provider.')
            self.set_submarine_payment_tab_warning(msg)
            return

        # update values
        self.lightning_send_amount_sat = self.swap_manager.get_send_amount(
            self.payee_outputs[0].value,  # claim tx fee reserve gets added in get_send_amount
            is_reverse=True,
        )
        self.last_server_mining_fee_sat = self.swap_manager.mining_fee
        self.expected_onchain_amount_sat = (
            self.payee_outputs[0].value + self.swap_manager.get_fee_for_txbatcher()
        )

        # get warning
        warning_text = self.get_swap_warning()
        if warning_text:
            self.set_submarine_payment_tab_warning(warning_text)
            return

        # There is no warning, show the normal view (amounts etc.)
        self.submarine_stacked_widget.setCurrentIndex(0)

        # label showing the payment amount (the amount the user entered in SendTab)
        self.submarine_onchain_send_amount_label.setText(f(self.payee_outputs[0].value))

        # the fee we pay to claim the funding output to the onchain address, shown as "Mining Fee"
        claim_tx_mining_fee = self.swap_manager.get_fee_for_txbatcher()
        self.submarine_claim_mining_fee_label.setText(f(claim_tx_mining_fee))

        assert self.lightning_send_amount_sat is not None
        self.submarine_lightning_send_amount_label.setText(f(self.lightning_send_amount_sat))
        # complete fee we pay to the server
        server_fee = self.lightning_send_amount_sat - self.expected_onchain_amount_sat
        self.submarine_server_fee_label.setText(f(server_fee))

        self.submarine_ok_button.setEnabled(True)

    def get_swap_warning(self) -> Optional[str]:
        f = self.main_window.format_amount_and_units
        ln_can_send = int(self.wallet.lnworker.num_sats_can_send())

        if self.expected_onchain_amount_sat < self.swap_manager.get_min_amount():
            return '\n'.join([
                _("Payment amount below the minimum possible swap amount."),
                _("Minimum amount: {}").format(f(self.swap_manager.get_min_amount())), "",
                _("You need to send a higher amount to be able to do a Submarine Payment."),
            ])

        too_low_outbound_liquidity_msg = ''.join([
            _("You don't have enough outgoing capacity in your lightning channels."), '\n',
            _("Your lightning channels can send: {}").format(f(ln_can_send)), '\n',
            _("For this transaction you need: {}").format(f(self.lightning_send_amount_sat)) if self.lightning_send_amount_sat else '',
            '\n\n' if self.lightning_send_amount_sat else '\n',
            _("To add outgoing capacity you can open a new lightning channel or do a submarine swap."),
        ])

        # prioritize showing the swap provider liquidity warning before the channel liquidity warning
        # as it could be annoying for the user to be told to open a new channel just to come back to
        # notice there is no provider supporting their swap amount
        if self.lightning_send_amount_sat is None:
            provider_liquidity = self.swap_manager.get_provider_max_forward_amount()
            if provider_liquidity < self.swap_manager.get_min_amount():
                provider_liquidity = 0
            msg = [
                _("The selected swap provider is unable to offer a forward swap of this value."),
                _("Available liquidity") + f": {f(provider_liquidity)}", "",
                _("In order to continue select a different provider or try to send a smaller amount."),
            ]
            # we don't know exactly how much we need to send on ln yet, so we can assume 0 provider fees
            probably_too_low_outbound_liquidity = self.expected_onchain_amount_sat > ln_can_send
            if probably_too_low_outbound_liquidity:
                msg.extend([
                    "",
                    "Please also note:",
                    too_low_outbound_liquidity_msg,
                ])
            return "\n".join(msg)

        # if we have lightning_send_amount_sat our provider has enough liquidity, so we know the exact
        # amount we need to send including the providers fees
        too_low_outbound_liquidity = self.lightning_send_amount_sat > ln_can_send
        if too_low_outbound_liquidity:
            return too_low_outbound_liquidity_msg

        return None

    def set_submarine_payment_tab_warning(self, warning: str):
        msg = _('Submarine Payment not possible:') + '\n' + warning
        self.submarine_warning_label.setText(msg)
        self.submarine_stacked_widget.setCurrentIndex(1)
        self.submarine_ok_button.setEnabled(False)

    # --- send change to lightning swap functionality ---
    def request_forward_swap(self):
        swap_dummy_output = self.tx.get_dummy_output(DummyAddress.SWAP)
        sm, transport = self.swap_manager, self.swap_transport
        assert sm and transport and swap_dummy_output and isinstance(swap_dummy_output.value, int)
        coro = sm.request_swap_for_amount(transport=transport, onchain_amount=int(swap_dummy_output.value))
        coro_dialog = RunCoroutineDialog(self, _('Requesting swap invoice...'), coro)
        try:
            swap, swap_invoice = coro_dialog.run()
        except (SwapServerError, UserFacingException) as e:
            self.show_error(str(e))
            return False
        except UserCancelled:
            return False
        self.tx.replace_output_address(DummyAddress.SWAP, swap.lockup_address)
        assert self.tx.get_dummy_output(DummyAddress.SWAP) is None
        self.tx.swap_invoice = swap_invoice
        self.tx.swap_payment_hash = swap.payment_hash
        return True


class ConfirmTxDialog(TxEditor):
    help_text = ''  #_('Set the mining fee of your transaction')

    def __init__(
        self, *,
        window: 'ElectrumWindow',
        make_tx,
        output_value: Union[int, str],
        payee_outputs: Optional[list[PartialTxOutput]] = None,
        context: TxEditorContext = TxEditorContext.PAYMENT,
        batching_candidates=None,
    ):

        TxEditor.__init__(
            self,
            window=window,
            make_tx=make_tx,
            output_value=output_value,
            payee_outputs=payee_outputs,
            title=_("New Transaction"), # todo: adapt title for channel funding tx, swaps
            context=context,
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
        self.fee_policy = fee_policy = self.get_fee_policy()
        if fee_policy.method != FeeMethod.FIXED:
            self.config.FEE_POLICY = fee_policy.get_descriptor()
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
