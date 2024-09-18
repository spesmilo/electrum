from typing import TYPE_CHECKING, Optional, Union

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton

from electrum.i18n import _
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.bitcoin import DummyAddress
from electrum.transaction import PartialTxOutput, PartialTransaction

from electrum.gui import messages
from . import util
from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, ColorScheme, WWLabel, read_QIcon, IconLabel, char_width_in_lineedit)
from .util import qt_event_listener, QtEventListener
from .amountedit import BTCAmountEdit
from .fee_slider import FeeSlider, FeeComboBox
from .my_treeview import create_toolbar_with_menu

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

CANNOT_RECEIVE_WARNING = _(
"""The requested amount is higher than what you can receive in your currently open channels.
If you continue, your funds will be locked until the remote server can find a path to pay you.
If the swap cannot be performed after 24h, you will be refunded.
Do you want to continue?"""
)


class InvalidSwapParameters(Exception): pass


class SwapDialog(WindowModalDialog, QtEventListener):

    def __init__(self, window: 'ElectrumWindow', is_reverse=None, recv_amount_sat=None, channels=None):
        WindowModalDialog.__init__(self, window, _('Submarine Swap'))
        self.window = window
        self.config = window.config
        self.lnworker = self.window.wallet.lnworker
        self.swap_manager = self.lnworker.swap_manager
        self.network = window.network
        self.channels = channels
        self.is_reverse = is_reverse if is_reverse is not None else True
        vbox = QVBoxLayout(self)
        toolbar, menu = create_toolbar_with_menu(self.config, '')
        menu.addConfig(
            self.config.cv.LIGHTNING_ALLOW_INSTANT_SWAPS,
        ).setEnabled(self.lnworker.can_have_recoverable_channels())
        vbox.addLayout(toolbar)
        self.description_label = WWLabel(self.get_description())
        self.send_amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.recv_amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.max_button = EnterButton(_("Max"), self.spend_max)
        btn_width = 10 * char_width_in_lineedit()
        self.max_button.setFixedWidth(btn_width)
        self.max_button.setCheckable(True)
        self.toggle_button = QPushButton('  \U000021c4  ')  # whitespace to force larger min width
        self.toggle_button.setEnabled(is_reverse is None)
        # send_follows is used to know whether the send amount field / receive
        # amount field should be adjusted after the fee slider was moved
        self.send_follows = False
        self.send_amount_e.follows = False
        self.recv_amount_e.follows = False
        self.toggle_button.clicked.connect(self.toggle_direction)
        # textChanged is triggered for both user and automatic action
        self.send_amount_e.textChanged.connect(self.on_send_edited)
        self.recv_amount_e.textChanged.connect(self.on_recv_edited)
        # textEdited is triggered only for user editing of the fields
        self.send_amount_e.textEdited.connect(self.uncheck_max)
        self.recv_amount_e.textEdited.connect(self.uncheck_max)
        self.send_amount_e.setEnabled(recv_amount_sat is None)
        self.recv_amount_e.setEnabled(recv_amount_sat is None)
        self.max_button.setEnabled(recv_amount_sat is None)
        fee_slider = FeeSlider(self.window, self.config, self.fee_slider_callback)
        fee_combo = FeeComboBox(fee_slider)
        fee_slider.update()
        self.fee_label = QLabel()
        self.server_fee_label = QLabel()
        vbox.addWidget(self.description_label)
        h = QGridLayout()
        self.send_label = IconLabel(text=_('You send')+':')
        self.recv_label = IconLabel(text=_('You receive')+':')
        h.addWidget(self.send_label, 1, 0)
        h.addWidget(self.send_amount_e, 1, 1)
        h.addWidget(self.max_button, 1, 2)
        h.addWidget(self.toggle_button, 1, 3)
        h.addWidget(self.recv_label, 2, 0)
        h.addWidget(self.recv_amount_e, 2, 1)
        h.addWidget(QLabel(_('Server fee')+':'), 4, 0)
        h.addWidget(self.server_fee_label, 4, 1, 1, 2)
        h.addWidget(QLabel(_('Mining fee')+':'), 5, 0)
        h.addWidget(self.fee_label, 5, 1, 1, 2)
        h.addWidget(fee_slider, 6, 1)
        h.addWidget(fee_combo, 6, 2)
        vbox.addLayout(h)
        vbox.addStretch(1)
        self.ok_button = OkButton(self)
        self.ok_button.setDefault(True)
        self.ok_button.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))
        if recv_amount_sat:
            self.init_recv_amount(recv_amount_sat)
        self.update()
        self.needs_tx_update = True
        self.window.gui_object.timer.timeout.connect(self.timer_actions)
        self.register_callbacks()

    def closeEvent(self, event):
        self.unregister_callbacks()
        event.accept()

    @qt_event_listener
    def on_event_fee_histogram(self, *args):
        self.on_send_edited()
        self.on_recv_edited()

    @qt_event_listener
    def on_event_fee(self, *args):
        self.on_send_edited()
        self.on_recv_edited()

    def timer_actions(self):
        if self.needs_tx_update:
            self.update_tx()
            self.update_ok_button()
            self.needs_tx_update = False

    def init_recv_amount(self, recv_amount_sat):
        if recv_amount_sat == '!':
            self.max_button.setChecked(True)
            self.spend_max()
        else:
            recv_amount_sat = max(recv_amount_sat, self.swap_manager.get_min_amount())
            self.recv_amount_e.setAmount(recv_amount_sat)

    def fee_slider_callback(self, dyn, pos, fee_rate):
        if dyn:
            if self.config.use_mempool_fees():
                self.config.cv.FEE_EST_DYNAMIC_MEMPOOL_SLIDERPOS.set(pos, save=False)
            else:
                self.config.cv.FEE_EST_DYNAMIC_ETA_SLIDERPOS.set(pos, save=False)
        else:
            self.config.cv.FEE_EST_STATIC_FEERATE.set(fee_rate, save=False)
        if self.send_follows:
            self.on_recv_edited()
        else:
            self.on_send_edited()
        self.update()

    def toggle_direction(self):
        self.is_reverse = not self.is_reverse
        self.send_amount_e.setAmount(None)
        self.recv_amount_e.setAmount(None)
        self.max_button.setChecked(False)
        self.update()

    def spend_max(self):
        if self.max_button.isChecked():
            if self.is_reverse:
                self._spend_max_reverse_swap()
            else:
                # spend_max_forward_swap will be called in update_tx
                pass
        else:
            self.send_amount_e.setAmount(None)
        self.needs_tx_update = True

    def uncheck_max(self):
        self.max_button.setChecked(False)
        self.update()

    def _spend_max_forward_swap(self, tx: Optional[PartialTransaction]) -> None:
        if tx:
            amount = tx.output_value_for_address(DummyAddress.SWAP)
            self.send_amount_e.setAmount(amount)
        else:
            self.send_amount_e.setAmount(None)
            self.max_button.setChecked(False)

    def _spend_max_reverse_swap(self) -> None:
        amount = min(self.lnworker.num_sats_can_send(), self.swap_manager.get_max_amount())
        self.send_amount_e.setAmount(amount)

    def on_send_edited(self):
        if self.send_amount_e.follows:
            return
        self.send_amount_e.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
        send_amount = self.send_amount_e.get_amount()
        recv_amount = self.swap_manager.get_recv_amount(send_amount, is_reverse=self.is_reverse)
        if self.is_reverse and send_amount and send_amount > self.lnworker.num_sats_can_send():
            # cannot send this much on lightning
            recv_amount = None
        if (not self.is_reverse) and recv_amount and recv_amount > self.lnworker.num_sats_can_receive():
            # cannot receive this much on lightning
            recv_amount = None
        self.recv_amount_e.follows = True
        self.recv_amount_e.setAmount(recv_amount)
        self.recv_amount_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
        self.recv_amount_e.follows = False
        self.send_follows = False
        self.needs_tx_update = True

    def on_recv_edited(self):
        if self.recv_amount_e.follows:
            return
        self.recv_amount_e.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
        recv_amount = self.recv_amount_e.get_amount()
        send_amount = self.swap_manager.get_send_amount(recv_amount, is_reverse=self.is_reverse)
        if self.is_reverse and send_amount and send_amount > self.lnworker.num_sats_can_send():
            send_amount = None
        self.send_amount_e.follows = True
        self.send_amount_e.setAmount(send_amount)
        self.send_amount_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
        self.send_amount_e.follows = False
        self.send_follows = True
        self.needs_tx_update = True

    def update(self):
        from .util import IconLabel
        sm = self.swap_manager
        send_icon = read_QIcon("lightning.png" if self.is_reverse else "bitcoin.png")
        self.send_label.setIcon(send_icon)
        recv_icon = read_QIcon("lightning.png" if not self.is_reverse else "bitcoin.png")
        self.recv_label.setIcon(recv_icon)
        self.description_label.setText(self.get_description())
        self.description_label.repaint()  # macOS hack for #6269
        server_mining_fee = sm.lockup_fee if self.is_reverse else sm.normal_fee
        server_fee_str = '%.2f'%sm.percentage + '%  +  '  + self.window.format_amount(server_mining_fee) + ' ' + self.window.base_unit()
        self.server_fee_label.setText(server_fee_str)
        self.server_fee_label.repaint()  # macOS hack for #6269
        self.needs_tx_update = True

    def update_fee(self, tx: Optional[PartialTransaction]) -> None:
        """Updates self.fee_label. No other side-effects."""
        if self.is_reverse:
            sm = self.swap_manager
            fee = sm.get_claim_fee()
        else:
            fee = tx.get_fee() if tx else None
        fee_text = self.window.format_amount(fee) + ' ' + self.window.base_unit() if fee else ''
        self.fee_label.setText(fee_text)
        self.fee_label.repaint()  # macOS hack for #6269

    def run(self):
        """Can raise InvalidSwapParameters."""
        if not self.exec():
            return
        if self.is_reverse:
            lightning_amount = self.send_amount_e.get_amount()
            onchain_amount = self.recv_amount_e.get_amount()
            if lightning_amount is None or onchain_amount is None:
                return
            coro = self.swap_manager.reverse_swap(
                lightning_amount_sat=lightning_amount,
                expected_onchain_amount_sat=onchain_amount + self.swap_manager.get_claim_fee(),
            )
            self.window.run_coroutine_from_thread(
                coro, _('Swapping funds'),
                on_result=lambda funding_txid: self.window.on_swap_result(funding_txid, is_reverse=True),
            )
            return True
        else:
            lightning_amount = self.recv_amount_e.get_amount()
            onchain_amount = self.send_amount_e.get_amount()
            if lightning_amount is None or onchain_amount is None:
                return
            if lightning_amount > self.lnworker.num_sats_can_receive():
                if not self.window.question(CANNOT_RECEIVE_WARNING):
                    return
            self.window.protect(self.do_normal_swap, (lightning_amount, onchain_amount))
            return True

    def update_tx(self) -> None:
        if self.is_reverse:
            self.update_fee(None)
            return
        is_max = self.max_button.isChecked()
        if is_max:
            tx = self._create_tx_safe('!')
            self._spend_max_forward_swap(tx)
        else:
            onchain_amount = self.send_amount_e.get_amount()
            tx = self._create_tx_safe(onchain_amount)
        self.update_fee(tx)

    def _create_tx(self, onchain_amount: Union[int, str, None]) -> PartialTransaction:
        assert not self.is_reverse
        if onchain_amount is None:
            raise InvalidSwapParameters("onchain_amount is None")
        coins = self.window.get_coins()
        if onchain_amount == '!':
            max_amount = sum(c.value_sats() for c in coins)
            max_swap_amount = self.swap_manager.max_amount_forward_swap()
            if max_swap_amount is None:
                raise InvalidSwapParameters("swap_manager.max_amount_forward_swap() is None")
            if max_amount > max_swap_amount:
                onchain_amount = max_swap_amount
        outputs = [PartialTxOutput.from_address_and_value(DummyAddress.SWAP, onchain_amount)]
        try:
            tx = self.window.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs,
                send_change_to_lightning=False,
            )
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            raise InvalidSwapParameters(str(e)) from e
        return tx

    def _create_tx_safe(self, onchain_amount: Union[int, str, None]) -> Optional[PartialTransaction]:
        try:
            return self._create_tx(onchain_amount=onchain_amount)
        except InvalidSwapParameters:
            return None

    def update_ok_button(self):
        """Updates self.ok_button. No other side-effects."""
        send_amount = self.send_amount_e.get_amount()
        recv_amount = self.recv_amount_e.get_amount()
        self.ok_button.setEnabled(bool(send_amount) and bool(recv_amount))

    def do_normal_swap(self, lightning_amount, onchain_amount, password):
        dummy_tx = self._create_tx(onchain_amount)
        assert dummy_tx
        sm = self.swap_manager
        coro = sm.request_normal_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount,
            channels=self.channels,
        )
        try:
            swap, invoice = self.network.run_from_another_thread(coro)
        except Exception as e:
            self.window.show_error(str(e))
            return
        tx = sm.create_funding_tx(swap, dummy_tx, password=password)
        coro2 = sm.wait_for_htlcs_and_broadcast(swap=swap, invoice=invoice, tx=tx)
        self.window.run_coroutine_dialog(
            coro2, _('Awaiting swap payment...'),
            on_result=lambda funding_txid: self.window.on_swap_result(funding_txid, is_reverse=False),
            on_cancelled=lambda: sm.cancel_normal_swap(swap))

    def get_description(self):
        onchain_funds = "onchain funds"
        lightning_funds = "lightning funds"

        return "Swap {fromType} for {toType}.\nThis will increase your {capacityType} capacity.".format(
            fromType=lightning_funds if self.is_reverse else onchain_funds,
            toType=onchain_funds if self.is_reverse else lightning_funds,
            capacityType="receiving" if self.is_reverse else "sending",
        )
