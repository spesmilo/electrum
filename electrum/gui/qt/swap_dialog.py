import enum
from typing import TYPE_CHECKING, Optional, Union, Tuple, Sequence

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QIcon, QPixmap, QColor
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton
from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView

from electrum_aionostr.util import from_nip19

from electrum.i18n import _
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, UserCancelled
from electrum.bitcoin import DummyAddress
from electrum.transaction import PartialTxOutput, PartialTransaction
from electrum.fee_policy import FeePolicy
from electrum.crypto import sha256
from electrum.submarine_swaps import NostrTransport

from electrum.gui import messages
from . import util
from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, ColorScheme, WWLabel, read_QIcon, IconLabel, char_width_in_lineedit)
from .util import qt_event_listener, QtEventListener
from .amountedit import BTCAmountEdit
from .fee_slider import FeeSlider, FeeComboBox
from .my_treeview import create_toolbar_with_menu, MyTreeView

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from electrum.submarine_swaps import SwapServerTransport, SwapOffer

CANNOT_RECEIVE_WARNING = _(
"""The requested amount is higher than what you can receive in your currently open channels.
If you continue, your funds will be locked until the remote server can find a path to pay you.
If the swap cannot be performed after 24h, you will be refunded.
Do you want to continue?"""
)


ROLE_NPUB = Qt.ItemDataRole.UserRole + 1000

class InvalidSwapParameters(Exception): pass


class SwapDialog(WindowModalDialog, QtEventListener):

    def __init__(self, window: 'ElectrumWindow', transport: 'SwapServerTransport', is_reverse=None, recv_amount_sat=None, channels=None):
        WindowModalDialog.__init__(self, window, _('Submarine Swap'))
        self.window = window
        self.config = window.config
        self.lnworker = self.window.wallet.lnworker
        self.swap_manager = self.lnworker.swap_manager
        self.network = window.network
        self.channels = channels
        self.is_reverse = is_reverse if is_reverse is not None else True
        vbox = QVBoxLayout(self)

        self.server_button = QPushButton()
        self.set_server_button_text(len(transport.get_recent_offers()) \
            if not self.config.SWAPSERVER_URL and isinstance(transport, NostrTransport) else 0
        )
        self.server_button.clicked.connect(lambda: self.choose_swap_server(transport))
        self.server_button.setEnabled(not self.config.SWAPSERVER_URL)
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

        self.fee_policy = FeePolicy(self.config.FEE_POLICY)
        self.fee_slider = FeeSlider(parent=self, network=self.network, fee_policy=self.fee_policy, callback=self.fee_slider_callback)
        self.fee_combo = FeeComboBox(self.fee_slider)
        self.fee_target_label = QLabel()
        self._set_fee_slider_visibility(is_visible=not self.is_reverse)

        self.swap_limits_label = QLabel()
        self.fee_label = QLabel()
        self.server_fee_label = QLabel()
        h = QGridLayout()
        h.addWidget(self.description_label, 0, 0, 1, 3)
        h.addWidget(self.toggle_button, 0, 3)
        self.send_label = IconLabel(text=_('You send')+':')
        self.recv_label = IconLabel(text=_('You receive')+':')
        h.addWidget(self.send_label, 1, 0)
        h.addWidget(self.send_amount_e, 1, 1)
        h.addWidget(self.max_button, 1, 2)
        h.addWidget(self.recv_label, 2, 0)
        h.addWidget(self.recv_amount_e, 2, 1)
        h.addWidget(QLabel(_('Swap limits')+':'), 4, 0)
        h.addWidget(self.swap_limits_label, 4, 1, 1, 2)
        h.addWidget(QLabel(_('Server fee')+':'), 5, 0)
        h.addWidget(self.server_fee_label, 5, 1, 1, 2)
        h.addWidget(QLabel(_('Mining fee')+':'), 6, 0)
        h.addWidget(self.fee_label, 6, 1, 1, 2)
        h.addWidget(self.fee_slider, 7, 1)
        h.addWidget(self.fee_combo, 7, 2)
        h.addWidget(self.fee_target_label, 7, 0)
        h.addWidget(QLabel(''), 8, 0)
        vbox.addLayout(h)
        vbox.addStretch()
        self.ok_button = OkButton(self)
        self.ok_button.setDefault(True)
        self.ok_button.setEnabled(False)
        buttons = Buttons(CancelButton(self), self.ok_button)
        vbox.addLayout(buttons)
        buttons.insertWidget(0, self.server_button)
        if recv_amount_sat:
            self.init_recv_amount(recv_amount_sat)
        self.update()
        self.needs_tx_update = True
        self.window.gui_object.timer.timeout.connect(self.timer_actions)
        self.fee_slider.update()
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

    @qt_event_listener
    def on_event_swap_offers_changed(self, recent_offers: Sequence['SwapOffer']):
        self.set_server_button_text(len(recent_offers))
        self.update()

    def set_server_button_text(self, offer_count: int):
        button_text = f' {offer_count} ' + (_('providers') if offer_count != 1 else _('provider'))
        self.server_button.setText(button_text)

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

    def fee_slider_callback(self, fee_rate):
        self.config.FEE_POLICY = self.fee_policy.get_descriptor()
        if not self.is_reverse:
            self.fee_target_label.setText(self.fee_policy.get_target_text())
        if self.send_follows:
            self.on_recv_edited()
        else:
            self.on_send_edited()
        self.update()

    def _set_fee_slider_visibility(self, *, is_visible: bool):
        if is_visible:
            self.fee_slider.setEnabled(True)
            self.fee_combo.setEnabled(True)
            self.fee_target_label.setText(self.fee_policy.get_target_text())
        else:
            self.fee_slider.setEnabled(False)
            self.fee_combo.setEnabled(False)
            # show the eta of the swap claim
            self.fee_target_label.setText(FeePolicy(self.config.FEE_POLICY_SWAPS).get_target_text())

    def toggle_direction(self):
        self.is_reverse = not self.is_reverse
        self._set_fee_slider_visibility(is_visible=not self.is_reverse)
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
        amount = min(self.lnworker.num_sats_can_send(), self.swap_manager.get_provider_max_forward_amount())
        amount = int(amount)  # round down msats
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
        sm = self.swap_manager
        w_base_unit = self.window.base_unit()
        send_icon = read_QIcon("lightning.png" if self.is_reverse else "bitcoin.png")
        self.send_label.setIcon(send_icon)
        recv_icon = read_QIcon("lightning.png" if not self.is_reverse else "bitcoin.png")
        self.recv_label.setIcon(recv_icon)
        self.description_label.setText(self.get_description())
        self.description_label.repaint()  # macOS hack for #6269
        min_swap_limit, max_swap_limit = self.get_client_swap_limits_sat()
        if max_swap_limit == 0:
            swap_name = _("reverse") if self.is_reverse else _("forward")
            swap_limit_str = _("No {} swap possible").format(swap_name)
        else:
            swap_limit_str = (f"{self.window.format_amount(min_swap_limit)} - "
                              f"{self.window.format_amount(max_swap_limit)} {w_base_unit}")
        self.swap_limits_label.setText(swap_limit_str)
        self.swap_limits_label.repaint()  # macOS hack for #6269
        server_mining_fee = sm.mining_fee
        server_fee_str = '%.2f'%sm.percentage + '%  +  '  + self.window.format_amount(server_mining_fee) + ' ' + w_base_unit
        self.server_fee_label.setText(server_fee_str)
        self.server_fee_label.repaint()  # macOS hack for #6269
        self.needs_tx_update = True
        # update icon
        pubkey = from_nip19(self.config.SWAPSERVER_NPUB)['object'].hex() if self.config.SWAPSERVER_NPUB else ''
        self.server_button.setIcon(SwapServerDialog._pubkey_to_q_icon(pubkey))

    def get_client_swap_limits_sat(self) -> Tuple[int, int]:
        """Returns the (min, max) client swap limits in sat."""
        sm = self.swap_manager

        if self.is_reverse:
            lower_limit = sm.get_min_amount()
            upper_limit = sm.client_max_amount_reverse_swap() or 0
        else:
            lower_limit = sm.get_send_amount(sm.get_min_amount(), is_reverse=False) or sm.get_min_amount()
            upper_limit = sm.client_max_amount_forward_swap() or 0

        if lower_limit > upper_limit:
            # if the max possible amount is below the lower limit no swap is possible
            lower_limit, upper_limit = 0, 0
        return lower_limit, upper_limit

    def update_fee(self, tx: Optional[PartialTransaction]) -> None:
        """Updates self.fee_label. No other side-effects."""
        if self.is_reverse:
            sm = self.swap_manager
            fee = sm.get_fee_for_txbatcher()
        else:
            fee = tx.get_fee() if tx else None
        fee_text = self.window.format_amount(fee) + ' ' + self.window.base_unit() if fee else _("no input")
        self.fee_label.setText(fee_text)
        self.fee_label.repaint()  # macOS hack for #6269

    def run(self, transport):
        """Can raise InvalidSwapParameters."""
        if not self.exec():
            return
        if self.is_reverse:
            lightning_amount = self.send_amount_e.get_amount()
            onchain_amount = self.recv_amount_e.get_amount()
            if lightning_amount is None or onchain_amount is None:
                return
            sm = self.swap_manager
            coro = sm.reverse_swap(
                transport=transport,
                lightning_amount_sat=lightning_amount,
                expected_onchain_amount_sat=onchain_amount + self.swap_manager.get_fee_for_txbatcher(),
            )
            try:
                # we must not leave the context, so we use run_couroutine_dialog
                funding_txid = self.window.run_coroutine_dialog(coro, _('Initiating swap...'))
            except Exception as e:
                self.window.show_error(f"Reverse swap failed: {str(e)}")
                return
            self.window.on_swap_result(funding_txid, is_reverse=True)
            return True
        else:
            lightning_amount = self.recv_amount_e.get_amount()
            onchain_amount = self.send_amount_e.get_amount()
            if lightning_amount is None or onchain_amount is None:
                return
            if lightning_amount > self.lnworker.num_sats_can_receive():
                if not self.window.question(CANNOT_RECEIVE_WARNING):
                    return
            self.window.protect(self.do_normal_swap, (transport, lightning_amount, onchain_amount))
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
            max_swap_amount = self.swap_manager.client_max_amount_forward_swap()
            if max_swap_amount is None:
                raise InvalidSwapParameters("swap_manager.client_max_amount_forward_swap() is None")
            if max_amount > max_swap_amount:
                onchain_amount = max_swap_amount
        outputs = [PartialTxOutput.from_address_and_value(DummyAddress.SWAP, onchain_amount)]
        try:
            tx = self.window.wallet.make_unsigned_transaction(
                fee_policy=self.fee_policy,
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

    async def _do_normal_swap(self, transport, lightning_amount, onchain_amount, password):
        dummy_tx = self._create_tx(onchain_amount)
        assert dummy_tx
        sm = self.swap_manager
        swap, invoice = await sm.request_normal_swap(
            transport=transport,
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount,
            channels=self.channels,
        )
        self._current_swap = swap
        tx = sm.create_funding_tx(swap, dummy_tx, password=password)
        txid = await sm.wait_for_htlcs_and_broadcast(transport=transport, swap=swap, invoice=invoice, tx=tx)
        return txid

    def do_normal_swap(self, transport, lightning_amount, onchain_amount, password):
        self._current_swap = None
        coro = self._do_normal_swap(transport, lightning_amount, onchain_amount, password)
        try:
            funding_txid = self.window.run_coroutine_dialog(coro, _('Awaiting swap payment...'))
        except UserCancelled:
            self.swap_manager.cancel_normal_swap(self._current_swap)
            self.window.show_message(_('Swap cancelled'))
            return
        except Exception as e:
            self.window.show_error(str(e))
            return
        self.window.on_swap_result(funding_txid, is_reverse=False)

    def get_description(self):
        onchain_funds = "onchain"
        lightning_funds = "lightning"

        return "Send {fromType}, receive {toType}.\nThis will increase your lightning {capacityType} capacity.\n".format(
            fromType=lightning_funds if self.is_reverse else onchain_funds,
            toType=onchain_funds if self.is_reverse else lightning_funds,
            capacityType="receiving" if self.is_reverse else "sending",
        )

    def choose_swap_server(self, transport: 'SwapServerTransport') -> None:
        self.window.choose_swapserver_dialog(transport)  # type: ignore
        self.update()
        self.on_send_edited()
        self.on_recv_edited()


class SwapServerDialog(WindowModalDialog, QtEventListener):

    class Columns(MyTreeView.BaseColumnsEnum):
        PUBKEY = enum.auto()
        FEE = enum.auto()
        MAX_FORWARD = enum.auto()
        MAX_REVERSE = enum.auto()
        LAST_SEEN = enum.auto()

    headers = {
        Columns.PUBKEY: _("Pubkey"),
        Columns.FEE: _("Fee"),
        Columns.MAX_FORWARD: _('Max Forward'),
        Columns.MAX_REVERSE: _('Max Reverse'),
        Columns.LAST_SEEN: _("Last seen"),
    }

    def __init__(self, window: 'ElectrumWindow', servers: Sequence['SwapOffer']):
        WindowModalDialog.__init__(self, window, _('Choose Swap Provider'))
        self.window = window
        self.config = window.config
        msg = '\n'.join([
            _("Please choose a provider from this list."),
            _("Note that fees and liquidity may be updated frequently.")
        ])
        self.servers_list = QTreeWidget()
        col_names = [self.headers[col_idx] for col_idx in sorted(self.headers.keys())]
        self.servers_list.setHeaderLabels(col_names)
        self.servers_list.header().setStretchLastSection(False)
        for col_idx in range(len(self.Columns)):
            sm = QHeaderView.ResizeMode.Stretch if col_idx == self.Columns.PUBKEY else QHeaderView.ResizeMode.ResizeToContents
            self.servers_list.header().setSectionResizeMode(col_idx, sm)
        self.update_servers_list(servers)
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.addWidget(WWLabel(msg))
        vbox.addWidget(self.servers_list)
        vbox.addStretch()
        self.ok_button = OkButton(self)
        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))
        self.setMinimumWidth(650)
        self.register_callbacks()

    def run(self):
        if self.exec() != 1:
            return None
        if item := self.servers_list.currentItem():
            return item.data(self.Columns.PUBKEY, ROLE_NPUB)
        return None

    def closeEvent(self, event):
        self.unregister_callbacks()
        event.accept()

    @qt_event_listener
    def on_event_swap_offers_changed(self, recent_offers: Sequence['SwapOffer']):
        self.update_servers_list(recent_offers)

    def update_servers_list(self, servers: Sequence['SwapOffer']):
        self.servers_list.clear()
        from electrum.util import age
        items = []
        for x in servers:
            labels = [""] * len(self.Columns)
            labels[self.Columns.PUBKEY] = x.server_pubkey
            labels[self.Columns.FEE] = f"{x.pairs.percentage}% + {x.pairs.mining_fee} sats"
            labels[self.Columns.MAX_FORWARD] = self.window.format_amount(x.pairs.max_forward) + ' ' + self.window.base_unit()
            labels[self.Columns.MAX_REVERSE] = self.window.format_amount(x.pairs.max_reverse) + ' ' + self.window.base_unit()
            labels[self.Columns.LAST_SEEN] = age(x.timestamp)
            item = QTreeWidgetItem(labels)
            item.setData(self.Columns.PUBKEY, ROLE_NPUB, x.server_npub)
            item.setIcon(self.Columns.PUBKEY, self._pubkey_to_q_icon(x.server_pubkey))
            items.append(item)
        self.servers_list.insertTopLevelItems(0, items)

    @staticmethod
    def _pubkey_to_q_icon(server_pubkey: str) -> QIcon:
        def str_to_rgb(color_input: str) -> int:
            input_hash = int.from_bytes(sha256(color_input), byteorder="big")
            r = (input_hash & 0xFF0000) >> 16
            g = (input_hash & 0x00FF00) >> 8
            b = input_hash & 0x0000FF
            return (r << 16) | (g << 8) | b

        color = QColor(str_to_rgb(server_pubkey))
        color_pixmap = QPixmap(100, 100)
        color_pixmap.fill(color)
        return QIcon(color_pixmap)
