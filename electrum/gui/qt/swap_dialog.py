from typing import TYPE_CHECKING, Optional, List

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QSlider, QHBoxLayout, QSpacerItem
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QPainter, QPen

from electrum.gui.qt.util import HelpButton
from electrum.i18n import _
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.lnutil import ln_dummy_address
from electrum.transaction import PartialTxOutput, PartialTransaction

from .util import (WindowModalDialog, Buttons, OkButton, CancelButton, read_QIcon)
from .fee_slider import FeeSlider, FeeComboBox

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

CANNOT_RECEIVE_WARNING = """
The requested amount is higher than what you can receive in your currently open channels.
If you continue, your funds will be locked until the remote server can find a path to pay you.
If the swap cannot be performed after 24h, you will be refunded.
Do you want to continue?
"""

HELP_TEXT = """
Reverse swap (adds receiving capacity):
 - User generates preimage and hash of preimage. Sends hash to server.
 - Server creates an LN invoice for hash.
 - User pays LN invoice, but server only holds the HTLC as preimage is unknown.
 - Server creates on-chain output locked to hash.
 - User spends on-chain output, revealing preimage.
 - Server fulfills HTLC using preimage.
  
Forward swap (adds sending capacity):
 - User generates an LN invoice with hash, and knows preimage.
 - User creates on-chain output locked to hash.
 - Server pays LN invoice. User reveals preimage.
 - Server spends the on-chain output using preimage.
 
Refund: 
 If something goes wrong after the onchain part of the swap was published,
 the onchain amount is being refunded after a certain waiting period.
"""

bold_font = QFont()
bold_font.setBold(True)


class SwapSlider(QSlider):
    """A custom slider to indicate forbidden values as red lines above
    the slider."""

    def __init__(self, *args, **kwargs):
        super().__init__(Qt.Horizontal, *args, **kwargs)
        self.setMinimumHeight(80)
        self.setMaximumWidth(400)
        self._forbidden_ranges = []

    def set_forbidden_ranges(self, ranges: List):
        self._forbidden_ranges = ranges
        self.update()

    def paintEvent(self, event):
        # paint the original slider
        super().paintEvent(event)

        total_amount = abs(self.minimum()) + self.maximum()
        handle_width = 13
        total_width = self.rect().width() - handle_width
        offset = handle_width / 2
        scale = total_width / total_amount
        zero_position = abs(self.minimum()) * scale + offset
        height = self.rect().height()

        painter = QPainter(self)
        pen = QPen()
        pen.setWidth(3)
        pen.setColor(Qt.red)
        painter.setPen(pen)

        # draw forbidden ranges
        for start, end in self._forbidden_ranges:
            start_position = zero_position + start * scale
            end_position = zero_position + end * scale
            painter.drawLine(
                start_position, height/2-10,
                end_position, height/2-10)


class SwapDialog(WindowModalDialog):
    tx: Optional[PartialTransaction]

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Submarine Swap'))
        self.window = window
        self.config = window.config
        self.lnworker = self.window.wallet.lnworker
        self.swap_manager = self.lnworker.swap_manager
        self.network = window.network
        self.tx = None  # for the forward-swap only
        self.is_reverse = True
        self.send_amount: Optional[int] = None
        self.receive_amount: Optional[int] = None

        vbox = QVBoxLayout(self)

        self.swap_slider = SwapSlider()
        self.swap_slider.valueChanged.connect(self.swap_slider_moved)

        self.swap_action_label = QLabel()
        self.swap_action_label.setFont(bold_font)
        self.help_button = HelpButton(HELP_TEXT)

        self.receive_hint = QLabel(_('add receiving\n capacity'))
        self.receive_hint.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.send_hint = QLabel(_('add sending\n capacity'))
        self.send_hint.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self.bitcoin_pixmap = read_QIcon("bitcoin.png").pixmap(QSize(15, 15))
        self.lightning_pixmap = read_QIcon("lightning.png").pixmap(QSize(15, 15))

        send_pixmap = self.lightning_pixmap
        receive_pixmap = self.bitcoin_pixmap

        self.send_icon_label = QLabel()
        self.send_icon_label.setPixmap(send_pixmap)
        self.send_amount_label = QLabel()
        self.send_amount_composed = QHBoxLayout()
        self.send_amount_composed.setAlignment(Qt.AlignLeft)
        self.send_amount_composed.addWidget(self.send_icon_label)
        self.send_amount_composed.addWidget(self.send_amount_label)
        self.send_amount_composed.addStretch(1)

        self.receive_icon_label = QLabel()
        self.receive_icon_label.setPixmap(receive_pixmap)
        self.receive_amount_label = QLabel()
        self.receive_amount_composed = QHBoxLayout()
        self.receive_amount_composed.setAlignment(Qt.AlignRight)
        self.receive_amount_composed.addWidget(self.receive_icon_label)
        self.receive_amount_composed.addWidget(self.receive_amount_label)
        self.receive_amount_composed.addStretch(1)

        self.service_fee_label = QLabel()
        self.server_mining_fee_label = QLabel()
        self.client_mining_fee_label = QLabel()
        self.total_fee_label = QLabel()

        fee_slider = FeeSlider(self.window, self.config,
                               self.fee_slider_callback)
        fee_combo = FeeComboBox(fee_slider)
        fee_slider.update()

        vbox.addWidget(QLabel(
            f"Add receiving or sending capacity to your Lightning wallet "
            f"by doing a swap.\n"))

        # swap slider
        hbox = QHBoxLayout()
        hbox.addWidget(self.receive_hint)
        hbox.addItem(QSpacerItem(20, 1))
        hbox.addWidget(self.swap_slider)
        hbox.addItem(QSpacerItem(20, 1))
        hbox.addWidget(self.send_hint)

        h = QGridLayout()
        # swap details
        h.addWidget(self.swap_action_label, 2, 1)
        h.addWidget(self.help_button, 2, 4)

        # you send label
        h.addWidget(QLabel("You send:"), 3, 0)
        h.addLayout(self.send_amount_composed, 3, 1)

        # you receive label
        h.addWidget(QLabel("You receive:"), 4, 0)
        h.addLayout(self.receive_amount_composed, 4, 1)

        # fee related
        h.addWidget(QLabel("\nFee breakdown:"), 6, 0)
        h.addWidget(QLabel(_('Service fee')+':'), 7, 0)
        h.addWidget(self.service_fee_label, 7, 1)
        h.addWidget(QLabel(_('Server mining fee')+':'), 8, 0)
        h.addWidget(self.server_mining_fee_label, 8, 1)
        h.addWidget(QLabel(_('Client mining fee')+':'), 9, 0)
        h.addWidget(self.client_mining_fee_label, 9, 1)
        h.addWidget(QLabel(_('Total fee')+':'), 10, 0)
        h.addWidget(self.total_fee_label, 10, 1)
        h.addWidget(QLabel(_('Set client fee:')), 11, 0)
        h.addWidget(fee_slider, 11, 1)
        h.addWidget(fee_combo, 11, 2)

        vbox.addLayout(hbox)
        vbox.addLayout(h)
        vbox.addStretch(1)

        self.ok_button = OkButton(self)
        self.ok_button.setDefault(True)
        self.ok_button.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))

    def update_and_init(self):
        self.update_swap_slider()
        self.swap_slider_moved(0)

    def update_swap_slider(self):
        """Sets the minimal and maximal amount that can be swapped for the swap
        slider as well as forbidden ranges."""
        # tx is updated again afterwards with send_amount in case of normal swap
        # this is just to estimate the maximal spendable onchain amount for HTLC
        self.update_tx('!')
        max_onchain_spend = self.tx.output_value_for_address(ln_dummy_address())
        # TODO: num_sats_can_send/receive currently ignores freezing of channels
        reverse = int(min(self.lnworker.num_sats_can_send(),
                          self.swap_manager.get_max_amount()))
        forward = int(min(self.lnworker.num_sats_can_receive(),
                          # maximally supported swap amount by provider
                          self.swap_manager.get_max_amount(),
                          max_onchain_spend))
        # we expect setRange to adjust the value of the swap slider to be in the
        # correct range, i.e., to correct an overflow when reducing the limits
        self.swap_slider.setRange(-reverse, forward)
        self.swap_slider.set_forbidden_ranges(
            [[-self.swap_manager.min_amount, self.swap_manager.min_amount]])
        self.swap_slider.repaint()

    def fee_slider_callback(self, dyn, pos, fee_rate):
        if dyn:
            if self.config.use_mempool_fees():
                self.config.set_key('depth_level', pos, False)
            else:
                self.config.set_key('fee_level', pos, False)
        else:
            self.config.set_key('fee_per_kb', fee_rate, False)

        self.update_swap_slider()
        self.swap_slider_moved(self.swap_slider.value())

    def swap_slider_moved(self, position):
        # pay_amount and receive_amounts are always with fees already included
        # so it reflects the net balance change after the swap
        if position < 0:  # reverse swap
            self.swap_action_label.setText(
                f"You add Lightning receiving capacity.")
            self.is_reverse = True

            pay_amount = abs(position)
            self.send_amount = pay_amount
            self.send_amount_label.setText(
                f"{pay_amount} sat" if pay_amount else "0 sat")
            self.send_icon_label.setPixmap(self.lightning_pixmap)

            receive_amount = self.swap_manager.get_recv_amount(
                send_amount=pay_amount, is_reverse=True)
            self.receive_amount = receive_amount
            self.receive_amount_label.setText(
                f"{receive_amount} sat" if receive_amount else "0 sat")
            self.receive_icon_label.setPixmap(self.bitcoin_pixmap)

            # fee breakdown
            service_fee = int(pay_amount * self.swap_manager.percentage / 100) + 1 \
                if pay_amount else 0
            self.service_fee_label.setText(
                f"{service_fee} sat (0.5%)")
            self.server_mining_fee_label.setText(
                f"{self.swap_manager.lockup_fee} sat (lockup fee)")
            self.client_mining_fee_label.setText(
                f"{self.swap_manager.get_claim_fee()} sat (claim fee)")

        else:  # forward (normal) swap
            self.swap_action_label.setText(
                f"You add Lightning sending capacity.")
            self.is_reverse = False
            self.send_amount = position

            self.update_tx(self.send_amount)
            # add lockup fees, but the swap amount is position
            pay_amount = position + self.tx.get_fee()
            self.send_amount_label.setText(
                f"{pay_amount} sat" if pay_amount else "")
            self.send_icon_label.setPixmap(self.bitcoin_pixmap)

            receive_amount = self.swap_manager.get_recv_amount(
                send_amount=position, is_reverse=False)
            self.receive_amount = receive_amount
            self.receive_amount_label.setText(
                f"{receive_amount} sat" if receive_amount else "0 sat")
            self.receive_icon_label.setPixmap(self.lightning_pixmap)

            # fee breakdown
            service_fee = int(receive_amount * self.swap_manager.percentage / 100) + 1 \
                if receive_amount else 0
            self.service_fee_label.setText(
                f"{service_fee} sat (0.5%)")
            self.server_mining_fee_label.setText(
                f"{self.swap_manager.normal_fee} sat (claim fee)")
            self.client_mining_fee_label.setText(
                f"{self.tx.get_fee()} sat (lockup fee)")

        if pay_amount and receive_amount:
            total_fee = pay_amount - receive_amount
        else:
            total_fee = None
        self.total_fee_label.setText(f"{total_fee} sat" if total_fee else "0 sat")

        if pay_amount and receive_amount:
            self.ok_button.setEnabled(True)
        else:
            # add more nuanced error reporting?
            self.swap_action_label.setText(
                "Swap below minimal swap size, change the slider.")
            self.ok_button.setEnabled(False)

    def update_tx(self, onchain_amount):
        if onchain_amount is None:
            self.tx = None
            self.ok_button.setEnabled(False)
            return
        outputs = [PartialTxOutput.from_address_and_value(ln_dummy_address(), onchain_amount)]
        coins = self.window.get_coins()
        try:
            self.tx = self.window.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs)
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            self.tx = None
            self.ok_button.setEnabled(False)

    def do_normal_swap(self, lightning_amount, onchain_amount, password):
        tx = self.tx
        assert tx
        coro = self.swap_manager.normal_swap(lightning_amount, onchain_amount, password, tx=tx)
        self.window.run_coroutine_from_thread(coro)

    def run(self):
        if not self.network:
            self.window.show_error(_("You are offline."))
            return
        self.window.run_coroutine_from_thread(
            self.swap_manager.get_pairs(), lambda x: self.update_and_init())
        if not self.exec_():
            return
        if self.is_reverse:
            lightning_amount = self.send_amount
            onchain_amount = self.receive_amount
            if lightning_amount is None or onchain_amount is None:
                return
            coro = self.swap_manager.reverse_swap(
                lightning_amount, onchain_amount + self.swap_manager.get_claim_fee())
            self.window.run_coroutine_from_thread(coro)
            msg = ''.join([
                _("Please keep Electrum running until the swap has completed.\n"),
                _("The swap server will publish a lockup transaction, "
                  "after which Electrum will send a Lightning payment.")
            ])
        else:
            lightning_amount = self.receive_amount
            onchain_amount = self.send_amount
            if lightning_amount is None or onchain_amount is None:
                return
            if lightning_amount > self.lnworker.num_sats_can_receive():
                if not self.window.question(CANNOT_RECEIVE_WARNING):
                    return
            self.window.protect(self.do_normal_swap, (lightning_amount, onchain_amount))
            msg = ''.join([
                _("Please keep Electrum running until the swap has completed.\n"),
                _("Electrum publishes a lockup transaction. Once it is confirmed, "
                  "you will receive a Lightning payment from the swap server.")
            ])
        self.window.show_warning(msg, title=_('Swap is processing'))
