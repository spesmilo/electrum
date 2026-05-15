#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2026 The Electrum Developers
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
from asyncio import Future
from typing import Optional, Union, Callable, TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal, pyqtProperty

from electrum import get_logger
from electrum.bitcoin import DummyAddress
from electrum.gui.common_qt.util import qt_event_listener, QtEventListener
from electrum.i18n import _
from electrum.submarine_swaps import SwapServerTransport, HttpTransport, NostrTransport
from electrum.util import get_asyncio_loop, wait_for2

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


class SubmarineSwapMixin(QtEventListener):

    _swaps_logger = get_logger(__name__)
    swapAvailabilityChanged = pyqtSignal()

    def __init__(self, create_sm_transport: Callable = None):
        self.swap_wallet = None
        self.config = None
        self.create_sm_transport = create_sm_transport
        self.swap_manager = None
        self.swap_transport = None  # type: Optional[SwapServerTransport]
        self.ongoing_swap_transport_connection_attempt = None  # type: Optional[Future]
        self._swapStatusMsg = ''

    swapStatusMsgChanged = pyqtSignal()
    @pyqtProperty(str, notify=swapStatusMsgChanged)
    def swapStatusMsg(self):
        return self._swapStatusMsg

    @swapStatusMsg.setter
    def swapStatusMsg(self, swap_status_msg: str):
        if self._swapStatusMsg != swap_status_msg:
            self._swapStatusMsg = swap_status_msg
            self.swapStatusMsgChanged.emit()

    def set_wallet_for_swap(self, wallet: 'Abstract_Wallet'):
        self.swap_wallet = wallet
        self.config = wallet.config
        self.swap_manager = wallet.lnworker.swap_manager if wallet.has_lightning() else None

    def get_message_for_swap_change(self, tx):
        msg = ''
        if self.ongoing_swap_transport_connection_attempt:
            msg = _("Fetching submarine swap providers...")
        elif dummy_output := tx.get_dummy_output(DummyAddress.SWAP):
            msg = _('Will send change to lightning')
            if self.swap_manager and self.swap_manager.is_initialized.is_set() and isinstance(dummy_output.value, int):
                ln_amount_we_recv = self.swap_manager.get_recv_amount(send_amount=dummy_output.value,
                                                                      is_reverse=False)
                if ln_amount_we_recv:
                    swap_fees = dummy_output.value - ln_amount_we_recv
                    msg += " [" + _("Swap fees:") + " " + self.config.format_amount_and_units(swap_fees) + "]."
        elif not tx.has_change():
            msg = _('No change output, so no need for swap')
        else:
            change_amount = sum(c.value for c in tx.get_change_outputs() if isinstance(c.value, int))
            if not self.swap_wallet.has_lightning():
                msg = _("Lightning is not enabled.")
            elif change_amount > int(self.swap_wallet.lnworker.num_sats_can_receive()):
                msg = _("Your channels cannot receive this amount.")
            elif self.swap_wallet.lnworker.swap_manager.is_initialized.is_set():
                min_amount = self.swap_wallet.lnworker.swap_manager.get_min_amount()
                max_amount = self.swap_wallet.lnworker.swap_manager.get_provider_max_reverse_amount()
                if change_amount < min_amount:
                    msg = _("Below the swap providers minimum value of {}.").format(
                        self.config.format_amount_and_units(min_amount)
                    )
                elif change_amount > max_amount:
                    msg = _('Change amount exceeds the swap providers maximum value of {}.').format(
                        self.config.format_amount_and_units(max_amount)
                    )
            else:
                msg = _('Will not send change to Lightning')
        return msg

    # --- Shared functionality for submarine swaps (change to ln and submarine payments) ---
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

        new_swap_transport = self.create_sm_transport() if self.create_sm_transport \
            else self.swap_manager.create_transport()

        if not new_swap_transport:
            # could not create transport, e.g. user declined to enable Nostr and has no http server configured
            self._swaps_logger.debug('could not create swap transport')
            self.swapAvailabilityChanged.emit()
            return

        async def _initialize_transport(transport):
            try:
                self.swapStatusMsg = 'initializing swap transport'
                if isinstance(transport, NostrTransport):
                    asyncio.create_task(transport.main_loop())
                else:
                    assert isinstance(transport, HttpTransport)
                    asyncio.create_task(transport.get_pairs_just_once())
                if not await self.wait_for_swap_transport(transport):
                    return
                self.swapStatusMsg = 'swap transport initialized'
                self.swap_transport = transport
            except Exception:
                self.swapStatusMsg = 'failed initializing swap transport'
                self._swaps_logger.exception("failed to create swap transport")
            finally:
                self.ongoing_swap_transport_connection_attempt = None
                self.swapAvailabilityChanged.emit()

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
            self._swaps_logger.debug(f"swap transport initialization timed out after {timeout} sec")

        if self.swap_manager.is_initialized.is_set():
            return True

        # timed out above
        if self.config.SWAPSERVER_URL:
            # http swapserver didn't return pairs
            self._swaps_logger.error(f"couldn't request pairs from {self.config.SWAPSERVER_URL=}")
            return False
        elif new_swap_transport.is_connected.is_set():
            assert isinstance(new_swap_transport, NostrTransport)
            # couldn't find announcement of configured swapserver, maybe it is gone.
            # update_submarine_payment_tab will tell the user to select a different swap server.
            return True

        # we couldn't even connect to the relays, this transport is useless. maybe network issues.
        return False

    def swap_transport_cleanup(self):
        self.unregister_callbacks()
        if self.ongoing_swap_transport_connection_attempt:
            self.ongoing_swap_transport_connection_attempt.cancel()
        if isinstance(self.swap_transport, NostrTransport):
            asyncio.run_coroutine_threadsafe(self.swap_transport.stop(), get_asyncio_loop())
        self.swap_transport = None  # HttpTransport doesn't need to be closed

    @qt_event_listener
    def on_event_swap_provider_changed(self):
        self.swapAvailabilityChanged.emit()

    @qt_event_listener
    def on_event_channel(self, wallet, _channel):
        # useful e.g. if the user quickly opens the tab after startup before the channels are initialized
        if wallet == self.swap_wallet and self.swap_manager and self.swap_manager.is_initialized.is_set():
            self.swapAvailabilityChanged.emit()

    @qt_event_listener
    def on_event_swap_offers_changed(self, _):
        if self.ongoing_swap_transport_connection_attempt:
            return
        self.swapAvailabilityChanged.emit()
