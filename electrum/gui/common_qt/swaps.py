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

from concurrent.futures import Future
from typing import Optional, Callable, TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal, pyqtProperty

from electrum import get_logger
from electrum.gui.common_qt.util import qt_event_listener, QtEventListener
from electrum.submarine_swaps import SwapServerTransport

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


class SubmarineSwapMixin(QtEventListener):

    _swaps_logger = get_logger(__name__)
    swapAvailabilityChanged = pyqtSignal()
    swapOffersChanged = pyqtSignal()

    def __init__(self, create_sm_transport: Callable = None):
        self.swap_wallet = None
        self.config = None
        self.create_sm_transport = create_sm_transport
        self.swap_manager = None
        self.swap_transport = None  # type: Optional[SwapServerTransport]

    def set_wallet_for_swap(self, wallet: 'Abstract_Wallet'):
        self.swap_wallet = wallet
        self.config = wallet.config
        self.swap_manager = wallet.lnworker.swap_manager if wallet.has_lightning() else None

    # --- Shared functionality for submarine swaps (change to ln and submarine payments) ---
    def prepare_swap_transport(self):
        if not self.swap_manager:
            return  # no swaps possible, lightning disabled
        if self.swap_transport is not None:
            if self.swap_transport.is_connected.is_set():
                # we already have a connected transport, no need to create a new one
                return
            if self.swap_transport.ongoing_connection_attempt:
                # another task is currently trying to connect
                return

        # there should only be a connected transport.
        # a useless transport should get cleaned up and not stored.
        assert self.swap_transport is None, "swap transport wasn't cleaned up properly"

        self.swap_transport = self.create_sm_transport() if self.create_sm_transport \
            else self.swap_manager.create_transport()

        if not self.swap_transport:
            # could not create transport, e.g. user declined to enable Nostr and has no http server configured
            self._swaps_logger.debug('could not create swap transport')
            self.swapAvailabilityChanged.emit()
            return

        def transport_initialize_done(future: Future):
            if future.cancelled() or future.exception() is not None:
                if self.swap_transport is not None:
                    self.swap_transport.destroy()
                    self.swap_transport = None
            self.swapAvailabilityChanged.emit()

        self.swap_transport.initialize(transport_initialize_done)

    def swap_transport_cleanup(self):
        self.unregister_callbacks()
        if self.swap_transport is not None:
            self.swap_transport.destroy()
            self.swap_transport = None

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
        if self.swap_transport and self.swap_transport.ongoing_connection_attempt:
            return
        self.swapOffersChanged.emit()
