import asyncio
from asyncio import Future
from typing import Optional, Union, Callable

from PyQt6.QtCore import pyqtSignal, pyqtProperty

from electrum import get_logger
from electrum.gui.common_qt.util import qt_event_listener, QtEventListener
from electrum.submarine_swaps import SwapServerTransport, HttpTransport, NostrTransport
from electrum.util import get_asyncio_loop, wait_for2


class SubmarineSwapMixin(QtEventListener):

    _swaps_logger = get_logger(__name__)
    swapAvailabilityChanged = pyqtSignal()

    def __init__(self, create_sm_transport: Callable = None):
        self.swap_wallet = None
        self.config = None
        self.create_sm_transport = create_sm_transport
        self.swap_manager = None
        self.swap_transport = None  # type: Optional[SwapServerTransport]
        # self.swapAvailabilityChanged.connect(self.on_swap_availability_changed, Qt.ConnectionType.QueuedConnection)
        self.ongoing_swap_transport_connection_attempt = None  # type: Optional[Future]
        self._swapStatus = ''

    swapStatusChanged = pyqtSignal()
    @pyqtProperty(str, notify=swapStatusChanged)
    def swapStatus(self):
        return self._swapStatus

    @swapStatus.setter
    def swapStatus(self, swap_status: str):
        if self._swapStatus != swap_status:
            self._swapStatus = swap_status
            self.swapStatusChanged.emit()

    def set_wallet_for_swap(self, wallet):
        self.swap_wallet = wallet
        self.config = wallet.config
        self.swap_manager = wallet.lnworker.swap_manager if wallet.has_lightning() else None

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
                self.swapStatus = 'initializing swap transport'
                if isinstance(transport, NostrTransport):
                    asyncio.create_task(transport.main_loop())
                else:
                    assert isinstance(transport, HttpTransport)
                    asyncio.create_task(transport.get_pairs_just_once())
                if not await self.wait_for_swap_transport(transport):
                    return
                self.swapStatus = 'swap transport initialized'
                self.swap_transport = transport
            except Exception:
                self.swapStatus = 'failed initializing swap transport'
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
