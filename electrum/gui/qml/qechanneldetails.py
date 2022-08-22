import asyncio

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Q_ENUMS

from electrum.i18n import _
from electrum.gui import messages
from electrum.logging import get_logger
from electrum.lnutil import LOCAL, REMOTE
from electrum.lnchannel import ChanCloseOption, ChannelState

from .qewallet import QEWallet
from .qetypes import QEAmount
from .util import QtEventListener, qt_event_listener, event_listener

class QEChannelDetails(QObject, QtEventListener):
    _logger = get_logger(__name__)

    class State: # subset, only ones we currently need in UI
        Closed = ChannelState.CLOSED
        Redeemed = ChannelState.REDEEMED

    Q_ENUMS(State)

    _wallet = None
    _channelid = None
    _channel = None

    channelChanged = pyqtSignal()
    channelCloseSuccess = pyqtSignal()
    channelCloseFailed = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    @event_listener
    def on_event_channel(self, wallet, channel):
        if wallet == self._wallet.wallet and self._channelid == channel.channel_id.hex():
            self.channelChanged.emit()

    def on_destroy(self):
        self.unregister_callbacks()

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

    channelidChanged = pyqtSignal()
    @pyqtProperty(str, notify=channelidChanged)
    def channelid(self):
        return self._channelid

    @channelid.setter
    def channelid(self, channelid: str):
        if self._channelid != channelid:
            self._channelid = channelid
            if channelid:
                self.load()
            self.channelidChanged.emit()

    def load(self):
        lnchannels = self._wallet.wallet.lnworker.channels
        for channel in lnchannels.values():
            #self._logger.debug('%s == %s ?' % (self._channelid, channel.channel_id))
            if self._channelid == channel.channel_id.hex():
                self._channel = channel
                self.channelChanged.emit()

    @pyqtProperty(str, notify=channelChanged)
    def name(self):
        if not self._channel:
            return
        return self._wallet.wallet.lnworker.get_node_alias(self._channel.node_id) or self._channel.node_id.hex()

    @pyqtProperty(str, notify=channelChanged)
    def pubkey(self):
        return self._channel.node_id.hex() #if self._channel else ''

    @pyqtProperty(str, notify=channelChanged)
    def short_cid(self):
        return self._channel.short_id_for_GUI()

    @pyqtProperty(str, notify=channelChanged)
    def state(self):
        return self._channel.get_state_for_GUI()

    @pyqtProperty(str, notify=channelChanged)
    def initiator(self):
        return 'Local' if self._channel.constraints.is_initiator else 'Remote'

    @pyqtProperty(QEAmount, notify=channelChanged)
    def capacity(self):
        self._capacity = QEAmount(amount_sat=self._channel.get_capacity())
        return self._capacity

    @pyqtProperty(QEAmount, notify=channelChanged)
    def canSend(self):
        self._can_send = QEAmount(amount_sat=self._channel.available_to_spend(LOCAL)/1000)
        return self._can_send

    @pyqtProperty(QEAmount, notify=channelChanged)
    def canReceive(self):
        self._can_receive = QEAmount(amount_sat=self._channel.available_to_spend(REMOTE)/1000)
        return self._can_receive

    @pyqtProperty(bool, notify=channelChanged)
    def frozenForSending(self):
        return self._channel.is_frozen_for_sending()

    @pyqtProperty(bool, notify=channelChanged)
    def frozenForReceiving(self):
        return self._channel.is_frozen_for_receiving()

    @pyqtProperty(str, notify=channelChanged)
    def channelType(self):
        return self._channel.storage['channel_type'].name_minimal

    @pyqtProperty(bool, notify=channelChanged)
    def isOpen(self):
        return self._channel.is_open()

    @pyqtProperty(bool, notify=channelChanged)
    def canClose(self):
        return self.canCoopClose or self.canForceClose

    @pyqtProperty(bool, notify=channelChanged)
    def canCoopClose(self):
        return ChanCloseOption.COOP_CLOSE in self._channel.get_close_options()

    @pyqtProperty(bool, notify=channelChanged)
    def canForceClose(self):
        return ChanCloseOption.LOCAL_FCLOSE in self._channel.get_close_options()

    @pyqtProperty(bool, notify=channelChanged)
    def canDelete(self):
        return self._channel.can_be_deleted()

    @pyqtProperty(str, notify=channelChanged)
    def message_force_close(self, notify=channelChanged):
        return _(messages.MSG_REQUEST_FORCE_CLOSE)

    @pyqtSlot()
    def freezeForSending(self):
        lnworker = self._channel.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self._channel.node_id):
            self._channel.set_frozen_for_sending(not self.frozenForSending)
            self.channelChanged.emit()
        else:
            self._logger.debug(messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP)

    @pyqtSlot()
    def freezeForReceiving(self):
        lnworker = self._channel.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self._channel.node_id):
            self._channel.set_frozen_for_receiving(not self.frozenForReceiving)
            self.channelChanged.emit()
        else:
            self._logger.debug(messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP)

    # this method assumes the qobject is not destroyed before the close either fails or succeeds
    @pyqtSlot(str)
    def close_channel(self, closetype):
        async def do_close(closetype, channel_id):
            try:
                if closetype == 'remote_force':
                    await self._wallet.wallet.lnworker.request_force_close(channel_id)
                elif closetype == 'local_force':
                    await self._wallet.wallet.lnworker.force_close_channel(channel_id)
                else:
                    await self._wallet.wallet.lnworker.close_channel(channel_id)
                self.channelCloseSuccess.emit()
            except Exception as e:
                self._logger.exception("Could not close channel: " + repr(e))
                self.channelCloseFailed.emit(_('Could not close channel: ') + repr(e))

        loop = self._wallet.wallet.network.asyncio_loop
        coro = do_close(closetype, self._channel.channel_id)
        asyncio.run_coroutine_threadsafe(coro, loop)

    @pyqtSlot()
    def deleteChannel(self):
        self._wallet.wallet.lnworker.remove_channel(self._channel.channel_id)
