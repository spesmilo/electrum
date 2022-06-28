from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Q_ENUMS

from electrum.logging import get_logger
from electrum.util import register_callback, unregister_callback
from electrum.lnutil import LOCAL, REMOTE

from .qewallet import QEWallet
from .qetypes import QEAmount

class QEChannelDetails(QObject):

    _logger = get_logger(__name__)
    _wallet = None
    _channelid = None
    _channel = None

    channelChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        register_callback(self.on_network, ['channel'])
        self.destroyed.connect(lambda: self.on_destroy())

    def on_network(self, event, *args):
        if event == 'channel':
            wallet, channel = args
            if wallet == self._wallet.wallet and self._channelid == channel.channel_id.hex():
                self.channelChanged.emit()

    def on_destroy(self):
        unregister_callback(self.on_network)

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
            self._logger.debug('%s == %s ?' % (self._channelid, channel.channel_id))
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

    @pyqtSlot()
    def freezeForSending(self):
        lnworker = self._channel.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self._channel.node_id):
            #self.is_frozen_for_sending = not self.is_frozen_for_sending
            self._channel.set_frozen_for_sending(not self.frozenForSending)
            self.channelChanged.emit()
        else:
            self._logger.debug('TODO: messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP')

    @pyqtSlot()
    def freezeForReceiving(self):
        lnworker = self._channel.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self._channel.node_id):
            #self.is_frozen_for_sending = not self.is_frozen_for_sending
            self._channel.set_frozen_for_receiving(not self.frozenForReceiving)
            self.channelChanged.emit()
        else:
            self._logger.debug('TODO: messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP')
