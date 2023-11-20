import threading
from enum import IntEnum

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, pyqtEnum

from electrum.i18n import _
from electrum.gui import messages
from electrum.logging import get_logger
from electrum.lnutil import LOCAL, REMOTE
from electrum.lnchannel import ChanCloseOption, ChannelState

from .auth import AuthMixin, auth_protect
from .qewallet import QEWallet
from .qetypes import QEAmount
from .util import QtEventListener, event_listener


class QEChannelDetails(AuthMixin, QObject, QtEventListener):
    _logger = get_logger(__name__)

    @pyqtEnum
    class State(IntEnum):  # subset, only ones we currently need in UI
        Closed = ChannelState.CLOSED
        Redeemed = ChannelState.REDEEMED

    channelChanged = pyqtSignal()
    channelCloseSuccess = pyqtSignal()
    channelCloseFailed = pyqtSignal([str], arguments=['message'])
    isClosingChanged = pyqtSignal()
    trampolineFrozenInGossipMode = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None
        self._channelid = None
        self._channel = None

        self._capacity = QEAmount()
        self._local_capacity = QEAmount()
        self._remote_capacity = QEAmount()
        self._can_receive = QEAmount()
        self._can_send = QEAmount()
        self._is_closing = False

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
        lnchannels = self._wallet.wallet.lnworker.get_channel_objects()
        for channel in lnchannels.values():
            if self._channelid == channel.channel_id.hex():
                self._channel = channel
                self.channelChanged.emit()

    @pyqtProperty(str, notify=channelChanged)
    def name(self):
        if not self._channel:
            return
        return self._wallet.wallet.lnworker.get_node_alias(self._channel.node_id) or ''

    @pyqtProperty(str, notify=channelChanged)
    def pubkey(self):
        return self._channel.node_id.hex()

    @pyqtProperty(str, notify=channelChanged)
    def shortCid(self):
        return self._channel.short_id_for_GUI()

    @pyqtProperty(str, notify=channelChanged)
    def state(self):
        return self._channel.get_state_for_GUI()

    @pyqtProperty(int, notify=channelChanged)
    def stateCode(self):
        return self._channel.get_state()

    @pyqtProperty(str, notify=channelChanged)
    def initiator(self):
        if self._channel.is_backup():
            return ''
        return 'Local' if self._channel.constraints.is_initiator else 'Remote'

    @pyqtProperty('QVariantMap', notify=channelChanged)
    def fundingOutpoint(self):
        outpoint = self._channel.funding_outpoint
        return {
            'txid': outpoint.txid,
            'index': outpoint.output_index
        }

    @pyqtProperty(str, notify=channelChanged)
    def closingTxid(self):
        if not self._channel.is_closed():
            return ''
        item = self._channel.get_closing_height()
        if item:
            closing_txid, closing_height, timestamp = item
            return closing_txid
        else:
            return ''

    @pyqtProperty(QEAmount, notify=channelChanged)
    def capacity(self):
        self._capacity.copyFrom(QEAmount(amount_sat=self._channel.get_capacity()))
        return self._capacity

    @pyqtProperty(QEAmount, notify=channelChanged)
    def localCapacity(self):
        if not self._channel.is_backup():
            self._local_capacity.copyFrom(QEAmount(amount_msat=self._channel.balance(LOCAL)))
        return self._local_capacity

    @pyqtProperty(QEAmount, notify=channelChanged)
    def remoteCapacity(self):
        if not self._channel.is_backup():
            self._remote_capacity.copyFrom(QEAmount(amount_msat=self._channel.balance(REMOTE)))
        return self._remote_capacity

    @pyqtProperty(QEAmount, notify=channelChanged)
    def canSend(self):
        if not self._channel.is_backup():
            self._can_send.copyFrom(QEAmount(amount_msat=self._channel.available_to_spend(LOCAL)))
        return self._can_send

    @pyqtProperty(QEAmount, notify=channelChanged)
    def canReceive(self):
        if not self._channel.is_backup():
            self._can_receive.copyFrom(QEAmount(amount_msat=self._channel.available_to_spend(REMOTE)))
        return self._can_receive

    @pyqtProperty(bool, notify=channelChanged)
    def frozenForSending(self):
        return self._channel.is_frozen_for_sending()

    @pyqtProperty(bool, notify=channelChanged)
    def frozenForReceiving(self):
        return self._channel.is_frozen_for_receiving()

    @pyqtProperty(str, notify=channelChanged)
    def channelType(self):
        return self._channel.storage['channel_type'].name_minimal if 'channel_type' in self._channel.storage else 'Channel Backup'

    @pyqtProperty(bool, notify=channelChanged)
    def isOpen(self):
        return self._channel.is_open()

    @pyqtProperty(bool, notify=channelChanged)
    def canClose(self):
        return self.canCoopClose or self.canLocalForceClose or self.canRequestForceClose

    @pyqtProperty(bool, notify=channelChanged)
    def canCoopClose(self):
        return ChanCloseOption.COOP_CLOSE in self._channel.get_close_options()

    @pyqtProperty(bool, notify=channelChanged)
    def canLocalForceClose(self):
        return ChanCloseOption.LOCAL_FCLOSE in self._channel.get_close_options()

    @pyqtProperty(bool, notify=channelChanged)
    def canRequestForceClose(self):
        return ChanCloseOption.REQUEST_REMOTE_FCLOSE in self._channel.get_close_options()

    @pyqtProperty(bool, notify=channelChanged)
    def canDelete(self):
        return self._channel.can_be_deleted()

    @pyqtProperty(str, notify=channelChanged)
    def messageForceClose(self):
        return messages.MSG_REQUEST_FORCE_CLOSE.strip()

    @pyqtProperty(str, notify=channelChanged)
    def messageForceCloseBackup(self):
        return ' '.join([
            _('If you force-close this channel, the funds you have in it will not be available for {} blocks.').format(self.toSelfDelay),
            _('During that time, funds will not be recoverable from your seed, and may be lost if you lose your device.'),
            _('To prevent that, please save this channel backup.'),
            _('It may be imported in another wallet with the same seed.')
        ])

    @pyqtProperty(bool, notify=channelChanged)
    def isBackup(self):
        return self._channel.is_backup()

    @pyqtProperty(str, notify=channelChanged)
    def backupType(self):
        if not self.isBackup:
            return ''
        return 'imported' if self._channel.is_imported else 'on-chain'

    @pyqtProperty(int, notify=channelChanged)
    def toSelfDelay(self):
        return self._channel.config[REMOTE].to_self_delay

    @pyqtProperty(bool, notify=isClosingChanged)
    def isClosing(self):
        # Note: isClosing only applies to a closing action started by this instance, not
        # whether the channel is closing
        return self._is_closing

    @pyqtSlot()
    def freezeForSending(self):
        lnworker = self._channel.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self._channel.node_id):
            self._channel.set_frozen_for_sending(not self.frozenForSending)
            self.channelChanged.emit()
        else:
            self._logger.debug(messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP)
            self.trampolineFrozenInGossipMode.emit()

    @pyqtSlot()
    def freezeForReceiving(self):
        lnworker = self._channel.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self._channel.node_id):
            self._channel.set_frozen_for_receiving(not self.frozenForReceiving)
            self.channelChanged.emit()
        else:
            self._logger.debug(messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP)

    @pyqtSlot(str)
    def closeChannel(self, closetype):
        self.do_close_channel(closetype)

    @auth_protect(message=_('Close Lightning channel?'))
    def do_close_channel(self, closetype):
        channel_id = self._channel.channel_id

        def handle_result(success: bool, msg: str = ''):
            try:
                if success:
                    self.channelCloseSuccess.emit()
                else:
                    self.channelCloseFailed.emit(msg)

                self._is_closing = False
                self.isClosingChanged.emit()
            except RuntimeError:  # QEChannelDetails might be deleted at this point if the user closed the dialog.
                pass

        def do_close():
            try:
                self._is_closing = True
                self.isClosingChanged.emit()
                if closetype == 'remote_force':
                    self._wallet.wallet.network.run_from_another_thread(self._wallet.wallet.lnworker.request_force_close(channel_id))
                elif closetype == 'local_force':
                    self._wallet.wallet.network.run_from_another_thread(self._wallet.wallet.lnworker.force_close_channel(channel_id))
                else:
                    self._wallet.wallet.network.run_from_another_thread(self._wallet.wallet.lnworker.close_channel(channel_id))
                self._logger.debug('Channel close successful')
                handle_result(True)
            except Exception as e:
                self._logger.exception("Could not close channel: " + repr(e))
                handle_result(False, _('Could not close channel: ') + repr(e))

        threading.Thread(target=do_close, daemon=True).start()

    @pyqtSlot()
    def deleteChannel(self):
        if self.isBackup:
            self._wallet.wallet.lnworker.remove_channel_backup(self._channel.channel_id)
        else:
            self._wallet.wallet.lnworker.remove_channel(self._channel.channel_id)

    @pyqtSlot(result=str)
    def channelBackup(self):
        return self._wallet.wallet.lnworker.export_channel_backup(self._channel.channel_id)

    @pyqtSlot(result=str)
    def channelBackupHelpText(self):
        return ' '.join([
            _("Channel backups can be imported in another instance of the same wallet."),
            _("In the Electrum mobile app, use the 'Send' button to scan this QR code."),
            '\n\n',
            _("Please note that channel backups cannot be used to restore your channels."),
            _("If you lose your wallet file, the only thing you can do with a backup is to request your channel to be closed, so that your funds will be sent on-chain."),
        ])
