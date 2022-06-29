from datetime import datetime, timedelta

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, register_callback, unregister_callback
from electrum.lnutil import LOCAL, REMOTE

from .qetypes import QEAmount

class QEChannelListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('cid','state','initiator','capacity','can_send','can_receive',
                 'l_csv_delay','r_csv_delay','send_frozen','receive_frozen',
                 'type','node_id','node_alias','short_cid','funding_tx')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    _network_signal = pyqtSignal(str, object)

    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.init_model()

        self._network_signal.connect(self.on_network_qt)
        interests = ['channel', 'channels_updated', 'gossip_peers',
                     'ln_gossip_sync_progress', 'unknown_channels',
                     'channel_db', 'gossip_db_loaded']
        # To avoid leaking references to "self" that prevent the
        # window from being GC-ed when closed, callbacks should be
        # methods of this class only, and specifically not be
        # partials, lambdas or methods of subobjects.  Hence...
        register_callback(self.on_network, interests)
        self.destroyed.connect(lambda: self.on_destroy())

    def on_network(self, event, *args):
        if event == 'channel':
            # Handle in GUI thread (_network_signal -> on_network_qt)
            self._network_signal.emit(event, args)
        else:
            self.on_network_qt(event, args)

    def on_network_qt(self, event, args=None):
        if event == 'channel':
            wallet, channel = args
            if wallet == self.wallet:
                self.on_channel_updated(channel)
        elif event == 'channels_updated':
            wallet, = args
            if wallet == self.wallet:
                self.init_model() # TODO: remove/add less crude than full re-init
        else:
            self._logger.debug('unhandled event %s: %s' % (event, repr(args)))

    def on_destroy(self):
        unregister_callback(self.on_network)

    def rowCount(self, index):
        return len(self.channels)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        tx = self.channels[index.row()]
        role_index = role - Qt.UserRole
        value = tx[self._ROLE_NAMES[role_index]]
        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.channels = []
        self.endResetModel()

    def channel_to_model(self, lnc):
        lnworker = self.wallet.lnworker
        item = {}
        item['cid'] = lnc.channel_id.hex()
        item['node_alias'] = lnworker.get_node_alias(lnc.node_id) or lnc.node_id.hex()
        item['short_cid'] = lnc.short_id_for_GUI()
        item['state'] = lnc.get_state_for_GUI()
        item['capacity'] = QEAmount(amount_sat=lnc.get_capacity())
        item['can_send'] = QEAmount(amount_msat=lnc.available_to_spend(LOCAL))
        item['can_receive'] = QEAmount(amount_msat=lnc.available_to_spend(REMOTE))
        self._logger.debug(repr(item))
        return item

    @pyqtSlot()
    def init_model(self):
        self._logger.debug('init_model')
        if not self.wallet.lnworker:
            self._logger.warning('lnworker should be defined')
            return

        channels = []

        lnchannels = self.wallet.lnworker.channels
        for channel in lnchannels.values():
            self._logger.debug(repr(channel))
            item = self.channel_to_model(channel)
            channels.append(item)

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(channels) - 1)
        self.channels = channels
        self.endInsertRows()

    def on_channel_updated(self, channel):
        i = 0
        for c in self.channels:
            if c['cid'] == channel.channel_id.hex():
                self.do_update(i,channel)
                break
            i = i + 1

    def do_update(self, modelindex, channel):
        modelitem = self.channels[modelindex]
        self._logger.debug(repr(modelitem))
        modelitem.update(self.channel_to_model(channel))

        mi = self.createIndex(modelindex, 0)
        self.dataChanged.emit(mi, mi, self._ROLE_KEYS)

    @pyqtSlot(str)
    def new_channel(self, cid):
        lnchannels = self.wallet.lnworker.channels
        for channel in lnchannels.values():
            self._logger.debug(repr(channel))
            if cid == channel.channel_id.hex():
                item = self.channel_to_model(channel)
                self._logger.debug(item)
                self.beginInsertRows(QModelIndex(), 0, 0)
                self.channels.insert(0,item)
                self.endInsertRows()
