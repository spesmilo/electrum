from datetime import datetime, timedelta

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, TxMinedInfo

from .qetypes import QEAmount

class QEChannelListModel(QAbstractListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.channels = []

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('cid','state','initiator','capacity','can_send','can_receive',
                 'l_csv_delat','r_csv_delay','send_frozen','receive_frozen',
                 'type','node_id','node_alias','short_cid','funding_tx')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

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
        item['node_alias'] = lnworker.get_node_alias(lnc.node_id) or lnc.node_id.hex()
        item['short_cid'] = lnc.short_id_for_GUI()
        item['state'] = lnc.get_state_for_GUI()
        item['capacity'] = QEAmount(amount_sat=lnc.get_capacity())
        self._logger.debug(repr(item))
        return item

    @pyqtSlot()
    def init_model(self):
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
