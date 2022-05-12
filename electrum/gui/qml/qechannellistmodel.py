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
                 'type','node_id','funding_tx')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def rowCount(self, index):
        return len(self.tx_history)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        tx = self.tx_history[index.row()]
        role_index = role - Qt.UserRole
        value = tx[self._ROLE_NAMES[role_index]]
        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        if isinstance(value, QEAmount):
            return value
        return str(value)

    @pyqtSlot()
    def init_model(self):
        if not self.wallet.lnworker:
            self._logger.warning('lnworker should be defined')
            return

        channels = self.wallet.lnworker.channels
        self._logger.debug(repr(channels))
        #channels = list(lnworker.channels.values()) if lnworker else []
