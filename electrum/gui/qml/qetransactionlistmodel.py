from datetime import datetime

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, TxMinedInfo

class QETransactionListModel(QAbstractListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.tx_history = []

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('txid','fee_sat','height','confirmations','timestamp','monotonic_timestamp',
                 'incoming','bc_value','bc_balance','date','label','txpos_in_block','fee',
                 'inputs','outputs')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def rowCount(self, index):
        return len(self.tx_history)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        tx = self.tx_history[index.row()]
        role_index = role - (Qt.UserRole + 1)
        value = tx[self._ROLE_NAMES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.tx_history = []
        self.endResetModel()

    # initial model data
    def init_model(self):
        history = self.wallet.get_detailed_history(show_addresses = True)
        txs = history['transactions']
        # use primitives
        for tx in txs:
            for output in tx['outputs']:
                output['value'] = output['value'].value

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(txs) - 1)
        self.tx_history = txs
        self.tx_history.reverse()
        self.endInsertRows()

    def update_tx(self, txid, info):
        i = 0
        for tx in self.tx_history:
            if tx['txid'] == txid:
                tx['height'] = info.height
                tx['confirmations'] = info.conf
                tx['timestamp'] = info.timestamp
                tx['date'] = datetime.fromtimestamp(info.timestamp)
                index = self.index(i,0)
                roles = [self._ROLE_RMAP[x] for x in ['height','confirmations','timestamp','date']]
                self.dataChanged.emit(index, index, roles)
                return
            i = i + 1

    @pyqtSlot(int)
    def updateBlockchainHeight(self, height):
        self._logger.debug('updating height to %d' % height)
        i = 0
        for tx in self.tx_history:
            if tx['height'] > 0:
                tx['confirmations'] = height - tx['height'] + 1
                index = self.index(i,0)
                roles = [self._ROLE_RMAP['confirmations']]
                self.dataChanged.emit(index, index, roles)
            i = i + 1
