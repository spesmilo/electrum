from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex, QByteArray

from electrum.util import register_callback, Satoshis
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet

class QETransactionsListModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tx_history = []

    _logger = get_logger(__name__)

    # define listmodel rolemap
    ROLES=('txid','fee_sat','height','confirmations','timestamp','monotonic_timestamp','incoming','bc_value',
        'bc_balance','date','label','txpos_in_block','fee','inputs','outputs')
    keys = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(ROLES))
    ROLENAMES = [bytearray(x.encode()) for x in ROLES]
    _ROLE_MAP = dict(zip(keys, ROLENAMES))

    def rowCount(self, index):
        return len(self.tx_history)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        tx = self.tx_history[index.row()]
        role_index = role - (Qt.UserRole + 1)
        value = tx[self.ROLES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def set_history(self, history):
        self.beginInsertRows(QModelIndex(), 0, len(history) - 1)
        self.tx_history = history
        self.tx_history.reverse()
        self.endInsertRows()

class QEWallet(QObject):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.get_history()

    _logger = get_logger(__name__)

    _historyModel = QETransactionsListModel()

    @pyqtProperty(QETransactionsListModel)
    def historyModel(self):
        return self._historyModel

    def get_history(self):
        history = self.wallet.get_detailed_history(show_addresses = True)
        txs = history['transactions']
        self._logger.info(txs)
        # use primitives
        for tx in txs:
            for output in tx['outputs']:
                output['value'] = output['value'].value
        self._historyModel.set_history(txs)

