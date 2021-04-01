from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.util import register_callback
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet

class QETransactionsListModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tx_history = []

    def rowCount(self, index):
        return len(self.tx_history)

    def data(self, index, role):
        if role == Qt.DisplayRole:
            return str(self.tx_history[index.row()]['bc_value'])

    def set_history(self, history):
        self.beginInsertRows(QModelIndex(), 0, len(history) - 1)
        self.tx_history = history
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
        self._historyModel.set_history(txs)

