from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex, QByteArray

from electrum.util import register_callback, Satoshis
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet
from electrum import bitcoin
from electrum.transaction import Transaction, tx_from_any, PartialTransaction, PartialTxOutput
from electrum.invoices import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED, PR_UNCONFIRMED, PR_TYPE_ONCHAIN, PR_TYPE_LN

class QETransactionsListModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tx_history = []

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('txid','fee_sat','height','confirmations','timestamp','monotonic_timestamp','incoming','bc_value',
        'bc_balance','date','label','txpos_in_block','fee','inputs','outputs')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

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
    def set_history(self, history):
        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(history) - 1)
        self.tx_history = history
        self.tx_history.reverse()
        self.endInsertRows()

class QEWallet(QObject):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self._historyModel = QETransactionsListModel()
        self.get_history()
        register_callback(self.on_request_status, ['request_status'])

    _logger = get_logger(__name__)

    dataChanged = pyqtSignal() # dummy to silence warnings

    requestStatus = pyqtSignal()
    def on_request_status(self, event, *args):
        self._logger.debug(str(event))
#        (wallet, addr, status) = args
#        self._historyModel.add_tx()
        self.requestStatus.emit()

    historyModelChanged = pyqtSignal()
    @pyqtProperty(QETransactionsListModel, notify=historyModelChanged)
    def historyModel(self):
        return self._historyModel

    @pyqtProperty('QString', notify=dataChanged)
    def txinType(self):
        return self.wallet.get_txin_type(self.wallet.dummy_address())

    @pyqtProperty(bool, notify=dataChanged)
    def isWatchOnly(self):
        return self.wallet.is_watching_only()

    @pyqtProperty(bool, notify=dataChanged)
    def isDeterministic(self):
        return self.wallet.is_deterministic()

    @pyqtProperty(bool, notify=dataChanged)
    def isEncrypted(self):
        return self.wallet.storage.is_encrypted()

    @pyqtProperty(bool, notify=dataChanged)
    def isHardware(self):
        return self.wallet.storage.is_encrypted_with_hw_device()

    @pyqtProperty('QString', notify=dataChanged)
    def derivationPath(self):
        return self.wallet.get_address_path_str(self.wallet.dummy_address())

    balanceChanged = pyqtSignal()

    @pyqtProperty(int, notify=balanceChanged)
    def frozenBalance(self):
        return self.wallet.get_frozen_balance()

    @pyqtProperty(int, notify=balanceChanged)
    def unconfirmedBalance(self):
        return self.wallet.get_balance()[1]

    @pyqtProperty(int, notify=balanceChanged)
    def confirmedBalance(self):
        c, u, x = self.wallet.get_balance()
        self._logger.info('balance: ' + str(c) + ' ' + str(u) + ' ' + str(x) + ' ')

        return c+x

    # lightning feature?
    isUptodateChanged = pyqtSignal()
    @pyqtProperty(bool, notify=isUptodateChanged)
    def isUptodate(self):
        return self.wallet.is_up_to_date()

    def get_history(self):
        history = self.wallet.get_detailed_history(show_addresses = True)
        txs = history['transactions']
        # use primitives
        for tx in txs:
            for output in tx['outputs']:
                output['value'] = output['value'].value
        self._historyModel.set_history(txs)
        self.historyModelChanged.emit()

    @pyqtSlot('QString', int, int, bool)
    def send_onchain(self, address, amount, fee=None, rbf=False):
        self._logger.info('send_onchain: ' + address + ' ' + str(amount))
        coins = self.wallet.get_spendable_coins(None)
        if not bitcoin.is_address(address):
            self._logger.warning('Invalid Bitcoin Address: ' + address)
            return False

        outputs = [PartialTxOutput.from_address_and_value(address, amount)]
        tx = self.wallet.make_unsigned_transaction(coins=coins,outputs=outputs)
        return True
