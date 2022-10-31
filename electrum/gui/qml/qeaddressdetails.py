from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger

from .qetransactionlistmodel import QETransactionListModel
from .qetypes import QEAmount
from .qewallet import QEWallet


class QEAddressDetails(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)

    _logger = get_logger(__name__)

    _wallet = None
    _address = None

    _label = None
    _frozen = False
    _scriptType = None
    _status = None
    _balance = QEAmount()
    _pubkeys = None
    _privkey = None
    _derivationPath = None
    _numtx = 0

    _historyModel = None

    detailsChanged = pyqtSignal()

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

    addressChanged = pyqtSignal()
    @pyqtProperty(str, notify=addressChanged)
    def address(self):
        return self._address

    @address.setter
    def address(self, address: str):
        if self._address != address:
            self._logger.debug('address changed')
            self._address = address
            self.addressChanged.emit()
            self.update()

    @pyqtProperty(str, notify=detailsChanged)
    def scriptType(self):
        return self._scriptType

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def balance(self):
        return self._balance

    @pyqtProperty('QStringList', notify=detailsChanged)
    def pubkeys(self):
        return self._pubkeys

    @pyqtProperty(str, notify=detailsChanged)
    def derivationPath(self):
        return self._derivationPath

    @pyqtProperty(int, notify=detailsChanged)
    def numTx(self):
        return self._numtx


    frozenChanged = pyqtSignal()
    @pyqtProperty(bool, notify=frozenChanged)
    def isFrozen(self):
        return self._frozen

    labelChanged = pyqtSignal()
    @pyqtProperty(str, notify=labelChanged)
    def label(self):
        return self._label

    @pyqtSlot(bool)
    def freeze(self, freeze: bool):
        if freeze != self._frozen:
            self._wallet.wallet.set_frozen_state_of_addresses([self._address], freeze=freeze)
            self._frozen = freeze
            self.frozenChanged.emit()
            self._wallet.balanceChanged.emit()

    @pyqtSlot(str)
    def set_label(self, label: str):
        if label != self._label:
            self._wallet.wallet.set_label(self._address, label)
            self._label = label
            self.labelChanged.emit()

    historyModelChanged = pyqtSignal()
    @pyqtProperty(QETransactionListModel, notify=historyModelChanged)
    def historyModel(self):
        if self._historyModel is None:
            self._historyModel = QETransactionListModel(self._wallet.wallet,
                                                        onchain_domain=[self._address], include_lightning=False)
        return self._historyModel

    def update(self):
        if self._wallet is None:
            self._logger.error('wallet undefined')
            return

        self._frozen = self._wallet.wallet.is_frozen_address(self._address)
        self.frozenChanged.emit()

        self._scriptType = self._wallet.wallet.get_txin_type(self._address)
        self._label = self._wallet.wallet.get_label_for_address(self._address)
        c, u, x = self._wallet.wallet.get_addr_balance(self._address)
        self._balance = QEAmount(amount_sat=c + u + x)
        self._pubkeys = self._wallet.wallet.get_public_keys(self._address)
        self._derivationPath = self._wallet.wallet.get_address_path_str(self._address)
        if self._wallet.derivationPrefix:
            self._derivationPath = self._derivationPath.replace('m', self._wallet.derivationPrefix)
        self._numtx = self._wallet.wallet.adb.get_address_history_len(self._address)
        assert self._numtx == self.historyModel.rowCount(0)
        self.detailsChanged.emit()
