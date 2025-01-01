from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.util import UserFacingException

from .auth import auth_protect, AuthMixin
from .qetransactionlistmodel import QETransactionListModel
from .qetypes import QEAmount
from .qewallet import QEWallet


class QEAddressDetails(AuthMixin, QObject):
    _logger = get_logger(__name__)

    detailsChanged = pyqtSignal()
    addressDeleteFailed = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None
        self._address = None

        self._label = None
        self._frozen = False
        self._scriptType = None
        self._status = None
        self._balance = QEAmount()
        self._pubkeys = None
        self._privkey = None
        self._derivationPath = None
        self._numtx = 0
        self._candelete = False

        self._historyModel = None

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
    def privkey(self):
        return self._privkey

    @pyqtProperty(str, notify=detailsChanged)
    def derivationPath(self):
        return self._derivationPath

    @pyqtProperty(int, notify=detailsChanged)
    def numTx(self):
        return self._numtx

    @pyqtProperty(bool, notify=detailsChanged)
    def canDelete(self):
        return self._candelete

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
    def setLabel(self, label: str):
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

    @pyqtSlot()
    def requestShowPrivateKey(self):
        self.retrieve_private_key()

    @auth_protect(method='wallet')
    def retrieve_private_key(self):
        try:
            self._privkey = self._wallet.wallet.export_private_key(self._address, self._wallet.password)
        except Exception as e:
            self._logger.error(f'problem retrieving privkey: {str(e)}')
            self._privkey = ''

        self.detailsChanged.emit()

    @pyqtSlot(result=bool)
    def deleteAddress(self):
        assert self.canDelete
        try:
            self._wallet.wallet.delete_address(self._address)
            self._wallet.historyModel.setDirty()
        except UserFacingException as e:
            self.addressDeleteFailed.emit(str(e))
            return False
        return True

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
        self._candelete = self.wallet.wallet.can_delete_address()
        self.detailsChanged.emit()
