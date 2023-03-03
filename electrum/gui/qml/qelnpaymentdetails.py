from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.util import bfh, format_time

from .qetypes import QEAmount
from .qewallet import QEWallet

class QELnPaymentDetails(QObject):
    _logger = get_logger(__name__)

    detailsChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None
        self._key = None
        self._date = None
        self._fee = QEAmount()
        self._amount = QEAmount()

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

    keyChanged = pyqtSignal()
    @pyqtProperty(str, notify=keyChanged)
    def key(self):
        return self._key

    @key.setter
    def key(self, key: str):
        if self._key != key:
            self._logger.debug('key set -> %s' % key)
            self._key = key
            self.keyChanged.emit()
            self.update()

    labelChanged = pyqtSignal()
    @pyqtProperty(str, notify=labelChanged)
    def label(self):
        return self._label

    @pyqtSlot(str)
    def set_label(self, label: str):
        if label != self._label:
            self._wallet.wallet.set_label(self._key, label)
            self._label = label
            self.labelChanged.emit()

    @pyqtProperty(str, notify=detailsChanged)
    def status(self):
        return self._status

    @pyqtProperty(str, notify=detailsChanged)
    def date(self):
        return self._date

    @pyqtProperty(str, notify=detailsChanged)
    def payment_hash(self):
        return self._phash

    @pyqtProperty(str, notify=detailsChanged)
    def preimage(self):
        return self._preimage

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def amount(self):
        return self._amount

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def fee(self):
        return self._fee

    def update(self):
        if self._wallet is None:
            self._logger.error('wallet undefined')
            return

        # TODO this is horribly inefficient. need a payment getter/query method
        tx = self._wallet.wallet.lnworker.get_lightning_history()[bfh(self._key)]
        self._logger.debug(str(tx))

        self._fee.msatsInt = 0 if not tx['fee_msat'] else int(tx['fee_msat'])
        self._amount.msatsInt = int(tx['amount_msat'])
        self._label = tx['label']
        self._date = format_time(tx['timestamp'])
        self._status = 'settled' # TODO: other states? get_lightning_history is deciding the filter for us :(
        self._phash = tx['payment_hash']
        self._preimage = tx['preimage']

        self.detailsChanged.emit()
