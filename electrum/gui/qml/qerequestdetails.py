from time import time

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer

from electrum.logging import get_logger
from electrum.invoices import PR_UNPAID, LN_EXPIRY_NEVER

from .qewallet import QEWallet
from .qetypes import QEAmount

class QERequestDetails(QObject):
    _logger = get_logger(__name__)


    _wallet = None
    _key = None
    _req = None
    _timer = None

    _amount = None

    detailsChanged = pyqtSignal() # generic request properties changed signal

    def __init__(self, parent=None):
        super().__init__(parent)

    def __del__(self):
        if self._wallet:
            self._wallet.requestStatusChanged.disconnect(self.updateRequestStatus)
        if self._timer:
            self._timer.stop()
            self._timer = None

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            if self._wallet:
                self._wallet.requestStatusChanged.disconnect(self.updateRequestStatus)
            self._wallet = wallet
            self.walletChanged.emit()

            wallet.requestStatusChanged.connect(self.updateRequestStatus)

            self.initRequest()

    keyChanged = pyqtSignal()
    @pyqtProperty(str, notify=keyChanged)
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if self._key != key:
            self._key = key
            self._logger.debug(f'key={key}')
            self.keyChanged.emit()
            self.initRequest()

    statusChanged = pyqtSignal()
    @pyqtProperty(int, notify=statusChanged)
    def status(self):
        req = self._wallet.wallet.get_request(self._key)
        return self._wallet.wallet.get_invoice_status(req)

    @pyqtProperty(str, notify=statusChanged)
    def status_str(self):
        return self._req.get_status_str(self.status)

    @pyqtProperty(bool, notify=detailsChanged)
    def isLightning(self):
        return self._req.is_lightning()

    @pyqtProperty(str, notify=detailsChanged)
    def address(self):
        addr = self._req.get_address()
        return addr if addr else ''

    @pyqtProperty(str, notify=detailsChanged)
    def message(self):
        return self._req.get_message()

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def amount(self):
        return self._amount

    @pyqtProperty(int, notify=detailsChanged)
    def timestamp(self):
        return self._req.get_time()

    @pyqtProperty(int, notify=detailsChanged)
    def expiration(self):
        return self._req.get_expiration_date()

    @pyqtProperty(str, notify=detailsChanged)
    def bolt11(self):
        return self._req.lightning_invoice

    @pyqtProperty(str, notify=detailsChanged)
    def bip21(self):
        return self._req.get_bip21_URI()


    @pyqtSlot(str, int)
    def updateRequestStatus(self, key, status):
        if key == self._key:
            self._logger.debug(f'request with key {key} updated status ({status})')
            self.statusChanged.emit()


    def initRequest(self):
        if self._wallet is None or self._key is None:
            return

        self._req = self._wallet.wallet.get_request(self._key)

        if self._req is None:
            self._logger.error(f'payment request key {self._key} unknown in wallet {self._wallet.name}')
            return

        self._amount = QEAmount(from_invoice=self._req)

        self.initStatusStringTimer()

    def initStatusStringTimer(self):
        if self.status == PR_UNPAID:
            if self.expiration > 0 and self.expiration != LN_EXPIRY_NEVER:
                self._timer = QTimer(self)
                self._timer.setSingleShot(True)
                self._timer.timeout.connect(self.updateStatusString)

                # very roughly according to util.time_difference
                exp_in = int(self.expiration - time())
                exp_in_min = int(exp_in/60)

                interval = 0
                if exp_in < 0:
                    interval = 0
                if exp_in_min < 2:
                    interval = 1000
                elif exp_in_min < 90:
                    interval = 1000 * 60
                elif exp_in_min < 1440:
                    interval = 1000 * 60 * 60

                if interval > 0:
                    self._logger.debug(f'setting status update timer to {interval}, req expires in {exp_in} seconds')
                    self._timer.setInterval(interval)  # msec
                    self._timer.start()


    @pyqtSlot()
    def updateStatusString(self):
        self.statusStringChanged.emit()
        self.initStatusStringTimer()

