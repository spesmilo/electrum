from enum import IntEnum
from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer, pyqtEnum

from electrum.logging import get_logger
from electrum.invoices import (
    PR_UNPAID, PR_EXPIRED, PR_UNKNOWN, PR_PAID, PR_INFLIGHT, PR_FAILED, PR_ROUTING, PR_UNCONFIRMED, LN_EXPIRY_NEVER
)
from electrum.lnutil import MIN_FUNDING_SAT

from .qewallet import QEWallet
from .qetypes import QEAmount
from .util import QtEventListener, event_listener, status_update_timer_interval


class QERequestDetails(QObject, QtEventListener):

    @pyqtEnum
    class Status(IntEnum):
        Unpaid = PR_UNPAID
        Expired = PR_EXPIRED
        Unknown = PR_UNKNOWN
        Paid = PR_PAID
        Inflight = PR_INFLIGHT
        Failed = PR_FAILED
        Routing = PR_ROUTING
        Unconfirmed = PR_UNCONFIRMED

    _logger = get_logger(__name__)

    detailsChanged = pyqtSignal()  # generic request properties changed signal
    statusChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None  # type: Optional[QEWallet]
        self._key = None
        self._req = None
        self._timer = None
        self._amount = None

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.updateStatusString)

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    def on_destroy(self):
        self.unregister_callbacks()
        if self._timer:
            self._timer.stop()
            self._timer = None

    @event_listener
    def on_event_request_status(self, wallet, key, status):
        if wallet == self._wallet.wallet and key == self._key:
            self._logger.debug('request status %d for key %s' % (status, key))
            self.statusChanged.emit()

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()
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

    @pyqtProperty(int, notify=statusChanged)
    def status(self):
        return self._wallet.wallet.get_invoice_status(self._req)

    @pyqtProperty(str, notify=statusChanged)
    def status_str(self):
        return self._req.get_status_str(self.status) if self._req else ''

    @pyqtProperty(bool, notify=detailsChanged)
    def isLightning(self):
        return self._req.is_lightning() if self._req else False

    @pyqtProperty(str, notify=detailsChanged)
    def address(self):
        addr = self._req.get_address() if self._req else ''
        return addr if addr else ''

    @pyqtProperty(str, notify=detailsChanged)
    def message(self):
        return self._req.get_message() if self._req else ''

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def amount(self):
        return self._amount

    @pyqtProperty(int, notify=detailsChanged)
    def timestamp(self):
        return self._req.get_time()

    @pyqtProperty(int, notify=detailsChanged)
    def expiration(self):
        return self._req.get_expiration_date()

    @pyqtProperty(str, notify=statusChanged)
    def paidTxid(self):
        """only used when Request status is PR_PAID"""
        if not self._req:
            return ''
        is_paid, conf_needed, txids = self._wallet.wallet._is_onchain_invoice_paid(self._req)
        if len(txids) > 0:
            return txids[0]
        return ''

    @pyqtProperty(str, notify=detailsChanged)
    def bolt11(self):
        wallet = self._wallet.wallet
        if not wallet.lnworker:
            return ''
        amount_sat = self._req.get_amount_sat() or 0 if self._req else 0
        can_receive = wallet.lnworker.num_sats_can_receive()
        will_req_zeroconf = wallet.lnworker.receive_requires_jit_channel(amount_msat=amount_sat*1000)
        if self._req and ((can_receive > 0 and amount_sat <= can_receive)
                          or (will_req_zeroconf and amount_sat >= MIN_FUNDING_SAT)):
            bolt11 = wallet.get_bolt11_invoice(self._req)
        else:
            return ''
        # encode lightning invoices as uppercase so QR encoding can use
        # alphanumeric mode; resulting in smaller QR codes
        bolt11 = bolt11.upper()
        return bolt11

    @pyqtProperty(str, notify=detailsChanged)
    def bip21(self):
        return self._req.get_bip21_URI() if self._req else ''

    def initRequest(self):
        if self._wallet is None or self._key is None:
            return

        self._req = self._wallet.wallet.get_request(self._key)

        if self._req is None:
            self._logger.error(f'payment request key {self._key} unknown in wallet {self._wallet.name}')
            return

        self._amount = QEAmount(from_invoice=self._req)

        self.detailsChanged.emit()
        self.statusChanged.emit()
        self.set_status_timer()

    def set_status_timer(self):
        if self.status == PR_UNPAID:
            if self.expiration > 0 and self.expiration != LN_EXPIRY_NEVER:
                self._logger.debug(f'set_status_timer, expiration={self.expiration}')
                interval = status_update_timer_interval(self.expiration)
                if interval > 0:
                    self._logger.debug(f'setting status update timer to {interval}')
                    self._timer.setInterval(interval)  # msec
                    self._timer.start()

    @pyqtSlot()
    def updateStatusString(self):
        self.statusChanged.emit()
        self.set_status_timer()

