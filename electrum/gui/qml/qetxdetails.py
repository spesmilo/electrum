from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum.util import format_time

from .qewallet import QEWallet
from .qetypes import QEAmount

class QETxDetails(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)

    _logger = get_logger(__name__)

    _wallet = None
    _txid = None

    _mempool_depth = None
    _date = None

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

    txidChanged = pyqtSignal()
    @pyqtProperty(str, notify=txidChanged)
    def txid(self):
        return self._txid

    @txid.setter
    def txid(self, txid: str):
        if self._txid != txid:
            self._logger.debug('txid set -> %s' % txid)
            self._txid = txid
            self.txidChanged.emit()
            self.update()

    labelChanged = pyqtSignal()
    @pyqtProperty(str, notify=labelChanged)
    def label(self):
        return self._label

    @pyqtSlot(str)
    def set_label(self, label: str):
        if label != self._label:
            self._wallet.wallet.set_label(self._txid, label)
            self._label = label
            self.labelChanged.emit()

    @pyqtProperty(str, notify=detailsChanged)
    def status(self):
        return self._status

    @pyqtProperty(str, notify=detailsChanged)
    def date(self):
        return self._date

    @pyqtProperty(str, notify=detailsChanged)
    def mempoolDepth(self):
        return self._mempool_depth

    @pyqtProperty(bool, notify=detailsChanged)
    def isMined(self):
        return self._is_mined

    @pyqtProperty(bool, notify=detailsChanged)
    def isLightningFundingTx(self):
        return self._is_lightning_funding_tx

    @pyqtProperty(bool, notify=detailsChanged)
    def canBump(self):
        return self._can_bump

    @pyqtProperty(bool, notify=detailsChanged)
    def canCancel(self):
        return self._can_dscancel

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def amount(self):
        return self._amount

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def fee(self):
        return self._fee

    @pyqtProperty('QVariantList', notify=detailsChanged)
    def inputs(self):
        return self._inputs

    @pyqtProperty('QVariantList', notify=detailsChanged)
    def outputs(self):
        return self._outputs

    def update(self):
        if self._wallet is None:
            self._logger.error('wallet undefined')
            return

        # abusing get_input_tx to get tx from txid
        tx = self._wallet.wallet.get_input_tx(self._txid)

        self._inputs = list(map(lambda x: x.to_json(), tx.inputs()))
        self._outputs = list(map(lambda x: {
            'address': x.get_ui_address_str(),
            'value': QEAmount(amount_sat=x.value),
            'is_mine': self._wallet.wallet.is_mine(x.get_ui_address_str())
            }, tx.outputs()))

        txinfo = self._wallet.wallet.get_tx_info(tx)
        self._status = txinfo.status
        self._label = txinfo.label
        self._amount = QEAmount(amount_sat=txinfo.amount) # can be None?
        self._fee = QEAmount(amount_sat=txinfo.fee)

        self._is_mined = txinfo.tx_mined_status != None
        if self._is_mined:
            self._date = format_time(txinfo.tx_mined_status.timestamp)
        else:
            #TODO mempool_depth_bytes can be None?
            self._mempool_depth = self._wallet.wallet.config.depth_tooltip(txinfo.mempool_depth_bytes)

        self._is_lightning_funding_tx = txinfo.is_lightning_funding_tx
        self._can_bump = txinfo.can_bump
        self._can_dscancel = txinfo.can_dscancel

        self._logger.debug(repr(txinfo.mempool_depth_bytes))
        self._logger.debug(repr(txinfo.can_broadcast))
        self._logger.debug(repr(txinfo.can_cpfp))
        self._logger.debug(repr(txinfo.can_save_as_local))
        self._logger.debug(repr(txinfo.can_remove))

        self.detailsChanged.emit()
