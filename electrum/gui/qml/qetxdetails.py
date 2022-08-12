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
    _label = ''

    _status = ''
    _amount = QEAmount(amount_sat=0)
    _fee = QEAmount(amount_sat=0)
    _inputs = []
    _outputs = []

    _is_lightning_funding_tx = False
    _can_bump = False
    _can_dscancel = False
    _can_broadcast = False
    _can_cpfp = False
    _can_save_as_local = False
    _can_remove = False

    _is_mined = False

    _mempool_depth = ''

    _date = ''
    _height = 0
    _confirmations = 0
    _txpos = -1
    _header_hash = ''

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

    @pyqtProperty(bool, notify=detailsChanged)
    def isMined(self):
        return self._is_mined

    @pyqtProperty(str, notify=detailsChanged)
    def mempoolDepth(self):
        return self._mempool_depth

    @pyqtProperty(str, notify=detailsChanged)
    def date(self):
        return self._date

    @pyqtProperty(int, notify=detailsChanged)
    def height(self):
        return self._height

    @pyqtProperty(int, notify=detailsChanged)
    def confirmations(self):
        return self._confirmations

    @pyqtProperty(int, notify=detailsChanged)
    def txpos(self):
        return self._txpos

    @pyqtProperty(str, notify=detailsChanged)
    def headerHash(self):
        return self._header_hash

    @pyqtProperty(bool, notify=detailsChanged)
    def isLightningFundingTx(self):
        return self._is_lightning_funding_tx

    @pyqtProperty(bool, notify=detailsChanged)
    def canBump(self):
        return self._can_bump

    @pyqtProperty(bool, notify=detailsChanged)
    def canCancel(self):
        return self._can_dscancel

    @pyqtProperty(bool, notify=detailsChanged)
    def canBroadcast(self):
        return self._can_broadcast

    @pyqtProperty(bool, notify=detailsChanged)
    def canCpfp(self):
        return self._can_cpfp

    @pyqtProperty(bool, notify=detailsChanged)
    def canSaveAsLocal(self):
        return self._can_save_as_local

    @pyqtProperty(bool, notify=detailsChanged)
    def canRemove(self):
        return self._can_remove

    def update(self):
        if self._wallet is None:
            self._logger.error('wallet undefined')
            return

        # abusing get_input_tx to get tx from txid
        tx = self._wallet.wallet.get_input_tx(self._txid)

        #self._logger.debug(repr(tx.to_json()))

        self._inputs = list(map(lambda x: x.to_json(), tx.inputs()))
        self._outputs = list(map(lambda x: {
            'address': x.get_ui_address_str(),
            'value': QEAmount(amount_sat=x.value),
            'is_mine': self._wallet.wallet.is_mine(x.get_ui_address_str())
            }, tx.outputs()))

        txinfo = self._wallet.wallet.get_tx_info(tx)

        #self._logger.debug(repr(txinfo))

        # can be None if outputs unrelated to wallet seed,
        # e.g. to_local local_force_close commitment CSV-locked p2wsh script
        if txinfo.amount is None:
            self._amount = QEAmount(amount_sat=0)
        else:
            self._amount = QEAmount(amount_sat=txinfo.amount)

        self._status = txinfo.status
        self._fee = QEAmount(amount_sat=txinfo.fee)

        self._is_mined = txinfo.tx_mined_status != None
        if self._is_mined:
            self.update_mined_status(txinfo.tx_mined_status)
        else:
            # TODO mempool_depth_bytes can be None if not mined?
            if txinfo.mempool_depth_bytes is None:
                self._logger.error('TX is not mined, yet mempool_depth_bytes is None')
            self._mempool_depth = self._wallet.wallet.config.depth_tooltip(txinfo.mempool_depth_bytes)

        self._is_lightning_funding_tx = txinfo.is_lightning_funding_tx
        self._can_bump = txinfo.can_bump
        self._can_dscancel = txinfo.can_dscancel
        self._can_broadcast = txinfo.can_broadcast
        self._can_cpfp = txinfo.can_cpfp
        self._can_save_as_local = txinfo.can_save_as_local
        self._can_remove = txinfo.can_remove

        self.detailsChanged.emit()

        if self._label != txinfo.label:
            self._label = txinfo.label
            self.labelChanged.emit()

    def update_mined_status(self, tx_mined_info):
        self._mempool_depth = ''
        self._date = format_time(tx_mined_info.timestamp)
        self._height = tx_mined_info.height
        self._confirmations = tx_mined_info.conf
        self._txpos = tx_mined_info.txpos
        self._header_hash = tx_mined_info.header_hash
