from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import format_time, TxMinedInfo
from electrum.transaction import tx_from_any, Transaction, PartialTxInput, Sighash, PartialTransaction, TxOutpoint
from electrum.network import Network
from electrum.address_synchronizer import TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_FUTURE
from electrum.wallet import TxSighashDanger

from .qewallet import QEWallet
from .qetypes import QEAmount
from .util import QtEventListener, event_listener


class QETxDetails(QObject, QtEventListener):
    _logger = get_logger(__name__)

    confirmRemoveLocalTx = pyqtSignal([str], arguments=['message'])
    txRemoved = pyqtSignal()
    saveTxError = pyqtSignal([str,str], arguments=['code', 'message'])
    saveTxSuccess = pyqtSignal()

    detailsChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

        self._wallet = None  # type: Optional[QEWallet]
        self._txid = ''
        self._rawtx = ''
        self._label = ''

        self._tx = None  # type: Optional[Transaction]

        self._status = ''
        self._amount = QEAmount()
        self._lnamount = QEAmount()
        self._fee = QEAmount()
        self._feerate_str = ''
        self._inputs = []
        self._outputs = []

        self._is_lightning_funding_tx = False
        self._can_bump = False
        self._can_dscancel = False
        self._can_broadcast = False
        self._can_cpfp = False
        self._can_save_as_local = False
        self._can_remove = False
        self._can_sign = False
        self._is_unrelated = False
        self._is_complete = False
        self._is_mined = False
        self._is_rbf_enabled = False
        self._lock_delay = 0
        self._sighash_danger = TxSighashDanger()

        self._mempool_depth = ''
        self._in_mempool = False

        self._date = ''
        self._timestamp = 0
        self._confirmations = 0
        self._header_hash = ''
        self._short_id = ""

    def on_destroy(self):
        self.unregister_callbacks()

    @event_listener
    def on_event_verified(self, wallet, txid, info):
        if wallet == self._wallet.wallet and txid == self._txid:
            self._logger.debug(f'verified event for our txid {txid}')
            self.update()

    @event_listener
    def on_event_new_transaction(self, wallet, tx):
        if wallet == self._wallet.wallet and tx.txid() == self._txid:
            self._logger.debug(f'new_transaction event for our txid {self._txid}')
            self.update()

    @event_listener
    def on_event_removed_transaction(self, wallet, tx):
        if wallet == self._wallet.wallet and tx.txid() == self._txid:
            self._logger.debug(f'removed my transaction {tx.txid()}')
            self.txRemoved.emit()

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
            self._logger.debug(f'txid set -> {txid}')
            self._txid = txid
            self.txidChanged.emit()
            self.update(from_txid=True)

    @pyqtProperty(str, notify=detailsChanged)
    def rawtx(self):
        return self._rawtx

    @rawtx.setter
    def rawtx(self, rawtx: str):
        if self._rawtx != rawtx:
            self._logger.debug(f'rawtx set -> {rawtx}')
            self._rawtx = rawtx
            if not rawtx:
                return
            try:
                self._tx = tx_from_any(rawtx, deserialize=True)
                self._txid = self._tx.txid()
                self.txidChanged.emit()
                self.update()
            except Exception as e:
                self._tx = None
                self._logger.error(repr(e))

    labelChanged = pyqtSignal()
    @pyqtProperty(str, notify=labelChanged)
    def label(self):
        return self._label

    @pyqtSlot(str)
    def setLabel(self, label: str):
        if label != self._label:
            self._wallet.wallet.set_label(self._txid, label)
            self._label = label
            self.labelChanged.emit()

    @pyqtProperty(str, notify=detailsChanged)
    def status(self):
        return self._status

    @pyqtProperty(str, notify=detailsChanged)
    def warning(self):
        return self._sighash_danger.get_long_message()

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def amount(self):
        return self._amount

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def lnAmount(self):
        return self._lnamount

    @pyqtProperty(QEAmount, notify=detailsChanged)
    def fee(self):
        return self._fee

    @pyqtProperty(str, notify=detailsChanged)
    def feeRateStr(self):
        return self._feerate_str

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

    @pyqtProperty(bool, notify=detailsChanged)
    def inMempool(self):
        return self._in_mempool

    @pyqtProperty(str, notify=detailsChanged)
    def date(self):
        return self._date

    @pyqtProperty(int, notify=detailsChanged)
    def timestamp(self):
        return self._timestamp

    @pyqtProperty(int, notify=detailsChanged)
    def confirmations(self):
        return self._confirmations

    @pyqtProperty(str, notify=detailsChanged)
    def shortId(self):
        return self._short_id

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

    @pyqtProperty(bool, notify=detailsChanged)
    def canSign(self):
        return self._can_sign

    @pyqtProperty(bool, notify=detailsChanged)
    def isUnrelated(self):
        return self._is_unrelated

    @pyqtProperty(bool, notify=detailsChanged)
    def isComplete(self):
        return self._is_complete

    @pyqtProperty(bool, notify=detailsChanged)
    def isRbfEnabled(self):
        return self._is_rbf_enabled

    @pyqtProperty(int, notify=detailsChanged)
    def lockDelay(self):
        return self._lock_delay

    @pyqtProperty(bool, notify=detailsChanged)
    def shouldConfirm(self):
        return self._sighash_danger.needs_confirm()

    def update(self, from_txid: bool = False):
        assert self._wallet

        if from_txid:
            self._tx = self._wallet.wallet.db.get_transaction(self._txid)
            assert self._tx is not None, f'unknown txid "{self._txid}"'

        #self._logger.debug(repr(self._tx.to_json()))

        self._logger.debug('adding info from wallet')
        self._tx.add_info_from_wallet(self._wallet.wallet)
        if not self._tx.is_complete() and self._tx.is_missing_info_from_network():
            Network.run_from_another_thread(
                self._tx.add_info_from_network(self._wallet.wallet.network, timeout=10))  # FIXME is this needed?...

        self._inputs = list(map(lambda x: {
            'short_id': x.prevout.short_name(),
            'value': x.value_sats(),
            'address': x.address,
            'is_mine': self._wallet.wallet.is_mine(x.address),
            'is_change': self._wallet.wallet.is_change(x.address)
        }, self._tx.inputs()))
        self._outputs = list(map(lambda x: {
            'address': x.get_ui_address_str(),
            'value': QEAmount(amount_sat=x.value),
            'short_id': '',  # TODO
            'is_mine': self._wallet.wallet.is_mine(x.get_ui_address_str()),
            'is_change': self._wallet.wallet.is_change(x.get_ui_address_str()),
            'is_billing': self._wallet.wallet.is_billing_address(x.get_ui_address_str())
        }, self._tx.outputs()))

        txinfo = self._wallet.wallet.get_tx_info(self._tx)

        self._logger.debug(repr(txinfo))

        # can be None if outputs unrelated to wallet seed,
        # e.g. to_local local_force_close commitment CSV-locked p2wsh script
        if txinfo.amount is None:
            self._amount.satsInt = 0
        else:
            self._amount.satsInt = txinfo.amount

        self._status = txinfo.status
        self._fee.satsInt = txinfo.fee

        self._feerate_str = ""
        if txinfo.fee is not None:
            size = self._tx.estimated_size()
            fee_per_kb = txinfo.fee / size * 1000
            self._feerate_str = self._wallet.wallet.config.format_fee_rate(fee_per_kb)

        self._sighash_danger = TxSighashDanger()

        self._lock_delay = 0
        self._in_mempool = False
        self._is_mined = False if not txinfo.tx_mined_status else txinfo.tx_mined_status.height > 0
        if self._is_mined:
            self.update_mined_status(txinfo.tx_mined_status)
        else:
            if txinfo.tx_mined_status.height in [TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT]:
                self._mempool_depth = self._wallet.wallet.config.depth_tooltip(txinfo.mempool_depth_bytes)
                self._in_mempool = True
            elif txinfo.tx_mined_status.height == TX_HEIGHT_FUTURE:
                self._lock_delay = txinfo.tx_mined_status.wanted_height - self._wallet.wallet.adb.get_local_height()
            if isinstance(self._tx, PartialTransaction):
                self._sighash_danger = self._wallet.wallet.check_sighash(self._tx)

        if self._wallet.wallet.lnworker:
            # Calling lnworker.get_onchain_history and wallet.get_full_history here
            # is inefficient. We should probably pass the tx_item to the constructor.
            lnworker_history = self._wallet.wallet.lnworker.get_onchain_history()
            if self._txid in lnworker_history:
                item = lnworker_history[self._txid]
                group_id = item.get('group_id')
                if group_id:
                    full_history = self._wallet.wallet.get_full_history()
                    group_item = full_history['group:' + group_id]
                    self._lnamount.satsInt = int(group_item['ln_value'].value)
                else:
                    self._lnamount.satsInt = int(item['amount_msat'] / 1000)
            else:
                self._lnamount.satsInt = 0

        self._is_complete = self._tx.is_complete()
        self._is_rbf_enabled = self._tx.is_rbf_enabled()
        self._is_unrelated = txinfo.amount is None and self._lnamount.isEmpty
        self._is_lightning_funding_tx = txinfo.is_lightning_funding_tx
        self._can_broadcast = txinfo.can_broadcast
        self._can_bump = txinfo.can_bump
        self._can_dscancel = txinfo.can_dscancel
        self._can_cpfp = txinfo.can_cpfp
        self._can_save_as_local = txinfo.can_save_as_local
        self._can_remove = txinfo.can_remove
        self._can_sign = (
            not self._is_complete
            and self._wallet.wallet.can_sign(self._tx)
            and not self._sighash_danger.needs_reject()
        )

        self.detailsChanged.emit()

        if self._label != txinfo.label:
            self._label = txinfo.label
            self.labelChanged.emit()

    def update_mined_status(self, tx_mined_info: TxMinedInfo):
        self._mempool_depth = ''
        self._date = format_time(tx_mined_info.timestamp)
        self._timestamp = tx_mined_info.timestamp
        self._confirmations = tx_mined_info.conf
        self._header_hash = tx_mined_info.header_hash
        self._short_id = tx_mined_info.short_id() or ""

    @pyqtSlot()
    def signAndBroadcast(self):
        self._sign(broadcast=True)

    @pyqtSlot()
    def sign(self):
        self._sign(broadcast=False)

    def _sign(self, broadcast):
        # TODO: connecting/disconnecting signal handlers here is hmm
        try:
            if broadcast:
                self._wallet.broadcastSucceeded.disconnect(self.onBroadcastSucceeded)
                self._wallet.broadcastFailed.disconnect(self.onBroadcastFailed)
        except Exception:
            pass

        if broadcast:
            self._wallet.broadcastSucceeded.connect(self.onBroadcastSucceeded)
            self._wallet.broadcastFailed.connect(self.onBroadcastFailed)
            self._wallet.sign_and_broadcast(self._tx, on_success=self.on_signed_tx)
        else:
            self._wallet.sign(self._tx, on_success=self.on_signed_tx)

        # side-effect: signing updates self._tx
        # we rely on this for broadcast

    def on_signed_tx(self, tx: Transaction):
        self._logger.debug('on_signed_tx')
        self.update()

    @pyqtSlot()
    def broadcast(self):
        assert self._tx.is_complete()

        try:
            self._wallet.broadcastFailed.disconnect(self.onBroadcastFailed)
        except Exception:
            pass
        self._wallet.broadcastFailed.connect(self.onBroadcastFailed)

        self._can_broadcast = False
        self.detailsChanged.emit()

        self._wallet.broadcast(self._tx)

    @pyqtSlot(str)
    def onBroadcastSucceeded(self, txid):
        if txid != self._txid:
            return

        self._logger.debug('onBroadcastSucceeded')
        try:
            self._wallet.broadcastSucceeded.disconnect(self.onBroadcastSucceeded)
        except Exception:
            pass

        self._can_broadcast = False
        self.detailsChanged.emit()

    @pyqtSlot(str, str, str)
    def onBroadcastFailed(self, txid, code, reason):
        if txid != self._txid:
            return

        try:
            self._wallet.broadcastFailed.disconnect(self.onBroadcastFailed)
        except Exception:
            pass

        self._can_broadcast = True
        self.detailsChanged.emit()

    @pyqtSlot()
    @pyqtSlot(bool)
    def removeLocalTx(self, confirm=False):
        assert self._can_remove, 'cannot remove'
        txid = self._txid
        assert txid, 'txid unset'

        if not confirm:
            num_child_txs = len(self._wallet.wallet.adb.get_depending_transactions(txid))
            question = _("Are you sure you want to remove this transaction?")
            if num_child_txs > 0:
                question = (
                    _("Are you sure you want to remove this transaction and {} child transactions?")
                    .format(num_child_txs))
            self.confirmRemoveLocalTx.emit(question)
            return

        self._wallet.wallet.adb.remove_transaction(txid)
        self._wallet.wallet.save_db()

        # NOTE: from here, the tx/txid is unknown and all properties are invalid.
        # UI should close TxDetails and avoid interacting with this qetxdetails instance.
        self._tx = None

    @pyqtSlot()
    def save(self):
        if not self._tx:
            return

        if self._wallet.save_tx(self._tx):
            self._can_save_as_local = False
            self._can_remove = True
            self.detailsChanged.emit()

    @pyqtSlot(result='QVariantList')
    def getSerializedTx(self):
        txqr = self._tx.to_qr_data()
        return [str(self._tx), txqr[0], txqr[1]]
