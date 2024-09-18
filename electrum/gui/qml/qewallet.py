import asyncio
import base64
import queue
import threading
import time
from typing import TYPE_CHECKING, Callable
from functools import partial

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer

from electrum.i18n import _
from electrum.invoices import InvoiceError, PR_PAID, PR_BROADCASTING, PR_BROADCAST
from electrum.logging import get_logger
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.transaction import PartialTransaction, Transaction
from electrum.util import InvalidPassword, event_listener, AddTransactionException, get_asyncio_loop
from electrum.plugin import run_hook
from electrum.wallet import Multisig_Wallet
from electrum.crypto import pw_decode_with_version_and_mac

from .auth import AuthMixin, auth_protect
from .qeaddresslistmodel import QEAddressCoinListModel
from .qechannellistmodel import QEChannelListModel
from .qeinvoicelistmodel import QEInvoiceListModel, QERequestListModel
from .qetransactionlistmodel import QETransactionListModel
from .qetypes import QEAmount
from .util import QtEventListener, qt_event_listener

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from .qeinvoice import QEInvoice


class QEWallet(AuthMixin, QObject, QtEventListener):
    __instances = []

    # this factory method should be used to instantiate QEWallet
    # so we have only one QEWallet for each electrum.wallet
    @classmethod
    def getInstanceFor(cls, wallet):
        for i in cls.__instances:
            if i.wallet == wallet:
                return i
        i = QEWallet(wallet)
        cls.__instances.append(i)
        return i

    _logger = get_logger(__name__)

    # emitted when wallet wants to display a user notification
    # actual presentation should be handled on app or window level
    userNotify = pyqtSignal(object, object)

    # shared signal for many static wallet properties
    dataChanged = pyqtSignal()

    balanceChanged = pyqtSignal()
    requestStatusChanged = pyqtSignal([str, int], arguments=['key', 'status'])
    requestCreateSuccess = pyqtSignal([str], arguments=['key'])
    requestCreateError = pyqtSignal([str], arguments=['error'])
    invoiceStatusChanged = pyqtSignal([str, int], arguments=['key', 'status'])
    invoiceCreateSuccess = pyqtSignal()
    invoiceCreateError = pyqtSignal([str, str], arguments=['code', 'error'])
    paymentAuthRejected = pyqtSignal()
    paymentSucceeded = pyqtSignal([str], arguments=['key'])
    paymentFailed = pyqtSignal([str, str], arguments=['key', 'reason'])
    requestNewPassword = pyqtSignal()
    signSucceeded = pyqtSignal([str], arguments=['txid'])
    signFailed = pyqtSignal([str], arguments=['message'])
    broadcastSucceeded = pyqtSignal([str], arguments=['txid'])
    broadcastFailed = pyqtSignal([str, str, str], arguments=['txid', 'code', 'reason'])
    saveTxSuccess = pyqtSignal([str], arguments=['txid'])
    saveTxError = pyqtSignal([str, str, str], arguments=['txid', 'code', 'message'])
    importChannelBackupFailed = pyqtSignal([str], arguments=['message'])
    otpRequested = pyqtSignal()
    otpSuccess = pyqtSignal()
    otpFailed = pyqtSignal([str, str], arguments=['code', 'message'])
    peersUpdated = pyqtSignal()
    seedRetrieved = pyqtSignal()

    _network_signal = pyqtSignal(str, object)

    def __init__(self, wallet: 'Abstract_Wallet', parent=None):
        super().__init__(parent)
        self.wallet = wallet

        self._logger = get_logger(f'{__name__}.[{wallet}]')

        self._synchronizing = False
        self._synchronizing_progress = ''

        self._historyModel = None
        self._addressCoinModel = None
        self._requestModel = None
        self._invoiceModel = None
        self._channelModel = None

        self._lightningbalance = QEAmount()
        self._confirmedbalance = QEAmount()
        self._unconfirmedbalance = QEAmount()
        self._frozenbalance = QEAmount()
        self._totalbalance = QEAmount()
        self._lightningcanreceive = QEAmount()
        self._lightningcansend = QEAmount()
        self._lightningbalancefrozen = QEAmount()

        self._seed = ''
        self._seed_passphrase = ''

        self.tx_notification_queue = queue.Queue()
        self.tx_notification_last_time = 0

        self.notification_timer = QTimer(self)
        self.notification_timer.setSingleShot(False)
        self.notification_timer.setInterval(500)  # msec
        self.notification_timer.timeout.connect(self.notify_transactions)

        self.sync_progress_timer = QTimer(self)
        self.sync_progress_timer.setSingleShot(False)
        self.sync_progress_timer.setInterval(2000)
        self.sync_progress_timer.timeout.connect(self.update_sync_progress)

        # post-construction init in GUI thread
        # QMetaObject.invokeMethod(self, 'qt_init', Qt.QueuedConnection)

        # To avoid leaking references to "self" that prevent the
        # window from being GC-ed when closed, callbacks should be
        # methods of this class only, and specifically not be
        # partials, lambdas or methods of subobjects.  Hence...

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())
        self.synchronizing = not wallet.is_up_to_date()

    synchronizingChanged = pyqtSignal()
    @pyqtProperty(bool, notify=synchronizingChanged)
    def synchronizing(self):
        return self._synchronizing

    @synchronizing.setter
    def synchronizing(self, synchronizing):
        if self._synchronizing != synchronizing:
            self._logger.debug(f'SYNC {self._synchronizing} -> {synchronizing}')
            self._synchronizing = synchronizing
            self.synchronizingChanged.emit()
            if synchronizing:
                if not self.sync_progress_timer.isActive():
                    self.update_sync_progress()
                    self.sync_progress_timer.start()
            else:
                self.sync_progress_timer.stop()

    synchronizingProgressChanged = pyqtSignal()
    @pyqtProperty(str, notify=synchronizingProgressChanged)
    def synchronizingProgress(self):
        return self._synchronizing_progress

    @synchronizingProgress.setter
    def synchronizingProgress(self, progress):
        if self._synchronizing_progress != progress:
            self._synchronizing_progress = progress
            self._logger.info(progress)
            self.synchronizingProgressChanged.emit()

    multipleChangeChanged = pyqtSignal()
    @pyqtProperty(bool, notify=multipleChangeChanged)
    def multipleChange(self):
        return self.wallet.multiple_change

    @multipleChange.setter
    def multipleChange(self, multiple_change):
        if self.wallet.multiple_change != multiple_change:
            self.wallet.multiple_change = multiple_change
            self.wallet.db.put('multiple_change', self.wallet.multiple_change)
            self.multipleChangeChanged.emit()

    @qt_event_listener
    def on_event_request_status(self, wallet, key, status):
        if wallet == self.wallet:
            self._logger.debug('request status %d for key %s' % (status, key))
            self.requestStatusChanged.emit(key, status)
            if status == PR_PAID:
                # might be new incoming LN payment, update history
                # TODO: only update if it was paid over lightning,
                # and even then, we can probably just add the payment instead
                # of recreating the whole history (expensive)
                self.historyModel.initModel(True)

    @event_listener
    def on_event_invoice_status(self, wallet, key, status):
        if wallet == self.wallet:
            self._logger.debug(f'invoice status update for key {key} to {status}')
            self.invoiceStatusChanged.emit(key, status)

    @qt_event_listener
    def on_event_new_transaction(self, wallet, tx):
        if wallet == self.wallet:
            self._logger.info(f'new transaction {tx.txid()}')
            self.add_tx_notification(tx)
            self.addressCoinModel.setDirty()
            self.historyModel.setDirty()  # assuming wallet.is_up_to_date triggers after
            self.balanceChanged.emit()

    @qt_event_listener
    def on_event_adb_tx_height_changed(self, adb, txid, old_height, new_height):
        if adb == self.wallet.adb:
            self._logger.info(f'tx_height_changed {txid}. {old_height} -> {new_height}')
            self.historyModel.setDirty()  # assuming wallet.is_up_to_date triggers after

    @qt_event_listener
    def on_event_removed_transaction(self, wallet, tx):
        # NOTE: this event only triggers once, only for the first deleted tx, when for imported wallets an address
        # is deleted along with multiple associated txs
        if wallet == self.wallet:
            self._logger.info(f'removed transaction {tx.txid()}')
            self.addressCoinModel.setDirty()
            self.historyModel.setDirty()
            self.balanceChanged.emit()

    @qt_event_listener
    def on_event_wallet_updated(self, wallet):
        if wallet == self.wallet:
            self._logger.debug('wallet_updated')
            self.balanceChanged.emit()
            self.synchronizing = not wallet.is_up_to_date()
            if not self.synchronizing:
                self.historyModel.initModel()  # refresh if dirty

    @event_listener
    def on_event_channel(self, wallet, channel):
        if wallet == self.wallet:
            self.balanceChanged.emit()
            self.peersUpdated.emit()

    @event_listener
    def on_event_channels_updated(self, wallet):
        if wallet == self.wallet:
            self.balanceChanged.emit()
            self.peersUpdated.emit()

    @qt_event_listener
    def on_event_payment_succeeded(self, wallet, key):
        if wallet == self.wallet:
            self.paymentSucceeded.emit(key)
            self.historyModel.initModel(True)  # TODO: be less dramatic

    @event_listener
    def on_event_payment_failed(self, wallet, key, reason):
        if wallet == self.wallet:
            self.paymentFailed.emit(key, reason)

    def on_destroy(self):
        self.unregister_callbacks()

    def add_tx_notification(self, tx):
        self._logger.debug('new transaction event')
        self.tx_notification_queue.put(tx)
        if not self.notification_timer.isActive():
            self._logger.debug('starting wallet notification timer')
            self.notification_timer.start()

    def notify_transactions(self):
        if self.tx_notification_queue.qsize() == 0:
            self._logger.debug('queue empty, stopping wallet notification timer')
            self.notification_timer.stop()
            return
        if not self.wallet.is_up_to_date():
            return  # no notifications while syncing
        now = time.time()
        rate_limit = 20  # seconds
        if self.tx_notification_last_time + rate_limit > now:
            return
        self.tx_notification_last_time = now
        self._logger.info("Notifying app about new transactions")
        txns = []
        while True:
            try:
                txns.append(self.tx_notification_queue.get_nowait())
            except queue.Empty:
                break

        config = self.wallet.config
        # Combine the transactions if there are at least three
        if len(txns) >= 3:
            total_amount = 0
            for tx in txns:
                tx_wallet_delta = self.wallet.get_wallet_delta(tx)
                if not tx_wallet_delta.is_relevant:
                    continue
                total_amount += tx_wallet_delta.delta
            self.userNotify.emit(self.wallet, _("{} new transactions: Total amount received in the new transactions {}").format(len(txns), config.format_amount_and_units(total_amount)))
        else:
            for tx in txns:
                tx_wallet_delta = self.wallet.get_wallet_delta(tx)
                if not tx_wallet_delta.is_relevant:
                    continue
                self.userNotify.emit(self.wallet,
                    _("New transaction: {}").format(config.format_amount_and_units(tx_wallet_delta.delta)))

    def update_sync_progress(self):
        if self.wallet.network.is_connected():
            num_sent, num_answered = self.wallet.adb.get_history_sync_state_details()
            self.synchronizingProgress = \
                ("{} ({}/{})".format(_("Synchronizing..."), num_answered, num_sent))

    historyModelChanged = pyqtSignal()
    @pyqtProperty(QETransactionListModel, notify=historyModelChanged)
    def historyModel(self):
        if self._historyModel is None:
            self._historyModel = QETransactionListModel(self.wallet)
        return self._historyModel

    addressCoinModelChanged = pyqtSignal()
    @pyqtProperty(QEAddressCoinListModel, notify=addressCoinModelChanged)
    def addressCoinModel(self):
        if self._addressCoinModel is None:
            self._addressCoinModel = QEAddressCoinListModel(self.wallet)
        return self._addressCoinModel

    requestModelChanged = pyqtSignal()
    @pyqtProperty(QERequestListModel, notify=requestModelChanged)
    def requestModel(self):
        if self._requestModel is None:
            self._requestModel = QERequestListModel(self.wallet)
        return self._requestModel

    invoiceModelChanged = pyqtSignal()
    @pyqtProperty(QEInvoiceListModel, notify=invoiceModelChanged)
    def invoiceModel(self):
        if self._invoiceModel is None:
            self._invoiceModel = QEInvoiceListModel(self.wallet)
        return self._invoiceModel

    channelModelChanged = pyqtSignal()
    @pyqtProperty(QEChannelListModel, notify=channelModelChanged)
    def channelModel(self):
        if self._channelModel is None:
            self._channelModel = QEChannelListModel(self.wallet)
        return self._channelModel

    nameChanged = pyqtSignal()
    @pyqtProperty(str, notify=nameChanged)
    def name(self):
        return self.wallet.basename()

    isLightningChanged = pyqtSignal()
    @pyqtProperty(bool, notify=isLightningChanged)
    def isLightning(self):
        return bool(self.wallet.lnworker)

    billingInfoChanged = pyqtSignal()
    @pyqtProperty('QVariantMap', notify=billingInfoChanged)
    def billingInfo(self):
        if self.wallet.wallet_type != '2fa':
            return {}
        return self.wallet.billing_info if self.wallet.billing_info is not None else {}

    @pyqtProperty(bool, notify=dataChanged)
    def canHaveLightning(self):
        return self.wallet.can_have_lightning()

    @pyqtProperty(str, notify=dataChanged)
    def walletType(self):
        return self.wallet.wallet_type

    @pyqtProperty(bool, notify=dataChanged)
    def isMultisig(self):
        return isinstance(self.wallet, Multisig_Wallet)

    @pyqtProperty(bool, notify=dataChanged)
    def hasSeed(self):
        return self.wallet.has_seed()

    @pyqtProperty(str, notify=dataChanged)
    def seed(self):
        return self._seed

    @pyqtProperty(str, notify=dataChanged)
    def seedPassphrase(self):
        return self._seed_passphrase

    @pyqtProperty(str, notify=dataChanged)
    def txinType(self):
        if self.wallet.wallet_type == 'imported':
            return self.wallet.txin_type
        return self.wallet.get_txin_type(self.wallet.dummy_address())

    @pyqtProperty(str, notify=dataChanged)
    def seedType(self):
        return self.wallet.get_seed_type()

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

    @pyqtProperty('QVariantList', notify=dataChanged)
    def keystores(self):
        result = []
        for k in self.wallet.get_keystores():
            result.append({
                'keystore_type': k.type,
                'watch_only': k.is_watching_only(),
                'derivation_prefix': (k.get_derivation_prefix() if k.is_deterministic() else '') or '',
                'master_pubkey': (k.get_master_public_key() if k.is_deterministic() else '') or '',
                'fingerprint': (k.get_root_fingerprint() if k.is_deterministic() else '') or '',
                'num_imported': len(k.keypairs) if k.can_import() else 0,
            })
        return result

    @pyqtProperty(str, notify=dataChanged)
    def lightningNodePubkey(self):
        return self.wallet.lnworker.node_keypair.pubkey.hex() if self.wallet.lnworker else ''

    @pyqtProperty(bool, notify=dataChanged)
    def lightningHasDeterministicNodeId(self):
        return self.wallet.lnworker.has_deterministic_node_id() if self.wallet.lnworker else False

    @pyqtProperty(str, notify=dataChanged)
    def derivationPrefix(self):
        keystores = self.wallet.get_keystores()
        if len(keystores) > 1:
            self._logger.debug('multiple keystores not supported yet')
        if len(keystores) == 0:
            self._logger.debug('no keystore')
            return ''
        if not self.isDeterministic:
            return ''
        return keystores[0].get_derivation_prefix()

    @pyqtProperty(str, notify=dataChanged)
    def masterPubkey(self):
        return self.wallet.get_master_public_key()

    @pyqtProperty(bool, notify=dataChanged)
    def canSignWithoutServer(self):
        return self.wallet.can_sign_without_server() if self.wallet.wallet_type == '2fa' else True

    @pyqtProperty(bool, notify=dataChanged)
    def canSignWithoutCosigner(self):
        if isinstance(self.wallet, Multisig_Wallet):
            if self.wallet.wallet_type == '2fa':  # 2fa is multisig, but it handles cosigning itself
                return True
            return self.wallet.m == 1
        return True

    @pyqtProperty(bool, notify=dataChanged)
    def canSignMessage(self):
        return not isinstance(self.wallet, Multisig_Wallet) and not self.wallet.is_watching_only()

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def frozenBalance(self):
        c, u, x = self.wallet.get_frozen_balance()
        self._frozenbalance.satsInt = c+x
        return self._frozenbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def unconfirmedBalance(self):
        self._unconfirmedbalance.satsInt = self.wallet.get_balance()[1]
        return self._unconfirmedbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def confirmedBalance(self):
        c, u, x = self.wallet.get_balance()
        self._confirmedbalance.satsInt = c+x
        return self._confirmedbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningBalance(self):
        if self.isLightning:
            self._lightningbalance.satsInt = int(self.wallet.lnworker.get_balance())
        return self._lightningbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningBalanceFrozen(self):
        if self.isLightning:
            self._lightningbalancefrozen.satsInt = int(self.wallet.lnworker.get_balance(frozen=True))
        return self._lightningbalancefrozen

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def totalBalance(self):
        total = self.confirmedBalance.satsInt + self.lightningBalance.satsInt
        self._totalbalance.satsInt = total
        return self._totalbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningCanSend(self):
        if self.isLightning:
            self._lightningcansend.satsInt = int(self.wallet.lnworker.num_sats_can_send())
        return self._lightningcansend

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningCanReceive(self):
        if self.isLightning:
            self._lightningcanreceive.satsInt = int(self.wallet.lnworker.num_sats_can_receive())
        return self._lightningcanreceive

    @pyqtProperty(int, notify=peersUpdated)
    def lightningNumPeers(self):
        if self.isLightning:
            return self.wallet.lnworker.num_peers()
        return 0

    @pyqtSlot()
    def enableLightning(self):
        self.wallet.init_lightning(password=self.password)
        self.isLightningChanged.emit()
        self.dataChanged.emit()

    @auth_protect()
    def sign(self, tx, *, broadcast: bool = False, on_success: Callable[[Transaction], None] = None, on_failure: Callable[[], None] = None):
        sign_hook = run_hook('tc_sign_wrapper', self.wallet, tx, partial(self.on_sign_complete, broadcast, on_success), partial(self.on_sign_failed, on_failure))
        if sign_hook:
            success = self.do_sign(tx, False)
            if success:
                self._logger.debug('plugin needs to sign tx too')
                sign_hook(tx)
                return
        else:
            success = self.do_sign(tx, broadcast)

        if success:
            if on_success:
                on_success(tx)
        else:
            if on_failure:
                on_failure()

    def do_sign(self, tx, broadcast):
        try:
            # ignore_warnings=True, because UI checks and asks user confirmation itself
            tx = self.wallet.sign_transaction(tx, self.password, ignore_warnings=True)
        except BaseException as e:
            self._logger.error(f'{e!r}')
            self.signFailed.emit(str(e))

        if tx is None:
            self._logger.info('did not sign')
            return False

        txid = tx.txid()
        self._logger.debug(f'do_sign(), txid={txid}')

        self.signSucceeded.emit(txid)

        if not tx.is_complete():
            self._logger.debug('tx not complete')
            broadcast = False

        if broadcast:
            self.broadcast(tx)
        else:
            # not broadcasted, so refresh history here
            self.historyModel.initModel(True)

        return True

    # this assumes a 2fa wallet, but there are no other tc_sign_wrapper hooks, so that's ok
    def on_sign_complete(self, broadcast, cb: Callable[[Transaction], None] = None, tx: Transaction = None):
        self.otpSuccess.emit()
        if cb:
            cb(tx)
        if broadcast:
            self.broadcast(tx)

    # this assumes a 2fa wallet, but there are no other tc_sign_wrapper hooks, so that's ok
    def on_sign_failed(self, cb: Callable[[], None] = None, error: str = None):
        self.otpFailed.emit('error', error)
        if cb:
            cb()

    def request_otp(self, on_submit):
        self._otp_on_submit = on_submit
        self.otpRequested.emit()

    @pyqtSlot(str)
    def submitOtp(self, otp):
        def submit_otp_task():
            self._otp_on_submit(otp)
        threading.Thread(target=submit_otp_task, daemon=True).start()

    def broadcast(self, tx):
        assert tx.is_complete()

        def broadcast_thread():
            self.wallet.set_broadcasting(tx, broadcasting_status=PR_BROADCASTING)
            try:
                self._logger.info('running broadcast in thread')
                self.wallet.network.run_from_another_thread(self.wallet.network.broadcast_transaction(tx))
            except TxBroadcastError as e:
                self._logger.error(repr(e))
                self.broadcastFailed.emit(tx.txid(), '', e.get_message_for_gui())
                self.wallet.set_broadcasting(tx, broadcasting_status=None)
            except BestEffortRequestFailed as e:
                self._logger.error(repr(e))
                self.broadcastFailed.emit(tx.txid(), '', repr(e))
                self.wallet.set_broadcasting(tx, broadcasting_status=None)
            else:
                self._logger.info('broadcast success')
                self.broadcastSucceeded.emit(tx.txid())
                self.historyModel.requestRefresh.emit()  # via qt thread
                self.wallet.set_broadcasting(tx, broadcasting_status=PR_BROADCAST)

        threading.Thread(target=broadcast_thread, daemon=True).start()

        # TODO: properly catch server side errors, e.g. bad-txns-inputs-missingorspent

    def save_tx(self, tx: 'PartialTransaction'):
        assert tx

        try:
            if not self.wallet.adb.add_transaction(tx):
                self.saveTxError.emit(tx.txid(), 'conflict',
                            _("Transaction could not be saved.") + "\n" + _("It conflicts with current history."))
                return
            self.wallet.save_db()
            self.saveTxSuccess.emit(tx.txid())
            self.historyModel.initModel(True)
            return True
        except AddTransactionException as e:
            self.saveTxError.emit(tx.txid(), 'error', str(e))
            return False

    def ln_auth_rejected(self):
        self.paymentAuthRejected.emit()

    @auth_protect(message=_('Pay lightning invoice?'), reject='ln_auth_rejected')
    def pay_lightning_invoice(self, invoice: 'QEInvoice'):
        amount_msat = invoice.get_amount_msat()

        def pay_thread():
            try:
                coro = self.wallet.lnworker.pay_invoice(invoice.lightning_invoice, amount_msat=amount_msat)
                fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
                fut.result()
            except Exception as e:
                self._logger.error(f'pay_invoice failed! {e!r}')
                self.paymentFailed.emit(invoice.get_id(), str(e))

        threading.Thread(target=pay_thread, daemon=True).start()

    @pyqtSlot()
    def deleteExpiredRequests(self):
        keys = self.wallet.delete_expired_requests()
        for key in keys:
            self.requestModel.delete_invoice(key)

    @pyqtSlot(QEAmount, str, int)
    @pyqtSlot(QEAmount, str, int, bool)
    @pyqtSlot(QEAmount, str, int, bool, bool)
    @pyqtSlot(QEAmount, str, int, bool, bool, bool)
    def createRequest(self, amount: QEAmount, message: str, expiration: int, lightning_only: bool = False, reuse_address: bool = False):
        self.deleteExpiredRequests()
        try:
            amount = amount.satsInt
            addr = self.wallet.get_unused_address()
            if addr is None:
                if reuse_address:
                    addr = self.wallet.get_receiving_address()
                elif lightning_only:
                    addr = None
                else:
                    msg = [
                        _('No address available.'),
                        _('All your addresses are used in pending requests.'),
                        _('To see the list, press and hold the Receive button.'),
                    ]
                    self.requestCreateError.emit(' '.join(msg))
                    return

            key = self.wallet.create_request(amount, message, expiration, addr)
        except InvoiceError as e:
            self.requestCreateError.emit(_('Error creating payment request') + ':\n' + str(e))
            return

        assert key is not None
        self._logger.debug(f'created request with key {key} addr {addr}')
        self.addressCoinModel.setDirty()
        self.requestModel.add_invoice(self.wallet.get_request(key))
        self.requestCreateSuccess.emit(key)

    @pyqtSlot(str)
    def deleteRequest(self, key: str):
        self._logger.debug('delete req %s' % key)
        self.wallet.delete_request(key)
        self.requestModel.delete_invoice(key)

    @pyqtSlot(str)
    def deleteInvoice(self, key: str):
        self._logger.debug('delete inv %s' % key)
        self.wallet.delete_invoice(key)
        self.invoiceModel.delete_invoice(key)

    @pyqtSlot(str, result=bool)
    def verifyPassword(self, password):
        if not self.wallet.has_password():
            return not bool(password)
        try:
            self.wallet.check_password(password)
            return True
        except InvalidPassword as e:
            return False

    @pyqtSlot(str, result=bool)
    def setPassword(self, password):
        if password == '':
            password = None

        storage = self.wallet.storage

        # HW wallet not supported yet
        if storage.is_encrypted_with_hw_device():
            return False

        current_password = self.password if self.password != '' else None

        try:
            self._logger.info('setting new password')
            self.wallet.update_password(current_password, password, encrypt_storage=True)
            self.password = password
            return True
        except InvalidPassword as e:
            self._logger.exception(repr(e))
            return False

    @pyqtSlot(str)
    def importAddresses(self, addresslist):
        self.wallet.import_addresses(addresslist.split())
        if self._addressCoinModel:
            self._addressCoinModel.setDirty()
        self.dataChanged.emit()

    @pyqtSlot(str)
    def importPrivateKeys(self, keyslist):
        self.wallet.import_private_keys(keyslist.split(), self.password)
        if self._addressCoinModel:
            self._addressCoinModel.setDirty()
        self.dataChanged.emit()

    @pyqtSlot(str)
    def importChannelBackup(self, backup_str):
        try:
            self.wallet.lnworker.import_channel_backup(backup_str)
        except Exception as e:
            self._logger.debug(f'could not import channel backup: {repr(e)}')
            self.importChannelBackupFailed.emit(f'Failed to import backup:\n\n{str(e)}')

    @pyqtSlot(str, result=bool)
    def isValidChannelBackup(self, backup_str):
        try:
            assert backup_str.startswith('channel_backup:')
            encrypted = backup_str[15:]
            xpub = self.wallet.get_fingerprint()
            decrypted = pw_decode_with_version_and_mac(encrypted, xpub)
            return True
        except Exception:
            return False

    @pyqtSlot()
    def requestShowSeed(self):
        self.retrieve_seed()

    @auth_protect(method='wallet')
    def retrieve_seed(self):
        try:
            self._seed = self.wallet.get_seed(self.password)
            self._seed_passphrase = self.wallet.keystore.get_passphrase(self.password)
            self.seedRetrieved.emit()
        except Exception:
            self._seed = ''
            self._seed_passphrase = ''

        self.dataChanged.emit()

    @pyqtSlot(str, result='QVariantList')
    def getSerializedTx(self, txid):
        tx = self.wallet.db.get_transaction(txid)
        txqr = tx.to_qr_data()
        return [str(tx), txqr[0], txqr[1]]

    @pyqtSlot(result='QVariantMap')
    def getBalancesForPiechart(self):
        confirmed, unconfirmed, unmatured, frozen, lightning, f_lightning = balances = self.wallet.get_balances_for_piechart()
        return {
            'confirmed': confirmed,
            'unconfirmed': unconfirmed,
            'unmatured': unmatured,
            'frozen': frozen,
            'lightning': int(lightning),
            'f_lightning': int(f_lightning),
            'total': sum([int(x) for x in list(balances)])
        }

    @pyqtSlot(str, result=bool)
    def isAddressMine(self, addr):
        return self.wallet.is_mine(addr)

    @pyqtSlot(str, str, result=str)
    def signMessage(self, address, message):
        sig = self.wallet.sign_message(address, message, self.password)
        return base64.b64encode(sig).decode('ascii')
