import asyncio
import queue
import threading
import time
from typing import Optional, TYPE_CHECKING
from functools import partial

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer

from electrum import bitcoin
from electrum.i18n import _
from electrum.invoices import InvoiceError, PR_DEFAULT_EXPIRATION_WHEN_CREATING, PR_PAID
from electrum.logging import get_logger
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.transaction import PartialTxOutput
from electrum.util import (parse_max_spend, InvalidPassword, event_listener)
from electrum.plugin import run_hook

from .auth import AuthMixin, auth_protect
from .qeaddresslistmodel import QEAddressListModel
from .qechannellistmodel import QEChannelListModel
from .qeinvoicelistmodel import QEInvoiceListModel, QERequestListModel
from .qetransactionlistmodel import QETransactionListModel
from .qetypes import QEAmount
from .util import QtEventListener, qt_event_listener

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


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

    isUptodateChanged = pyqtSignal()
    requestStatusChanged = pyqtSignal([str,int], arguments=['key','status'])
    requestCreateSuccess = pyqtSignal([str], arguments=['key'])
    requestCreateError = pyqtSignal([str,str], arguments=['code','error'])
    invoiceStatusChanged = pyqtSignal([str,int], arguments=['key','status'])
    invoiceCreateSuccess = pyqtSignal()
    invoiceCreateError = pyqtSignal([str,str], arguments=['code','error'])
    paymentSucceeded = pyqtSignal([str], arguments=['key'])
    paymentFailed = pyqtSignal([str,str], arguments=['key','reason'])
    requestNewPassword = pyqtSignal()
    transactionSigned = pyqtSignal([str], arguments=['txid'])
    broadcastSucceeded = pyqtSignal([str], arguments=['txid'])
    broadcastFailed = pyqtSignal([str,str,str], arguments=['txid','code','reason'])
    labelsUpdated = pyqtSignal()
    otpRequested = pyqtSignal()
    otpSuccess = pyqtSignal()
    otpFailed = pyqtSignal([str,str], arguments=['code','message'])

    _network_signal = pyqtSignal(str, object)

    _isUpToDate = False
    _synchronizing = False
    _synchronizing_progress = ''

    def __init__(self, wallet: 'Abstract_Wallet', parent=None):
        super().__init__(parent)
        self.wallet = wallet

        self._historyModel = None
        self._addressModel = None
        self._requestModel = None
        self._invoiceModel = None
        self._channelModel = None

        self.tx_notification_queue = queue.Queue()
        self.tx_notification_last_time = 0

        self.notification_timer = QTimer(self)
        self.notification_timer.setSingleShot(False)
        self.notification_timer.setInterval(500)  # msec
        self.notification_timer.timeout.connect(self.notify_transactions)

        # To avoid leaking references to "self" that prevent the
        # window from being GC-ed when closed, callbacks should be
        # methods of this class only, and specifically not be
        # partials, lambdas or methods of subobjects.  Hence...

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    @pyqtProperty(bool, notify=isUptodateChanged)
    def isUptodate(self):
        return self._isUpToDate

    synchronizingChanged = pyqtSignal()
    @pyqtProperty(bool, notify=synchronizingChanged)
    def synchronizing(self):
        return self._synchronizing

    @synchronizing.setter
    def synchronizing(self, synchronizing):
        if self._synchronizing != synchronizing:
            self._synchronizing = synchronizing
            self.synchronizingChanged.emit()

    synchronizingProgressChanged = pyqtSignal()
    @pyqtProperty(str, notify=synchronizingProgressChanged)
    def synchronizing_progress(self):
        return self._synchronizing_progress

    @synchronizing_progress.setter
    def synchronizing_progress(self, progress):
        if self._synchronizing_progress != progress:
            self._synchronizing_progress = progress
            self.synchronizingProgressChanged.emit()

    @event_listener
    def on_event_status(self):
        self._logger.debug('status')
        uptodate = self.wallet.is_up_to_date()
        if self._isUpToDate != uptodate:
            self._isUpToDate = uptodate
            self.isUptodateChanged.emit()

        if self.wallet.network.is_connected():
            server_height = self.wallet.network.get_server_height()
            server_lag = self.wallet.network.get_local_height() - server_height
            # Server height can be 0 after switching to a new server
            # until we get a headers subscription request response.
            # Display the synchronizing message in that case.
            if not self._isUpToDate or server_height == 0:
                num_sent, num_answered = self.wallet.adb.get_history_sync_state_details()
                self.synchronizing_progress = ("{} ({}/{})"
                                .format(_("Synchronizing..."), num_answered, num_sent))
                self.synchronizing = True
            else:
                self.synchronizing_progress = ''
                self.synchronizing = False

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
                self.historyModel.init_model()

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
            self.addressModel.setDirty()
            self.historyModel.init_model() # TODO: be less dramatic

    @qt_event_listener
    def on_event_verified(self, wallet, txid, info):
        if wallet == self.wallet:
            self.historyModel.update_tx(txid, info)

    @event_listener
    def on_event_wallet_updated(self, wallet):
        if wallet == self.wallet:
            self._logger.debug('wallet %s updated' % str(wallet))
            self.balanceChanged.emit()

    @event_listener
    def on_event_channel(self, wallet, channel):
        if wallet == self.wallet:
            self.balanceChanged.emit()

    @event_listener
    def on_event_channels_updated(self, wallet):
        if wallet == self.wallet:
            self.balanceChanged.emit()

    @qt_event_listener
    def on_event_payment_succeeded(self, wallet, key):
        if wallet == self.wallet:
            self.paymentSucceeded.emit(key)
            self.historyModel.init_model() # TODO: be less dramatic

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

    historyModelChanged = pyqtSignal()
    @pyqtProperty(QETransactionListModel, notify=historyModelChanged)
    def historyModel(self):
        if self._historyModel is None:
            self._historyModel = QETransactionListModel(self.wallet)
        return self._historyModel

    addressModelChanged = pyqtSignal()
    @pyqtProperty(QEAddressListModel, notify=addressModelChanged)
    def addressModel(self):
        if self._addressModel is None:
            self._addressModel = QEAddressListModel(self.wallet)
        return self._addressModel

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

    @pyqtProperty(bool, notify=dataChanged)
    def canHaveLightning(self):
        return self.wallet.can_have_lightning()

    @pyqtProperty(str, notify=dataChanged)
    def walletType(self):
        return self.wallet.wallet_type

    @pyqtProperty(bool, notify=dataChanged)
    def hasSeed(self):
        return self.wallet.has_seed()

    @pyqtProperty(str, notify=dataChanged)
    def txinType(self):
        if self.wallet.wallet_type == 'imported':
            return self.wallet.txin_type
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

    @pyqtProperty(str, notify=dataChanged)
    def derivationPrefix(self):
        keystores = self.wallet.get_keystores()
        if len(keystores) > 1:
            self._logger.debug('multiple keystores not supported yet')
        if len(keystores) == 0:
            self._logger.debug('no keystore')
            return ''
        return keystores[0].get_derivation_prefix()

    @pyqtProperty(str, notify=dataChanged)
    def masterPubkey(self):
        return self.wallet.get_master_public_key()

    balanceChanged = pyqtSignal()

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def frozenBalance(self):
        c, u, x = self.wallet.get_frozen_balance()
        self._frozenbalance = QEAmount(amount_sat=c+x)
        return self._frozenbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def unconfirmedBalance(self):
        self._unconfirmedbalance = QEAmount(amount_sat=self.wallet.get_balance()[1])
        return self._unconfirmedbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def confirmedBalance(self):
        c, u, x = self.wallet.get_balance()
        self._confirmedbalance = QEAmount(amount_sat=c+x)
        return self._confirmedbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningBalance(self):
        if not self.isLightning:
            self._lightningbalance = QEAmount()
        else:
            self._lightningbalance = QEAmount(amount_sat=int(self.wallet.lnworker.get_balance()))
        return self._lightningbalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def totalBalance(self):
        total = self.confirmedBalance.satsInt + self.lightningBalance.satsInt
        self._totalBalance = QEAmount(amount_sat=total)
        return self._totalBalance

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningCanSend(self):
        if not self.isLightning:
            self._lightningcansend = QEAmount()
        else:
            self._lightningcansend = QEAmount(amount_sat=int(self.wallet.lnworker.num_sats_can_send()))
        return self._lightningcansend

    @pyqtProperty(QEAmount, notify=balanceChanged)
    def lightningCanReceive(self):
        if not self.isLightning:
            self._lightningcanreceive = QEAmount()
        else:
            self._lightningcanreceive = QEAmount(amount_sat=int(self.wallet.lnworker.num_sats_can_receive()))
        return self._lightningcanreceive

    @pyqtSlot()
    def enableLightning(self):
        self.wallet.init_lightning(password=None) # TODO pass password if needed
        self.isLightningChanged.emit()

    @pyqtSlot(str, int, int, bool)
    def send_onchain(self, address, amount, fee=None, rbf=False):
        self._logger.info('send_onchain: %s %d' % (address,amount))
        coins = self.wallet.get_spendable_coins(None)
        if not bitcoin.is_address(address):
            self._logger.warning('Invalid Bitcoin Address: ' + address)
            return False

        outputs = [PartialTxOutput.from_address_and_value(address, amount)]
        self._logger.info(str(outputs))
        output_values = [x.value for x in outputs]
        if any(parse_max_spend(outval) for outval in output_values):
            output_value = '!'
        else:
            output_value = sum(output_values)
        self._logger.info(str(output_value))
        # see qt/confirm_tx_dialog qt/main_window
        tx = self.wallet.make_unsigned_transaction(coins=coins,outputs=outputs, fee=None)
        self._logger.info(str(tx.to_json()))

        use_rbf = bool(self.wallet.config.get('use_rbf', True))
        tx.set_rbf(use_rbf)
        self.sign(tx, broadcast=True)

    @auth_protect
    def sign(self, tx, *, broadcast: bool = False):
        sign_hook = run_hook('tc_sign_wrapper', self.wallet, tx, partial(self.on_sign_complete, broadcast),
                             self.on_sign_failed)
        if sign_hook:
            self.do_sign(tx, False)
            self._logger.debug('plugin needs to sign tx too')
            sign_hook(tx)
            return

        self.do_sign(tx, broadcast)

    def do_sign(self, tx, broadcast):
        tx = self.wallet.sign_transaction(tx, self.password)

        if tx is None:
            self._logger.info('did not sign')
            return

        txid = tx.txid()
        self._logger.debug(f'txid={txid}')

        self.transactionSigned.emit(txid)

        if not tx.is_complete():
            self._logger.info('tx not complete')
            return

        if broadcast:
            self.broadcast(tx)

    # this assumes a 2fa wallet, but there are no other tc_sign_wrapper hooks, so that's ok
    def on_sign_complete(self, broadcast, tx):
        self.otpSuccess.emit()
        if broadcast:
            self.broadcast(tx)

    def on_sign_failed(self, error):
        self.otpFailed.emit('error', error)

    def request_otp(self, on_submit):
        self._otp_on_submit = on_submit
        self.otpRequested.emit()

    @pyqtSlot(str)
    def submitOtp(self, otp):
        self._otp_on_submit(otp)

    def broadcast(self, tx):
        assert tx.is_complete()

        network = self.wallet.network # TODO not always defined?

        def broadcast_thread():
            try:
                self._logger.info('running broadcast in thread')
                result = network.run_from_another_thread(network.broadcast_transaction(tx))
                self._logger.info(repr(result))
            except TxBroadcastError as e:
                self._logger.error(repr(e))
                self.broadcastFailed.emit(tx.txid(),'',repr(e))
            except BestEffortRequestFailed as e:
                self._logger.error(repr(e))
                self.broadcastFailed.emit(tx.txid(),'',repr(e))
            else:
                self.broadcastSucceeded.emit(tx.txid())

        threading.Thread(target=broadcast_thread).start()

        #TODO: properly catch server side errors, e.g. bad-txns-inputs-missingorspent

    paymentAuthRejected = pyqtSignal()
    def ln_auth_rejected(self):
        self.paymentAuthRejected.emit()

    @pyqtSlot(str)
    @auth_protect(reject='ln_auth_rejected')
    def pay_lightning_invoice(self, invoice_key):
        self._logger.debug('about to pay LN')
        invoice = self.wallet.get_invoice(invoice_key)
        assert(invoice)
        assert(invoice.lightning_invoice)

        amount_msat = invoice.get_amount_msat()

        def pay_thread():
            try:
                coro = self.wallet.lnworker.pay_invoice(invoice.lightning_invoice, amount_msat=amount_msat)
                fut = asyncio.run_coroutine_threadsafe(coro, self.wallet.network.asyncio_loop)
                fut.result()
            except Exception as e:
                self.paymentFailed.emit(invoice.get_id(), repr(e))

        threading.Thread(target=pay_thread).start()

    def create_bitcoin_request(self, amount: int, message: str, expiration: int, ignore_gap: bool) -> Optional[str]:
        addr = self.wallet.get_unused_address()
        if addr is None:
            if not self.wallet.is_deterministic():  # imported wallet
                # TODO implement
                return
                #msg = [
                    #_('No more addresses in your wallet.'), ' ',
                    #_('You are using a non-deterministic wallet, which cannot create new addresses.'), ' ',
                    #_('If you want to create new addresses, use a deterministic wallet instead.'), '\n\n',
                    #_('Creating a new payment request will reuse one of your addresses and overwrite an existing request. Continue anyway?'),
                   #]
                #if not self.question(''.join(msg)):
                    #return
                #addr = self.wallet.get_receiving_address()
            else:  # deterministic wallet
                if not ignore_gap:
                    self.requestCreateError.emit('gaplimit',_("Warning: The next address will not be recovered automatically if you restore your wallet from seed; you may need to add it manually.\n\nThis occurs because you have too many unused addresses in your wallet. To avoid this situation, use the existing addresses first.\n\nCreate anyway?"))
                    return
                addr = self.wallet.create_new_address(False)

        req_key = self.wallet.create_request(amount, message, expiration, addr)
        #try:
            #self.wallet.add_payment_request(req)
        #except Exception as e:
            #self.logger.exception('Error adding payment request')
            #self.requestCreateError.emit('fatal',_('Error adding payment request') + ':\n' + repr(e))
        #else:
            ## TODO: check this flow. Only if alias is defined in config. OpenAlias?
            #pass
            ##self.sign_payment_request(addr)

        return req_key, addr

    @pyqtSlot(QEAmount, str, int)
    @pyqtSlot(QEAmount, str, int, bool)
    @pyqtSlot(QEAmount, str, int, bool, bool)
    def createRequest(self, amount: QEAmount, message: str, expiration: int, is_lightning: bool = False, ignore_gap: bool = False):
        # TODO: unify this method and create_bitcoin_request
        try:
            if is_lightning:
                if not self.wallet.lnworker.channels:
                    self.requestCreateError.emit('fatal',_("You need to open a Lightning channel first."))
                    return
                # TODO maybe show a warning if amount exceeds lnworker.num_sats_can_receive (as in kivy)
                # TODO fallback address robustness
                addr = self.wallet.get_unused_address()
                key = self.wallet.create_request(amount.satsInt, message, expiration, addr)
            else:
                key, addr = self.create_bitcoin_request(amount.satsInt, message, expiration, ignore_gap)
                if not key:
                    return
                self.addressModel.init_model()
        except InvoiceError as e:
            self.requestCreateError.emit('fatal',_('Error creating payment request') + ':\n' + str(e))
            return

        assert key is not None
        self.requestModel.add_invoice(self.wallet.get_request(key))
        self.requestCreateSuccess.emit(key)

    @pyqtSlot()
    @pyqtSlot(bool)
    def createDefaultRequest(self, ignore_gap: bool = False):
        try:
            default_expiry = self.wallet.config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)
            if self.wallet.lnworker and self.wallet.lnworker.channels:
                addr = None
                if self.wallet.config.get('bolt11_fallback', True):
                    addr = self.wallet.get_unused_address()
                    # if addr is None, we ran out of addresses
                    if addr is None:
                        # TODO: remove oldest unpaid request having a fallback address and try again
                        pass
                key = self.wallet.create_request(None, None, default_expiry, addr)
            else:
                key, addr = self.create_bitcoin_request(None, None, default_expiry, ignore_gap)
                if not key:
                    return
                # self.addressModel.init_model()
        except InvoiceError as e:
            self.requestCreateError.emit('fatal',_('Error creating payment request') + ':\n' + str(e))
            return

        assert key is not None
        self.requestModel.add_invoice(self.wallet.get_request(key))
        self.requestCreateSuccess.emit(key)

    @pyqtSlot(str)
    def delete_request(self, key: str):
        self._logger.debug('delete req %s' % key)
        self.wallet.delete_request(key)
        self.requestModel.delete_invoice(key)

    @pyqtSlot(str, result='QVariant')
    def get_request(self, key: str):
        return self.requestModel.get_model_invoice(key)

    @pyqtSlot(str)
    def delete_invoice(self, key: str):
        self._logger.debug('delete inv %s' % key)
        self.wallet.delete_invoice(key)
        self.invoiceModel.delete_invoice(key)

    @pyqtSlot(str, result='QVariant')
    def get_invoice(self, key: str):
        return self.invoiceModel.get_model_invoice(key)

    @pyqtSlot(str, result=bool)
    def verify_password(self, password):
        try:
            self.wallet.storage.check_password(password)
            return True
        except InvalidPassword as e:
            return False

    @pyqtSlot(str)
    def set_password(self, password):
        storage = self.wallet.storage

        # HW wallet not supported yet
        if storage.is_encrypted_with_hw_device():
            return

        try:
            self.wallet.update_password(self.password, password, encrypt_storage=True)
            self.password = password
        except InvalidPassword as e:
            self._logger.exception(repr(e))
