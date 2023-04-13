import threading
from typing import TYPE_CHECKING, Optional
import asyncio
from urllib.parse import urlparse

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Q_ENUMS, QTimer

from electrum import bitcoin
from electrum import lnutil
from electrum.i18n import _
from electrum.invoices import Invoice
from electrum.invoices import (PR_UNPAID, PR_EXPIRED, PR_UNKNOWN, PR_PAID, PR_INFLIGHT,
                               PR_FAILED, PR_ROUTING, PR_UNCONFIRMED, PR_BROADCASTING, PR_BROADCAST, LN_EXPIRY_NEVER)
from electrum.lnaddr import LnInvoiceException
from electrum.logging import get_logger
from electrum.transaction import PartialTxOutput
from electrum.util import (parse_URI, InvalidBitcoinURI, InvoiceError,
                           maybe_extract_lightning_payment_identifier, get_asyncio_loop)
from electrum.lnutil import format_short_channel_id
from electrum.lnurl import decode_lnurl, request_lnurl, callback_lnurl
from electrum.bitcoin import COIN
from electrum.paymentrequest import PaymentRequest

from .qetypes import QEAmount
from .qewallet import QEWallet
from .util import status_update_timer_interval, QtEventListener, event_listener


class QEInvoice(QObject, QtEventListener):
    class Type:
        Invalid = -1
        OnchainInvoice = 0
        LightningInvoice = 1
        LNURLPayRequest = 2

    class Status:
        Unpaid = PR_UNPAID
        Expired = PR_EXPIRED
        Unknown = PR_UNKNOWN
        Paid = PR_PAID
        Inflight = PR_INFLIGHT
        Failed = PR_FAILED
        Routing = PR_ROUTING
        Unconfirmed = PR_UNCONFIRMED

    Q_ENUMS(Type)
    Q_ENUMS(Status)

    _logger = get_logger(__name__)

    invoiceChanged = pyqtSignal()
    invoiceSaved = pyqtSignal([str], arguments=['key'])
    amountOverrideChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None  # type: Optional[QEWallet]
        self._isSaved = False
        self._canSave = False
        self._canPay = False
        self._key = None
        self._invoiceType = QEInvoice.Type.Invalid
        self._effectiveInvoice = None
        self._userinfo = ''
        self._lnprops = {}
        self._amount = QEAmount()
        self._amountOverride = QEAmount()

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.updateStatusString)

        self._amountOverride.valueChanged.connect(self._on_amountoverride_value_changed)

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    def on_destroy(self):
        self.unregister_callbacks()

    @event_listener
    def on_event_payment_succeeded(self, wallet, key):
        if wallet == self._wallet.wallet and key == self.key:
            self.statusChanged.emit()
            self.determine_can_pay()
            self.userinfo = _('Paid!')

    @event_listener
    def on_event_payment_failed(self, wallet, key, reason):
        if wallet == self._wallet.wallet and key == self.key:
            self.statusChanged.emit()
            self.determine_can_pay()
            self.userinfo = _('Payment failed: ') + reason

    @event_listener
    def on_event_invoice_status(self, wallet, key, status):
        if self._wallet and wallet == self._wallet.wallet and key == self.key:
            self.update_userinfo()
            self.determine_can_pay()
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

    @pyqtProperty(int, notify=invoiceChanged)
    def invoiceType(self):
        return self._invoiceType

    # not a qt setter, don't let outside set state
    def setInvoiceType(self, invoiceType: Type):
        self._invoiceType = invoiceType

    @pyqtProperty(str, notify=invoiceChanged)
    def message(self):
        return self._effectiveInvoice.message if self._effectiveInvoice else ''

    @pyqtProperty('quint64', notify=invoiceChanged)
    def time(self):
        return self._effectiveInvoice.time if self._effectiveInvoice else 0

    @pyqtProperty('quint64', notify=invoiceChanged)
    def expiration(self):
        return self._effectiveInvoice.exp if self._effectiveInvoice else 0

    @pyqtProperty(str, notify=invoiceChanged)
    def address(self):
        return self._effectiveInvoice.get_address() if self._effectiveInvoice else ''

    @pyqtProperty(QEAmount, notify=invoiceChanged)
    def amount(self):
        if not self._effectiveInvoice:
            self._amount.clear()
            return self._amount
        self._amount.copyFrom(QEAmount(from_invoice=self._effectiveInvoice))
        return self._amount

    @pyqtProperty(QEAmount, notify=amountOverrideChanged)
    def amountOverride(self):
        return self._amountOverride

    @amountOverride.setter
    def amountOverride(self, new_amount):
        self._logger.debug(f'set new override amount {repr(new_amount)}')
        self._amountOverride.copyFrom(new_amount)
        self.amountOverrideChanged.emit()

    @pyqtSlot()
    def _on_amountoverride_value_changed(self):
        self.update_userinfo()
        self.determine_can_pay()

    statusChanged = pyqtSignal()
    @pyqtProperty(int, notify=statusChanged)
    def status(self):
        if not self._effectiveInvoice:
            return PR_UNKNOWN
        return self._wallet.wallet.get_invoice_status(self._effectiveInvoice)

    @pyqtProperty(str, notify=statusChanged)
    def status_str(self):
        if not self._effectiveInvoice:
            return ''
        status = self._wallet.wallet.get_invoice_status(self._effectiveInvoice)
        return self._effectiveInvoice.get_status_str(status)

    isSavedChanged = pyqtSignal()
    @pyqtProperty(bool, notify=isSavedChanged)
    def isSaved(self):
        return self._isSaved

    canSaveChanged = pyqtSignal()
    @pyqtProperty(bool, notify=canSaveChanged)
    def canSave(self):
        return self._canSave

    @canSave.setter
    def canSave(self, canSave):
        if self._canSave != canSave:
            self._canSave = canSave
            self.canSaveChanged.emit()

    canPayChanged = pyqtSignal()
    @pyqtProperty(bool, notify=canPayChanged)
    def canPay(self):
        return self._canPay

    @canPay.setter
    def canPay(self, canPay):
        if self._canPay != canPay:
            self._canPay = canPay
            self.canPayChanged.emit()

    keyChanged = pyqtSignal()
    @pyqtProperty(str, notify=keyChanged)
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if self._key != key:
            self._key = key
            if self._effectiveInvoice and self._effectiveInvoice.get_id() == key:
                return
            invoice = self._wallet.wallet.get_invoice(key)
            self._logger.debug(f'invoice from key {key}: {repr(invoice)}')
            self.set_effective_invoice(invoice)
            self.keyChanged.emit()

    userinfoChanged = pyqtSignal()
    @pyqtProperty(str, notify=userinfoChanged)
    def userinfo(self):
        return self._userinfo

    @userinfo.setter
    def userinfo(self, userinfo):
        if self._userinfo != userinfo:
            self._userinfo = userinfo
            self.userinfoChanged.emit()

    @pyqtProperty('QVariantMap', notify=invoiceChanged)
    def lnprops(self):
        return self._lnprops

    def set_lnprops(self):
        self._lnprops = {}
        if not self.invoiceType == QEInvoice.Type.LightningInvoice:
            return

        lnaddr = self._effectiveInvoice._lnaddr
        ln_routing_info = lnaddr.get_routing_info('r')
        self._logger.debug(str(ln_routing_info))

        self._lnprops = {
            'pubkey': lnaddr.pubkey.serialize().hex(),
            'payment_hash': lnaddr.paymenthash.hex(),
            'r': [{
                'node': self.name_for_node_id(x[-1][0]),
                'scid': format_short_channel_id(x[-1][1])
                } for x in ln_routing_info] if ln_routing_info else []
        }

    def name_for_node_id(self, node_id):
        return self._wallet.wallet.lnworker.get_node_alias(node_id) or node_id.hex()

    def set_effective_invoice(self, invoice: Invoice):
        self._effectiveInvoice = invoice

        if invoice is None:
            self.setInvoiceType(QEInvoice.Type.Invalid)
        else:
            if invoice.is_lightning():
                self.setInvoiceType(QEInvoice.Type.LightningInvoice)
            else:
                self.setInvoiceType(QEInvoice.Type.OnchainInvoice)
            self._isSaved = self._wallet.wallet.get_invoice(invoice.get_id()) is not None

        self.set_lnprops()

        self.update_userinfo()
        self.determine_can_pay()

        self.invoiceChanged.emit()
        self.statusChanged.emit()
        self.isSavedChanged.emit()

        self.set_status_timer()

    def set_status_timer(self):
        if self.status != PR_EXPIRED:
            if self.expiration > 0 and self.expiration != LN_EXPIRY_NEVER:
                interval = status_update_timer_interval(self.time + self.expiration)
                if interval > 0:
                    self._timer.setInterval(interval)  # msec
                    self._timer.start()
        else:
            self.update_userinfo()
            self.determine_can_pay() # status went to PR_EXPIRED

    @pyqtSlot()
    def updateStatusString(self):
        self.statusChanged.emit()
        self.set_status_timer()

    def update_userinfo(self):
        self.userinfo = ''

        if not self.amountOverride.isEmpty:
            amount = self.amountOverride
        else:
            amount = self.amount

        if self.amount.isEmpty:
            self.userinfo = _('Enter the amount you want to send')

        if amount.isEmpty and self.status == PR_UNPAID: # unspecified amount
            return

        if self.invoiceType == QEInvoice.Type.LightningInvoice:
            if self.status in [PR_UNPAID, PR_FAILED]:
                if self.get_max_spendable_lightning() >= amount.satsInt:
                    lnaddr = self._effectiveInvoice._lnaddr
                    if lnaddr.amount and amount.satsInt < lnaddr.amount * COIN:
                        self.userinfo = _('Cannot pay less than the amount specified in the invoice')
                elif self.address and self.get_max_spendable_onchain() < amount.satsInt:
                    # TODO: validate address?
                    # TODO: subtract fee?
                    self.userinfo = _('Insufficient balance')
            else:
                self.userinfo = {
                        PR_EXPIRED: _('This invoice has expired'),
                        PR_PAID: _('This invoice was already paid'),
                        PR_INFLIGHT: _('Payment in progress...'),
                        PR_ROUTING: _('Payment in progress'),
                        PR_UNKNOWN: _('Invoice has unknown status'),
                    }[self.status]
        elif self.invoiceType == QEInvoice.Type.OnchainInvoice:
            if self.status in [PR_UNPAID, PR_FAILED]:
                if not ((amount.isMax and self.get_max_spendable_onchain() > 0) or (self.get_max_spendable_onchain() >= amount.satsInt)):
                    self.userinfo = _('Insufficient balance')
            else:
                self.userinfo = {
                        PR_EXPIRED: _('This invoice has expired'),
                        PR_PAID: _('This invoice was already paid'),
                        PR_BROADCASTING: _('Payment in progress...') + ' (' +  _('broadcasting') + ')',
                        PR_BROADCAST:  _('Payment in progress...') + ' (' +  _('broadcast successfully') + ')',
                        PR_UNCONFIRMED: _('Payment in progress...') + ' (' +  _('waiting for confirmation') + ')',
                        PR_UNKNOWN: _('Invoice has unknown status'),
                    }[self.status]

    def determine_can_pay(self):
        self.canPay = False
        self.canSave = False

        if not self.amountOverride.isEmpty:
            amount = self.amountOverride
        else:
            amount = self.amount

        self.canSave = True

        if amount.isEmpty and self.status == PR_UNPAID: # unspecified amount
            return

        if self.invoiceType == QEInvoice.Type.LightningInvoice:
            if self.status in [PR_UNPAID, PR_FAILED]:
                if self.get_max_spendable_lightning() >= amount.satsInt:
                    lnaddr = self._effectiveInvoice._lnaddr
                    if not (lnaddr.amount and amount.satsInt < lnaddr.amount * COIN):
                        self.canPay = True
                elif self.address and self.get_max_spendable_onchain() > amount.satsInt:
                    # TODO: validate address?
                    # TODO: subtract fee?
                    self.canPay = True
        elif self.invoiceType == QEInvoice.Type.OnchainInvoice:
            if self.status in [PR_UNPAID, PR_FAILED]:
                if amount.isMax and self.get_max_spendable_onchain() > 0:
                    # TODO: dust limit?
                    self.canPay = True
                elif self.get_max_spendable_onchain() >= amount.satsInt:
                    # TODO: subtract fee?
                    self.canPay = True

    @pyqtSlot()
    def pay_lightning_invoice(self):
        if not self.canPay:
            raise Exception('can not pay invoice, canPay is false')

        if self.invoiceType != QEInvoice.Type.LightningInvoice:
            raise Exception('pay_lightning_invoice can only pay lightning invoices')

        if self.amount.isEmpty:
            if self.amountOverride.isEmpty:
                raise Exception('can not pay 0 amount')
            # TODO: is update amount_msat for overrideAmount sufficient?
            self._effectiveInvoice.amount_msat = self.amountOverride.satsInt * 1000

        self._wallet.pay_lightning_invoice(self._effectiveInvoice)

    def get_max_spendable_onchain(self):
        spendable = self._wallet.confirmedBalance.satsInt
        if not self._wallet.wallet.config.get('confirmed_only', False):
            spendable += self._wallet.unconfirmedBalance.satsInt
        return spendable

    def get_max_spendable_lightning(self):
        return self._wallet.wallet.lnworker.num_sats_can_send() if self._wallet.wallet.lnworker else 0

class QEInvoiceParser(QEInvoice):
    _logger = get_logger(__name__)

    validationSuccess = pyqtSignal()
    validationWarning = pyqtSignal([str,str], arguments=['code', 'message'])
    validationError = pyqtSignal([str,str], arguments=['code', 'message'])

    invoiceCreateError = pyqtSignal([str,str], arguments=['code', 'message'])

    lnurlRetrieved = pyqtSignal()
    lnurlError = pyqtSignal([str,str], arguments=['code', 'message'])

    _bip70PrResolvedSignal = pyqtSignal([PaymentRequest], arguments=['pr'])

    def __init__(self, parent=None):
        super().__init__(parent)

        self._recipient = ''
        self._bip70PrResolvedSignal.connect(self._bip70_payment_request_resolved)

        self.clear()

    recipientChanged = pyqtSignal()
    @pyqtProperty(str, notify=recipientChanged)
    def recipient(self):
        return self._recipient

    @recipient.setter
    def recipient(self, recipient: str):
        self.canPay = False
        self._recipient = recipient
        self.amountOverride = QEAmount()
        if recipient:
            self.validateRecipient(recipient)
        self.recipientChanged.emit()

    @pyqtProperty('QVariantMap', notify=lnurlRetrieved)
    def lnurlData(self):
        return self._lnurlData

    @pyqtProperty(bool, notify=lnurlRetrieved)
    def isLnurlPay(self):
        return self._lnurlData is not None

    @pyqtSlot()
    def clear(self):
        self.recipient = ''
        self.setInvoiceType(QEInvoice.Type.Invalid)
        self._bip21 = None
        self._lnurlData = None
        self.canSave = False
        self.canPay = False
        self.userinfo = ''
        self.invoiceChanged.emit()

    def setValidOnchainInvoice(self, invoice: Invoice):
        self._logger.debug('setValidOnchainInvoice')
        if invoice.is_lightning():
            raise Exception('unexpected LN invoice')
        self.set_effective_invoice(invoice)

    def setValidLightningInvoice(self, invoice: Invoice):
        self._logger.debug('setValidLightningInvoice')
        if not invoice.is_lightning():
            raise Exception('unexpected Onchain invoice')
        self.set_effective_invoice(invoice)

    def setValidLNURLPayRequest(self):
        self._logger.debug('setValidLNURLPayRequest')
        self.setInvoiceType(QEInvoice.Type.LNURLPayRequest)
        self._effectiveInvoice = None
        self.invoiceChanged.emit()

    def create_onchain_invoice(self, outputs, message, payment_request, uri):
        return self._wallet.wallet.create_invoice(
            outputs=outputs,
            message=message,
            pr=payment_request,
            URI=uri
            )

    def _bip70_payment_request_resolved(self, pr: 'PaymentRequest'):
        self._logger.debug('resolved payment request')
        if pr.verify(self._wallet.wallet.contacts):
            invoice = Invoice.from_bip70_payreq(pr, height=0)
            if self._wallet.wallet.get_invoice_status(invoice) == PR_PAID:
                self.validationError.emit('unknown', _('Invoice already paid'))
            elif pr.has_expired():
                self.validationError.emit('unknown', _('Payment request has expired'))
            else:
                self.setValidOnchainInvoice(invoice)
                self.validationSuccess.emit()
        else:
            self.validationError.emit('unknown', f"invoice error:\n{pr.error}")

    def validateRecipient(self, recipient):
        if not recipient:
            self.setInvoiceType(QEInvoice.Type.Invalid)
            return

        maybe_lightning_invoice = recipient

        try:
            self._bip21 = parse_URI(recipient, lambda pr: self._bip70PrResolvedSignal.emit(pr))
            if self._bip21:
                if 'r' in self._bip21 or ('name' in self._bip21 and 'sig' in self._bip21): # TODO set flag in util?
                    # let callback handle state
                    return
                if ':' not in recipient:
                    # address only
                    # create bare invoice
                    outputs = [PartialTxOutput.from_address_and_value(self._bip21['address'], 0)]
                    invoice = self.create_onchain_invoice(outputs, None, None, None)
                    self._logger.debug(repr(invoice))
                    self.setValidOnchainInvoice(invoice)
                    self.validationSuccess.emit()
                    return
                else:
                    # fallback lightning invoice?
                    if 'lightning' in self._bip21:
                        maybe_lightning_invoice = self._bip21['lightning']
        except InvalidBitcoinURI as e:
            self._bip21 = None

        lninvoice = None
        maybe_lightning_invoice = maybe_extract_lightning_payment_identifier(maybe_lightning_invoice)
        if maybe_lightning_invoice is not None:
            if maybe_lightning_invoice.startswith('lnurl'):
                self.resolve_lnurl(maybe_lightning_invoice)
                return
            try:
                lninvoice = Invoice.from_bech32(maybe_lightning_invoice)
            except InvoiceError as e:
                e2 = e.__cause__
                if isinstance(e2, LnInvoiceException):
                    self.validationError.emit('unknown', _("Error parsing Lightning invoice") + f":\n{e2}")
                    self.clear()
                    return
                if isinstance(e2, lnutil.IncompatibleOrInsaneFeatures):
                    self.validationError.emit('unknown', _("Invoice requires unknown or incompatible Lightning feature") + f":\n{e2!r}")
                    self.clear()
                    return
                self._logger.exception(repr(e))

        if not lninvoice and not self._bip21:
            self.validationError.emit('unknown',_('Unknown invoice'))
            self.clear()
            return

        if lninvoice:
            if not self._wallet.wallet.has_lightning():
                if not self._bip21:
                    if lninvoice.get_address():
                        self.setValidLightningInvoice(lninvoice)
                        self.validationSuccess.emit()
                    else:
                        self.validationError.emit('no_lightning',_('Detected valid Lightning invoice, but Lightning not enabled for wallet and no fallback address found.'))
                else:
                    self._logger.debug('flow with LN but not LN enabled AND having bip21 uri')
                    self.setValidOnchainInvoice(self._bip21['address'])
            else:
                self.setValidLightningInvoice(lninvoice)
                if not self._wallet.wallet.lnworker.channels:
                    self.validationWarning.emit('no_channels',_('Detected valid Lightning invoice, but there are no open channels'))
                else:
                    self.validationSuccess.emit()
        else:
            self._logger.debug('flow without LN but having bip21 uri')
            if 'amount' not in self._bip21:
                amount = 0
            else:
                amount = self._bip21['amount']
            outputs = [PartialTxOutput.from_address_and_value(self._bip21['address'], amount)]
            self._logger.debug(outputs)
            message = self._bip21['message'] if 'message' in self._bip21 else ''
            invoice = self.create_onchain_invoice(outputs, message, None, self._bip21)
            self._logger.debug(repr(invoice))
            self.setValidOnchainInvoice(invoice)
            self.validationSuccess.emit()

    def resolve_lnurl(self, lnurl):
        self._logger.debug('resolve_lnurl')
        url = decode_lnurl(lnurl)
        self._logger.debug(f'{repr(url)}')

        def resolve_task():
            try:
                coro = request_lnurl(url)
                fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
                self.on_lnurl(fut.result())
            except Exception as e:
                self.validationError.emit('lnurl', repr(e))

        threading.Thread(target=resolve_task, daemon=True).start()

    def on_lnurl(self, lnurldata):
        self._logger.debug('on_lnurl')
        self._logger.debug(f'{repr(lnurldata)}')

        self._lnurlData = {
            'domain': urlparse(lnurldata.callback_url).netloc,
            'callback_url' : lnurldata.callback_url,
            'min_sendable_sat': lnurldata.min_sendable_sat,
            'max_sendable_sat': lnurldata.max_sendable_sat,
            'metadata_plaintext': lnurldata.metadata_plaintext,
            'comment_allowed': lnurldata.comment_allowed
        }
        self.setValidLNURLPayRequest()
        self.lnurlRetrieved.emit()

    @pyqtSlot('quint64')
    @pyqtSlot('quint64', str)
    def lnurlGetInvoice(self, amount, comment=None):
        assert self._lnurlData
        self._logger.debug(f'{repr(self._lnurlData)}')

        amount = self.amountOverride.satsInt
        if self.lnurlData['min_sendable_sat'] != 0:
            try:
                assert amount >= self.lnurlData['min_sendable_sat']
                assert amount <= self.lnurlData['max_sendable_sat']
            except:
                self.lnurlError.emit('amount', _('Amount out of bounds'))
                return

        if self._lnurlData['comment_allowed'] == 0:
            comment = None

        self._logger.debug(f'fetching callback url {self._lnurlData["callback_url"]}')
        def fetch_invoice_task():
            try:
                params = { 'amount': amount * 1000 }
                if comment:
                    params['comment'] = comment
                coro = callback_lnurl(self._lnurlData['callback_url'], params)
                fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
                self.on_lnurl_invoice(amount, fut.result())
            except Exception as e:
                self._logger.error(repr(e))
                self.lnurlError.emit('lnurl', str(e))

        threading.Thread(target=fetch_invoice_task, daemon=True).start()

    def on_lnurl_invoice(self, orig_amount, invoice):
        self._logger.debug('on_lnurl_invoice')
        self._logger.debug(f'{repr(invoice)}')

        # assure no shenanigans with the bolt11 invoice we get back
        lninvoice = Invoice.from_bech32(invoice['pr'])
        if orig_amount * 1000 != lninvoice.amount_msat:
            raise Exception('Unexpected amount in invoice, differs from lnurl-pay specified amount')

        self.recipient = invoice['pr']

    @pyqtSlot()
    def save_invoice(self):
        if not self._effectiveInvoice:
            return
        if self.isSaved:
            return

        if not self._effectiveInvoice.amount_msat and not self.amountOverride.isEmpty:
            if self.invoiceType == QEInvoice.Type.OnchainInvoice and self.amountOverride.isMax:
                self._effectiveInvoice.amount_msat = '!'
            else:
                self._effectiveInvoice.amount_msat = self.amountOverride.satsInt * 1000

        self.canSave = False

        self._wallet.wallet.save_invoice(self._effectiveInvoice)
        self.key = self._effectiveInvoice.get_id()
        self._wallet.invoiceModel.addInvoice(self.key)
        self.invoiceSaved.emit(self.key)
