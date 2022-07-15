import asyncio
from datetime import datetime

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Q_ENUMS

from electrum.logging import get_logger
from electrum.i18n import _
from electrum.util import (parse_URI, create_bip21_uri, InvalidBitcoinURI, InvoiceError,
                           maybe_extract_lightning_payment_identifier)
from electrum.invoices import Invoice
from electrum.invoices import (PR_UNPAID,PR_EXPIRED,PR_UNKNOWN,PR_PAID,PR_INFLIGHT,
                               PR_FAILED,PR_ROUTING,PR_UNCONFIRMED,LN_EXPIRY_NEVER)
from electrum.transaction import PartialTxOutput
from electrum.lnaddr import lndecode
from electrum import bitcoin
from electrum import lnutil
from electrum.lnaddr import LnInvoiceException

from .qewallet import QEWallet
from .qetypes import QEAmount

class QEInvoice(QObject):
    class Type:
        Invalid = -1
        OnchainOnlyAddress = 0
        OnchainInvoice = 1
        LightningInvoice = 2
        LightningAndOnchainInvoice = 3

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

    _wallet = None
    _canSave = False
    _canPay = False
    _key = None

    def __init__(self, parent=None):
        super().__init__(parent)

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

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

    def get_max_spendable_onchain(self):
        c, u, x = self._wallet.wallet.get_balance()
        #TODO determine real max
        return c


class QEInvoiceParser(QEInvoice):

    _logger = get_logger(__name__)

    _invoiceType = QEInvoice.Type.Invalid
    _recipient = ''
    _effectiveInvoice = None
    _amount = QEAmount()
    _userinfo = ''

    invoiceChanged = pyqtSignal()
    invoiceSaved = pyqtSignal()

    validationSuccess = pyqtSignal()
    validationWarning = pyqtSignal([str,str], arguments=['code', 'message'])
    validationError = pyqtSignal([str,str], arguments=['code', 'message'])

    invoiceCreateError = pyqtSignal([str,str], arguments=['code', 'message'])

    def __init__(self, parent=None):
        super().__init__(parent)
        self.clear()

    @pyqtProperty(int, notify=invoiceChanged)
    def invoiceType(self):
        return self._invoiceType

    # not a qt setter, don't let outside set state
    def setInvoiceType(self, invoiceType: QEInvoice.Type):
        self._invoiceType = invoiceType

    recipientChanged = pyqtSignal()
    @pyqtProperty(str, notify=recipientChanged)
    def recipient(self):
        return self._recipient

    @recipient.setter
    def recipient(self, recipient: str):
        #if self._recipient != recipient:
        self._recipient = recipient
        if recipient:
            self.validateRecipient(recipient)
        self.recipientChanged.emit()

    @pyqtProperty(str, notify=invoiceChanged)
    def message(self):
        return self._effectiveInvoice.message if self._effectiveInvoice else ''

    @pyqtProperty(QEAmount, notify=invoiceChanged)
    def amount(self):
        # store ref to QEAmount on instance, otherwise we get destroyed when going out of scope
        self._amount = QEAmount()
        if not self._effectiveInvoice:
            return self._amount
        self._amount = QEAmount(from_invoice=self._effectiveInvoice)
        return self._amount

    @pyqtProperty('quint64', notify=invoiceChanged)
    def expiration(self):
        return self._effectiveInvoice.exp if self._effectiveInvoice else 0

    @pyqtProperty('quint64', notify=invoiceChanged)
    def time(self):
        return self._effectiveInvoice.time if self._effectiveInvoice else 0

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

    # single address only, TODO: n outputs
    @pyqtProperty(str, notify=invoiceChanged)
    def address(self):
        return self._effectiveInvoice.get_address() if self._effectiveInvoice else ''

    @pyqtProperty('QVariantMap', notify=invoiceChanged)
    def lnprops(self):
        if not self.invoiceType == QEInvoice.Type.LightningInvoice:
            return {}
        lnaddr = self._effectiveInvoice._lnaddr
        self._logger.debug(str(lnaddr))
        self._logger.debug(str(lnaddr.get_routing_info('t')))
        return {
            'pubkey': lnaddr.pubkey.serialize().hex(),
            't': '', #lnaddr.get_routing_info('t')[0][0].hex(),
            'r': '' #lnaddr.get_routing_info('r')[0][0][0].hex()
        }

    @pyqtSlot()
    def clear(self):
        self.recipient = ''
        self.setInvoiceType(QEInvoice.Type.Invalid)
        self._bip21 = None
        self.canSave = False
        self.canPay = False
        self.userinfo = ''
        self.invoiceChanged.emit()

    # don't parse the recipient string, but init qeinvoice from an invoice key
    # this should not emit validation signals
    @pyqtSlot(str)
    def initFromKey(self, key):
        self.clear()
        invoice = self._wallet.wallet.get_invoice(key)
        self._logger.debug(repr(invoice))
        if invoice:
            self.set_effective_invoice(invoice)
            self.key = key

    def set_effective_invoice(self, invoice: Invoice):
        self._effectiveInvoice = invoice

        if invoice.is_lightning():
            self.setInvoiceType(QEInvoice.Type.LightningInvoice)
        else:
            self.setInvoiceType(QEInvoice.Type.OnchainInvoice)

        self.canSave = True

        self.determine_can_pay()

        self.invoiceChanged.emit()
        self.statusChanged.emit()

    def determine_can_pay(self):
        if self.invoiceType == QEInvoice.Type.LightningInvoice:
            if self.status in [PR_UNPAID, PR_FAILED]:
                if self.get_max_spendable_lightning() >= self.amount.satsInt:
                    self.canPay = True
                else:
                    self.userinfo = _('Can\'t pay, insufficient balance')
            else:
                self.userinfo = {
                        PR_EXPIRED: _('Can\'t pay, invoice is expired'),
                        PR_PAID: _('Can\'t pay, invoice is already paid'),
                        PR_INFLIGHT: _('Can\'t pay, invoice is already being paid'),
                        PR_ROUTING: _('Can\'t pay, invoice is already being paid'),
                        PR_UNKNOWN: _('Can\'t pay, invoice has unknown status'),
                    }[self.status]
        elif self.invoiceType == QEInvoice.Type.OnchainInvoice:
            if self.status in [PR_UNPAID, PR_FAILED]:
                if self.get_max_spendable_onchain() >= self.amount.satsInt:
                    self.canPay = True
                else:
                    self.userinfo = _('Can\'t pay, insufficient balance')
            else:
                self.userinfo = {
                        PR_EXPIRED: _('Can\'t pay, invoice is expired'),
                        PR_PAID: _('Can\'t pay, invoice is already paid'),
                        PR_UNCONFIRMED: _('Can\'t pay, invoice is already paid'),
                        PR_UNKNOWN: _('Can\'t pay, invoice has unknown status'),
                    }[self.status]


    def get_max_spendable_lightning(self):
        return self._wallet.wallet.lnworker.num_sats_can_send()

    def setValidAddressOnly(self):
        self._logger.debug('setValidAddressOnly')
        self.setInvoiceType(QEInvoice.Type.OnchainOnlyAddress)
        self._effectiveInvoice = None
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

    def create_onchain_invoice(self, outputs, message, payment_request, uri):
        return self._wallet.wallet.create_invoice(
            outputs=outputs,
            message=message,
            pr=payment_request,
            URI=uri
            )

    def validateRecipient(self, recipient):
        if not recipient:
            self.setInvoiceType(QEInvoice.Type.Invalid)
            return

        maybe_lightning_invoice = recipient

        def _payment_request_resolved(request):
            self._logger.debug('resolved payment request')
            outputs = request.get_outputs()
            invoice = self.create_onchain_invoice(outputs, None, request, None)
            self.setValidOnchainInvoice(invoice)

        try:
            self._bip21 = parse_URI(recipient, _payment_request_resolved)
            if self._bip21:
                if 'r' in self._bip21 or ('name' in self._bip21 and 'sig' in self._bip21): # TODO set flag in util?
                    # let callback handle state
                    return
                if ':' not in recipient:
                    # address only
                    self.setValidAddressOnly()
                    self.validationSuccess.emit()
                    return
                else:
                    # fallback lightning invoice?
                    if 'lightning' in self._bip21:
                        maybe_lightning_invoice = self._bip21['lightning']
        except InvalidBitcoinURI as e:
            self._bip21 = None
            self._logger.debug(repr(e))

        lninvoice = None
        maybe_lightning_invoice = maybe_extract_lightning_payment_identifier(maybe_lightning_invoice)
        if maybe_lightning_invoice is not None:
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
                    # TODO: lightning onchain fallback in ln invoice
                    #self.validationError.emit('no_lightning',_('Detected valid Lightning invoice, but Lightning not enabled for wallet'))
                    self.setValidLightningInvoice(lninvoice)
                    self.clear()
                    return
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
            if 'amount' not in self._bip21: #TODO can we have amount-less invoices?
                self.validationError.emit('no_amount', 'no amount in uri')
                return
            outputs = [PartialTxOutput.from_address_and_value(self._bip21['address'], self._bip21['amount'])]
            self._logger.debug(outputs)
            message = self._bip21['message'] if 'message' in self._bip21 else ''
            invoice = self.create_onchain_invoice(outputs, message, None, self._bip21)
            self._logger.debug(repr(invoice))
            self.setValidOnchainInvoice(invoice)
            self.validationSuccess.emit()

    @pyqtSlot()
    def save_invoice(self):
        self.canSave = False
        if not self._effectiveInvoice:
            return
        # TODO detect duplicate?
        self.key = self._wallet.wallet.get_key_for_outgoing_invoice(self._effectiveInvoice)
        self._wallet.wallet.save_invoice(self._effectiveInvoice)
        self.invoiceSaved.emit()


class QEUserEnteredPayment(QEInvoice):
    _logger = get_logger(__name__)

    _recipient = None
    _message = None
    _amount = QEAmount()

    validationError = pyqtSignal([str,str], arguments=['code','message'])
    invoiceCreateError = pyqtSignal([str,str], arguments=['code', 'message'])
    invoiceSaved = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.clear()

    recipientChanged = pyqtSignal()
    @pyqtProperty(str, notify=recipientChanged)
    def recipient(self):
        return self._recipient

    @recipient.setter
    def recipient(self, recipient: str):
        if self._recipient != recipient:
            self._recipient = recipient
            self.validate()
            self.recipientChanged.emit()

    messageChanged = pyqtSignal()
    @pyqtProperty(str, notify=messageChanged)
    def message(self):
        return self._message

    @message.setter
    def message(self, message):
        if self._message != message:
            self._message = message
            self.messageChanged.emit()

    amountChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=amountChanged)
    def amount(self):
        return self._amount

    @amount.setter
    def amount(self, amount):
        if self._amount != amount:
            self._amount = amount
            self.validate()
            self.amountChanged.emit()


    def validate(self):
        self.canPay = False
        self.canSave = False
        self._logger.debug('validate')

        if not self._recipient:
            self.validationError.emit('recipient', _('Recipient not specified.'))
            return

        if not bitcoin.is_address(self._recipient):
            self.validationError.emit('recipient', _('Invalid Bitcoin address'))
            return

        if self._amount.isEmpty:
            self.validationError.emit('amount', _('Invalid amount'))
            return

        if self._amount.isMax:
            self.canPay = True
        else:
            self.canSave = True
            if self.get_max_spendable_onchain() >= self._amount.satsInt:
                self.canPay = True

    @pyqtSlot()
    def save_invoice(self):
        assert self.canSave
        assert not self._amount.isMax

        self._logger.debug('saving invoice to %s, amount=%s, message=%s' % (self._recipient, repr(self._amount), self._message))

        inv_amt = self._amount.satsInt

        try:
            outputs = [PartialTxOutput.from_address_and_value(self._recipient, inv_amt)]
            self._logger.debug(repr(outputs))
            invoice = self._wallet.wallet.create_invoice(outputs=outputs, message=self._message, pr=None, URI=None)
        except InvoiceError as e:
            self.invoiceCreateError.emit('fatal', _('Error creating payment') + ':\n' + str(e))
            return

        self.key = self._wallet.wallet.get_key_for_outgoing_invoice(invoice)
        self._wallet.wallet.save_invoice(invoice)
        self.invoiceSaved.emit()

    @pyqtSlot()
    def clear(self):
        self._recipient = None
        self._amount = QEAmount()
        self._message = None
        self.canSave = False
        self.canPay = False
