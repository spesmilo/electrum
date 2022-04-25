import asyncio
from datetime import datetime

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Q_ENUMS

from electrum.logging import get_logger
from electrum.i18n import _
from electrum.keystore import bip39_is_checksum_valid
from electrum.util import (parse_URI, create_bip21_uri, InvalidBitcoinURI, InvoiceError,
                           maybe_extract_bolt11_invoice)
from electrum.invoices import Invoice, OnchainInvoice, LNInvoice
from electrum.transaction import PartialTxOutput

from .qewallet import QEWallet
from .qetypes import QEAmount

class QEInvoice(QObject):

    _logger = get_logger(__name__)

    class Type:
        Invalid = -1
        OnchainOnlyAddress = 0
        OnchainInvoice = 1
        LightningInvoice = 2
        LightningAndOnchainInvoice = 3

    Q_ENUMS(Type)

    _wallet = None
    _invoiceType = Type.Invalid
    _recipient = ''
    _effectiveInvoice = None

    invoiceChanged = pyqtSignal()
    invoiceSaved = pyqtSignal()

    validationSuccess = pyqtSignal()
    validationWarning = pyqtSignal([str,str], arguments=['code', 'message'])
    validationError = pyqtSignal([str,str], arguments=['code', 'message'])

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.clear()

    @pyqtProperty(int, notify=invoiceChanged)
    def invoiceType(self):
        return self._invoiceType

    # not a qt setter, don't let outside set state
    def setInvoiceType(self, invoiceType: Type):
        self._invoiceType = invoiceType

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()

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
        self._amount = QEAmount() #
        if not self._effectiveInvoice:
            return self._amount
        sats = self._effectiveInvoice.get_amount_sat()
        if not sats:
            return self._amount
        self._amount = QEAmount(amount_sat=sats)
        return self._amount

    @pyqtProperty('quint64', notify=invoiceChanged)
    def expiration(self):
        return self._effectiveInvoice.exp if self._effectiveInvoice else 0

    @pyqtProperty('quint64', notify=invoiceChanged)
    def time(self):
        return self._effectiveInvoice.time if self._effectiveInvoice else 0

    @pyqtSlot()
    def clear(self):
        self.recipient = ''
        self.invoiceSetsAmount = False
        self.setInvoiceType(QEInvoice.Type.Invalid)
        self._bip21 = None
        self.invoiceChanged.emit()

    # don't parse the recipient string, but init qeinvoice from an invoice key
    # this should not emit validation signals
    @pyqtSlot(str)
    def initFromKey(self, key):
        invoice = self._wallet.wallet.get_invoice(key)
        self._logger.debug(repr(invoice))
        if invoice:
            self.set_effective_invoice(invoice)

    def set_effective_invoice(self, invoice: Invoice):
        self._effectiveInvoice = invoice
        if invoice.is_lightning():
            self.setInvoiceType(QEInvoice.Type.LightningInvoice)
        else:
            self.setInvoiceType(QEInvoice.Type.OnchainInvoice)
        self.invoiceChanged.emit()

    def setValidAddressOnly(self):
        self._logger.debug('setValidAddressOnly')
        self.setInvoiceType(QEInvoice.Type.OnchainOnlyAddress)
        self._effectiveInvoice = None ###TODO
        self.invoiceChanged.emit()

    def setValidOnchainInvoice(self, invoice: OnchainInvoice):
        self._logger.debug('setValidOnchainInvoice')
        self.set_effective_invoice(invoice)

    def setValidLightningInvoice(self, invoice: LNInvoice):
        self._logger.debug('setValidLightningInvoice')
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
        try:
            maybe_lightning_invoice = maybe_extract_bolt11_invoice(maybe_lightning_invoice)
            lninvoice = LNInvoice.from_bech32(maybe_lightning_invoice)
        except InvoiceError as e:
            pass

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
            elif not self._wallet.wallet.lnworker.channels:
                self.validationWarning.emit('no_channels',_('Detected valid Lightning invoice, but there are no open channels'))
                self.setValidLightningInvoice(lninvoice)
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
        if not self._effectiveInvoice:
            return
        # TODO detect duplicate?
        self._wallet.wallet.save_invoice(self._effectiveInvoice)
        self.invoiceSaved.emit()

    @pyqtSlot(str, 'quint64', str)
    def create_invoice(self, address: str, amount: int, message: str):
        # create onchain invoice from user entered fields
        # (any other type of invoice is created from parsing recipient)
        self._logger.debug('saving invoice to %s' % address)
        if not address:
            self.invoiceCreateError.emit('fatal', _('Recipient not specified.') + ' ' + _('Please scan a Bitcoin address or a payment request'))
            return

        if not bitcoin.is_address(address):
            self.invoiceCreateError.emit('fatal', _('Invalid Bitcoin address'))
            return

        if not self.amount:
            self.invoiceCreateError.emit('fatal', _('Invalid amount'))
            return



        #
        if self.is_max:
            amount = '!'
        else:
            try:
                amount = self.app.get_amount(self.amount)
            except:
                self.app.show_error(_('Invalid amount') + ':\n' + self.amount)
                return

