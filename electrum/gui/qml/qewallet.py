from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl

from typing import Optional, TYPE_CHECKING, Sequence, List, Union

from electrum.i18n import _
from electrum.util import register_callback, Satoshis, format_time
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet
from electrum import bitcoin
from electrum.transaction import PartialTxOutput
from electrum.invoices import   (Invoice, InvoiceError, PR_TYPE_ONCHAIN, PR_TYPE_LN,
                                 PR_DEFAULT_EXPIRATION_WHEN_CREATING, PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED, PR_UNCONFIRMED, PR_TYPE_ONCHAIN, PR_TYPE_LN)

from .qerequestlistmodel import QERequestListModel
from .qetransactionlistmodel import QETransactionListModel
from .qeaddresslistmodel import QEAddressListModel

class QEWallet(QObject):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self._historyModel = QETransactionListModel(wallet)
        self._addressModel = QEAddressListModel(wallet)
        self._requestModel = QERequestListModel(wallet)

        self._historyModel.init_model()
        self._requestModel.init_model()

        register_callback(self.on_request_status, ['request_status'])
        register_callback(self.on_status, ['status'])

    _logger = get_logger(__name__)

    dataChanged = pyqtSignal() # dummy to silence warnings

    requestCreateSuccess = pyqtSignal()
    requestCreateError = pyqtSignal([str,str], arguments=['code','error'])

    requestStatus = pyqtSignal()
    def on_request_status(self, event, *args):
        self._logger.debug(str(event))
        self.requestStatus.emit()

    historyModelChanged = pyqtSignal()
    @pyqtProperty(QETransactionListModel, notify=historyModelChanged)
    def historyModel(self):
        return self._historyModel

    addressModelChanged = pyqtSignal()
    @pyqtProperty(QEAddressListModel, notify=addressModelChanged)
    def addressModel(self):
        return self._addressModel

    requestModelChanged = pyqtSignal()
    @pyqtProperty(QERequestListModel, notify=requestModelChanged)
    def requestModel(self):
        return self._requestModel

    @pyqtProperty('QString', notify=dataChanged)
    def txinType(self):
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

    @pyqtProperty('QString', notify=dataChanged)
    def derivationPath(self):
        keystores = self.wallet.get_keystores()
        if len(keystores) > 1:
            self._logger.debug('multiple keystores not supported yet')
        return keystores[0].get_derivation_prefix()

    balanceChanged = pyqtSignal()

    @pyqtProperty(int, notify=balanceChanged)
    def frozenBalance(self):
        return self.wallet.get_frozen_balance()

    @pyqtProperty(int, notify=balanceChanged)
    def unconfirmedBalance(self):
        return self.wallet.get_balance()[1]

    @pyqtProperty(int, notify=balanceChanged)
    def confirmedBalance(self):
        c, u, x = self.wallet.get_balance()
        self._logger.info('balance: ' + str(c) + ' ' + str(u) + ' ' + str(x) + ' ')

        return c+x

    def on_status(self, status):
        self._logger.info('wallet: status update: ' + str(status))
        self.isUptodateChanged.emit()

    # lightning feature?
    isUptodateChanged = pyqtSignal()
    @pyqtProperty(bool, notify=isUptodateChanged)
    def isUptodate(self):
        return self.wallet.is_up_to_date()

    @pyqtSlot('QString', int, int, bool)
    def send_onchain(self, address, amount, fee=None, rbf=False):
        self._logger.info('send_onchain: ' + address + ' ' + str(amount))
        coins = self.wallet.get_spendable_coins(None)
        if not bitcoin.is_address(address):
            self._logger.warning('Invalid Bitcoin Address: ' + address)
            return False

        outputs = [PartialTxOutput.from_address_and_value(address, amount)]
        tx = self.wallet.make_unsigned_transaction(coins=coins,outputs=outputs)
        return True

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

        req = self.wallet.make_payment_request(addr, amount, message, expiration)
        try:
            self.wallet.add_payment_request(req)
        except Exception as e:
            self.logger.exception('Error adding payment request')
            self.requestCreateError.emit('fatal',_('Error adding payment request') + ':\n' + repr(e))
        else:
            # TODO: check this flow. Only if alias is defined in config. OpenAlias?
            pass
            #self.sign_payment_request(addr)
        self._requestModel.add_request(req)
        return addr

    @pyqtSlot(int, 'QString', int)
    @pyqtSlot(int, 'QString', int, bool)
    @pyqtSlot(int, 'QString', int, bool, bool)
    def create_invoice(self, amount: int, message: str, expiration: int, is_lightning: bool = False, ignore_gap: bool = False):
        expiry = expiration #TODO: self.config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)
        try:
            if is_lightning:
                if not self.wallet.lnworker.channels:
                    self.requestCreateError.emit('fatal',_("You need to open a Lightning channel first."))
                    return
                # TODO maybe show a warning if amount exceeds lnworker.num_sats_can_receive (as in kivy)
                key = self.wallet.lnworker.add_request(amount, message, expiry)
            else:
                key = self.create_bitcoin_request(amount, message, expiry, ignore_gap)
                if not key:
                    return
                self._addressModel.init_model()
        except InvoiceError as e:
            self.requestCreateError.emit('fatal',_('Error creating payment request') + ':\n' + str(e))
            return

        assert key is not None
        self.requestCreateSuccess.emit()

        # TODO:copy to clipboard
        #r = self.wallet.get_request(key)
        #content = r.invoice if r.is_lightning() else r.get_address()
        #title = _('Invoice') if is_lightning else _('Address')
        #self.do_copy(content, title=title)
