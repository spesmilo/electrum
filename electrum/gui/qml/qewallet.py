from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex, QByteArray

from typing import Optional, TYPE_CHECKING, Sequence, List, Union

from electrum.i18n import _
from electrum.util import register_callback, Satoshis, format_time
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet
from electrum import bitcoin
from electrum.transaction import Transaction, tx_from_any, PartialTransaction, PartialTxOutput
from electrum.invoices import   (Invoice, InvoiceError, PR_TYPE_ONCHAIN, PR_TYPE_LN,
                                 PR_DEFAULT_EXPIRATION_WHEN_CREATING, PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED, PR_UNCONFIRMED, PR_TYPE_ONCHAIN, PR_TYPE_LN)

from .qerequestlistmodel import QERequestListModel

class QETransactionListModel(QAbstractListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.tx_history = []

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('txid','fee_sat','height','confirmations','timestamp','monotonic_timestamp','incoming','bc_value',
        'bc_balance','date','label','txpos_in_block','fee','inputs','outputs')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def rowCount(self, index):
        return len(self.tx_history)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        tx = self.tx_history[index.row()]
        role_index = role - (Qt.UserRole + 1)
        value = tx[self._ROLE_NAMES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.tx_history = []
        self.endResetModel()

    # initial model data
    def init_model(self):
        history = self.wallet.get_detailed_history(show_addresses = True)
        txs = history['transactions']
        # use primitives
        for tx in txs:
            for output in tx['outputs']:
                output['value'] = output['value'].value

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(txs) - 1)
        self.tx_history = txs
        self.tx_history.reverse()
        self.endInsertRows()

class QEAddressListModel(QAbstractListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.receive_addresses = []
        self.change_addresses = []


    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('type','address','label','balance','numtx', 'held')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def rowCount(self, index):
        return len(self.receive_addresses) + len(self.change_addresses)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        if index.row() > len(self.receive_addresses) - 1:
            address = self.change_addresses[index.row() - len(self.receive_addresses)]
        else:
            address = self.receive_addresses[index.row()]
        role_index = role - (Qt.UserRole + 1)
        value = address[self._ROLE_NAMES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.receive_addresses = []
        self.change_addresses = []
        self.endResetModel()

    # initial model data
    @pyqtSlot()
    def init_model(self):
        r_addresses = self.wallet.get_receiving_addresses()
        c_addresses = self.wallet.get_change_addresses()
        n_addresses = len(r_addresses) + len(c_addresses)

        def insert_row(atype, alist, address):
            item = {}
            item['type'] = atype
            item['address'] = address
            item['numtx'] = self.wallet.get_address_history_len(address)
            item['label'] = self.wallet.get_label(address)
            c, u, x = self.wallet.get_addr_balance(address)
            item['balance'] = c + u + x
            item['held'] = self.wallet.is_frozen_address(address)
            alist.append(item)

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, n_addresses - 1)
        for address in r_addresses:
            insert_row('receive', self.receive_addresses, address)
        for address in c_addresses:
            insert_row('change', self.change_addresses, address)
        self.endInsertRows()

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
    requestCreateError = pyqtSignal([str], arguments=['error'])

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

    def create_bitcoin_request(self, amount: int, message: str, expiration: int) -> Optional[str]:
        addr = self.wallet.get_unused_address()
        if addr is None:
            # TODO implement
            return
            #if not self.wallet.is_deterministic():  # imported wallet
                #msg = [
                    #_('No more addresses in your wallet.'), ' ',
                    #_('You are using a non-deterministic wallet, which cannot create new addresses.'), ' ',
                    #_('If you want to create new addresses, use a deterministic wallet instead.'), '\n\n',
                    #_('Creating a new payment request will reuse one of your addresses and overwrite an existing request. Continue anyway?'),
                   #]
                #if not self.question(''.join(msg)):
                    #return
                #addr = self.wallet.get_receiving_address()
            #else:  # deterministic wallet
                #if not self.question(_("Warning: The next address will not be recovered automatically if you restore your wallet from seed; you may need to add it manually.\n\nThis occurs because you have too many unused addresses in your wallet. To avoid this situation, use the existing addresses first.\n\nCreate anyway?")):
                    #return
                #addr = self.wallet.create_new_address(False)
        req = self.wallet.make_payment_request(addr, amount, message, expiration)
        try:
            self.wallet.add_payment_request(req)
        except Exception as e:
            self.logger.exception('Error adding payment request')
            self.requestCreateError.emit(_('Error adding payment request') + ':\n' + repr(e))
        else:
            # TODO: check this flow. Only if alias is defined in config. OpenAlias?
            pass
            #self.sign_payment_request(addr)
        self._requestModel.add_request(req)
        return addr

    @pyqtSlot(int, 'QString', int)
    def create_invoice(self, amount: int, message: str, expiration: int, is_lightning: bool = False):
        expiry = expiration #TODO: self.config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)
        try:
            if is_lightning:
                if not self.wallet.lnworker.channels:
                    #self.show_error(_("You need to open a Lightning channel first."))
                    self.requestCreateError.emit(_("You need to open a Lightning channel first."))
                    return
                # TODO maybe show a warning if amount exceeds lnworker.num_sats_can_receive (as in kivy)
                key = self.wallet.lnworker.add_request(amount, message, expiry)
            else:
                key = self.create_bitcoin_request(amount, message, expiry)
                if not key:
                    return
                #self.address_list.update()
                self._addressModel.init_model()
        except InvoiceError as e:
            self.requestCreateError.emit(_('Error creating payment request') + ':\n' + str(e))
            return

        assert key is not None
        self.requestCreateSuccess.emit()

        # TODO:copy to clipboard
        #r = self.wallet.get_request(key)
        #content = r.invoice if r.is_lightning() else r.get_address()
        #title = _('Invoice') if is_lightning else _('Address')
        #self.do_copy(content, title=title)
