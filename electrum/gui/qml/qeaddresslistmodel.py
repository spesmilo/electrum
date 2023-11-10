from typing import TYPE_CHECKING, List

from PyQt6.QtCore import pyqtSlot, QSortFilterProxyModel, pyqtSignal, pyqtProperty
from PyQt6.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis

from .qetypes import QEAmount

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.transaction import PartialTxInput


class QEAddressCoinFilterProxyModel(QSortFilterProxyModel):
    _logger = get_logger(__name__)

    def __init__(self, parent_model, parent=None):
        super().__init__(parent)
        self._filter_text = None
        self._show_coins = True
        self._show_addresses = True
        self._show_used = False
        self._parent_model = parent_model
        self.setSourceModel(parent_model)

    countChanged = pyqtSignal()
    @pyqtProperty(int, notify=countChanged)
    def count(self):
        return self.rowCount(QModelIndex())

    def filterAcceptsRow(self, s_row, s_parent):
        parent_model = self.sourceModel()
        addridx = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['addridx'])
        if addridx is None:  # coin
            if not self._show_coins:
                return False
        else:
            if not self._show_addresses:
                return False
            balance = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['balance'])
            numtx = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['numtx'])
            if balance.isEmpty and numtx and not self._show_used:
                return False
        if self._filter_text:
            label = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['label'])
            address = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['address'])
            outpoint = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['outpoint'])
            amount_i = parent_model.data(parent_model.index(s_row, 0, s_parent), parent_model._ROLE_RMAP['amount'])
            amount = parent_model.wallet.config.format_amount(amount_i.satsInt) if amount_i else None
            filter_text = self._filter_text.casefold()
            for item in [label, address, outpoint, amount]:
                if item is not None and filter_text in str(item).casefold():
                    return True
            return False
        return True

    showAddressesCoinsChanged = pyqtSignal()
    @pyqtProperty(int, notify=showAddressesCoinsChanged)
    def showAddressesCoins(self) -> int:
        result = 0
        if self._show_addresses:
            result += 1
        if self._show_coins:
            result += 2
        return result

    @showAddressesCoins.setter
    def showAddressesCoins(self, show_addresses_coins: int):
        show_addresses = show_addresses_coins in [1, 3]
        show_coins = show_addresses_coins in [2, 3]

        if self._show_addresses != show_addresses or self._show_coins != show_coins:
            self._show_addresses = show_addresses
            self._show_coins = show_coins
            self.invalidateFilter()
            self.showAddressesCoinsChanged.emit()

    showUsedChanged = pyqtSignal()
    @pyqtProperty(bool, notify=showUsedChanged)
    def showUsed(self) -> bool:
        return self._show_used

    @showUsed.setter
    def showUsed(self, show_used: bool):
        if self._show_used != show_used:
            self._show_used = show_used
            self.invalidateFilter()
            self.showUsedChanged.emit()

    filterTextChanged = pyqtSignal()
    @pyqtProperty(str, notify=filterTextChanged)
    def filterText(self) -> str:
        return self._filter_text

    @filterText.setter
    def filterText(self, filter_text: str):
        if self._filter_text != filter_text:
            self._filter_text = filter_text
            self.invalidateFilter()
            self.filterTextChanged.emit()


class QEAddressCoinListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('type', 'addridx', 'address', 'label', 'balance', 'numtx', 'held', 'height', 'amount', 'outpoint',
                 'short_outpoint', 'short_id', 'txid')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def __init__(self, wallet: 'Abstract_Wallet', parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self._items = []
        self._filterModel = None

        self._dirty = True
        self.initModel()

    def rowCount(self, index):
        return len(self._items)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        address = self._items[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
        try:
            value = address[self._ROLE_NAMES[role_index]]
        except KeyError:
            return None
        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self._items = []
        self.endResetModel()

    def addr_to_model(self, addrtype: str, addridx: int, address: str):
        c, u, x = self.wallet.get_addr_balance(address)
        item = {
            'type': addrtype,
            'addridx': addridx,
            'address': address,
            'numtx': self.wallet.adb.get_address_history_len(address),
            'label': self.wallet.get_label_for_address(address),
            'balance': QEAmount(amount_sat=c + u + x),
            'held': self.wallet.is_frozen_address(address)
        }
        return item

    def coin_to_model(self, addrtype: str, coin: 'PartialTxInput'):
        txid = coin.prevout.txid.hex()
        short_id = ''
        # check below duplicated from TxInput as we cannot get short_id unambiguously
        if coin.block_txpos is not None and coin.block_txpos >= 0:
            short_id = str(coin.short_id)
        item = {
            'type': addrtype,
            'amount': QEAmount(amount_sat=coin.value_sats()),
            'address': coin.address,
            'height': coin.block_height,
            'outpoint': coin.prevout.to_str(),
            'short_outpoint': coin.prevout.short_name(),
            'short_id': short_id,
            'txid': txid,
            'label': self.wallet.get_label_for_txid(txid) or '',
            'held': self.wallet.is_frozen_coin(coin),
            'coin': coin
        }
        return item

    @pyqtSlot()
    def setDirty(self):
        self._dirty = True

    # initial model data
    @pyqtSlot()
    def initModel(self):
        if not self._dirty:
            return

        r_addresses = self.wallet.get_receiving_addresses()
        c_addresses = self.wallet.get_change_addresses() if self.wallet.wallet_type != 'imported' else []
        n_addresses = len(r_addresses) + len(c_addresses)

        def insert_address(atype, address, addridx):
            item = self.addr_to_model(atype, addridx, address)
            self._items.append(item)

            utxos = self.wallet.get_utxos([address])
            utxos.sort(key=lambda x: x.block_height)
            for i, coin in enumerate(utxos):
                self._items.append(self.coin_to_model(atype, coin))

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, n_addresses - 1)
        if self.wallet.wallet_type != 'imported':
            for i, address in enumerate(r_addresses):
                insert_address('receive', address, i)
            for i, address in enumerate(c_addresses):
                insert_address('change', address, i)
        else:
            for i, address in enumerate(r_addresses):
                insert_address('imported', address, i)
        self.endInsertRows()

        self._dirty = False

        if self._filterModel is not None:
            self._filterModel.invalidate()

    @pyqtSlot(str)
    def updateAddress(self, address):
        for i, a in enumerate(self._items):
            if a['address'] == address:
                self.do_update(i, a)
                return

    @pyqtSlot(str)
    def deleteAddress(self, address):
        first = -1
        last = -1
        for i, a in enumerate(self._items):
            if a['address'] == address:
                if first < 0:
                    first = i
                last = i
        if not first >= 0:
            return
        self.beginRemoveRows(QModelIndex(), first, last)
        self._items = self._items[0:first] + self._items[last+1:]
        self.endRemoveRows()

    def updateCoin(self, outpoint):
        for i, a in enumerate(self._items):
            if a.get('outpoint') == outpoint:
                self.do_update(i, a)
                return

    def do_update(self, modelindex, modelitem):
        mi = self.createIndex(modelindex, 0)
        self._logger.debug(repr(modelitem))
        if modelitem.get('outpoint'):
            modelitem.update(self.coin_to_model(modelitem['type'], modelitem['coin']))
        else:
            modelitem.update(self.addr_to_model(modelitem['type'], modelitem['addridx'], modelitem['address']))
        self._logger.debug(repr(modelitem))
        self.dataChanged.emit(mi, mi, self._ROLE_KEYS)

    filterModelChanged = pyqtSignal()
    @pyqtProperty(QEAddressCoinFilterProxyModel, notify=filterModelChanged)
    def filterModel(self):
        if self._filterModel is None:
            self._filterModel = QEAddressCoinFilterProxyModel(self)
        return self._filterModel

    @pyqtSlot(bool, list)
    def setFrozenForItems(self, freeze: bool, items: List[str]):
        self._logger.debug(f'set frozen to {freeze} for {items!r}')
        coins = list(filter(lambda x: ':' in x, items))
        if len(coins):
            self.wallet.set_frozen_state_of_coins(coins, freeze)
            for coin in coins:
                self.updateCoin(coin)
        addresses = list(filter(lambda x: ':' not in x, items))
        if len(addresses):
            self.wallet.set_frozen_state_of_addresses(addresses, freeze)
            for address in addresses:
                self.updateAddress(address)

