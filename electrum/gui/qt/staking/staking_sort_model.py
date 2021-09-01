import threading
from datetime import date
from decimal import Decimal
from enum import IntEnum

from PyQt5.QtCore import (Qt, QModelIndex, QSortFilterProxyModel, QItemSelectionModel)

from electrum.gui.qt.custom_model import CustomModel
from electrum.gui.qt.history_list import HistoryNode
from electrum.i18n import _
from electrum.logging import Logger
from electrum.util import (profiler, TxMinedInfo,
                           OrderedDictWithIndex, timestamp_to_datetime,
                           Satoshis)


class StakingColumns(IntEnum):
    STATUS = 0
    DESCRIPTION = 1
    AMOUNT = 2
    BALANCE = 3
    TXID = 4


class StakingSortModel(QSortFilterProxyModel):
    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex):
        item1 = self.sourceModel().data(source_left, Qt.UserRole)
        item2 = self.sourceModel().data(source_right, Qt.UserRole)
        if item1 is None or item2 is None:
            raise Exception(f'UserRole not set for column {source_left.column()}')
        v1 = item1.value()
        v2 = item2.value()
        if v1 is None or isinstance(v1, Decimal) and v1.is_nan(): v1 = -float("inf")
        if v2 is None or isinstance(v2, Decimal) and v2.is_nan(): v2 = -float("inf")
        try:
            return v1 < v2
        except:
            return False


def get_item_key(tx_item):
    return tx_item.get('txid') or tx_item['payment_hash']


class StakingModel(CustomModel, Logger):

    def __init__(self, parent: 'ElectrumWindow'):
        CustomModel.__init__(self, parent, len(StakingColumns))
        Logger.__init__(self)
        self.parent = parent
        self.view = None
        self.transactions = OrderedDictWithIndex()
        self.tx_status_cache = {}  # type: Dict[str, Tuple[int, str]]

    def set_view(self, staking_list: 'StakingList'):
        # After constructing both, this method needs to be called.
        self.view = staking_list  # type: StakingList
        self.set_visibility_of_columns()

    def update_label(self, index):
        tx_item = index.internalPointer().get_data()
        tx_item['label'] = self.parent.wallet.get_label_for_txid(get_item_key(tx_item))
        topLeft = bottomRight = self.createIndex(index.row(), StakingColumns.DESCRIPTION)
        self.dataChanged.emit(topLeft, bottomRight, [Qt.DisplayRole])
        self.parent.utxo_list.update()

    def get_domain(self):
        """Overridden in address_dialog.py"""
        return self.parent.wallet.get_addresses()

    def should_include_lightning_payments(self) -> bool:
        """Overridden in address_dialog.py"""
        return True

    @profiler
    def refresh(self, reason: str):
        self.logger.info(f"refreshing... reason: {reason}")
        assert self.parent.gui_thread == threading.current_thread(), 'must be called from GUI thread'
        assert self.view, 'view not set'
        if self.view.maybe_defer_update():
            return
        selected = self.view.selectionModel().currentIndex()
        selected_row = None
        if selected:
            selected_row = selected.row()
        fx = self.parent.fx
        if fx: fx.history_used_spot = False
        wallet = self.parent.wallet
        self.set_visibility_of_columns()
        transactions = wallet.get_full_history(
            self.parent.fx,
            onchain_domain=self.get_domain(),
            include_lightning=self.should_include_lightning_payments())
        if transactions == self.transactions:
            return
        old_length = self._root.childCount()
        if old_length != 0:
            self.beginRemoveRows(QModelIndex(), 0, old_length)
            self.transactions.clear()
            self._root = HistoryNode(self, None)
            self.endRemoveRows()
        parents = {}
        for tx_item in transactions.values():
            node = HistoryNode(self, tx_item)
            group_id = tx_item.get('group_id')
            if group_id is None:
                self._root.addChild(node)
            else:
                parent = parents.get(group_id)
                if parent is None:
                    # create parent if it does not exist
                    self._root.addChild(node)
                    parents[group_id] = node
                else:
                    # if parent has no children, create two children
                    if parent.childCount() == 0:
                        child_data = dict(parent.get_data())
                        node1 = HistoryNode(self, child_data)
                        parent.addChild(node1)
                        parent._data['label'] = child_data.get('group_label')
                        parent._data['bc_value'] = child_data.get('bc_value', Satoshis(0))
                        parent._data['ln_value'] = child_data.get('ln_value', Satoshis(0))
                    # add child to parent
                    parent.addChild(node)
                    # update parent data
                    parent._data['balance'] = tx_item['balance']
                    parent._data['value'] += tx_item['value']
                    if 'group_label' in tx_item:
                        parent._data['label'] = tx_item['group_label']
                    if 'bc_value' in tx_item:
                        parent._data['bc_value'] += tx_item['bc_value']
                    if 'ln_value' in tx_item:
                        parent._data['ln_value'] += tx_item['ln_value']
                    if 'fiat_value' in tx_item:
                        parent._data['fiat_value'] += tx_item['fiat_value']
                    if tx_item.get('txid') == group_id:
                        parent._data['lightning'] = False
                        parent._data['txid'] = tx_item['txid']
                        parent._data['timestamp'] = tx_item['timestamp']
                        parent._data['height'] = tx_item['height']
                        parent._data['confirmations'] = tx_item['confirmations']

        new_length = self._root.childCount()
        self.beginInsertRows(QModelIndex(), 0, new_length - 1)
        self.transactions = transactions
        self.endInsertRows()

        if selected_row:
            self.view.selectionModel().select(self.createIndex(selected_row, 0),
                                              QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.view.filter()
        # update time filter
        if not self.view.years and self.transactions:
            start_date = date.today()
            end_date = date.today()
            if len(self.transactions) > 0:
                start_date = self.transactions.value_from_pos(0).get('date') or start_date
                end_date = self.transactions.value_from_pos(len(self.transactions) - 1).get('date') or end_date
            self.view.years = [str(i) for i in range(start_date.year, end_date.year + 1)]
            self.view.period_combo.insertItems(1, self.view.years)
        # update tx_status_cache
        self.tx_status_cache.clear()
        for txid, tx_item in self.transactions.items():
            if not tx_item.get('lightning', False):
                tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
                self.tx_status_cache[txid] = self.parent.wallet.get_tx_status(txid, tx_mined_info)

    def set_visibility_of_columns(self):
        def set_visible(col: int, b: bool):
            self.view.showColumn(col) if b else self.view.hideColumn(col)

        # txid
        set_visible(StakingColumns.TXID, False)
        # fiat
        history = self.parent.fx.show_history()
        cap_gains = self.parent.fx.get_history_capital_gains_config()
        set_visible(StakingColumns.FIAT_VALUE, history)
        set_visible(StakingColumns.FIAT_ACQ_PRICE, history and cap_gains)
        set_visible(StakingColumns.FIAT_CAP_GAINS, history and cap_gains)

    def update_fiat(self, idx):
        tx_item = idx.internalPointer().get_data()
        key = tx_item['txid']
        fee = tx_item.get('fee')
        value = tx_item['value'].value
        fiat_fields = self.parent.wallet.get_tx_item_fiat(key, value, self.parent.fx, fee.value if fee else None)
        tx_item.update(fiat_fields)
        self.dataChanged.emit(idx, idx, [Qt.DisplayRole, Qt.ForegroundRole])

    def update_tx_mined_status(self, tx_hash: str, tx_mined_info: TxMinedInfo):
        try:
            row = self.transactions.pos_from_key(tx_hash)
            tx_item = self.transactions[tx_hash]
        except KeyError:
            return
        self.tx_status_cache[tx_hash] = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)
        tx_item.update({
            'confirmations': tx_mined_info.conf,
            'timestamp': tx_mined_info.timestamp,
            'txpos_in_block': tx_mined_info.txpos,
            'date': timestamp_to_datetime(tx_mined_info.timestamp),
        })
        topLeft = self.createIndex(row, 0)
        bottomRight = self.createIndex(row, len(StakingColumns) - 1)
        self.dataChanged.emit(topLeft, bottomRight)

    def on_fee_histogram(self):
        for tx_hash, tx_item in list(self.transactions.items()):
            if tx_item.get('lightning'):
                continue
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            if tx_mined_info.conf > 0:
                # note: we could actually break here if we wanted to rely on the order of txns in self.transactions
                continue
            self.update_tx_mined_status(tx_hash, tx_mined_info)

    def headerData(self, section: int, orientation: Qt.Orientation, role: Qt.ItemDataRole):
        assert orientation == Qt.Horizontal
        if role != Qt.DisplayRole:
            return None
        return {
            StakingColumns.STATUS: _('Date'),
            StakingColumns.DESCRIPTION: _('Description'),
            StakingColumns.AMOUNT: _('Amount'),
            StakingColumns.BALANCE: _('Balance'),
            StakingColumns.TXID: 'TXID',
        }[section]

    def flags(self, idx):
        extra_flags = Qt.NoItemFlags  # type: Qt.ItemFlag
        if idx.column() in self.view.editable_columns:
            extra_flags |= Qt.ItemIsEditable
        return super().flags(idx) | int(extra_flags)

    @staticmethod
    def tx_mined_info_from_tx_item(tx_item):
        tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                    conf=tx_item['confirmations'],
                                    timestamp=tx_item['timestamp'])
        return tx_mined_info
