from datetime import datetime, timedelta

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, TxMinedInfo

from .qetypes import QEAmount
from .util import QtEventListener, qt_event_listener

class QETransactionListModel(QAbstractListModel, QtEventListener):
    def __init__(self, wallet, parent=None, *, onchain_domain=None, include_lightning=True):
        super().__init__(parent)
        self.wallet = wallet
        self.onchain_domain = onchain_domain
        self.include_lightning = include_lightning

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())
        self.requestRefresh.connect(lambda: self.init_model())

        self.init_model()

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('txid','fee_sat','height','confirmations','timestamp','monotonic_timestamp',
                 'incoming','value','balance','date','label','txpos_in_block','fee',
                 'inputs','outputs','section','type','lightning','payment_hash','key','complete')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    requestRefresh = pyqtSignal()

    def on_destroy(self):
        self.unregister_callbacks()

    @qt_event_listener
    def on_event_verified(self, wallet, txid, info):
        if wallet == self.wallet:
            self._logger.debug('verified event for txid %s' % txid)
            self.on_tx_verified(txid, info)

    def rowCount(self, index):
        return len(self.tx_history)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        tx = self.tx_history[index.row()]
        role_index = role - Qt.UserRole

        try:
            value = tx[self._ROLE_NAMES[role_index]]
        except KeyError as e:
            self._logger.error(f'non-existing key "{self._ROLE_NAMES[role_index]}" requested')
            value = None

        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.tx_history = []
        self.endResetModel()

    def tx_to_model(self, tx):
        #self._logger.debug(str(tx))
        item = tx

        item['key'] = item['txid'] if 'txid' in item else item['payment_hash']

        if 'lightning' not in item:
            item['lightning'] = False

        if item['lightning']:
            item['value'] = QEAmount(amount_sat=item['value'].value, amount_msat=item['amount_msat'])
            item['balance'] = QEAmount(amount_sat=item['balance'].value, amount_msat=item['amount_msat'])
            if item['type'] == 'payment':
                item['incoming'] = True if item['direction'] == 'received' else False
            item['confirmations'] = 0
        else:
            item['value'] = QEAmount(amount_sat=item['value'].value)
            item['balance'] = QEAmount(amount_sat=item['balance'].value)

        if 'txid' in item:
            tx = self.wallet.get_input_tx(item['txid'])
            item['complete'] = tx.is_complete()

        # newly arriving txs, or (partially/fully signed) local txs have no (block) timestamp
        if not item['timestamp']:
            txinfo = self.wallet.get_tx_info(tx)
            item['section'] = 'mempool' if item['complete'] and not txinfo.can_broadcast else 'local'
        else:
            item['section'] = self.get_section_by_timestamp(item['timestamp'])
            item['date'] = self.format_date_by_section(item['section'], datetime.fromtimestamp(item['timestamp']))

        return item

    def get_section_by_timestamp(self, timestamp):
        txts = datetime.fromtimestamp(timestamp)
        today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)

        if (txts > today):
            return 'today'
        elif (txts > today - timedelta(days=1)):
            return 'yesterday'
        elif (txts > today - timedelta(days=7)):
            return 'lastweek'
        elif (txts > today - timedelta(days=31)):
            return 'lastmonth'
        else:
            return 'older'

    def format_date_by_section(self, section, date):
        #TODO: l10n
        dfmt = {
            'today': '%H:%M:%S',
            'yesterday': '%H:%M:%S',
            'lastweek': '%a, %H:%M:%S',
            'lastmonth': '%a %d, %H:%M:%S',
            'older': '%G-%m-%d %H:%M:%S'
        }
        if section not in dfmt:
            section = 'older'
        return date.strftime(dfmt[section])

    # initial model data
    @pyqtSlot()
    def init_model(self):
        self._logger.debug('retrieving history')
        history = self.wallet.get_full_history(onchain_domain=self.onchain_domain,
                                               include_lightning=self.include_lightning)
        txs = []
        for key, tx in history.items():
            txs.append(self.tx_to_model(tx))

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(txs) - 1)
        self.tx_history = txs
        self.tx_history.reverse()
        self.endInsertRows()

    def on_tx_verified(self, txid, info):
        i = 0
        for tx in self.tx_history:
            if 'txid' in tx and tx['txid'] == txid:
                tx['height'] = info.height
                tx['confirmations'] = info.conf
                tx['timestamp'] = info.timestamp
                tx['section'] = self.get_section_by_timestamp(info.timestamp)
                tx['date'] = self.format_date_by_section(tx['section'], datetime.fromtimestamp(info.timestamp))
                index = self.index(i,0)
                roles = [self._ROLE_RMAP[x] for x in ['section','height','confirmations','timestamp','date']]
                self.dataChanged.emit(index, index, roles)
                return
            i = i + 1

    @pyqtSlot(str, str)
    def update_tx_label(self, key, label):
        i = 0
        for tx in self.tx_history:
            if tx['key'] == key:
                tx['label'] = label
                index = self.index(i,0)
                self.dataChanged.emit(index, index, [self._ROLE_RMAP['label']])
                return
            i = i + 1

    @pyqtSlot(int)
    def updateBlockchainHeight(self, height):
        self._logger.debug('updating height to %d' % height)
        i = 0
        for tx in self.tx_history:
            if 'height' in tx and tx['height'] > 0:
                tx['confirmations'] = height - tx['height'] + 1
                index = self.index(i,0)
                roles = [self._ROLE_RMAP['confirmations']]
                self.dataChanged.emit(index, index, roles)
            i = i + 1
