import asyncio
import concurrent
from enum import IntEnum

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, pyqtEnum
from PyQt6.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum import Network, keystore
from electrum.bip32 import BIP32Node
from electrum.bip39_recovery import account_discovery
from electrum.logging import get_logger
from electrum.util import get_asyncio_loop

from .util import TaskThread


class QEBip39RecoveryListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    @pyqtEnum
    class State(IntEnum):
        Idle = -1
        Scanning = 0
        Success = 1
        Failed = 2
        Cancelled = 3

    recoveryFailed = pyqtSignal()
    stateChanged = pyqtSignal()

    # define listmodel rolemap
    _ROLE_NAMES=('description', 'derivation_path', 'script_type')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self._accounts = []
        self._thread = None
        self._root_seed = None
        self._state = QEBip39RecoveryListModel.State.Idle

    def rowCount(self, index):
        return len(self._accounts)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        account = self._accounts[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
        value = account[self._ROLE_NAMES[role_index]]
        if isinstance(value, (bool, list, int, str)) or value is None:
            return value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self._accounts = []
        self.endResetModel()

    @pyqtProperty(int, notify=stateChanged)
    def state(self):
        return self._state

    @state.setter
    def state(self, state: State):
        if state != self._state:
            self._state = state
            self.stateChanged.emit()

    @pyqtSlot(str, str)
    @pyqtSlot(str, str, str)
    def startScan(self, wallet_type: str, seed: str, seed_extra_words: str = None):
        if not seed or not wallet_type:
            return

        assert wallet_type == 'standard'

        self._root_seed = keystore.bip39_to_seed(seed, seed_extra_words)

        self.clear()

        self._thread = TaskThread(self)
        network = Network.get_instance()
        coro = account_discovery(network, self.get_account_xpub)
        self.state = QEBip39RecoveryListModel.State.Scanning
        fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
        self._thread.add(
            fut.result,
            on_success=self.on_recovery_success,
            on_error=self.on_recovery_error,
            cancel=fut.cancel,
        )

    def addAccount(self, account):
        self._logger.debug(f'addAccount {account!r}')
        self.beginInsertRows(QModelIndex(), len(self._accounts), len(self._accounts))
        self._accounts.append(account)
        self.endInsertRows()

    def on_recovery_success(self, accounts):
        self.state = QEBip39RecoveryListModel.State.Success

        for account in accounts:
            self.addAccount(account)

        self._thread.stop()

    def on_recovery_error(self, exc_info):
        e = exc_info[1]
        if isinstance(e, concurrent.futures.CancelledError):
            self.state = QEBip39RecoveryListModel.State.Cancelled
            return
        self._logger.error(f'recovery error', exc_info=exc_info)
        self.state = QEBip39RecoveryListModel.State.Failed
        self._thread.stop()

    def get_account_xpub(self, account_path):
        root_node = BIP32Node.from_rootseed(self._root_seed, xtype='standard')
        account_node = root_node.subkey_at_private_derivation(account_path)
        account_xpub = account_node.to_xpub()
        return account_xpub
