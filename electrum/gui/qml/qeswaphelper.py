import asyncio
import concurrent
import threading
import time
from enum import IntEnum
from typing import Union, Optional

from PyQt6.QtCore import (pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer, pyqtEnum, QAbstractListModel, Qt,
                          QModelIndex)

from electrum.i18n import _
from electrum.bitcoin import DummyAddress
from electrum.logging import get_logger
from electrum.transaction import PartialTxOutput, PartialTransaction
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, profiler, get_asyncio_loop, age
from electrum.submarine_swaps import NostrTransport

from electrum.gui import messages

from .auth import AuthMixin, auth_protect
from .qetypes import QEAmount
from .qewallet import QEWallet
from .util import QtEventListener, qt_event_listener


class InvalidSwapParameters(Exception): pass


class QESwapServerNPubListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES= ('npub', 'timestamp', 'percentage_fee', 'normal_mining_fee', 'reverse_mining_fee', 'claim_mining_fee',
                  'min_amount', 'max_amount')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._services = []

    def rowCount(self, index):
        return len(self._services)

    # also expose rowCount as a property
    countChanged = pyqtSignal()
    @pyqtProperty(int, notify=countChanged)
    def count(self):
        return len(self._services)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        service = self._services[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
        value = service[self._ROLE_NAMES[role_index]]
        if isinstance(value, (bool, list, int, str)) or value is None:
            return value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self._services = []
        self.endResetModel()

    def initModel(self, items):
        self.beginInsertRows(QModelIndex(), len(items), len(items))
        self._services = [{
                'npub': x['pubkey'],
                'percentage_fee': x['percentage_fee'],
                'normal_mining_fee': x['normal_mining_fee'],
                'reverse_mining_fee': x['reverse_mining_fee'],
                'claim_mining_fee': x['claim_mining_fee'],
                'min_amount': x['min_amount'],
                'max_amount': x['max_amount'],
                'timestamp': age(x['timestamp']),
            }
            for x in items
        ]
        self.endInsertRows()
        self.countChanged.emit()

    @pyqtSlot(str, result=int)
    def indexFor(self, npub: str):
        for i, item in enumerate(self._services):
            if npub == item['npub']:
                return i
        return -1


class QESwapHelper(AuthMixin, QObject, QtEventListener):
    _logger = get_logger(__name__)

    MESSAGE_SWAP_HOWTO = ' '.join([
            _('Move the slider to set the amount and direction of the swap.'),
            _('Swapping lightning funds for onchain funds will increase your capacity to receive lightning payments.'),
        ])

    @pyqtEnum
    class State(IntEnum):
        Initializing = 0
        Initialized = 1
        NoService = 2
        ServiceReady = 3
        Started = 4
        Failed = 5
        Success = 6
        Cancelled = 7

    confirm = pyqtSignal([str], arguments=['message'])
    error = pyqtSignal([str], arguments=['message'])
    undefinedNPub = pyqtSignal()
    offersUpdated = pyqtSignal()
    requestTxUpdate = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None  # type: Optional[QEWallet]
        self._sliderPos = 0
        self._rangeMin = -1
        self._rangeMax = 1
        self._tx = None
        self._valid = False
        self._state = QESwapHelper.State.Initialized
        self._userinfo = QESwapHelper.MESSAGE_SWAP_HOWTO
        self._tosend = QEAmount()
        self._toreceive = QEAmount()
        self._serverfeeperc = ''
        self._server_miningfee = QEAmount()
        self._miningfee = QEAmount()
        self._isReverse = False
        self._canCancel = False
        self._swap = None
        self._fut_htlc_wait = None

        self._service_available = False
        self._send_amount = 0
        self._receive_amount = 0

        self._leftVoid = 0
        self._rightVoid = 0

        self._available_swapservers = None

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

        self._fwd_swap_updatetx_timer = QTimer(self)
        self._fwd_swap_updatetx_timer.setSingleShot(True)
        self._fwd_swap_updatetx_timer.timeout.connect(self.fwd_swap_updatetx)
        self.requestTxUpdate.connect(self.tx_update_pushback_timer)

        self.offersUpdated.connect(self.on_offers_updated)

    def on_destroy(self):
        self.unregister_callbacks()

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self.init_swap_manager()
            self.walletChanged.emit()

    sliderPosChanged = pyqtSignal()
    @pyqtProperty(float, notify=sliderPosChanged)
    def sliderPos(self):
        return self._sliderPos

    @sliderPos.setter
    def sliderPos(self, sliderPos):
        if self._sliderPos != sliderPos:
            self._sliderPos = sliderPos
            self.swap_slider_moved()
            self.sliderPosChanged.emit()

    rangeMinChanged = pyqtSignal()
    @pyqtProperty(float, notify=rangeMinChanged)
    def rangeMin(self):
        return self._rangeMin

    @rangeMin.setter
    def rangeMin(self, rangeMin):
        if self._rangeMin != rangeMin:
            self._rangeMin = rangeMin
            self.rangeMinChanged.emit()

    rangeMaxChanged = pyqtSignal()
    @pyqtProperty(float, notify=rangeMaxChanged)
    def rangeMax(self):
        return self._rangeMax

    @rangeMax.setter
    def rangeMax(self, rangeMax):
        if self._rangeMax != rangeMax:
            self._rangeMax = rangeMax
            self.rangeMaxChanged.emit()

    leftVoidChanged = pyqtSignal()
    @pyqtProperty(float, notify=leftVoidChanged)
    def leftVoid(self):
        return self._leftVoid

    rightVoidChanged = pyqtSignal()
    @pyqtProperty(float, notify=rightVoidChanged)
    def rightVoid(self):
        return self._rightVoid

    validChanged = pyqtSignal()
    @pyqtProperty(bool, notify=validChanged)
    def valid(self):
        return self._valid

    @valid.setter
    def valid(self, valid):
        if self._valid != valid:
            self._valid = valid
            self.validChanged.emit()

    stateChanged = pyqtSignal()
    @pyqtProperty(int, notify=stateChanged)
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        if self._state != state:
            self._state = state
            self.stateChanged.emit()

    userinfoChanged = pyqtSignal()
    @pyqtProperty(str, notify=userinfoChanged)
    def userinfo(self):
        return self._userinfo

    @userinfo.setter
    def userinfo(self, userinfo):
        if self._userinfo != userinfo:
            self._userinfo = userinfo
            self.userinfoChanged.emit()

    tosendChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=tosendChanged)
    def tosend(self):
        return self._tosend

    @tosend.setter
    def tosend(self, tosend):
        if self._tosend != tosend:
            self._tosend = tosend
            self.tosendChanged.emit()

    toreceiveChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=toreceiveChanged)
    def toreceive(self):
        return self._toreceive

    @toreceive.setter
    def toreceive(self, toreceive):
        if self._toreceive != toreceive:
            self._toreceive = toreceive
            self.toreceiveChanged.emit()

    serverMiningfeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=serverMiningfeeChanged)
    def serverMiningfee(self):
        return self._server_miningfee

    @serverMiningfee.setter
    def serverMiningfee(self, server_miningfee):
        if self._server_miningfee != server_miningfee:
            self._server_miningfee = server_miningfee
            self.serverMiningfeeChanged.emit()

    serverfeepercChanged = pyqtSignal()
    @pyqtProperty(str, notify=serverfeepercChanged)
    def serverfeeperc(self):
        return self._serverfeeperc

    @serverfeeperc.setter
    def serverfeeperc(self, serverfeeperc):
        if self._serverfeeperc != serverfeeperc:
            self._serverfeeperc = serverfeeperc
            self.serverfeepercChanged.emit()

    miningfeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=miningfeeChanged)
    def miningfee(self):
        return self._miningfee

    @miningfee.setter
    def miningfee(self, miningfee):
        if self._miningfee != miningfee:
            self._miningfee = miningfee
            self.miningfeeChanged.emit()

    isReverseChanged = pyqtSignal()
    @pyqtProperty(bool, notify=isReverseChanged)
    def isReverse(self):
        return self._isReverse

    @isReverse.setter
    def isReverse(self, isReverse):
        if self._isReverse != isReverse:
            self._isReverse = isReverse
            self.isReverseChanged.emit()

    canCancelChanged = pyqtSignal()
    @pyqtProperty(bool, notify=canCancelChanged)
    def canCancel(self):
        return self._canCancel

    @canCancel.setter
    def canCancel(self, canCancel):
        if self._canCancel != canCancel:
            self._canCancel = canCancel
            self.canCancelChanged.emit()

    availableSwapServersChanged = pyqtSignal()
    @pyqtProperty(QESwapServerNPubListModel, notify=availableSwapServersChanged)
    def availableSwapServers(self):
        if not self._available_swapservers:
            self._available_swapservers = QESwapServerNPubListModel(self._wallet.wallet.config)

        return self._available_swapservers

    def on_offers_updated(self):
        self.availableSwapServers.initModel(self.recent_offers)

    @pyqtSlot(result=bool)
    def isNostr(self):
        return True  # TODO

    @pyqtSlot()
    def init_swap_manager(self):
        self._logger.debug('init_swap_manager')
        if (lnworker := self._wallet.wallet.lnworker) is None:
            return
        swap_manager = lnworker.swap_manager

        assert not swap_manager.is_server, 'running as swap server not supported'

        # if not self._wallet.wallet.config.SWAPSERVER_URL and not self._wallet.wallet.config.SWAPSERVER_NPUB:  # TODO enable nostr
        #     self._logger.debug('nostr is preferred but swapserver npub still undefined')

        # FIXME: clearing is_initialized, we might be called because the npub was changed
        swap_manager.is_initialized.clear()
        self.state = QESwapHelper.State.Initialized if swap_manager.is_initialized.is_set() else QESwapHelper.State.Initializing

        swap_transport = swap_manager.create_transport()

        def query_task(transport):
            with transport:
                try:
                    async def wait_initialized():
                        try:
                            await asyncio.wait_for(swap_manager.is_initialized.wait(), timeout=15)
                            self._logger.debug('swapmanager initialized')
                            self.state = QESwapHelper.State.Initialized
                        except asyncio.TimeoutError:
                            self._logger.debug('swapmanager init timeout')
                            self.state = QESwapHelper.State.NoService
                            return

                    if not swap_manager.is_initialized.is_set():
                        self.userinfo = _('Initializing...')
                        fut = asyncio.run_coroutine_threadsafe(wait_initialized(), get_asyncio_loop())
                        fut.result()
                except Exception as e:
                    try:  # swaphelper might be destroyed at this point
                        self.userinfo = _('Error') + ': ' + str(e)
                        self.state = QESwapHelper.State.NoService
                        self._logger.error(str(e))
                    except RuntimeError:
                        pass

                if isinstance(transport, NostrTransport):
                    now = int(time.time())
                    if not swap_manager.is_initialized.is_set():
                        if not transport.is_connected.is_set():
                            self.userinfo = _('Error') + ': ' + '\n'.join([
                                _('Could not connect to a Nostr relay.'),
                                _('Please check your relays and network connection')
                            ])
                            self.state = QESwapHelper.State.NoService
                            return
                        self.recent_offers = [x for x in transport.offers.values() if now - x['timestamp'] < NostrTransport.NOSTR_EVENT_TIMEOUT]
                        if not self.recent_offers:
                            self.userinfo = _('Could not find a swap provider.')
                            self.state = QESwapHelper.State.NoService
                            return

                        self.offersUpdated.emit()
                        self.undefinedNPub.emit()
                        return
                    else:
                        self.recent_offers = [x for x in transport.offers.values() if now - x['timestamp'] < NostrTransport.NOSTR_EVENT_TIMEOUT]
                        if not self.recent_offers:
                            self.userinfo = _('Could not find a swap provider.')
                            self.state = QESwapHelper.State.NoService
                            return

                        self.offersUpdated.emit()

                self.state = QESwapHelper.State.ServiceReady
                self.userinfo = QESwapHelper.MESSAGE_SWAP_HOWTO
                self.init_swap_slider_range()

        threading.Thread(target=query_task, args=(swap_transport,), daemon=True).start()

    @pyqtSlot()
    def npubSelectionCancelled(self):
        if not self._wallet.wallet.config.SWAPSERVER_NPUB:
            self._logger.debug('nostr is preferred but swapserver npub still undefined')
            self.userinfo = _('No swap provider selected.')
            self.state = QESwapHelper.State.NoService

    def init_swap_slider_range(self):
        lnworker = self._wallet.wallet.lnworker
        swap_manager = lnworker.swap_manager

        """Sets the minimal and maximal amount that can be swapped for the swap
        slider."""
        # tx is updated again afterwards with send_amount in case of normal swap
        # this is just to estimate the maximal spendable onchain amount for HTLC
        self.update_tx('!')
        try:
            max_onchain_spend = self._tx.output_value_for_address(DummyAddress.SWAP)
        except AttributeError:  # happens if there are no utxos
            max_onchain_spend = 0
        reverse = int(min(lnworker.num_sats_can_send(),
                          swap_manager.get_max_amount()))
        max_recv_amt_ln = int(lnworker.num_sats_can_receive())
        max_recv_amt_oc = swap_manager.get_send_amount(max_recv_amt_ln, is_reverse=False) or 0
        forward = int(min(max_recv_amt_oc,
                          # maximally supported swap amount by provider
                          swap_manager.get_max_amount(),
                          max_onchain_spend))
        # we expect range to adjust the value of the swap slider to be in the
        # correct range, i.e., to correct an overflow when reducing the limits
        self._logger.debug(f'Slider range {-reverse} - {forward}')
        self.rangeMin = -reverse
        self.rangeMax = forward
        # percentage of void, right or left
        if reverse < forward:
            self._leftVoid = 0.5 * (forward - reverse) / forward
            self._rightVoid = 0
        elif reverse > forward:
            self._leftVoid = 0
            self._rightVoid = - 0.5 * (forward - reverse) / reverse
        else:
            self._leftVoid = 0
            self._rightVoid = 0
        self.leftVoidChanged.emit()
        self.rightVoidChanged.emit()

        self.swap_slider_moved()

    @profiler
    def update_tx(self, onchain_amount: Union[int, str]):
        """Updates the transaction associated with a forward swap."""
        if onchain_amount is None:
            self._tx = None
            self.valid = False
            return
        outputs = [PartialTxOutput.from_address_and_value(DummyAddress.SWAP, onchain_amount)]
        coins = self._wallet.wallet.get_spendable_coins(None)
        try:
            self._tx = self._wallet.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs)
        except (NotEnoughFunds, NoDynamicFeeEstimates):
            self._tx = None
            self.valid = False

    @qt_event_listener
    def on_event_fee_histogram(self, *args):
        self.swap_slider_moved()

    @qt_event_listener
    def on_event_fee(self, *args):
        self.swap_slider_moved()

    def swap_slider_moved(self):
        if self._state in [QESwapHelper.State.Initializing, QESwapHelper.State.Initialized, QESwapHelper.State.NoService]:
            return

        position = int(self._sliderPos)

        swap_manager = self._wallet.wallet.lnworker.swap_manager

        # pay_amount and receive_amounts are always with fees already included
        # so they reflect the net balance change after the swap
        self.isReverse = (position < 0)
        self._send_amount = abs(position)
        self.tosend = QEAmount(amount_sat=self._send_amount)
        self._receive_amount = swap_manager.get_recv_amount(send_amount=self._send_amount, is_reverse=self.isReverse)
        self.toreceive = QEAmount(amount_sat=self._receive_amount)
        # fee breakdown
        self.serverfeeperc = f'{swap_manager.percentage:0.1f}%'
        server_miningfee = swap_manager.lockup_fee if self.isReverse else swap_manager.normal_fee
        self.serverMiningfee = QEAmount(amount_sat=server_miningfee)
        if self.isReverse:
            self.check_valid(self._send_amount, self._receive_amount)
        else:
            # update tx only if slider isn't moved for a while
            self.valid = False
            # trigger tx_update_pushback_timer through signal, as this might be called from other thread
            self.requestTxUpdate.emit()

    def tx_update_pushback_timer(self):
        self._fwd_swap_updatetx_timer.start(250)

    def check_valid(self, send_amount, receive_amount):
        if send_amount and receive_amount:
            self.valid = True
        else:
            # add more nuanced error reporting?
            self.valid = False

    def fwd_swap_updatetx(self):
        self.update_tx(self._send_amount)
        # add lockup fees, but the swap amount is position
        pay_amount = self._send_amount + self._tx.get_fee() if self._tx else 0
        self.miningfee = QEAmount(amount_sat=self._tx.get_fee()) if self._tx else QEAmount()
        self.check_valid(pay_amount, self._receive_amount)

    def do_normal_swap(self, lightning_amount, onchain_amount):
        assert self._tx
        if lightning_amount is None or onchain_amount is None:
            return
        loop = get_asyncio_loop()

        def swap_task():
            with self._wallet.wallet.lnworker.swap_manager.create_transport() as transport:
                coro = self._wallet.wallet.lnworker.swap_manager.request_normal_swap(
                    transport,
                    lightning_amount_sat=lightning_amount,
                    expected_onchain_amount_sat=onchain_amount,
                )
                try:
                    dummy_tx = self._create_tx(onchain_amount)
                    fut = asyncio.run_coroutine_threadsafe(coro, loop)
                    self.userinfo = _('Performing swap...')
                    self.state = QESwapHelper.State.Started
                    self._swap, invoice = fut.result()

                    tx = self._wallet.wallet.lnworker.swap_manager.create_funding_tx(self._swap, dummy_tx, password=self._wallet.password)
                    coro2 = self._wallet.wallet.lnworker.swap_manager.wait_for_htlcs_and_broadcast(transport, swap=self._swap, invoice=invoice, tx=tx)
                    self._fut_htlc_wait = fut = asyncio.run_coroutine_threadsafe(coro2, loop)

                    self.canCancel = True
                    txid = fut.result()
                    try:  # swaphelper might be destroyed at this point
                        if txid:
                            self.userinfo = ' '.join([
                                _('Success!'),
                                messages.MSG_FORWARD_SWAP_FUNDING_MEMPOOL,
                            ])
                            self.state = QESwapHelper.State.Success
                        else:
                            self.userinfo = _('Swap failed!')
                            self.state = QESwapHelper.State.Failed
                    except RuntimeError:
                        pass
                except concurrent.futures.CancelledError:
                    self._wallet.wallet.lnworker.swap_manager.cancel_normal_swap(self._swap)
                    self.userinfo = _('Swap cancelled')
                    self.state = QESwapHelper.State.Cancelled
                except Exception as e:
                    try:  # swaphelper might be destroyed at this point
                        self.state = QESwapHelper.State.Failed
                        self.userinfo = _('Error') + ': ' + str(e)
                        self._logger.error(str(e))
                    except RuntimeError:
                        pass
                finally:
                    try:  # swaphelper might be destroyed at this point
                        self.canCancel = False
                        self._swap = None
                        self._fut_htlc_wait = None
                    except RuntimeError:
                        pass

        threading.Thread(target=swap_task, daemon=True).start()

    def _create_tx(self, onchain_amount: Union[int, str, None]) -> PartialTransaction:
        # TODO: func taken from qt GUI, this should be common code
        assert not self.isReverse
        if onchain_amount is None:
            raise InvalidSwapParameters("onchain_amount is None")
        # coins = self.window.get_coins()
        coins = self._wallet.wallet.get_spendable_coins()
        if onchain_amount == '!':
            max_amount = sum(c.value_sats() for c in coins)
            max_swap_amount = self._wallet.wallet.lnworker.swap_manager.max_amount_forward_swap()
            if max_swap_amount is None:
                raise InvalidSwapParameters("swap_manager.max_amount_forward_swap() is None")
            if max_amount > max_swap_amount:
                onchain_amount = max_swap_amount
        outputs = [PartialTxOutput.from_address_and_value(DummyAddress.SWAP, onchain_amount)]
        try:
            tx = self._wallet.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs,
                send_change_to_lightning=False,
            )
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            raise InvalidSwapParameters(str(e)) from e
        return tx

    def do_reverse_swap(self, lightning_amount, onchain_amount):
        if lightning_amount is None or onchain_amount is None:
            return

        def swap_task():
            swap_manager = self._wallet.wallet.lnworker.swap_manager
            loop = get_asyncio_loop()
            with self._wallet.wallet.lnworker.swap_manager.create_transport() as transport:
                coro = swap_manager.reverse_swap(
                    transport,
                    lightning_amount_sat=lightning_amount,
                    expected_onchain_amount_sat=onchain_amount + swap_manager.get_claim_fee(),
                )
                try:
                    time.sleep(1)  # FIXME: this is needed because transport hasn't finished initializing yet.
                    fut = asyncio.run_coroutine_threadsafe(coro, loop)
                    self.userinfo = _('Performing swap...')
                    self.state = QESwapHelper.State.Started
                    txid = fut.result()
                    try:  # swaphelper might be destroyed at this point
                        if txid:
                            self.userinfo = ' '.join([
                                _('Success!'),
                                messages.MSG_REVERSE_SWAP_FUNDING_MEMPOOL,
                            ])
                            self.state = QESwapHelper.State.Success
                        else:
                            self.userinfo = _('Swap failed!')
                            self.state = QESwapHelper.State.Failed
                    except RuntimeError:
                        pass
                except Exception as e:
                    try:  # swaphelper might be destroyed at this point
                        self.state = QESwapHelper.State.Failed
                        msg = _('Timeout') if isinstance(e, TimeoutError) else str(e)
                        self.userinfo = _('Error') + ': ' + msg
                        self._logger.error(str(e))
                    except RuntimeError:
                        pass

        threading.Thread(target=swap_task, daemon=True).start()

    @pyqtSlot()
    def executeSwap(self):
        if not self._wallet.wallet.network:
            self.error.emit(_("You are offline."))
            return
        self._do_execute_swap()

    @auth_protect(message=_('Confirm Lightning swap?'))
    def _do_execute_swap(self):
        if self.isReverse:
            lightning_amount = self._send_amount
            onchain_amount = self._receive_amount
            self.do_reverse_swap(lightning_amount, onchain_amount)
        else:
            lightning_amount = self._receive_amount
            onchain_amount = self._send_amount
            self.do_normal_swap(lightning_amount, onchain_amount)

    @pyqtSlot()
    def cancelNormalSwap(self):
        assert self._swap
        self.canCancel = False
        self._fut_htlc_wait.cancel()
