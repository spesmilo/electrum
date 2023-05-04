import asyncio
import threading
import math
from typing import Union

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QTimer, Q_ENUMS

from electrum.i18n import _
from electrum.lnutil import ln_dummy_address
from electrum.logging import get_logger
from electrum.transaction import PartialTxOutput
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, profiler, get_asyncio_loop

from .auth import AuthMixin, auth_protect
from .qetypes import QEAmount
from .qewallet import QEWallet
from .util import QtEventListener, qt_event_listener

class QESwapHelper(AuthMixin, QObject, QtEventListener):
    _logger = get_logger(__name__)

    class State:
        Initialized = 0
        ServiceReady = 1
        Started = 2
        Failed = 3
        Success = 4

    Q_ENUMS(State)

    confirm = pyqtSignal([str], arguments=['message'])
    error = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None
        self._sliderPos = 0
        self._rangeMin = 0
        self._rangeMax = 0
        self._tx = None
        self._valid = False
        self._state = QESwapHelper.State.Initialized
        self._userinfo = ' '.join([
            _('Move the slider to set the amount and direction of the swap.'),
            _('Swapping lightning funds for onchain funds will increase your capacity to receive lightning payments.'),
        ])
        self._tosend = QEAmount()
        self._toreceive = QEAmount()
        self._serverfeeperc = ''
        self._server_miningfee = QEAmount()
        self._miningfee = QEAmount()
        self._isReverse = False

        self._service_available = False
        self._send_amount = 0
        self._receive_amount = 0

        self._leftVoid = 0
        self._rightVoid = 0

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

        self._fwd_swap_updatetx_timer = QTimer(self)
        self._fwd_swap_updatetx_timer.setSingleShot(True)
        # self._fwd_swap_updatetx_timer.setInterval(500)
        self._fwd_swap_updatetx_timer.timeout.connect(self.fwd_swap_updatetx)

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
            self.init_swap_slider_range()
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


    def init_swap_slider_range(self):
        lnworker = self._wallet.wallet.lnworker
        if not lnworker:
            return
        swap_manager = lnworker.swap_manager
        try:
            asyncio.run(swap_manager.get_pairs())
            self.state = QESwapHelper.State.ServiceReady
        except Exception as e:
            self.error.emit(_('Swap service unavailable'))
            self._logger.error(f'could not get pairs for swap: {repr(e)}')
            return

        """Sets the minimal and maximal amount that can be swapped for the swap
        slider."""
        # tx is updated again afterwards with send_amount in case of normal swap
        # this is just to estimate the maximal spendable onchain amount for HTLC
        self.update_tx('!')
        try:
            max_onchain_spend = self._tx.output_value_for_address(ln_dummy_address())
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
        outputs = [PartialTxOutput.from_address_and_value(ln_dummy_address(), onchain_amount)]
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
        if self._state == QESwapHelper.State.Initialized:
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

    def do_normal_swap(self, lightning_amount, onchain_amount, password):
        assert self._tx
        if lightning_amount is None or onchain_amount is None:
            return

        if password is None:
            password = self._wallet.password

        loop = get_asyncio_loop()
        coro = self._wallet.wallet.lnworker.swap_manager.normal_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount,
            password=password,
            tx=self._tx,
        )

        def swap_task():
            try:
                fut = asyncio.run_coroutine_threadsafe(coro, loop)
                self.userinfo = _('Performing swap...')
                self.state = QESwapHelper.State.Started
                txid = fut.result()
                try: # swaphelper might be destroyed at this point
                    self.userinfo = ' '.join([
                        _('Success!'),
                        _('Your funding transaction has been broadcast.'),
                        _('The swap will be finalized once your transaction is confirmed.'),
                        _('You will need to be online to finalize the swap, or the transaction will be refunded to you after some delay.'),
                    ])
                    self.state = QESwapHelper.State.Success
                except RuntimeError:
                    pass
            except Exception as e:
                try: # swaphelper might be destroyed at this point
                    self.state = QESwapHelper.State.Failed
                    self.userinfo = _('Error') + ': ' + str(e)
                    self._logger.error(str(e))
                except RuntimeError:
                    pass

        threading.Thread(target=swap_task, daemon=True).start()

    def do_reverse_swap(self, lightning_amount, onchain_amount):
        if lightning_amount is None or onchain_amount is None:
            return
        swap_manager = self._wallet.wallet.lnworker.swap_manager
        loop = get_asyncio_loop()
        coro = swap_manager.reverse_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount + swap_manager.get_claim_fee(),
        )

        def swap_task():
            try:
                fut = asyncio.run_coroutine_threadsafe(coro, loop)
                self.userinfo = _('Performing swap...')
                self.state = QESwapHelper.State.Started
                success = fut.result()
                try: # swaphelper might be destroyed at this point
                    if success:
                        self.userinfo = ' '.join([
                            _('Success!'),
                            _('The funding transaction has been detected.'),
                            _('Your claiming transaction will be broadcast when the funding transaction is confirmed.'),
                            _('You may choose to broadcast it earlier, although that would not be trustless.'),
                        ])
                        self.state = QESwapHelper.State.Success
                    else:
                        self.userinfo = _('Swap failed!')
                        self.state = QESwapHelper.State.Failed
                except RuntimeError:
                    pass
            except Exception as e:
                try: # swaphelper might be destroyed at this point
                    self.state = QESwapHelper.State.Failed
                    self.userinfo = _('Error') + ': ' + str(e)
                    self._logger.error(str(e))
                except RuntimeError:
                    pass

        threading.Thread(target=swap_task, daemon=True).start()

    @pyqtSlot()
    def executeSwap(self):
        if not self._wallet.wallet.network:
            self.error.emit(_("You are offline."))
            return
        if self.isReverse:
            self._do_execute_reverse_swap()
        else:
            self._do_execute_forward_swap()

    @auth_protect(method='pin', message=_('Confirm Lightning swap?'))
    def _do_execute_reverse_swap(self):
        lightning_amount = self._send_amount
        onchain_amount = self._receive_amount
        self.do_reverse_swap(lightning_amount, onchain_amount)

    @auth_protect(method='keystore_else_pin', message=_('Confirm Lightning swap?'))
    def _do_execute_forward_swap(self, password=None):
        lightning_amount = self._receive_amount
        onchain_amount = self._send_amount
        self.do_normal_swap(lightning_amount, onchain_amount, password)
