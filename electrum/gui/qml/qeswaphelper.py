import asyncio
from typing import TYPE_CHECKING, Optional, Union

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.lnutil import ln_dummy_address
from electrum.transaction import PartialTxOutput
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, profiler

from .qewallet import QEWallet
from .qetypes import QEAmount
from .auth import AuthMixin, auth_protect

class QESwapHelper(AuthMixin, QObject):
    _logger = get_logger(__name__)

    _wallet = None
    _sliderPos = 0
    _rangeMin = 0
    _rangeMax = 0
    _tx = None
    _valid = False
    _userinfo = ''
    _tosend = QEAmount()
    _toreceive = QEAmount()
    _serverfeeperc = ''
    _serverfee = QEAmount()
    _miningfee = QEAmount()
    _isReverse = False

    _send_amount = 0
    _receive_amount = 0

    error = pyqtSignal([str], arguments=['message'])
    confirm = pyqtSignal([str], arguments=['message'])

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

    validChanged = pyqtSignal()
    @pyqtProperty(bool, notify=validChanged)
    def valid(self):
        return self._valid

    @valid.setter
    def valid(self, valid):
        if self._valid != valid:
            self._valid = valid
            self.validChanged.emit()

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

    serverfeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=serverfeeChanged)
    def serverfee(self):
        return self._serverfee

    @serverfee.setter
    def serverfee(self, serverfee):
        if self._serverfee != serverfee:
            self._serverfee = serverfee
            self.serverfeeChanged.emit()

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
        swap_manager = lnworker.swap_manager
        asyncio.run(swap_manager.get_pairs())
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
        max_recv_amt_ln = int(swap_manager.num_sats_can_receive())
        max_recv_amt_oc = swap_manager.get_send_amount(max_recv_amt_ln, is_reverse=False) or float('inf')
        forward = int(min(max_recv_amt_oc,
                          # maximally supported swap amount by provider
                          swap_manager.get_max_amount(),
                          max_onchain_spend))
        # we expect range to adjust the value of the swap slider to be in the
        # correct range, i.e., to correct an overflow when reducing the limits
        self._logger.debug(f'Slider range {-reverse} - {forward}')
        self.rangeMin = -reverse
        self.rangeMax = forward

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

    def swap_slider_moved(self):
        position = int(self._sliderPos)

        swap_manager = self._wallet.wallet.lnworker.swap_manager

        # pay_amount and receive_amounts are always with fees already included
        # so they reflect the net balance change after the swap
        if position < 0:  # reverse swap
            self.userinfo = _('Adds Lightning receiving capacity.')
            self.isReverse = True

            pay_amount = abs(position)
            self._send_amount = pay_amount
            self.tosend = QEAmount(amount_sat=pay_amount)

            receive_amount = swap_manager.get_recv_amount(
                send_amount=pay_amount, is_reverse=True)
            self._receive_amount = receive_amount
            self.toreceive = QEAmount(amount_sat=receive_amount)

            # fee breakdown
            self.serverfeeperc = f'{swap_manager.percentage:0.1f}%'
            self.serverfee = QEAmount(amount_sat=swap_manager.lockup_fee)
            self.miningfee = QEAmount(amount_sat=swap_manager.get_claim_fee())

        else:  # forward (normal) swap
            self.userinfo = _('Adds Lightning sending capacity.')
            self.isReverse = False
            self._send_amount = position

            self.update_tx(self._send_amount)
            # add lockup fees, but the swap amount is position
            pay_amount = position + self._tx.get_fee() if self._tx else 0
            self.tosend = QEAmount(amount_sat=pay_amount)

            receive_amount = swap_manager.get_recv_amount(send_amount=position, is_reverse=False)
            self._receive_amount = receive_amount
            self.toreceive = QEAmount(amount_sat=receive_amount)

            # fee breakdown
            self.serverfeeperc = f'{swap_manager.percentage:0.1f}%'
            self.serverfee = QEAmount(amount_sat=swap_manager.normal_fee)
            self.miningfee = QEAmount(amount_sat=self._tx.get_fee()) if self._tx else QEAmount()

        if pay_amount and receive_amount:
            self.valid = True
        else:
            # add more nuanced error reporting?
            self.userinfo = _('Swap below minimal swap size, change the slider.')
            self.valid = False

    def do_normal_swap(self, lightning_amount, onchain_amount, password):
        assert self._tx
        if lightning_amount is None or onchain_amount is None:
            return
        loop = self._wallet.wallet.network.asyncio_loop
        coro = self._wallet.wallet.lnworker.swap_manager.normal_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount,
            password=password,
            tx=self._tx,
        )
        asyncio.run_coroutine_threadsafe(coro, loop)

    def do_reverse_swap(self, lightning_amount, onchain_amount, password):
        if lightning_amount is None or onchain_amount is None:
            return
        swap_manager = self._wallet.wallet.lnworker.swap_manager
        loop = self._wallet.wallet.network.asyncio_loop
        coro = swap_manager.reverse_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount + swap_manager.get_claim_fee(),
        )
        asyncio.run_coroutine_threadsafe(coro, loop)

    @pyqtSlot()
    @pyqtSlot(bool)
    def executeSwap(self, confirm=False):
        if not self._wallet.wallet.network:
            self.error.emit(_("You are offline."))
            return
        if confirm:
            self._do_execute_swap()
            return

        if self.isReverse:
            self.confirm.emit(_('Do you want to do a reverse submarine swap?'))
        else:
            self.confirm.emit(_('Do you want to do a submarine swap? '
                'You will need to wait for the swap transaction to confirm.'
            ))

    @auth_protect
    def _do_execute_swap(self):
        if self.isReverse:
            lightning_amount = self._send_amount
            onchain_amount = self._receive_amount
            self.do_reverse_swap(lightning_amount, onchain_amount, None)
        else:
            lightning_amount = self._receive_amount
            onchain_amount = self._send_amount
            self.do_normal_swap(lightning_amount, onchain_amount, None)
