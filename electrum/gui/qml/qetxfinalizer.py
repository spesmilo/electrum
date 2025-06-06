import copy
from enum import IntEnum
import threading
from decimal import Decimal
from typing import Optional, TYPE_CHECKING
from functools import partial

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, pyqtEnum

from electrum.logging import get_logger
from electrum.i18n import _
from electrum.bitcoin import DummyAddress
from electrum.transaction import PartialTxOutput, PartialTransaction, Transaction, TxOutpoint
from electrum.util import NotEnoughFunds, profiler, quantize_feerate, UserFacingException
from electrum.wallet import CannotBumpFee, CannotDoubleSpendTx, CannotCPFP, BumpFeeStrategy, sweep_preparations
from electrum import keystore
from electrum.plugin import run_hook
from electrum.fee_policy import FeePolicy, FeeMethod

from .qewallet import QEWallet
from .qetypes import QEAmount
from .util import QtEventListener, event_listener

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


class FeeSlider(QObject):

    @pyqtEnum
    class FSMethod(IntEnum):
        FEERATE = 0
        ETA = 1
        MEMPOOL = 2

        def to_fee_method(self) -> 'FeeMethod':
            return {
                self.FEERATE: FeeMethod.FEERATE,
                self.ETA: FeeMethod.ETA,
                self.MEMPOOL: FeeMethod.MEMPOOL,
            }[self]

        @classmethod
        def from_fee_method(cls, fm: FeeMethod) -> 'FeeSlider.FSMethod':
            return {
                FeeMethod.FEERATE: cls.FEERATE,
                FeeMethod.ETA: cls.ETA,
                FeeMethod.MEMPOOL: cls.MEMPOOL,
            }[fm]

    def __init__(self, parent=None):
        super().__init__(parent)

        self._wallet = None  # type: Optional[QEWallet]
        self._sliderSteps = 0
        self._sliderPos = 0
        self._fee_policy = None
        self._target = ''
        self._config = None  # type: Optional[SimpleConfig]

    walletChanged = pyqtSignal()
    @pyqtProperty(QEWallet, notify=walletChanged)
    def wallet(self):
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        if self._wallet != wallet:
            self._wallet = wallet
            self._config = self._wallet.wallet.config
            self.read_config()
            self.walletChanged.emit()

    sliderStepsChanged = pyqtSignal()
    @pyqtProperty(int, notify=sliderStepsChanged)
    def sliderSteps(self):
        return self._sliderSteps

    sliderPosChanged = pyqtSignal()
    @pyqtProperty(int, notify=sliderPosChanged)
    def sliderPos(self):
        return self._sliderPos

    @sliderPos.setter
    def sliderPos(self, sliderPos):
        if self._sliderPos != sliderPos:
            self._sliderPos = sliderPos
            self.save_config()
            self.sliderPosChanged.emit()

    methodChanged = pyqtSignal()
    @pyqtProperty(int, notify=methodChanged)
    def method(self) -> int:
        fsmethod = self.FSMethod.from_fee_method(self._fee_policy.method)
        return int(fsmethod)

    @method.setter
    def method(self, method: int):
        fsmethod = self.FSMethod(method)
        method = fsmethod.to_fee_method()
        if self._fee_policy.method != method:
            self._fee_policy.set_method(method)
            self.update_slider()
            self.methodChanged.emit()
            self.save_config()

    targetChanged = pyqtSignal()
    @pyqtProperty(str, notify=targetChanged)
    def target(self):
        return self._target

    @target.setter
    def target(self, target):
        if self._target != target:
            self._target = target
            self.targetChanged.emit()

    def update_slider(self):
        self._sliderSteps = self._fee_policy.get_slider_max()
        self._sliderPos = self._fee_policy.get_slider_pos()
        self.sliderStepsChanged.emit()
        self.sliderPosChanged.emit()

    def update_target(self):
        self.target = self._fee_policy.get_target_text()

    def read_config(self):
        self._fee_policy = FeePolicy(self._config.FEE_POLICY)
        self.update_slider()
        self.methodChanged.emit()
        self.update_target()
        self.update()

    def save_config(self):
        value = int(self._sliderPos)
        self._fee_policy.set_value_from_slider_pos(value)
        self._config.FEE_POLICY = self._fee_policy.get_descriptor()
        self.update_target()
        self.update()

    def update(self):
        raise NotImplementedError()


class TxFeeSlider(FeeSlider):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._fee = QEAmount()
        self._feeRate = ''
        self._rbf = False
        self._tx = None
        self._inputs = []
        self._outputs = []
        self._finalized_txid = ''
        self._valid = False
        self._warning = ''

    feeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=feeChanged)
    def fee(self):
        return self._fee

    @fee.setter
    def fee(self, fee):
        if self._fee != fee:
            self._fee.copyFrom(fee)
            self.feeChanged.emit()

    feeRateChanged = pyqtSignal()
    @pyqtProperty(str, notify=feeRateChanged)
    def feeRate(self):
        return self._feeRate

    @feeRate.setter
    def feeRate(self, feeRate):
        if self._feeRate != feeRate:
            self._feeRate = feeRate
            self.feeRateChanged.emit()

    rbfChanged = pyqtSignal()
    @pyqtProperty(bool, notify=rbfChanged)
    def rbf(self):
        return self._rbf

    @rbf.setter
    def rbf(self, rbf):
        if self._rbf != rbf:
            self._rbf = rbf
            self.update()
            self.rbfChanged.emit()

    inputsChanged = pyqtSignal()
    @pyqtProperty('QVariantList', notify=inputsChanged)
    def inputs(self):
        return self._inputs

    @inputs.setter
    def inputs(self, inputs):
        if self._inputs != inputs:
            self._inputs = inputs
            self.inputsChanged.emit()

    outputsChanged = pyqtSignal()
    @pyqtProperty('QVariantList', notify=outputsChanged)
    def outputs(self):
        return self._outputs

    @outputs.setter
    def outputs(self, outputs):
        if self._outputs != outputs:
            self._outputs = outputs
            self.outputsChanged.emit()

    finalizedTxidChanged = pyqtSignal()
    @pyqtProperty(str, notify=finalizedTxidChanged)
    def finalizedTxid(self):
        return self._finalized_txid

    @finalizedTxid.setter
    def finalizedTxid(self, finalized_txid):
        if self._finalized_txid != finalized_txid:
            self._finalized_txid = finalized_txid
            self.finalizedTxidChanged.emit()

    warningChanged = pyqtSignal()
    @pyqtProperty(str, notify=warningChanged)
    def warning(self):
        return self._warning

    @warning.setter
    def warning(self, warning):
        if self._warning != warning:
            self._warning = warning
            self.warningChanged.emit()

    validChanged = pyqtSignal()
    @pyqtProperty(bool, notify=validChanged)
    def valid(self):
        return self._valid

    @pyqtSlot()
    def doUpdate(self):
        self.update()

    def update_from_tx(self, tx):
        tx_size = tx.estimated_size()
        fee = tx.get_fee()
        feerate = Decimal(fee) / tx_size  # sat/byte

        self.fee = QEAmount(amount_sat=int(fee))
        self.feeRate = f'{feerate:.1f}'
        self.finalizedTxid = tx.txid()

        self.update_inputs_from_tx(tx)
        self.update_outputs_from_tx(tx)

    def update_inputs_from_tx(self, tx):
        inputs = []
        for inp in tx.inputs():
            # addr = self.wallet.adb.get_txin_address(txin)
            addr = inp.address
            address_str = '<address unknown>' if addr is None else addr

            txin_value = inp.value_sats() if inp.value_sats() else 0

            inputs.append({
                'address': address_str,
                'short_id': str(inp.short_id),
                'value': QEAmount(amount_sat=txin_value),
                'is_coinbase': inp.is_coinbase_input(),
                'is_mine': self._wallet.wallet.is_mine(addr),
                'is_change': self._wallet.wallet.is_change(addr),
                'prevout_txid': inp.prevout.txid.hex(),
                'is_swap': False
            })
        self.inputs = inputs

    def update_outputs_from_tx(self, tx):
        sm = self._wallet.wallet.lnworker.swap_manager if self._wallet.wallet.lnworker else None

        outputs = []
        for idx, o in enumerate(tx.outputs()):
            outputs.append({
                'address': o.get_ui_address_str(),
                'value': o.value,
                'short_id': str(TxOutpoint(bytes.fromhex(tx.txid()), idx).short_name()) if tx.txid() else '',
                'is_mine': self._wallet.wallet.is_mine(o.get_ui_address_str()),
                'is_change': self._wallet.wallet.is_change(o.get_ui_address_str()),
                'is_billing': self._wallet.wallet.is_billing_address(o.get_ui_address_str()),
                'is_swap': False if not sm else sm.is_lockup_address_for_a_swap(o.get_ui_address_str()) or o.get_ui_address_str() == DummyAddress.SWAP,
                'is_accounting': self._wallet.wallet.is_accounting_address(o.get_ui_address_str()),
                'is_reserve': o.is_utxo_reserve
            })
        self.outputs = outputs

    def update_fee_warning_from_tx(self, *, tx: PartialTransaction, invoice_amt: Optional[int]):
        if invoice_amt is None:
            invoice_amt = sum([txo.value for txo in tx.outputs() if not txo.is_mine])
            if invoice_amt == 0:
                invoice_amt = tx.output_value()
        fee_warning_tuple = self._wallet.wallet.get_tx_fee_warning(
            invoice_amt=invoice_amt, tx_size=tx.estimated_size(), fee=tx.get_fee(), txid=tx.txid())
        if fee_warning_tuple:
            allow_send, long_warning, short_warning = fee_warning_tuple
            self.warning = _('Warning') + ': ' + long_warning
        else:
            self.warning = ''


class QETxFinalizer(TxFeeSlider):
    _logger = get_logger(__name__)

    finished = pyqtSignal([bool, bool, bool], arguments=['signed', 'saved', 'complete'])
    signError = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None, *, make_tx=None, accept=None):
        super().__init__(parent)
        self.f_make_tx = make_tx
        self.f_accept = accept

        self._address = ''
        self._amount = QEAmount()
        self._effectiveAmount = QEAmount()
        self._extraFee = QEAmount()
        self._canRbf = False

    addressChanged = pyqtSignal()
    @pyqtProperty(str, notify=addressChanged)
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        if self._address != address:
            self._address = address
            self.addressChanged.emit()

    amountChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=amountChanged)
    def amount(self):
        return self._amount

    @amount.setter
    def amount(self, amount):
        if self._amount != amount:
            self._logger.debug(str(amount))
            self._amount.copyFrom(amount)
            self.amountChanged.emit()

    effectiveAmountChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=effectiveAmountChanged)
    def effectiveAmount(self):
        return self._effectiveAmount

    extraFeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=extraFeeChanged)
    def extraFee(self):
        return self._extraFee

    @extraFee.setter
    def extraFee(self, extrafee):
        if self._extraFee != extrafee:
            self._extraFee.copyFrom(extrafee)
            self.extraFeeChanged.emit()

    canRbfChanged = pyqtSignal()
    @pyqtProperty(bool, notify=canRbfChanged)
    def canRbf(self):
        return self._canRbf

    @canRbf.setter
    def canRbf(self, canRbf):
        if self._canRbf != canRbf:
            self._canRbf = canRbf
            self.canRbfChanged.emit()
        self.rbf = self._canRbf  # if we can RbF, we do RbF

    @profiler
    def make_tx(self, amount):
        self._logger.debug(f'make_tx amount={amount}')

        if self.f_make_tx:
            tx = self.f_make_tx(amount, self._fee_policy)
        else:
            # default impl
            coins = self._wallet.wallet.get_spendable_coins(None)
            outputs = [PartialTxOutput.from_address_and_value(self.address, amount)]
            tx = self._wallet.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs,
                fee_policy=self._fee_policy,
                rbf=self._rbf)

        self._logger.debug('fee: %d, inputs: %d, outputs: %d' % (tx.get_fee(), len(tx.inputs()), len(tx.outputs())))

        return tx

    def update(self):
        if not self._wallet:
            self._logger.debug('wallet not set, ignoring update()')
            return

        try:
            # make unsigned transaction
            amount = '!' if self._amount.isMax else self._amount.satsInt
            tx = self.make_tx(amount=amount)
        except NotEnoughFunds:
            self.warning = self._wallet.wallet.get_text_not_enough_funds_mentioning_frozen(for_amount=amount)
            self._valid = False
            self.validChanged.emit()
            return
        except Exception as e:
            self._logger.error(str(e))
            self.warning = repr(e)
            self._valid = False
            self.validChanged.emit()
            return

        self._tx = tx

        amount = self._amount.satsInt if not self._amount.isMax else tx.output_value()

        self._effectiveAmount.satsInt = amount
        self.effectiveAmountChanged.emit()

        self.update_from_tx(tx)

        x_fee = run_hook('get_tx_extra_fee', self._wallet.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            self.extraFee = QEAmount(amount_sat=x_fee_amount)

        self.update_fee_warning_from_tx(tx=tx, invoice_amt=amount)

        if self._amount.isMax and not self.warning:
            if reserve_sats := sum(txo.value for txo in tx.outputs() if txo.is_utxo_reserve):
                reserve_str = self._config.format_amount_and_units(reserve_sats)
                self.warning = ' '.join([
                    _('Warning') + ':',
                    _('Could not spend max: a security reserve of {} was kept for your Lightning channels.')
                    .format(reserve_str)
                ])

        self._valid = True
        self.validChanged.emit()

    @pyqtSlot()
    def saveOrShow(self):
        if not self._valid or not self._tx:
            self._logger.debug('no valid tx')
            return

        saved = False
        if self._tx.txid():
            if self._wallet.save_tx(self._tx):
                saved = True

        self.finished.emit(False, saved, self._tx.is_complete())

    @pyqtSlot()
    def signAndSend(self):
        if not self._valid or not self._tx:
            self._logger.debug('no valid tx')
            return

        if self.f_accept:
            self.f_accept(self._tx)
            return

        self._wallet.sign_and_broadcast(self._tx, on_success=partial(self.on_signed_tx, False), on_failure=self.on_sign_failed)

    @pyqtSlot()
    def sign(self):
        if not self._valid or not self._tx:
            self._logger.error('no valid tx')
            return

        self._wallet.sign(self._tx, on_success=partial(self.on_signed_tx, True), on_failure=self.on_sign_failed)

    def on_signed_tx(self, save: bool, tx: Transaction):
        self._logger.debug('on_signed_tx')
        saved = False
        if save and self._tx.txid():
            if self._wallet.save_tx(self._tx):
                saved = True
            else:
                self._logger.error('Could not save tx')
        self.finished.emit(True, saved, tx.is_complete())

    def on_sign_failed(self, msg: str = None):
        self._logger.debug('on_sign_failed')
        self.signError.emit(msg)

    @pyqtSlot(result='QVariantList')
    def getSerializedTx(self):
        txqr = self._tx.to_qr_data()
        label = self._wallet.wallet.get_label_for_txid(self._tx.txid())
        return [str(self._tx), txqr[0], txqr[1], label]


class TxMonMixin(QtEventListener):
    """ mixin for watching an existing TX based on its txid for verified or removed event.
        requires self._wallet to contain a QEWallet instance.
        exposes txid qt property.
        calls get_tx() once txid is set.
        calls tx_verified() and emits txMined signal once tx is verified.
        emits txRemoved signal if tx is removed (e.g. replace-by-fee)
    """
    txMined = pyqtSignal()
    txRemoved = pyqtSignal()

    def __init__(self, parent=None):
        self._logger.debug('TxMonMixin.__init__')

        self._txid = ''

        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    def on_destroy(self):
        self.unregister_callbacks()

    @event_listener
    def on_event_verified(self, wallet, txid, info):
        if wallet == self._wallet.wallet and txid == self._txid:
            self._logger.debug('verified event for our txid %s' % txid)
            self.tx_verified()
            self.txMined.emit()

    @event_listener
    def on_event_removed_transaction(self, wallet, tx):
        if wallet == self._wallet.wallet and tx.txid() == self._txid:
            self._logger.debug('remove tx for our txid %s' % self._txid)
            self.tx_removed()
            self.txRemoved.emit()

    txidChanged = pyqtSignal()
    @pyqtProperty(str, notify=txidChanged)
    def txid(self):
        return self._txid

    @txid.setter
    def txid(self, txid):
        if self._txid != txid:
            self._txid = txid
            self.get_tx()
            self.txidChanged.emit()

    # override
    def get_tx(self) -> None:
        pass

    # override
    def tx_verified(self) -> None:
        pass

    # override
    def tx_removed(self) -> None:
        pass


class QETxRbfFeeBumper(TxFeeSlider, TxMonMixin):
    _logger = get_logger(__name__)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._oldfee = QEAmount()
        self._oldfee_rate = 0
        self._orig_tx = None
        self._rbf = True
        self._bump_method = BumpFeeStrategy.PRESERVE_PAYMENT.name
        self._bump_methods_available = []

    oldfeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=oldfeeChanged)
    def oldfee(self):
        return self._oldfee

    @oldfee.setter
    def oldfee(self, oldfee):
        if self._oldfee != oldfee:
            self._oldfee.copyFrom(oldfee)
            self.oldfeeChanged.emit()

    oldfeeRateChanged = pyqtSignal()
    @pyqtProperty(str, notify=oldfeeRateChanged)
    def oldfeeRate(self):
        return self._oldfee_rate

    @oldfeeRate.setter
    def oldfeeRate(self, oldfeerate):
        if self._oldfee_rate != oldfeerate:
            self._oldfee_rate = oldfeerate
            self.oldfeeRateChanged.emit()

    bumpMethodChanged = pyqtSignal()
    @pyqtProperty(str, notify=bumpMethodChanged)
    def bumpMethod(self):
        return self._bump_method

    @bumpMethod.setter
    def bumpMethod(self, bumpmethod: str) -> None:
        if self._bump_method != bumpmethod:
            self._bump_method = bumpmethod
            self.bumpMethodChanged.emit()
            self.update()

    bumpMethodsAvailableChanged = pyqtSignal()
    @pyqtProperty('QVariantList', notify=bumpMethodsAvailableChanged)
    def bumpMethodsAvailable(self):
        return self._bump_methods_available

    def get_tx(self):
        assert self._txid
        self._orig_tx = self._wallet.wallet.db.get_transaction(self._txid)
        assert self._orig_tx

        strategies, def_strat_idx = self._wallet.wallet.get_bumpfee_strategies_for_tx(tx=self._orig_tx)
        self._bump_methods_available = [{'value': strat.name, 'text': strat.text()} for strat in strategies]
        self.bumpMethodsAvailableChanged.emit()
        self.bumpMethod = strategies[def_strat_idx].name

        if not isinstance(self._orig_tx, PartialTransaction):
            self._orig_tx = PartialTransaction.from_tx(self._orig_tx)

        if not self._orig_tx.add_info_from_wallet_and_network(wallet=self._wallet.wallet, show_error=self._logger.error):
            return

        self.update_from_tx(self._orig_tx)

        self.oldfee = self.fee
        self.oldfeeRate = self.feeRate
        self.update()

    def tx_verified(self):
        self._valid = False
        self.validChanged.emit()
        self.warning = _('Base transaction has been mined')

    def tx_removed(self):
        self._valid = False
        self.validChanged.emit()
        self.warning = _('Base transaction disappeared')

    def update(self):
        if not self._txid or not self._orig_tx:
            # not initialized yet
            return

        fee_per_kb = self._fee_policy.fee_per_kb(self._wallet.wallet.network)
        if fee_per_kb is None:
            # dynamic method and no network
            self._logger.debug('no fee_per_kb')
            self.warning = _('Cannot determine dynamic fees, not connected')
            return

        new_fee_rate = fee_per_kb / 1000
        if new_fee_rate <= float(self._oldfee_rate):
            self._valid = False
            self.validChanged.emit()
            self.warning = _("The new fee rate needs to be higher than the old fee rate.")
            return
        try:
            self._tx = self._wallet.wallet.bump_fee(
                tx=self._orig_tx,
                new_fee_rate=new_fee_rate,
                strategy=BumpFeeStrategy[self._bump_method],
            )
        except CannotBumpFee as e:
            self._valid = False
            self.validChanged.emit()
            self._logger.error(str(e))
            self.warning = str(e)
            return
        else:
            self.warning = ''

        self._tx.set_rbf(self.rbf)

        self.update_from_tx(self._tx)
        self.update_fee_warning_from_tx(tx=self._tx, invoice_amt=None)

        self._valid = True
        self.validChanged.emit()

    @pyqtSlot(result=str)
    def getNewTx(self):
        return str(self._tx)


class QETxCanceller(TxFeeSlider, TxMonMixin):
    _logger = get_logger(__name__)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._oldfee = QEAmount()
        self._oldfee_rate = 0
        self._orig_tx = None
        self._txid = ''
        self._rbf = True

    oldfeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=oldfeeChanged)
    def oldfee(self):
        return self._oldfee

    @oldfee.setter
    def oldfee(self, oldfee):
        if self._oldfee != oldfee:
            self._oldfee.copyFrom(oldfee)
            self.oldfeeChanged.emit()

    oldfeeRateChanged = pyqtSignal()
    @pyqtProperty(str, notify=oldfeeRateChanged)
    def oldfeeRate(self):
        return self._oldfee_rate

    @oldfeeRate.setter
    def oldfeeRate(self, oldfeerate):
        if self._oldfee_rate != oldfeerate:
            self._oldfee_rate = oldfeerate
            self.oldfeeRateChanged.emit()

    def get_tx(self):
        assert self._txid
        self._orig_tx = self._wallet.wallet.db.get_transaction(self._txid)
        assert self._orig_tx

        if not isinstance(self._orig_tx, PartialTransaction):
            self._orig_tx = PartialTransaction.from_tx(self._orig_tx)

        if not self._orig_tx.add_info_from_wallet_and_network(wallet=self._wallet.wallet, show_error=self._logger.error):
            return

        self.update_from_tx(self._orig_tx)

        self.oldfee = self.fee
        self.oldfeeRate = self.feeRate
        self.update()

    def tx_verified(self):
        self._valid = False
        self.validChanged.emit()
        self.warning = _('Base transaction has been mined')

    def tx_removed(self):
        self._valid = False
        self.validChanged.emit()
        self.warning = _('Base transaction disappeared')

    def update(self):
        if not self._txid or not self._orig_tx:
            # not initialized yet
            return

        fee_per_kb = self._fee_policy.fee_per_kb(self._wallet.wallet.network)
        if fee_per_kb is None:
            # dynamic method and no network
            self._logger.debug('no fee_per_kb')
            self.warning = _('Cannot determine dynamic fees, not connected')
            return

        new_fee_rate = fee_per_kb / 1000
        if new_fee_rate <= float(self._oldfee_rate):
            self._valid = False
            self.validChanged.emit()
            self.warning = _("The new fee rate needs to be higher than the old fee rate.")
            return

        try:
            self._tx = self._wallet.wallet.dscancel(
                tx=self._orig_tx,
                new_fee_rate=new_fee_rate,
            )
        except CannotDoubleSpendTx as e:
            self._valid = False
            self.validChanged.emit()
            self._logger.error(str(e))
            self.warning = str(e)
            return
        else:
            self.warning = ''

        self._tx.set_rbf(self.rbf)

        self.update_from_tx(self._tx)
        self.update_fee_warning_from_tx(tx=self._tx, invoice_amt=None)

        self._valid = True
        self.validChanged.emit()

    @pyqtSlot(result=str)
    def getNewTx(self):
        return str(self._tx)


class QETxCpfpFeeBumper(TxFeeSlider, TxMonMixin):
    _logger = get_logger(__name__)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._input_amount = QEAmount()
        self._output_amount = QEAmount()
        self._total_fee = QEAmount()
        self._total_fee_rate = 0
        self._total_size = 0

        self._parent_tx = None
        self._new_tx = None
        self._parent_tx_size = 0
        self._parent_fee = 0
        self._max_fee = 0
        self._txid = ''
        self._rbf = True

    totalFeeChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=totalFeeChanged)
    def totalFee(self):
        return self._total_fee

    @totalFee.setter
    def totalFee(self, totalfee):
        if self._total_fee != totalfee:
            self._total_fee.copyFrom(totalfee)
            self.totalFeeChanged.emit()

    totalFeeRateChanged = pyqtSignal()
    @pyqtProperty(str, notify=totalFeeRateChanged)
    def totalFeeRate(self):
        return self._total_fee_rate

    @totalFeeRate.setter
    def totalFeeRate(self, totalfeerate):
        if self._total_fee_rate != totalfeerate:
            self._total_fee_rate = totalfeerate
            self.totalFeeRateChanged.emit()

    inputAmountChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=inputAmountChanged)
    def inputAmount(self):
        return self._input_amount

    outputAmountChanged = pyqtSignal()
    @pyqtProperty(QEAmount, notify=outputAmountChanged)
    def outputAmount(self):
        return self._output_amount

    totalSizeChanged = pyqtSignal()
    @pyqtProperty(int, notify=totalSizeChanged)
    def totalSize(self):
        return self._total_size

    def get_tx(self):
        assert self._txid
        self._parent_tx = self._wallet.wallet.db.get_transaction(self._txid)
        assert self._parent_tx

        if isinstance(self._parent_tx, PartialTransaction):
            self._logger.error('unexpected PartialTransaction')
            return

        self._parent_tx_size = self._parent_tx.estimated_size()
        self._parent_fee = self._wallet.wallet.get_tx_info(self._parent_tx).fee

        if self._parent_fee is None:
            self._logger.error(_("Can't CPFP: unknown fee for parent transaction."))
            self.warning = _("Can't CPFP: unknown fee for parent transaction.")
            return

        self._new_tx = self._wallet.wallet.cpfp(self._parent_tx, 0)
        self._total_size = self._parent_tx_size + self._new_tx.estimated_size()
        self.totalSizeChanged.emit()
        self._max_fee = self._new_tx.output_value()
        self._input_amount.satsInt = self._max_fee

        self.update()

    def get_child_fee_from_total_feerate(self, fee_per_kb: Optional[int]) -> Optional[int]:
        if fee_per_kb is None:
            return None
        fee = fee_per_kb * self._total_size / 1000 - self._parent_fee
        fee = round(fee)
        fee = min(self._max_fee, fee)
        fee = max(self._total_size, fee)  # pay at least 1 sat/byte for combined size
        return fee

    def tx_verified(self):
        self._valid = False
        self.validChanged.emit()
        self.warning = _('Base transaction has been mined')

    def tx_removed(self):
        self._valid = False
        self.validChanged.emit()
        self.warning = _('Base transaction disappeared')

    def update(self):
        if not self._txid:  # not initialized yet
            return

        assert self._parent_tx

        self._valid = False
        self.validChanged.emit()
        self.warning = ''

        fee_per_kb = self._fee_policy.fee_per_kb(self._wallet.wallet.network)
        if fee_per_kb is None:
            # dynamic method and no network
            self._logger.debug('no fee_per_kb')
            self.warning = _('Cannot determine dynamic fees, not connected')
            return

        if self._parent_fee is None:
            self._logger.error(_("Can't CPFP: unknown fee for parent transaction."))
            self.warning = _("Can't CPFP: unknown fee for parent transaction.")
            return

        fee = self.get_child_fee_from_total_feerate(fee_per_kb=fee_per_kb)

        if fee is None:
            self._logger.warning('no fee')
            self.warning = _('No fee')
            return
        if fee > self._max_fee:
            self._logger.warning('max fee exceeded')
            self.warning = _('Max fee exceeded')
            return

        comb_fee = fee + self._parent_fee
        comb_feerate = comb_fee / self._total_size

        self._fee.satsInt = fee
        self._output_amount.satsInt = self._max_fee - fee
        self.outputAmountChanged.emit()

        self._total_fee.satsInt = fee + self._parent_fee
        self._total_fee_rate = str(quantize_feerate(comb_feerate))

        try:
            self._new_tx = self._wallet.wallet.cpfp(self._parent_tx, fee)
        except CannotCPFP as e:
            self._logger.error(str(e))
            self.warning = str(e)
            return

        child_feerate = fee / self._new_tx.estimated_size()
        self.feeRate = str(quantize_feerate(child_feerate))

        self.update_inputs_from_tx(self._new_tx)
        self.update_outputs_from_tx(self._new_tx)

        self._valid = True
        self.validChanged.emit()

    @pyqtSlot(result=str)
    def getNewTx(self):
        return str(self._new_tx)


class QETxSweepFinalizer(QETxFinalizer):
    _logger = get_logger(__name__)

    txinsRetrieved = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._private_keys = ''
        self._txins = None
        self._amount = QEAmount(is_max=True)

        self.txinsRetrieved.connect(self.update)

    privateKeysChanged = pyqtSignal()
    @pyqtProperty(str, notify=privateKeysChanged)
    def privateKeys(self):
        return self._private_keys

    @privateKeys.setter
    def privateKeys(self, private_keys):
        if self._private_keys != private_keys:
            self._private_keys = private_keys
            self.update_privkeys()
            self.privateKeysChanged.emit()

    def make_sweep_tx(self):
        address = self._wallet.wallet.get_receiving_address()
        assert self._wallet.wallet.is_mine(address)

        coins, keypairs = copy.deepcopy(self._txins)
        outputs = [PartialTxOutput.from_address_and_value(address, value='!')]

        tx = self._wallet.wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=None, rbf=self._rbf, is_sweep=True)
        self._logger.debug('fee: %d, inputs: %d, outputs: %d' % (tx.get_fee(), len(tx.inputs()), len(tx.outputs())))

        tx.sign(keypairs)
        return tx

    def update_privkeys(self):
        privkeys = keystore.get_private_keys(self._private_keys)

        def fetch_privkeys_info():
            try:
                self._txins = self._wallet.wallet.network.run_from_another_thread(sweep_preparations(privkeys, self._wallet.wallet.network))
                self._logger.debug(f'txins {self._txins!r}')
            except UserFacingException as e:
                self.warning = str(e)
                return
            self.txinsRetrieved.emit()

        threading.Thread(target=fetch_privkeys_info, daemon=True).start()

    def update(self):
        if not self._wallet:
            self._logger.debug('wallet not set, ignoring update()')
            return
        if not self._private_keys:
            self._logger.debug('private keys not set, ignoring update()')
            return

        try:
            # make unsigned transaction
            tx = self.make_sweep_tx()
        except Exception as e:
            self._logger.error(str(e))
            self.warning = repr(e)
            self._valid = False
            self.validChanged.emit()
            return

        self._tx = tx

        amount = tx.output_value()

        self._effectiveAmount.satsInt = amount
        self.effectiveAmountChanged.emit()

        self.update_from_tx(tx)
        self.update_fee_warning_from_tx(tx=self._tx, invoice_amt=amount)

        self._valid = True
        self.validChanged.emit()

        self.on_signed_tx(False, tx)

    @pyqtSlot()
    def send(self):
        self._wallet.broadcast(self._tx)
        self._wallet.wallet.set_label(self._tx.txid(), _('Sweep transaction'))
