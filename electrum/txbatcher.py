import asyncio
import threading
import copy

from typing import Dict, Sequence
from . import util
from .logging import Logger
from .util import log_exceptions
from .transaction import PartialTransaction, PartialTxOutput, Transaction
from .address_synchronizer import TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE
from .lnsweep import SweepInfo
from typing import Optional

# This class batches outgoing payments and incoming utxo sweeps.
# It ensures that we do not send a payment twice.
#
# Explanation of the problem:
# Suppose we are asked to send two payments: first o1, and then o2.
# We replace tx1(o1) (that pays to o1) with tx1'(o1,o2), that pays to o1 and o2.
# tx1 and tx1' use the same inputs, so they cannot both be mined in the same blockchain.
# If tx1 is mined instead of tx1', we now need to pay o2, so we will broadcast a new transaction tx2(o2).
# However, tx1 may be removed from the blockchain, due to a reorg, and a chain with tx1' can become the valid one.
# In that case, we might pay o2 twice: with tx1' and with tx2
#
# The following code prevents that by making tx2 a child of tx1.
# This is denoted by tx2(tx1|o2).
#
# Example:
#
# output 1:     tx1(o1) ---------------
#                                      \
# output 2:     tx1'(o1,o2)-------      ----> tx2(tx1|o2) ------
#                                 \     \                       \
# output 3:     tx1''(o1,o2,o3)    \     ---> tx2'(tx1|o2,o3)    ---->  tx3(tx2|o3)  (if tx2 is mined)
#                                   \
#                                    -------------------------------->  tx3(tx1'|o3) (if tx1' is mined)
#
# In the above example, we have to make 3 payments.
# Suppose we have broadcast tx1, tx1' and tx1''
#  - if tx1 gets mined, we broadcast: tx2'(tx1|o2,o3)
#  - if tx1' gets mined, we broadcast tx3(tx1'|o3)
#
# Note that there are two possible execution paths that may lead to the creation of tx3:
#   - as a child of tx2
#   - as a child of tx1'
#
# A batch is a set of incompatible txs, such as [tx1, tx1', tx1''].
# Note that we do not persist older batches. We only persist the current batch in self.batch_txids.
# Thus, if we need to broadcast tx2 or tx2', then self.batch_txids is reset, and the old batch is forgotten.
#
# If we cannot RBF a transaction (because the server returns an error), then we create a new batch,
# as if the transaction had been mined.
#   if cannot_rbf(tx1)  -> broadcast tx2(tx1,o2). The new base is now tx2(tx,o2)
#   if cannot_rbf(tx1') -> broadcast tx3(tx1'|o3)
#
#
# Notes:
#
# 1. CPFP:
# When a batch is forgotten but not mined (because the server returned an error), we no longer bump its fee.
# However, the current code does not theat the next batch as a CPFP when computing the fee.
#
# 2. Reorgs:
# This code does not guarantee that a payment or a sweep will happen.
# This is fine for sweeps; it is the responsibility of the caller (lnwatcher) to add them again.
# To make payments reorg-safe, we would need to persist more data and redo failed payments.
#
# 3. batch_payments and batch_inputs are not persisted.
# In the case of sweeps, lnwatcher ensures that SweepInfo is added again after a client restart.
# In order to generalize that logic to payments, callers would need to pass a unique ID along with
# the payment output, so that we can prevent paying twice.

from .json_db import locked

class TxBatcher(Logger):

    SLEEP_INTERVAL = 1
    RETRY_DELAY = 60

    def __init__(self, wallet):
        Logger.__init__(self)
        self.wallet = wallet
        self.config = wallet.config
        self.lock = threading.RLock()
        self.batch_payments = []       # list of payments we need to make
        self.batch_inputs = {}         # list of inputs we need to sweep
        # list of tx that were broadcast. Each tx is a RBF replacement of the previous one. Ony one can get mined.
        self._batch_txids = wallet.db.get_stored_item("batch_txids", [])
        self._base_tx = None           # current batch tx. last element of batch_txids

        if self._batch_txids:
            last_txid = self._batch_txids[-1]
            tx = self.wallet.adb.get_transaction(last_txid)
            if tx:
                tx = PartialTransaction.from_tx(tx)
                tx.add_info_from_wallet(self.wallet) # this adds input amounts
                self._base_tx = tx
                self.logger.info(f'found base_tx {last_txid}')

        self._parent_tx = None
        self._unconfirmed_sweeps = set()  # list of inputs we are sweeping (until spending tx is confirmed)

    def is_mine(self, txid):
        return txid in self._batch_txids

    @locked
    def add_batch_payment(self, output: 'PartialTxOutput'):
        # todo: maybe we should raise NotEnoughFunds here
        # currently, the GUI checks that we have enough funds
        self.batch_payments.append(output)

    @locked
    def add_sweep_info(self, sweep_info: 'SweepInfo'):
        txin = sweep_info.txin
        if txin.prevout in self._unconfirmed_sweeps:
            return
        # early return if the spending tx is confirmed
        # if its block is orphaned, the txin will be added again
        prevout = txin.prevout.to_str()
        prev_txid, index = prevout.split(':')
        if spender_txid := self.wallet.adb.db.get_spent_outpoint(prev_txid, int(index)):
            tx_mined_status = self.wallet.adb.get_tx_height(spender_txid)
            if tx_mined_status.height > 0:
                return
        self._unconfirmed_sweeps.add(txin.prevout)
        self.logger.info(f'add_sweep_info: {sweep_info.name} {sweep_info.txin.prevout.to_str()}')
        self.batch_inputs[txin.prevout] = sweep_info
        # transfer knowledge
        if self._base_tx:
            for base_txin in self._base_tx.inputs():
                if base_txin.prevout == txin.prevout:
                    if hasattr(txin, 'make_witness'):
                        base_txin.make_witness = txin.make_witness
                        base_txin.privkey = txin.privkey
                        base_txin.witness_script = txin.witness_script
                        base_txin.script_sig = txin.script_sig

    def get_base_tx(self) -> Optional[Transaction]:
        return self._base_tx

    def _find_confirmed_base_tx(self) -> Optional[Transaction]:
        for txid in self._batch_txids:
            tx_mined_status = self.wallet.adb.get_tx_height(txid)
            if tx_mined_status.conf > 0:
                tx = self.wallet.adb.get_transaction(txid)
                tx = PartialTransaction.from_tx(tx)
                tx.add_info_from_wallet(self.wallet) # needed for txid
                return tx

    @locked
    def _to_pay_after(self, tx) -> Sequence[PartialTxOutput]:
        if not tx:
            return self.batch_payments
        to_pay = []
        outputs = copy.deepcopy(tx.outputs())
        for x in self.batch_payments:
            if x not in outputs:
                to_pay.append(x)
            else:
                outputs.remove(x)
        return to_pay

    @locked
    def _to_sweep_after(self, tx) -> Dict[str, SweepInfo]:
        tx_prevouts = set(txin.prevout for txin in tx.inputs()) if tx else set()
        result = []
        for k,v in self.batch_inputs.items():
            prevout = v.txin.prevout
            prev_txid, index = prevout.to_str().split(':')
            if not self.wallet.adb.db.get_transaction(prev_txid):
                continue
            if spender_txid := self.wallet.adb.db.get_spent_outpoint(prev_txid, int(index)):
                tx_mined_status = self.wallet.adb.get_tx_height(spender_txid)
                if tx_mined_status.height not in [TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE]:
                    continue
            if prevout in tx_prevouts:
                continue
            result.append((k,v))
        return dict(result)

    def _should_bump_fee(self, base_tx) -> bool:
        if base_tx is None:
            return False
        if not self.is_mine(base_tx.txid()):
            return False
        base_tx_fee = base_tx.get_fee()
        recommended_fee = self.config.estimate_fee(base_tx.estimated_size(), allow_fallback_to_static_rates=True)
        should_bump_fee = base_tx_fee * 1.1 < recommended_fee
        if should_bump_fee:
            self.logger.info(f'base tx fee too low {base_tx_fee} < {recommended_fee}. we will bump the fee')
        return should_bump_fee

    @log_exceptions
    async def run(self):
        while True:
            await asyncio.sleep(self.SLEEP_INTERVAL)
            password = self.wallet.get_unlocked_password()
            if self.wallet.has_keystore_encryption() and not password:
                continue
            await self._maybe_broadcast_legacy_htlc_txs()
            tx = self._find_confirmed_base_tx()
            if tx:
                self.logger.info(f'base tx confirmed {tx.txid()}')
                self._clear_unconfirmed_sweeps(tx)
                self._start_new_batch(tx)
            base_tx = self.get_base_tx()
            to_pay = self._to_pay_after(base_tx)
            to_sweep = self._to_sweep_after(base_tx)
            to_sweep_now = {}
            for k, v in to_sweep.items():
                can_broadcast, wanted_height = self._can_broadcast(v, base_tx)
                if can_broadcast:
                    to_sweep_now[k] = v
                else:
                    self.wallet.add_future_tx(v, wanted_height)
            if not to_pay and not to_sweep_now and not self._should_bump_fee(base_tx):
                continue
            try:
                tx = self._create_batch_tx(base_tx, to_sweep_now, to_pay, password)
            except Exception as e:
                self.logger.exception(f'Cannot create batch transaction: {repr(e)}')
                if base_tx:
                    self._start_new_batch(base_tx)
                    continue
                await asyncio.sleep(self.RETRY_DELAY)
                continue
            self.logger.info(f'created tx with {len(tx.inputs())} inputs and {len(tx.outputs())} outputs')
            self.logger.info(f'{str(tx)}')
            if await self.wallet.network.try_broadcasting(tx, 'batch'):
                self.wallet.adb.add_transaction(tx)
                if tx.has_change():
                    self._batch_txids.append(tx.txid())
                    self._base_tx = tx
                else:
                    self.logger.info(f'starting new batch because current base tx does not have change')
                    self.start_new_batch(tx)
            else:
                # most likely reason is that base_tx is not replaceable
                # this may be the case if it has children (because we don't pay enough fees to replace them)
                # or if we are trying to sweep unconfirmed inputs (replacement-adds-unconfirmed error)
                self.logger.info(f'cannot broadcast tx {tx}')
                if base_tx:
                    self.logger.info(f'starting new batch because could not broadcast')
                    self.start_new_batch(base_tx)

    def _create_batch_tx(self, base_tx, to_sweep, to_pay, password):
        self.logger.info(f'to_sweep: {list(to_sweep.keys())}')
        self.logger.info(f'to_pay: {to_pay}')
        inputs = []
        outputs = []
        locktime = base_tx.locktime if base_tx else None
        # sort inputs so that txin-txout pairs are first
        for sweep_info in sorted(to_sweep.values(), key=lambda x: not bool(x.txout)):
            if sweep_info.cltv_abs is not None:
                if locktime is None or locktime < sweep_info.cltv_abs:
                    # nLockTime must be greater than or equal to the stack operand.
                    locktime = sweep_info.cltv_abs
            inputs.append(copy.deepcopy(sweep_info.txin))
            if sweep_info.txout:
                outputs.append(sweep_info.txout)
        self.logger.info(f'locktime: {locktime}')
        outputs += to_pay
        inputs += self._create_inputs_from_tx_change(self._parent_tx) if self._parent_tx else []
        tx = self.wallet.create_transaction(
            base_tx=base_tx,
            inputs=inputs,
            outputs=outputs,
            password=password,
            locktime=locktime,
            BIP69_sort=False,
            merge_duplicate_outputs=False,
        )
        # this assert will fail if we merge duplicate outputs
        for o in outputs: assert o in tx.outputs()
        assert tx.is_complete()
        return tx

    def _clear_unconfirmed_sweeps(self, tx):
        # this ensure that we can accept an input again
        # if the spending tx has been removed from the blockchain
        # fixme: what if there are several batches?
        for txin in tx.inputs():
            if txin.prevout in self._unconfirmed_sweeps:
                self._unconfirmed_sweeps.remove(txin.prevout)

    @locked
    def _start_new_batch(self, tx):
        use_change = tx and tx.has_change() and any([txout in self.batch_payments for txout in tx.outputs()])
        self.batch_payments = self._to_pay_after(tx)
        self.batch_inputs = self._to_sweep_after(tx)
        self._batch_txids.clear()
        self._base_tx = None
        self._parent_tx = tx if use_change else None

    def _create_inputs_from_tx_change(self, parent_tx):
        inputs = []
        for o in parent_tx.get_change_outputs():
            coins = self.wallet.adb.get_addr_utxo(o.address)
            inputs += list(coins.values())
        for txin in inputs:
            txin.nsequence = 0xffffffff - 2
        return inputs

    def _can_broadcast(self, sweep_info: 'SweepInfo', base_tx):
        prevout = sweep_info.txin.prevout.to_str()
        name = sweep_info.name
        prev_txid, index = prevout.split(':')
        can_broadcast = True
        wanted_height = None
        local_height = self.wallet.network.get_local_height()
        if sweep_info.cltv_abs:
            wanted_height = sweep_info.cltv_abs
            if wanted_height - local_height > 0:
                can_broadcast = False
                # self.logger.debug(f"pending redeem for {prevout}. waiting for {name}: CLTV ({local_height=}, {wanted_height=})")
        prev_height = self.wallet.adb.get_tx_height(prev_txid).height
        if sweep_info.csv_delay:
            if prev_height > 0:
                wanted_height = prev_height + sweep_info.csv_delay - 1
            else:
                wanted_height = local_height + sweep_info.csv_delay
            if wanted_height - local_height > 0:
                can_broadcast = False
                # self.logger.debug(
                #     f"pending redeem for {prevout}. waiting for {name}: CSV "
                #     f"({local_height=}, {wanted_height=}, {prev_height.height=}, {sweep_info.csv_delay=})")
        if base_tx and prev_height <= 0:
            # we cannot add unconfirmed inputs to existing base_tx (per RBF rules)
            # thus, we will wait until the current batch is confirmed
            can_broadcast = False
            wanted_height = prev_height
        return can_broadcast, wanted_height

    @locked
    async def _maybe_broadcast_legacy_htlc_txs(self):
        """ pre-anchor htlc txs cannot be batched """
        for sweep_info in list(self.batch_inputs.values()):
            if sweep_info.name == 'first-stage-htlc':
                if not self.can_broadcast(sweep_info)[0]:
                    continue
                self.logger.info('legacy first-stage htlc tx')
                tx = PartialTransaction.from_io([sweep_info.txin], [sweep_info.txout], locktime=sweep_info.cltv_abs, version=2)
                self.lnworker.wallet.sign_transaction(tx, password=None, ignore_warnings=True)
                if await self.wallet.network.try_broadcasting(tx, sweep_info.name):
                    self.wallet.adb.add_transaction(tx)
                    self.batch_inputs.pop(sweep_info.txin.prevout)

