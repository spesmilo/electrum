import asyncio
import threading
import copy

from typing import Dict, Sequence
from . import util
from .bitcoin import dust_threshold
from .logging import Logger
from .util import log_exceptions, NotEnoughFunds, BelowDustLimit, NoDynamicFeeEstimates
from .transaction import PartialTransaction, PartialTxOutput, Transaction
from .address_synchronizer import TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE
from .lnsweep import SweepInfo
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .wallet import Abstract_Wallet

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

from .json_db import locked, StoredDict
from .fee_policy import FeePolicy



class TxBatcher(Logger):

    SLEEP_INTERVAL = 1

    def __init__(self, wallet: 'Abstract_Wallet'):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self.storage = wallet.db.get_stored_item("tx_batches", {})
        self.tx_batches = {}
        self.wallet = wallet
        for key, item_storage in self.storage.items():
            self.tx_batches[key] = TxBatch(self.wallet, item_storage)
        self._legacy_htlcs = {}

    @locked
    def add_payment_output(self, key: str, output: 'PartialTxOutput', fee_policy_descriptor: str):
        batch = self._maybe_create_new_batch(key, fee_policy_descriptor)
        batch.add_payment_output(output)

    @locked
    def add_sweep_input(self, key: str, sweep_info: 'SweepInfo', fee_policy_descriptor: str):
        if sweep_info.txin and sweep_info.txout:
            # todo: don't use name, detect sighash
            if sweep_info.name == 'first-stage-htlc':
                if sweep_info.txin.prevout not in self._legacy_htlcs:
                    self.logger.info(f'received {sweep_info.name}')
                    self._legacy_htlcs[sweep_info.txin.prevout] = sweep_info
                return
        if not sweep_info.can_be_batched:
            # create a batch only for that input
            key = sweep_info.txin.prevout.to_str()
        batch = self._maybe_create_new_batch(key, fee_policy_descriptor)
        batch.add_sweep_input(sweep_info)

    def _maybe_create_new_batch(self, key, fee_policy_descriptor: str):
        if key not in self.storage:
            self.storage[key] = { 'fee_policy': fee_policy_descriptor, 'txids': [] }
            self.tx_batches[key] = TxBatch(self.wallet, self.storage[key])
        elif self.storage[key]['fee_policy'] != fee_policy_descriptor:
            # maybe update policy?
            self.logger.warning('fee policy passed to txbatcher inconsistent with existing batch')
        return self.tx_batches[key]

    def _delete_batch(self, key):
        self.logger.info(f'deleting TxBatch {key}')
        self.storage.pop(key)
        self.tx_batches.pop(key)

    def find_batch_of_txid(self, txid) -> str:
        for k, v in self.tx_batches.items():
            if v.is_mine(txid):
                return k

    def is_mine(self, txid):
        # used to prevent GUI from interfering
        return bool(self.find_batch_of_txid(txid))

    @log_exceptions
    async def run(self):
        while True:
            await asyncio.sleep(self.SLEEP_INTERVAL)
            password = self.wallet.get_unlocked_password()
            if self.wallet.has_keystore_encryption() and not password:
                continue
            if not (self.wallet.network and self.wallet.network.is_connected()):
                continue
            for key, txbatch in list(self.tx_batches.items()):
                try:
                    await txbatch.run_iteration(password)
                    if txbatch.is_done():
                        self._delete_batch(key)
                except Exception as e:
                    self.logger.exception(f'TxBatch error: {repr(e)}')
                    self._delete_batch(key)
                    continue
            for sweep_info in self._legacy_htlcs.values():
                await self._maybe_redeem_legacy_htlcs(sweep_info)

    async def _maybe_redeem_legacy_htlcs(self, sweep_info):
        local_height = self.wallet.network.get_local_height()
        wanted_height = sweep_info.cltv_abs
        if wanted_height - local_height > 0:
            return
        # fixme: what if sweep info has a csv?
        outpoint = sweep_info.txin.prevout.to_str()
        prev_txid, index = outpoint.split(':')
        if spender_txid := self.wallet.adb.db.get_spent_outpoint(prev_txid, int(index)):
            tx_mined_status = self.wallet.adb.get_tx_height(spender_txid)
            if tx_mined_status.height > 0:
                return
            if tx_mined_status.height not in [TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE]:
                return
        self.logger.info(f'will broadcast standalone tx {sweep_info.name}')
        tx = PartialTransaction.from_io([sweep_info.txin], [sweep_info.txout], locktime=sweep_info.cltv_abs, version=2)
        self.wallet.sign_transaction(tx, password=None, ignore_warnings=True)
        if await self.wallet.network.try_broadcasting(tx, sweep_info.name):
            self.wallet.adb.add_transaction(tx)



class TxBatch(Logger):

    def __init__(self, wallet, storage: StoredDict):
        Logger.__init__(self)
        self.wallet = wallet
        self.lock = threading.RLock()
        self.batch_payments = []       # list of payments we need to make
        self.batch_inputs = {}         # list of inputs we need to sweep
        # list of tx that were broadcast. Each tx is a RBF replacement of the previous one. Ony one can get mined.
        self._batch_txids = storage['txids']
        self.fee_policy = FeePolicy(storage['fee_policy'])
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
    def add_payment_output(self, output: 'PartialTxOutput'):
        # todo: maybe we should raise NotEnoughFunds here
        self.batch_payments.append(output)

    def is_dust(self, sweep_info):
        if sweep_info.name in ['local_anchor', 'remote_anchor']:
            return False
        if sweep_info.txout is not None:
            return False
        value = sweep_info.txin._trusted_value_sats
        witness_size = len(sweep_info.txin.make_witness(71*b'\x00'))
        tx_size_vbytes = 84 + witness_size//4     # assumes no batching, sweep to p2wpkh
        self.logger.info(f'{sweep_info.name} size = {tx_size_vbytes}')
        fee = self.fee_policy.estimate_fee(tx_size_vbytes, network=self.wallet.network, allow_fallback_to_static_rates=True)
        return value - fee <= dust_threshold()

    @locked
    def add_sweep_input(self, sweep_info: 'SweepInfo'):
        if self.is_dust(sweep_info):
            raise BelowDustLimit
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
        recommended_fee = self.fee_policy.estimate_fee(base_tx.estimated_size(), network=self.wallet.network)
        should_bump_fee = base_tx_fee * 1.1 < recommended_fee
        if should_bump_fee:
            self.logger.info(f'base tx fee too low {base_tx_fee} < {recommended_fee}. we will bump the fee')
        return should_bump_fee

    def is_done(self):
        # todo: require more than one confirmation
        return len(self.batch_inputs) == 0 and len(self.batch_payments) == 0 and len(self._batch_txids) == 0

    async def run_iteration(self, password):
        conf_tx = self._find_confirmed_base_tx()
        if conf_tx:
            self.logger.info(f'base tx confirmed {conf_tx.txid()}')
            self._clear_unconfirmed_sweeps(conf_tx)
            self._start_new_batch(conf_tx)

        base_tx = self.get_base_tx()
        # if base tx has been RBF-replaced, detect it here
        try:
            tx = self.create_next_transaction(base_tx, password)
        except NoDynamicFeeEstimates:
            self.logger.debug('no dynamic fee estimates available')
            return
        except Exception as e:
            if base_tx:
                self.logger.exception(f'Cannot create batch transaction: {repr(e)}')
                self._start_new_batch(base_tx)
                return
            else:
                # will be caught by txBatcher
                raise

        if tx is None:
            # nothing to do
            return

        if await self.wallet.network.try_broadcasting(tx, 'batch'):
            self.wallet.adb.add_transaction(tx)
            if tx.has_change():
                self._batch_txids.append(tx.txid())
                self._base_tx = tx
            else:
                self.logger.info(f'starting new batch because current base tx does not have change')
                self._start_new_batch(tx)
        else:
            # most likely reason is that base_tx is not replaceable
            # this may be the case if it has children (because we don't pay enough fees to replace them)
            # or if we are trying to sweep unconfirmed inputs (replacement-adds-unconfirmed error)
            self.logger.info(f'cannot broadcast tx {tx}')
            if base_tx:
                self.logger.info(f'starting new batch because could not broadcast')
                self._start_new_batch(base_tx)


    def create_next_transaction(self, base_tx, password):
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
            return
        while True:
            tx = self._create_batch_tx(base_tx, to_sweep_now, to_pay, password)
            # 100 kb max standardness rule
            if tx.estimated_size() < 100_000:
                break
            to_sweep_now = to_sweep_now[0:len(to_sweep_now)//2]
            to_pay = to_pay[0:len(to_pay)//2]

        self.logger.info(f'created tx with {len(tx.inputs())} inputs and {len(tx.outputs())} outputs')
        self.logger.info(f'{str(tx)}')
        return tx

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
        # add sweep info base_tx inputs
        if base_tx:
            for txin in base_tx.inputs():
                if sweep_info := self.batch_inputs.get(txin.prevout):
                    if hasattr(txin, 'make_witness'):
                        txin.make_witness = sweep_info.txin.make_witness
                        txin.privkey = sweep_info.txin.privkey
                        txin.witness_script = sweep_info.txin.witness_script
                        txin.script_sig = sweep_info.txin.script_sig
        # create tx
        tx = self.wallet.make_unsigned_transaction(
            fee_policy=self.fee_policy,
            base_tx=base_tx,
            inputs=inputs,
            outputs=outputs,
            locktime=locktime,
            BIP69_sort=False,
            merge_duplicate_outputs=False,
        )
        self.wallet.sign_transaction(tx, password)
        # this assert will fail if we merge duplicate outputs
        for o in outputs: assert o in tx.outputs()
        assert tx.is_complete()
        return tx

    def _clear_unconfirmed_sweeps(self, tx):
        # this ensures that we can accept an input again,
        # in case the sweeping tx has been removed from the blockchain after a reorg
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

    def _can_broadcast(self, sweep_info: 'SweepInfo', base_tx: 'Transaction'):
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
        prev_height = self.wallet.adb.get_tx_height(prev_txid).height
        if sweep_info.csv_delay:
            if prev_height > 0:
                wanted_height = prev_height + sweep_info.csv_delay - 1
                if wanted_height - local_height > 0:
                    can_broadcast = False
            else:
                can_broadcast = False
                wanted_height = local_height + sweep_info.csv_delay
        if base_tx and prev_height <= 0:
            # we cannot add unconfirmed inputs to existing base_tx (per RBF rules)
            # thus, we will wait until the current batch is confirmed
            if can_broadcast:
                can_broadcast = False
                wanted_height = local_height + 1
        return can_broadcast, wanted_height

