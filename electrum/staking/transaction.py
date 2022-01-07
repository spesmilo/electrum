from .tx_type import TxType
from ..util import bh2u
from electrum import bitcoin
from electrum.bitcoin import opcodes
from electrum.transaction import BCDataStream, Transaction, TxOutput
from typing import NamedTuple, Optional, TYPE_CHECKING
from decimal import Decimal

if TYPE_CHECKING:
    from ..wallet_db import WalletDB


class TxParseError(Exception):
    pass

class StakingDepositTxError(TxParseError):
    pass

class StakingClaimRewardsTxError(TxParseError):
    pass

class StakingWithdrawalTxError(TxParseError):
    pass

class StakingInfo(NamedTuple):
    deposit_height: int                         # height of block that mined tx
    staking_period: int                         # stake duration (in blocks)
    staking_amount: Decimal                     # amount staked (in COIN currency)
    accumulated_reward: Decimal                 # reward amount (in COIN currency)
    fulfilled: bool                             # indicates if stake is finished
    paid_out: bool                              # indicates if stake is withdrawn


class TypeAwareTransaction(Transaction):
    def __init__(self, raw: str, tx_type: TxType):
        super().__init__(raw)
        self.tx_type = tx_type

    @property
    def is_staking_tx(self) -> bool:
        return False

    @property
    def tx_type(self):
        return self._tx_type

    @tx_type.setter
    def tx_type(self, tx_type: TxType):
        if not isinstance(tx_type, TxType):
            raise ValueError(f'tx_type has to be TxType not {type(tx_type).__name__}')
        self._tx_type = tx_type

    @classmethod
    def from_tx(cls, tx: Transaction, db: Optional['WalletDB'] = None):
        if not isinstance(tx, Transaction):
            raise ValueError(f'Wrong transaction type {type(tx).__name__}')

        tx_type = TxType.NONE
        try:
            return StakingDepositTx.from_tx(tx, db)
        except StakingDepositTxError as err:
            # print(err)
            pass
        try:
            return StakingClaimRewardsTx.from_tx(tx, db)
        except StakingClaimRewardsTxError as err:
            # print(err)
            pass
        try:
            return StakingWithdrawalTx.from_tx(tx, db)
        except StakingWithdrawalTxError as err:
            # print(err)
            pass

        raw = tx.serialize()
        return cls(raw, tx_type)


class StakingDepositTx(TypeAwareTransaction):
    STAKING_TX_HEADER = '53'
    STAKING_TX_DEPOSIT_SUBHEADER = '44'

    # TODO: Move staking params somewhere global
    MIN_STAKING_AMOUNT = 5 * bitcoin.COIN
    NUM_STAKING_PERIODS = 4

    def __init__(self, raw: str, tx_type: TxType):
        super().__init__(raw, tx_type)
        self._staking_info = None
        self.staking_period_index = None
        self.staking_output_index = None

    @property
    def is_staking_tx(self) -> bool:
        return True

    def update_staking_info(self, network):
        # can raise network exception
        staking_info = network.run_from_another_thread(
            network.get_stake(self.txid(), timeout=10)
        )
        staking_info['accumulated_reward'] = Decimal(f"{staking_info['accumulated_reward']:.8f}")
        staking_info['staking_amount'] = Decimal(f"{staking_info['staking_amount']:.8f}")

        self.staking_info = StakingInfo(**staking_info)

    @property
    def staking_info(self) -> StakingInfo:
        return self._staking_info

    @staking_info.setter
    def staking_info(self, staking_info: StakingInfo):
        if not isinstance(staking_info, StakingInfo):
            raise ValueError(f'staking_info has to be StakingInfo not {type(staking_info).__name__}')
        self._staking_info = staking_info

    @classmethod
    def from_tx(cls, tx: Transaction, db: Optional['WalletDB'] = None):
        stakinginfo_output = tx.outputs()[0]
        vds = BCDataStream()
        vds.write(stakinginfo_output.scriptpubkey)
        opreturn = vds.read_bytes(1)
        pushsize = vds.read_bytes(1)
        header = vds.read_bytes(1)
        subheader = vds.read_bytes(1)
        if (opreturn.hex() != opcodes.OP_RETURN.hex()
                or header.hex() != cls.STAKING_TX_HEADER
                or subheader.hex() != cls.STAKING_TX_DEPOSIT_SUBHEADER):
            raise StakingDepositTxError(f'tx: {tx.txid()} is not staking deposit tx')

        # Read and validate staking vout index
        outputindex = vds.read_compact_size()
        if (outputindex == 0
                or outputindex >= len(tx.outputs())
                or tx.outputs()[outputindex].value < cls.MIN_STAKING_AMOUNT):
            raise StakingDepositTxError(f'tx: {tx.txid()} outputs do not fulfill staking tx requirements')

        # Read and validate staking period index

        stakingperiod = vds.read_compact_size()
        if stakingperiod >= cls.NUM_STAKING_PERIODS:
            raise StakingDepositTxError(f'tx: {tx.txid()} period does not fulfill staking tx requirements')

        raw = tx.serialize()
        print(f'tx: {tx.txid()} is staking deposit')
        instance = cls(raw, TxType.STAKING_DEPOSIT)
        instance.staking_period_index = stakingperiod
        instance.staking_output_index = outputindex
        return instance


class StakingClaimRewardsTx(TypeAwareTransaction):
    def __init__(self, raw: str, tx_type: TxType):
        super().__init__(raw, tx_type)

    @classmethod
    def from_tx(cls, tx: Transaction, db: Optional['WalletDB'] = None):
        contains_staking_inputs = False

        raw = tx.serialize()
        instance = cls(raw, TxType.STAKING_CLAIM_REWARDS)
        inputs_value = 0
        rewards = 0
        for input in instance.inputs():
            input_tx = db.get_transaction(input.prevout.txid.hex())
            if not input_tx:
                continue
            tx_type = input_tx.tx_type if hasattr(input_tx, 'tx_type') else TxType.NONE
            if tx_type == TxType.STAKING_DEPOSIT and input_tx.staking_output_index == input.prevout.out_idx:
                contains_staking_inputs = True
                # TODO: store info about staking details in db so we can pull that data here to get accumulated reward value
                # rewards += input_tx.staking_info.accumulated_reward
            inputs_value += input_tx.outputs()[input.prevout.out_idx].value
        outputs_value = sum([output.value for output in instance.outputs()])
        if contains_staking_inputs and inputs_value < outputs_value:
            instance.staking_reward = rewards
        else:
            raise StakingClaimRewardsTxError()
        print(f'tx: {tx.txid()} is staking claim rewards')
        return instance


class StakingWithdrawalTx(TypeAwareTransaction):
    def __init__(self, raw: str, tx_type: TxType):
        super().__init__(raw, tx_type)

    @classmethod
    def from_tx(cls, tx: Transaction, db: Optional['WalletDB'] = None):
        contains_staking_inputs = False

        raw = tx.serialize()
        instance = cls(raw, TxType.STAKING_WITHDRAWAL)
        inputs_value = 0
        rewards = 0
        for input in instance.inputs():
            input_tx = db.get_transaction(input.prevout.txid.hex())
            if not input_tx:
                continue
            tx_type = input_tx.tx_type if hasattr(input_tx, 'tx_type') else TxType.NONE
            if tx_type == TxType.STAKING_DEPOSIT and input_tx.staking_output_index == input.prevout.out_idx:
                contains_staking_inputs = True
                # rewards += input_tx.staking_info.accumulated_reward
            inputs_value += input_tx.outputs()[input.prevout.out_idx].value
        outputs_value = sum([output.value for output in instance.outputs()])
        penalty = 0
        # TODO: store info about staking conditions so we can pull staking penalty here
        # penalty = penalty_percentage_by_the_time_tx_was_issued * outputs_value
        if contains_staking_inputs and inputs_value > outputs_value:
            print(f'tx: {tx.txid()} is staking withdrawal')
            instance.staking_penalty = penalty
            return instance
        else:
            raise StakingWithdrawalTxError()