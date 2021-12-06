from .tx_type import TxType
from ..util import bh2u
from electrum import bitcoin
from electrum.bitcoin import opcodes
from electrum.transaction import BCDataStream, Transaction, TxOutput
from typing import NamedTuple
from decimal import Decimal

class StakingDepositTxError(Exception):
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
    def from_tx(cls, tx: Transaction):
        if not isinstance(tx, Transaction):
            raise ValueError(f'Wrong transaction type {type(tx).__name__}')

        tx_type = TxType.NONE
        try:
            return StakingDepositTx.from_tx(tx)
        except StakingDepositTxError as err:
            print(err)
        # TODO: detect stake withdrawal and other types here as well

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

    @property
    def is_staking_tx(self) -> bool:
        return True

    def update_staking_info(self, network):
        # can raise network exception
        staking_info = network.run_from_another_thread(
            network.get_stake(self.txid(), timeout=10)
        )

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
    def from_tx(cls, tx: Transaction):
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
        return cls(raw, TxType.STAKING_DEPOSIT)
