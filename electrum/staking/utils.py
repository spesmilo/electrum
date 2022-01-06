from typing import Tuple, Optional, TYPE_CHECKING

from .tx_type import TxType
from electrum.bitcoin import opcodes, construct_script, COIN

if TYPE_CHECKING:
    from electrum.util import TxMinedInfo
    from electrum.wallet_db import WalletDB

TX_STATUS_INDEX_OFFSET = 9
TX_TYPES_SPENDABLE = (
    TxType.NONE,
    TxType.STAKING_WITHDRAWAL,
    TxType.STAKING_CLAIM_REWARDS,
)

STAKING_TX_HEADER = '53'
STAKING_TX_DEPOSIT_SUBHEADER = '44'
MIN_STAKING_AMOUNT = 5 * COIN
NUM_STAKING_PERIODS = 4


def get_staking_metadata_output_script(period_index: int, stake_index: int) -> str:
    return construct_script([opcodes.OP_RETURN, STAKING_TX_HEADER + STAKING_TX_DEPOSIT_SUBHEADER + f"{stake_index:0{2}X}" + f"{period_index:0{2}X}"])


def get_tx_type_aware_tx_status(
        tx_hash: str,
        tx_mined_info: 'TxMinedInfo',
        status: int,
        status_str: str,
        db: 'WalletDB'
) -> Tuple[int, str]:
    if status_str == 'unknown':
        return status, status_str

    tx = db.get_transaction(tx_hash)

    confirmations = tx_mined_info.conf
    # unconfirmed alert or recovery
    if confirmations == 0:
        if not hasattr(tx, 'tx_type'):
            return status, status_str
        if tx.tx_type == TxType.NONE:
            return status, status_str
        # reserve tx_type + 1 for unconfirmed tx icon
        return TX_STATUS_INDEX_OFFSET + tx.tx_type + 1, status_str

    if tx.tx_type == TxType.NONE:
        return status, status_str
    return TX_STATUS_INDEX_OFFSET + tx.tx_type, status_str


def filter_spendable_coins(utxos: list, db):
    acceptable_tx_types = TX_TYPES_SPENDABLE
    filtered_utxos = []
    for utxo in utxos:
        tx_hex = utxo.prevout.txid.hex()
        tx = db.get_transaction(tx_hex)
        if tx.tx_type in acceptable_tx_types:
            filtered_utxos.append(utxo)
    return filtered_utxos
