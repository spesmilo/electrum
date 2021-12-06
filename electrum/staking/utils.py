from typing import Tuple, Optional, TYPE_CHECKING

from .transaction import TypeAwareTransaction
from .tx_type import TxType
from ..wallet_db import WalletDB

if TYPE_CHECKING:
    from electrum.util import TxMinedInfo

TX_STATUS_INDEX_OFFSET = 10
TX_TYPES_LIKE_STANDARD = (
    TxType.NONE,
    TxType.STAKING_WITHDRAWAL,
)


def get_tx_type_aware_tx_status(
        tx_hash: str,
        tx_mined_info: 'TxMinedInfo',
        status: int,
        status_str: str,
        db: WalletDB
) -> Tuple[int, str]:
    if status_str == 'unknown':
        return status, status_str

    tx = db.get_transaction(tx_hash)

    confirmations = tx_mined_info.conf
    # unconfirmed alert or recovery
    if confirmations == 0:
        if not hasattr(tx, 'tx_type'):
            return status, status_str
        if tx.tx_type in TX_TYPES_LIKE_STANDARD:
            return status, status_str
        # reserve tx_type + 1 for unconfirmed tx icon
        return TX_STATUS_INDEX_OFFSET + tx.tx_type + 1, status_str

    if tx.tx_type in TX_TYPES_LIKE_STANDARD:
        return status, status_str
    return TX_STATUS_INDEX_OFFSET + tx.tx_type, status_str


def filter_spendable_coins(utxos: list, db):
    acceptable_tx_types = TX_TYPES_LIKE_STANDARD + (TxType.RECOVERY,)
    filtered_utxos = []
    for utxo in utxos:
        tx_hex = utxo.prevout.txid.hex()
        tx = db.get_transaction(tx_hex)
        if tx.tx_type in acceptable_tx_types:
            filtered_utxos.append(utxo)
    return filtered_utxos
