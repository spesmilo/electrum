from typing import Tuple

from .tx_type import TxType


TX_STATUS_INDEX_SHIFT = 10
TX_TYPES_LIKE_STANDARD = (
    TxType.NONVAULT,
    TxType.INSTANT,
    TxType.ALERT_CONFIRMED,
)


def update_tx_status(tx_hash, tx_mined_info: 'TxMinedInfo', status: int, status_str: str, db) -> Tuple[int, str]:
    if status_str == 'unknown':
        return status, status_str

    tx = db.get_transaction(tx_hash)

    if tx.tx_type in TX_TYPES_LIKE_STANDARD:
        if tx.tx_type == TxType.ALERT_CONFIRMED:
            # alert confirmed with icon like nonvault confirmed
            status = TX_STATUS_INDEX_SHIFT - 1
        return status, status_str

    confirmations = tx_mined_info.conf
    # unconfirmed alert or recovery
    if confirmations == 0:
        if tx.tx_type == TxType.RECOVERY:
            # last item in TX_ICONS represents unconfirmed recovery tx
            return TX_STATUS_INDEX_SHIFT + tx.tx_type + 1, status_str
        return TX_STATUS_INDEX_SHIFT, status_str
    return TX_STATUS_INDEX_SHIFT + tx.tx_type, status_str


def filter_spendable_coins(utxos: list, db):
    acceptable_tx_types = TX_TYPES_LIKE_STANDARD + (TxType.RECOVERY,)
    filtered_utxos = []
    for utxo in utxos:
        tx_hex = utxo.prevout.txid.hex()
        tx = db.get_transaction(tx_hex)
        if tx.tx_type in acceptable_tx_types:
            filtered_utxos.append(utxo)
    return filtered_utxos
