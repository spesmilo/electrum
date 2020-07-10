from enum import IntEnum

from ..transaction import Transaction


class TxType(IntEnum):
    NONVAULT = 0
    ALERT_PENDING = 1
    ALERT_RECOVERED = 2
    RECOVERY = 3
    INSTANT = 4
    ALERT_CONFIRMED = 5

    @classmethod
    def from_str(cls, str_type: str):
        for t in cls:
            if t.name == str_type:
                return t
            if str(t.value) == str_type:
                return t
        raise ValueError(f"Cannot get TxType for '{str_type}'")


class ThreeKeysTransaction(Transaction):
    def __init__(self, raw: str, tx_type: TxType):
        super().__init__(raw)
        self.tx_type = tx_type

    @property
    def tx_type(self):
        return self._tx_type

    @tx_type.setter
    def tx_type(self, tx_type):
        if not isinstance(tx_type, TxType):
            raise ValueError(f'tx_type has to be TxType not {type(tx_type).__name__}')
        self._tx_type = tx_type

    @classmethod
    def from_tx(cls, tx: Transaction):
        if not isinstance(tx, Transaction):
            raise ValueError(f'Wrong transaction type {type(tx).__name__}')
        raw = tx.serialize()
        return cls(raw, TxType.NONVAULT)
