from enum import IntEnum

from electrum.i18n import _


class TxType(IntEnum):
    # numbering here is used in assigning icons to transactions in history tab
    # (with some magic twist in utils.get_tx_type_aware_tx_status method)
    NONE = 0,
    STAKING_DEPOSIT = 1,
    STAKING_WITHDRAWAL = 3,

    @classmethod
    def from_str(cls, str_type: str):
        for t in cls:
            if t.name == str_type:
                return t
            if str(t.value) == str_type:
                return t
        raise ValueError(f"Cannot get TxType for '{str_type}'")


TX_TYPES_DISPLAY_MAP = {
    TxType.NONE.name: _('Standard'),
    TxType.STAKING_DEPOSIT.name: _('Stake Deposit'),
    TxType.STAKING_WITHDRAWAL.name: _('Stake Withdrawal'),
}
