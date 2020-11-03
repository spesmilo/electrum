from enum import IntEnum

from electrum.i18n import _


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


TX_TYPES_DISPLAY_MAP = {
    TxType.NONVAULT.name: _('Standard'),
    TxType.ALERT_PENDING.name: _('Secure'),
    TxType.ALERT_RECOVERED.name: _('Secure'),
    TxType.RECOVERY.name: _('Cancel'),
    TxType.INSTANT.name: _('Secure fast'),
    TxType.ALERT_CONFIRMED.name: _('Secure'),
}
