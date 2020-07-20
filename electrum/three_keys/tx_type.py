from enum import IntEnum


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
