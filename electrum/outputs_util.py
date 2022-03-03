import re

from electrum.bitcoin import is_address, address_to_script
from .transaction import PartialTxOutput, CustomTxOutput
from electrum.defichain import AccountToAccount
from typing import Optional, Union

ADDRESS_PATTERN = r'^(.*?)\s*\<([0-9A-Za-z]{1,})\>$'


def parse_address(line):

    r = line.strip()
    m = re.match(ADDRESS_PATTERN, r)
    address = str(m.group(2) if m else r)
    assert is_address(address)
    return address


def compose_payto_outputs(
        addr_from: str,
        addr_to: str,
        token_id: int,
        is_max: bool,
        payto_scriptpubkey: Optional[bytes],
        amount: Union[int, str, None] = 0):
    if payto_scriptpubkey is None:
        return None

    # assert is_max != (amount is not None and int(amount) > 0)

    value = '!' if is_max else amount
    outputs = None
    if token_id == 0:
        outputs = [PartialTxOutput(scriptpubkey=payto_scriptpubkey, value=value)]
    else:
        a2a = AccountToAccount(address_to_script(addr_from),
            {address_to_script(parse_address(addr_to)): {token_id: value}}
        )
        outputs = [CustomTxOutput(tx=a2a, value=0)]
    return outputs
