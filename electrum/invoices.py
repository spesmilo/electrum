import time
from typing import TYPE_CHECKING, List, Optional, Union, Dict, Any
from decimal import Decimal

import attr

from .json_db import StoredObject
from .i18n import _
from .util import age, InvoiceError
from .lnaddr import lndecode, LnAddr
from . import constants
from .bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from .bitcoin import address_to_script
from .transaction import PartialTxOutput

if TYPE_CHECKING:
    from .paymentrequest import PaymentRequest

# convention: 'invoices' = outgoing , 'request' = incoming

# status of payment requests
PR_UNPAID   = 0     # if onchain: invoice amt not reached by txs in mempool+chain. if LN: invoice not paid.
PR_EXPIRED  = 1     # invoice is unpaid and expiry time reached
PR_UNKNOWN  = 2     # e.g. invoice not found
PR_PAID     = 3     # if onchain: paid and mined (1 conf). if LN: invoice is paid.
PR_INFLIGHT = 4     # only for LN. payment attempt in progress
PR_FAILED   = 5     # only for LN. we attempted to pay it, but all attempts failed
PR_ROUTING  = 6     # only for LN. *unused* atm.
PR_UNCONFIRMED = 7  # only onchain. invoice is satisfied but tx is not mined yet.
PR_SCHEDULED = 8  # lightning invoice will be paid once channel liquidity is available


pr_color = {
    PR_UNPAID:   (.7, .7, .7, 1),
    PR_PAID:     (.2, .9, .2, 1),
    PR_UNKNOWN:  (.7, .7, .7, 1),
    PR_EXPIRED:  (.9, .2, .2, 1),
    PR_INFLIGHT: (.9, .6, .3, 1),
    PR_FAILED:   (.9, .2, .2, 1),
    PR_ROUTING: (.9, .6, .3, 1),
    PR_UNCONFIRMED: (.9, .6, .3, 1),
    PR_SCHEDULED: (.9, .6, .3, 1),
}

pr_tooltips = {
    PR_UNPAID:_('Unpaid'),
    PR_PAID:_('Paid'),
    PR_UNKNOWN:_('Unknown'),
    PR_EXPIRED:_('Expired'),
    PR_INFLIGHT:_('In progress'),
    PR_FAILED:_('Failed'),
    PR_ROUTING: _('Computing route...'),
    PR_UNCONFIRMED: _('Unconfirmed'),
    PR_SCHEDULED: _('Scheduled'),
}

PR_DEFAULT_EXPIRATION_WHEN_CREATING = 24*60*60  # 1 day
pr_expiration_values = {
    0: _('Never'),
    10*60: _('10 minutes'),
    60*60: _('1 hour'),
    24*60*60: _('1 day'),
    7*24*60*60: _('1 week'),
}
assert PR_DEFAULT_EXPIRATION_WHEN_CREATING in pr_expiration_values


def _decode_outputs(outputs) -> List[PartialTxOutput]:
    if outputs is None:
        return None
    ret = []
    for output in outputs:
        if not isinstance(output, PartialTxOutput):
            output = PartialTxOutput.from_legacy_tuple(*output)
        ret.append(output)
    return ret


# hack: BOLT-11 is not really clear on what an expiry of 0 means.
# It probably interprets it as 0 seconds, so already expired...
# Our higher level invoices code however uses 0 for "never".
# Hence set some high expiration here
LN_EXPIRY_NEVER = 100 * 365 * 24 * 60 * 60  # 100 years



@attr.s
class Invoice(StoredObject):

    # mandatory fields
    amount_msat = attr.ib(kw_only=True)  # type: Optional[Union[int, str]]  # can be '!' or None
    message = attr.ib(type=str, kw_only=True)
    time = attr.ib(type=int, kw_only=True, validator=attr.validators.instance_of(int))  # timestamp of the invoice
    exp = attr.ib(type=int, kw_only=True, validator=attr.validators.instance_of(int))   # expiration delay (relative). 0 means never

    # optional fields.
    # an request (incoming) can be satisfied onchain, using lightning or using a swap
    # an invoice (outgoing) is constructed from a source: bip21, bip70, lnaddr

    # onchain only
    outputs = attr.ib(kw_only=True, converter=_decode_outputs)  # type: List[PartialTxOutput]
    height = attr.ib(type=int, kw_only=True, validator=attr.validators.instance_of(int)) # only for receiving
    bip70 = attr.ib(type=str, kw_only=True)  # type: Optional[str]
    #bip70_requestor = attr.ib(type=str, kw_only=True)  # type: Optional[str]

    # lightning only
    lightning_invoice = attr.ib(type=str, kw_only=True)

    __lnaddr = None

    def is_lightning(self):
        return self.lightning_invoice is not None

    def get_status_str(self, status):
        status_str = pr_tooltips[status]
        if status == PR_UNPAID:
            if self.exp > 0 and self.exp != LN_EXPIRY_NEVER:
                expiration = self.get_expiration_date()
                status_str = _('Expires') + ' ' + age(expiration, include_seconds=True)
        return status_str

    def get_address(self) -> str:
        """returns the first address, to be displayed in GUI"""
        if self.is_lightning():
            return self._lnaddr.get_fallback_address() or None
        else:
            return self.outputs[0].address

    def get_outputs(self):
        if self.is_lightning():
            address = self.get_address()
            outputs = [PartialTxOutput.from_address_and_value(address, int(self.get_amount_sat()))] if address else []
        else:
            outputs = self.outputs
        return outputs

    def get_expiration_date(self):
        # 0 means never
        return self.exp + self.time if self.exp else 0

    def get_amount_msat(self):
        return self.amount_msat

    def get_time(self):
        return self.time

    def get_message(self):
        return self.message

    def get_amount_sat(self) -> Union[int, str]:
        """
        Returns an integer satoshi amount, or '!' or None.
        Callers who need msat precision should call get_amount_msat()
        """
        amount_msat = self.amount_msat
        if amount_msat is None:
            return None
        return int(amount_msat / 1000)

    def get_bip21_URI(self):
        from electrum.util import create_bip21_uri
        addr = self.get_address()
        amount = int(self.get_amount_sat())
        message = self.message
        uri = create_bip21_uri(addr, amount, message)
        return str(uri)

    @lightning_invoice.validator
    def _validate_invoice_str(self, attribute, value):
        if value is not None:
            lndecode(value)  # this checks the str can be decoded

    @amount_msat.validator
    def _validate_amount(self, attribute, value):
        if value is None:
            return
        if isinstance(value, int):
            if not (0 <= value <= TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN * 1000):
                raise InvoiceError(f"amount is out-of-bounds: {value!r} msat")
        elif isinstance(value, str):
            if value != '!':
                raise InvoiceError(f"unexpected amount: {value!r}")
        else:
            raise InvoiceError(f"unexpected amount: {value!r}")

    @property
    def _lnaddr(self) -> LnAddr:
        if self.__lnaddr is None:
            self.__lnaddr = lndecode(self.lightning_invoice)
        return self.__lnaddr

    @property
    def rhash(self) -> str:
        return self._lnaddr.paymenthash.hex()

    @classmethod
    def from_bech32(cls, invoice: str) -> 'Invoice':
        """Constructs Invoice object from BOLT-11 string.
        Might raise InvoiceError.
        """
        try:
            lnaddr = lndecode(invoice)
        except Exception as e:
            raise InvoiceError(e) from e
        amount_msat = lnaddr.get_amount_msat()
        timestamp = lnaddr.date
        exp_delay = lnaddr.get_expiry()
        message = lnaddr.get_description()
        return Invoice(
            message=message,
            amount_msat=amount_msat,
            time=timestamp,
            exp=exp_delay,
            outputs=None,
            bip70=None,
            height=0,
            lightning_invoice=invoice,
        )

    @classmethod
    def from_bip70_payreq(cls, pr: 'PaymentRequest', height:int) -> 'Invoice':
        return Invoice(
            amount_msat=pr.get_amount()*1000,
            message=pr.get_memo(),
            time=pr.get_time(),
            exp=pr.get_expiration_date() - pr.get_time(),
            outputs=pr.get_outputs(),
            bip70=pr.raw.hex(),
            height=height,
            lightning_invoice=None,
        )

    def to_debug_json(self) -> Dict[str, Any]:
        d = self.to_json()
        d.update({
            'pubkey': self._lnaddr.pubkey.serialize().hex(),
            'amount_BTC': str(self._lnaddr.amount),
            'rhash': self._lnaddr.paymenthash.hex(),
            'description': self._lnaddr.get_description(),
            'exp': self._lnaddr.get_expiry(),
            'time': self._lnaddr.date,
            # 'tags': str(lnaddr.tags),
        })
        return d
