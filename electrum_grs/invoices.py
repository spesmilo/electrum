import attr
import time
from typing import TYPE_CHECKING, List

from .json_db import StoredObject
from .i18n import _
from .util import age
from .lnaddr import lndecode
from . import constants
from .bitcoin import COIN
from .transaction import PartialTxOutput

if TYPE_CHECKING:
    from .paymentrequest import PaymentRequest

# convention: 'invoices' = outgoing , 'request' = incoming

# types of payment requests
PR_TYPE_ONCHAIN = 0
PR_TYPE_LN = 2

# status of payment requests
PR_UNPAID   = 0
PR_EXPIRED  = 1
PR_UNKNOWN  = 2     # sent but not propagated
PR_PAID     = 3     # send and propagated
PR_INFLIGHT = 4     # unconfirmed
PR_FAILED   = 5
PR_ROUTING  = 6

pr_color = {
    PR_UNPAID:   (.7, .7, .7, 1),
    PR_PAID:     (.2, .9, .2, 1),
    PR_UNKNOWN:  (.7, .7, .7, 1),
    PR_EXPIRED:  (.9, .2, .2, 1),
    PR_INFLIGHT: (.9, .6, .3, 1),
    PR_FAILED:   (.9, .2, .2, 1),
    PR_ROUTING: (.9, .6, .3, 1),
}

pr_tooltips = {
    PR_UNPAID:_('Pending'),
    PR_PAID:_('Paid'),
    PR_UNKNOWN:_('Unknown'),
    PR_EXPIRED:_('Expired'),
    PR_INFLIGHT:_('In progress'),
    PR_FAILED:_('Failed'),
    PR_ROUTING: _('Computing route...'),
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
    type = attr.ib(type=int)
    message = attr.ib(type=str)
    amount = attr.ib(type=int)
    exp = attr.ib(type=int)
    time = attr.ib(type=int)

    def is_lightning(self):
        return self.type == PR_TYPE_LN

    def get_status_str(self, status):
        status_str = pr_tooltips[status]
        if status == PR_UNPAID:
            if self.exp > 0 and self.exp != LN_EXPIRY_NEVER:
                expiration = self.exp + self.time
                status_str = _('Expires') + ' ' + age(expiration, include_seconds=True)
            else:
                status_str = _('Pending')
        return status_str

@attr.s
class OnchainInvoice(Invoice):
    id = attr.ib(type=str)
    outputs = attr.ib(type=list, converter=_decode_outputs)
    bip70 = attr.ib(type=str) # may be None
    requestor = attr.ib(type=str) # may be None

    def get_address(self) -> str:
        assert len(self.outputs) == 1
        return self.outputs[0].address

    @classmethod
    def from_bip70_payreq(cls, pr: 'PaymentRequest') -> 'OnchainInvoice':
        return OnchainInvoice(
            type=PR_TYPE_ONCHAIN,
            amount=pr.get_amount(),
            outputs=pr.get_outputs(),
            message=pr.get_memo(),
            id=pr.get_id(),
            time=pr.get_time(),
            exp=pr.get_expiration_date() - pr.get_time(),
            bip70=pr.raw.hex() if pr else None,
            requestor=pr.get_requestor(),
        )

@attr.s
class LNInvoice(Invoice):
    rhash = attr.ib(type=str)
    invoice = attr.ib(type=str)

    @classmethod
    def from_bech32(klass, invoice: str) -> 'LNInvoice':
        lnaddr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        amount = int(lnaddr.amount * COIN) if lnaddr.amount else None
        return LNInvoice(
            type = PR_TYPE_LN,
            amount = amount,
            message = lnaddr.get_description(),
            time = lnaddr.date,
            exp = lnaddr.get_expiry(),
            rhash = lnaddr.paymenthash.hex(),
            invoice = invoice,
        )


def invoice_from_json(x: dict) -> Invoice:
    if x.get('type') == PR_TYPE_LN:
        return LNInvoice(**x)
    else:
        return OnchainInvoice(**x)
