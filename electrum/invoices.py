import time
from typing import TYPE_CHECKING, List, Optional, Union, Dict, Any, Sequence
from decimal import Decimal

import attr

from .json_db import StoredObject
from .i18n import _
from .util import age, InvoiceError, format_satoshis
from .lnutil import hex_to_bytes
from .lnaddr import lndecode, LnAddr
from . import constants
from .bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from .bitcoin import address_to_script
from .transaction import PartialTxOutput
from .crypto import sha256d

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
PR_BROADCASTING = 8    # onchain, tx is being broadcast
PR_BROADCAST    = 9    # onchain, tx was broadcast, is not yet in our history

pr_color = {
    PR_UNPAID:   (.7, .7, .7, 1),
    PR_PAID:     (.2, .9, .2, 1),
    PR_UNKNOWN:  (.7, .7, .7, 1),
    PR_EXPIRED:  (.9, .2, .2, 1),
    PR_INFLIGHT: (.9, .6, .3, 1),
    PR_FAILED:   (.9, .2, .2, 1),
    PR_ROUTING:  (.9, .6, .3, 1),
    PR_BROADCASTING:  (.9, .6, .3, 1),
    PR_BROADCAST:  (.9, .6, .3, 1),
    PR_UNCONFIRMED: (.9, .6, .3, 1),
}

pr_tooltips = {
    PR_UNPAID:_('Unpaid'),
    PR_PAID:_('Paid'),
    PR_UNKNOWN:_('Unknown'),
    PR_EXPIRED:_('Expired'),
    PR_INFLIGHT:_('In progress'),
    PR_BROADCASTING:_('Broadcasting'),
    PR_BROADCAST:_('Broadcast successfully'),
    PR_FAILED:_('Failed'),
    PR_ROUTING: _('Computing route...'),
    PR_UNCONFIRMED: _('Unconfirmed'),
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


def _decode_outputs(outputs) -> Optional[List[PartialTxOutput]]:
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
class BaseInvoice(StoredObject):
    """
    Base class for Invoice and Request
    In the code, we use 'invoice' for outgoing payments, and 'request' for incoming payments.
    """

    # mandatory fields
    amount_msat = attr.ib(kw_only=True)  # type: Optional[Union[int, str]]  # can be '!' or None
    message = attr.ib(type=str, kw_only=True)
    time = attr.ib(type=int, kw_only=True, validator=attr.validators.instance_of(int))  # timestamp of the invoice
    exp = attr.ib(type=int, kw_only=True, validator=attr.validators.instance_of(int))   # expiration delay (relative). 0 means never

    # optional fields.
    # an request (incoming) can be satisfied onchain, using lightning or using a swap
    # an invoice (outgoing) is constructed from a source: bip21, bip70, lnaddr

    # onchain only
    outputs = attr.ib(kw_only=True, converter=_decode_outputs)  # type: Optional[List[PartialTxOutput]]
    height = attr.ib(type=int, kw_only=True, validator=attr.validators.instance_of(int)) # only for receiving
    bip70 = attr.ib(type=str, kw_only=True)  # type: Optional[str]
    #bip70_requestor = attr.ib(type=str, kw_only=True)  # type: Optional[str]


    def is_lightning(self) -> bool:
        raise NotImplementedError()

    def get_address(self) -> Optional[str]:
        """returns the first address, to be displayed in GUI"""
        raise NotImplementedError()

    @property
    def rhash(self) -> str:
        raise NotImplementedError()

    def get_status_str(self, status):
        status_str = pr_tooltips[status]
        if status == PR_UNPAID:
            if self.exp > 0 and self.exp != LN_EXPIRY_NEVER:
                expiration = self.get_expiration_date()
                status_str = _('Expires') + ' ' + age(expiration, include_seconds=True)
        return status_str

    def get_outputs(self) -> Sequence[PartialTxOutput]:
        outputs = self.outputs or []
        if not outputs:
            address = self.get_address()
            amount = self.get_amount_sat()
            if address and amount is not None:
                outputs = [PartialTxOutput.from_address_and_value(address, int(amount))]
        return outputs

    def get_expiration_date(self):
        # 0 means never
        return self.exp + self.time if self.exp else 0

    @staticmethod
    def _get_cur_time():  # for unit tests
        return time.time()

    def has_expired(self) -> bool:
        exp = self.get_expiration_date()
        return bool(exp) and exp < self._get_cur_time()

    def get_amount_msat(self) -> Union[int, str, None]:
        return self.amount_msat

    def get_time(self):
        return self.time

    def get_message(self):
        return self.message

    def get_amount_sat(self) -> Union[int, str, None]:
        """
        Returns an integer satoshi amount, or '!' or None.
        Callers who need msat precision should call get_amount_msat()
        """
        amount_msat = self.amount_msat
        if amount_msat in [None, "!"]:
            return amount_msat
        return int(amount_msat // 1000)

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
    def from_bip70_payreq(cls, pr: 'PaymentRequest', *, height: int = 0) -> 'Invoice':
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

    def get_id(self) -> str:
        if self.is_lightning():
            return self.rhash
        else:  # on-chain
            return get_id_from_onchain_outputs(outputs=self.get_outputs(), timestamp=self.time)

    def as_dict(self, status):
        d = {
            'is_lightning': self.is_lightning(),
            'amount_BTC': format_satoshis(self.get_amount_sat()),
            'message': self.message,
            'timestamp': self.get_time(),
            'expiry': self.exp,
            'status': status,
            'status_str': self.get_status_str(status),
            'id': self.get_id(),
            'amount_sat': self.get_amount_sat(),
        }
        if self.is_lightning():
            d['amount_msat'] = self.get_amount_msat()
        return d


@attr.s
class Invoice(BaseInvoice):
    lightning_invoice = attr.ib(type=str, kw_only=True)  # type: Optional[str]
    __lnaddr = None
    _broadcasting_status = None # can be None or PR_BROADCASTING or PR_BROADCAST

    def is_lightning(self):
        return self.lightning_invoice is not None

    def get_broadcasting_status(self):
        return self._broadcasting_status

    def get_address(self) -> Optional[str]:
        address = None
        if self.outputs:
            address = self.outputs[0].address if len(self.outputs) > 0 else None
        if not address and self.is_lightning():
            address = self._lnaddr.get_fallback_address() or None
        return address

    @property
    def _lnaddr(self) -> LnAddr:
        if self.__lnaddr is None:
            self.__lnaddr = lndecode(self.lightning_invoice)
        return self.__lnaddr

    @property
    def rhash(self) -> str:
        assert self.is_lightning()
        return self._lnaddr.paymenthash.hex()

    @lightning_invoice.validator
    def _validate_invoice_str(self, attribute, value):
        if value is not None:
            lnaddr = lndecode(value)  # this checks the str can be decoded
            self.__lnaddr = lnaddr    # save it, just to avoid having to recompute later

    def can_be_paid_onchain(self) -> bool:
        if self.is_lightning():
            return bool(self._lnaddr.get_fallback_address())
        else:
            return True

    def to_debug_json(self) -> Dict[str, Any]:
        d = self.to_json()
        d.update({
            'pubkey': self._lnaddr.pubkey.serialize().hex(),
            'amount_BTC': str(self._lnaddr.amount),
            'rhash': self._lnaddr.paymenthash.hex(),
            'description': self._lnaddr.get_description(),
            'exp': self._lnaddr.get_expiry(),
            'time': self._lnaddr.date,
        })
        if ln_routing_info := self._lnaddr.get_routing_info('r'):
            # show the last hop of routing hints. (our invoices only have one hop)
            d['r_tags'] = [str((a.hex(),b.hex(),c,d,e)) for a,b,c,d,e in ln_routing_info[-1]]
        return d


@attr.s
class Request(BaseInvoice):
    payment_hash = attr.ib(type=bytes, kw_only=True, converter=hex_to_bytes)  # type: Optional[bytes]

    def is_lightning(self):
        return self.payment_hash is not None

    def get_address(self) -> Optional[str]:
        address = None
        if self.outputs:
            address = self.outputs[0].address if len(self.outputs) > 0 else None
        return address

    @property
    def rhash(self) -> str:
        assert self.is_lightning()
        return self.payment_hash.hex()

    def get_bip21_URI(
        self,
        *,
        lightning_invoice: Optional[str] = None,
    ) -> Optional[str]:
        from electrum.util import create_bip21_uri
        addr = self.get_address()
        amount = self.get_amount_sat()
        if amount is not None:
            amount = int(amount)
        message = self.message
        extra = {}
        if self.time and self.exp:
            extra['time'] = str(int(self.time))
            extra['exp'] = str(int(self.exp))
        if lightning_invoice:
            extra['lightning'] = lightning_invoice
        if not addr and lightning_invoice:
            return "bitcoin:?lightning="+lightning_invoice
        if not addr and not lightning_invoice:
            return None
        uri = create_bip21_uri(addr, amount, message, extra_query_params=extra)
        return str(uri)


def get_id_from_onchain_outputs(outputs: Sequence[PartialTxOutput], *, timestamp: int) -> str:
    outputs_str = "\n".join(f"{txout.scriptpubkey.hex()}, {txout.value}" for txout in outputs)
    return sha256d(outputs_str + "%d" % timestamp).hex()[0:10]
