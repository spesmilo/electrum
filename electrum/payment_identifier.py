import asyncio
import time
import urllib
import re
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from typing import NamedTuple, Optional, Callable, List, TYPE_CHECKING, Tuple, Union

from . import bitcoin
from .contacts import AliasNotFoundException
from .i18n import _
from .invoices import Invoice
from .logging import Logger
from .util import parse_max_spend, InvoiceError
from .util import get_asyncio_loop, log_exceptions
from .transaction import PartialTxOutput
from .lnurl import decode_lnurl, request_lnurl, callback_lnurl, LNURLError, lightning_address_to_url
from .bitcoin import opcodes, construct_script
from .lnaddr import LnInvoiceException
from .lnutil import IncompatibleOrInsaneFeatures
from .bip21 import parse_bip21_URI, InvalidBitcoinURI, LIGHTNING_URI_SCHEME, BITCOIN_BIP21_URI_SCHEME
from . import paymentrequest

if TYPE_CHECKING:
    from .wallet import Abstract_Wallet
    from .transaction import Transaction


def maybe_extract_lightning_payment_identifier(data: str) -> Optional[str]:
    data = data.strip()  # whitespaces
    data = data.lower()
    if data.startswith(LIGHTNING_URI_SCHEME + ':ln'):
        cut_prefix = LIGHTNING_URI_SCHEME + ':'
        data = data[len(cut_prefix):]
    if data.startswith('ln'):
        return data
    return None


def is_uri(data: str) -> bool:
    data = data.lower()
    if (data.startswith(LIGHTNING_URI_SCHEME + ":") or
            data.startswith(BITCOIN_BIP21_URI_SCHEME + ':')):
        return True
    return False


RE_ALIAS = r'(.*?)\s*\<([0-9A-Za-z]{1,})\>'
RE_EMAIL = r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Z|a-z]{2,7}\b'
RE_DOMAIN = r'\b([A-Za-z0-9-]+\.)+[A-Z|a-z]{2,7}\b'
RE_SCRIPT_FN = r'script\((.*)\)'


class PaymentIdentifierState(IntEnum):
    EMPTY = 0               # Initial state.
    INVALID = 1             # Unrecognized PI
    AVAILABLE = 2           # PI contains a payable destination
                            # payable means there's enough addressing information to submit to one
                            # of the channels Electrum supports (on-chain, lightning)
    NEED_RESOLVE = 3        # PI contains a recognized destination format, but needs an online resolve step
    LNURLP_FINALIZE = 4     # PI contains a resolved LNURLp, but needs amount and comment to resolve to a bolt11
    MERCHANT_NOTIFY = 5     # PI contains a valid payment request and on-chain destination. It should notify
                            # the merchant payment processor of the tx after on-chain broadcast,
                            # and supply a refund address (bip70)
    MERCHANT_ACK = 6        # PI notified merchant. nothing to be done.
    ERROR = 50              # generic error
    NOT_FOUND = 51          # PI contains a recognized destination format, but resolve step was unsuccessful
    MERCHANT_ERROR = 52     # PI failed notifying the merchant after broadcasting onchain TX
    INVALID_AMOUNT = 53     # Specified amount not accepted


class PaymentIdentifierType(IntEnum):
    UNKNOWN = 0
    SPK = 1
    BIP21 = 2
    BIP70 = 3
    MULTILINE = 4
    BOLT11 = 5
    LNURLP = 6
    EMAILLIKE = 7
    OPENALIAS = 8
    LNADDR = 9
    DOMAINLIKE = 10


class FieldsForGUI(NamedTuple):
    recipient: Optional[str]
    amount: Optional[int]
    description: Optional[str]
    validated: Optional[bool]
    comment: Optional[int]
    amount_range: Optional[Tuple[int, int]]


class PaymentIdentifier(Logger):
    """
    Takes:
        * bitcoin addresses or script
        * paytomany csv
        * openalias
        * bip21 URI
        * lightning-URI (containing bolt11 or lnurl)
        * bolt11 invoice
        * lnurl
        * lightning address
    """

    def __init__(self, wallet: Optional['Abstract_Wallet'], text: str):
        Logger.__init__(self)
        self._state = PaymentIdentifierState.EMPTY
        self.wallet = wallet
        self.contacts = wallet.contacts if wallet is not None else None
        self.config = wallet.config if wallet is not None else None
        self.text = text.strip()
        self._type = PaymentIdentifierType.UNKNOWN
        self.error = None    # if set, GUI should show error and stop
        self.warning = None  # if set, GUI should ask user if they want to proceed
        # more than one of those may be set
        self.multiline_outputs = None
        self._is_max = False
        self.bolt11 = None  # type: Optional[Invoice]
        self.bip21 = None
        self.spk = None
        self.spk_is_address = False
        #
        self.emaillike = None
        self.domainlike = None
        self.openalias_data = None
        #
        self.bip70 = None
        self.bip70_data = None
        self.merchant_ack_status = None
        self.merchant_ack_message = None
        #
        self.lnurl = None
        self.lnurl_data = None

        self.parse(text)

    @property
    def type(self):
        return self._type

    def set_state(self, state: 'PaymentIdentifierState'):
        self.logger.debug(f'PI state {self._state.name} -> {state.name}')
        self._state = state

    @property
    def state(self):
        return self._state

    def need_resolve(self):
        return self._state == PaymentIdentifierState.NEED_RESOLVE

    def need_finalize(self):
        return self._state == PaymentIdentifierState.LNURLP_FINALIZE

    def need_merchant_notify(self):
        return self._state == PaymentIdentifierState.MERCHANT_NOTIFY

    def is_valid(self):
        return self._state not in [PaymentIdentifierState.INVALID, PaymentIdentifierState.EMPTY]

    def is_available(self):
        return self._state in [PaymentIdentifierState.AVAILABLE]

    def is_lightning(self):
        return bool(self.lnurl) or bool(self.bolt11)

    def is_onchain(self):
        if self._type in [PaymentIdentifierType.SPK, PaymentIdentifierType.MULTILINE, PaymentIdentifierType.BIP70,
                          PaymentIdentifierType.OPENALIAS]:
            return True
        if self._type in [PaymentIdentifierType.LNURLP, PaymentIdentifierType.BOLT11, PaymentIdentifierType.LNADDR]:
            return bool(self.bolt11) and bool(self.bolt11.get_address())
        if self._type == PaymentIdentifierType.BIP21:
            return bool(self.bip21.get('address', None)) or (bool(self.bolt11) and bool(self.bolt11.get_address()))

    def is_multiline(self):
        return bool(self.multiline_outputs)

    def is_multiline_max(self):
        return self.is_multiline() and self._is_max

    def is_amount_locked(self):
        if self._type == PaymentIdentifierType.BIP21:
            return bool(self.bip21.get('amount'))
        elif self._type == PaymentIdentifierType.BIP70:
            return not self.need_resolve()  # always fixed after resolve?
        elif self._type == PaymentIdentifierType.BOLT11:
            return bool(self.bolt11.get_amount_sat())
        elif self._type in [PaymentIdentifierType.LNURLP, PaymentIdentifierType.LNADDR]:
            # amount limits known after resolve, might be specific amount or locked to range
            if self.need_resolve():
                return False
            if self.need_finalize():
                self.logger.debug(f'lnurl f {self.lnurl_data.min_sendable_sat}-{self.lnurl_data.max_sendable_sat}')
                return not (self.lnurl_data.min_sendable_sat < self.lnurl_data.max_sendable_sat)
            return True
        elif self._type == PaymentIdentifierType.MULTILINE:
            return True
        else:
            return False

    def is_error(self) -> bool:
        return self._state >= PaymentIdentifierState.ERROR

    def get_error(self) -> str:
        return self.error

    def parse(self, text: str):
        # parse text, set self._type and self.error
        text = text.strip()
        if not text:
            return
        if outputs := self._parse_as_multiline(text):
            self._type = PaymentIdentifierType.MULTILINE
            self.multiline_outputs = outputs
            if self.error:
                self.set_state(PaymentIdentifierState.INVALID)
            else:
                self.set_state(PaymentIdentifierState.AVAILABLE)
        elif invoice_or_lnurl := maybe_extract_lightning_payment_identifier(text):
            if invoice_or_lnurl.startswith('lnurl'):
                self._type = PaymentIdentifierType.LNURLP
                try:
                    self.lnurl = decode_lnurl(invoice_or_lnurl)
                    self.set_state(PaymentIdentifierState.NEED_RESOLVE)
                except Exception as e:
                    self.error = _("Error parsing LNURL") + f":\n{e}"
                    self.set_state(PaymentIdentifierState.INVALID)
                    return
            else:
                self._type = PaymentIdentifierType.BOLT11
                try:
                    self.bolt11 = Invoice.from_bech32(invoice_or_lnurl)
                except InvoiceError as e:
                    self.error = self._get_error_from_invoiceerror(e)
                    self.set_state(PaymentIdentifierState.INVALID)
                    self.logger.debug(f'Exception cause {e.args!r}')
                    return
                self.set_state(PaymentIdentifierState.AVAILABLE)
        elif text.lower().startswith(BITCOIN_BIP21_URI_SCHEME + ':'):
            try:
                out = parse_bip21_URI(text)
            except InvalidBitcoinURI as e:
                self.error = _("Error parsing URI") + f":\n{e}"
                self.set_state(PaymentIdentifierState.INVALID)
                return
            self.bip21 = out
            self.bip70 = out.get('r')
            if self.bip70:
                self._type = PaymentIdentifierType.BIP70
                self.set_state(PaymentIdentifierState.NEED_RESOLVE)
            else:
                self._type = PaymentIdentifierType.BIP21
                # check optional lightning in bip21, set self.bolt11 if valid
                bolt11 = out.get('lightning')
                if bolt11:
                    try:
                        self.bolt11 = Invoice.from_bech32(bolt11)
                        # carry BIP21 onchain address in Invoice.outputs in case bolt11 doesn't contain a fallback
                        # address but the BIP21 URI has one.
                        if bip21_address := self.bip21.get('address'):
                            amount = self.bip21.get('amount', 0)
                            self.bolt11.outputs = [PartialTxOutput.from_address_and_value(bip21_address, amount)]
                    except InvoiceError as e:
                        self.logger.debug(self._get_error_from_invoiceerror(e))
                self.set_state(PaymentIdentifierState.AVAILABLE)
        elif self.parse_output(text)[0]:
            scriptpubkey, is_address = self.parse_output(text)
            self._type = PaymentIdentifierType.SPK
            self.spk = scriptpubkey
            self.spk_is_address = is_address
            self.set_state(PaymentIdentifierState.AVAILABLE)
        elif self.contacts and (contact := self.contacts.by_name(text)):
            if contact['type'] == 'address':
                self._type = PaymentIdentifierType.BIP21
                self.bip21 = {
                    'address': contact['address'],
                    'label': contact['name']
                }
                self.set_state(PaymentIdentifierState.AVAILABLE)
            elif contact['type'] == 'openalias':
                self._type = PaymentIdentifierType.EMAILLIKE
                self.emaillike = contact['address']
                self.set_state(PaymentIdentifierState.NEED_RESOLVE)
        elif re.match(RE_EMAIL, text):
            self._type = PaymentIdentifierType.EMAILLIKE
            self.emaillike = text
            self.set_state(PaymentIdentifierState.NEED_RESOLVE)
        elif re.match(RE_DOMAIN, text):
            self._type = PaymentIdentifierType.DOMAINLIKE
            self.domainlike = text
            self.set_state(PaymentIdentifierState.NEED_RESOLVE)
        elif self.error is None:
            truncated_text = f"{text[:100]}..." if len(text) > 100 else text
            self.error = f"Unknown payment identifier:\n{truncated_text}"
            self.set_state(PaymentIdentifierState.INVALID)

    def resolve(self, *, on_finished: Callable[['PaymentIdentifier'], None]) -> None:
        assert self._state == PaymentIdentifierState.NEED_RESOLVE
        coro = self._do_resolve(on_finished=on_finished)
        asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    @log_exceptions
    async def _do_resolve(self, *, on_finished: Callable[['PaymentIdentifier'], None] = None):
        try:
            if self.emaillike or self.domainlike:
                # TODO: parallel lookup?
                key = self.emaillike if self.emaillike else self.domainlike
                data = await self.resolve_openalias(key)
                if data:
                    self.openalias_data = data
                    self.logger.debug(f'OA: {data!r}')
                    address = data.get('address')
                    if not data.get('validated'):
                        self.warning = _(
                            'WARNING: the alias "{}" could not be validated via an additional '
                            'security check, DNSSEC, and thus may not be correct.').format(key)
                    try:
                        assert bitcoin.is_address(address)
                        scriptpubkey = bitcoin.address_to_script(address)
                        self._type = PaymentIdentifierType.OPENALIAS
                        self.spk = scriptpubkey
                        self.set_state(PaymentIdentifierState.AVAILABLE)
                    except Exception as e:
                        self.error = str(e)
                        self.set_state(PaymentIdentifierState.NOT_FOUND)
                elif self.emaillike:
                    lnurl = lightning_address_to_url(self.emaillike)
                    try:
                        data = await request_lnurl(lnurl)
                        self._type = PaymentIdentifierType.LNADDR
                        self.lnurl = lnurl
                        self.lnurl_data = data
                        self.set_state(PaymentIdentifierState.LNURLP_FINALIZE)
                    except LNURLError as e:
                        self.set_state(PaymentIdentifierState.NOT_FOUND)
                    except Exception as e:
                        # NOTE: any other exception is swallowed here (e.g. DNS error)
                        # as the user may be typing and we have an incomplete emaillike
                        self.set_state(PaymentIdentifierState.NOT_FOUND)
                else:
                    self.set_state(PaymentIdentifierState.NOT_FOUND)
            elif self.bip70:
                pr = await paymentrequest.get_payment_request(self.bip70)
                if pr.verify():
                    self.bip70_data = pr
                    self.set_state(PaymentIdentifierState.MERCHANT_NOTIFY)
                else:
                    self.error = pr.error
                    self.set_state(PaymentIdentifierState.ERROR)
            elif self.lnurl:
                data = await request_lnurl(self.lnurl)
                self.lnurl_data = data
                self.set_state(PaymentIdentifierState.LNURLP_FINALIZE)
                self.logger.debug(f'LNURL data: {data!r}')
            else:
                self.set_state(PaymentIdentifierState.ERROR)
                return
        except Exception as e:
            self.error = str(e)
            self.logger.error(f"_do_resolve() got error: {e!r}")
            self.set_state(PaymentIdentifierState.ERROR)
        finally:
            if on_finished:
                on_finished(self)

    def finalize(
        self,
        *,
        amount_sat: int = 0,
        comment: str = None,
        on_finished: Callable[['PaymentIdentifier'], None] = None,
    ):
        assert self._state == PaymentIdentifierState.LNURLP_FINALIZE
        coro = self._do_finalize(amount_sat=amount_sat, comment=comment, on_finished=on_finished)
        asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    @log_exceptions
    async def _do_finalize(
        self,
        *,
        amount_sat: int = None,
        comment: str = None,
        on_finished: Callable[['PaymentIdentifier'], None] = None,
    ):
        from .invoices import Invoice
        try:
            if not self.lnurl_data:
                raise Exception("Unexpected missing LNURL data")

            if not (self.lnurl_data.min_sendable_sat <= amount_sat <= self.lnurl_data.max_sendable_sat):
                self.error = _('Amount must be between {} and {} sat.').format(
                    self.lnurl_data.min_sendable_sat, self.lnurl_data.max_sendable_sat)
                self.set_state(PaymentIdentifierState.INVALID_AMOUNT)
                return

            if self.lnurl_data.comment_allowed == 0:
                comment = None
            params = {'amount': amount_sat * 1000}
            if comment:
                params['comment'] = comment

            try:
                invoice_data = await callback_lnurl(self.lnurl_data.callback_url, params=params)
            except LNURLError as e:
                self.error = f"LNURL request encountered error: {e}"
                self.set_state(PaymentIdentifierState.ERROR)
                return

            bolt11_invoice = invoice_data.get('pr')
            invoice = Invoice.from_bech32(bolt11_invoice)
            if invoice.get_amount_sat() != amount_sat:
                raise Exception("lnurl returned invoice with wrong amount")
            # this will change what is returned by get_fields_for_GUI
            self.bolt11 = invoice
            self.set_state(PaymentIdentifierState.AVAILABLE)
        except Exception as e:
            self.error = str(e)
            self.logger.error(f"_do_finalize() got error: {e!r}")
            self.set_state(PaymentIdentifierState.ERROR)
        finally:
            if on_finished:
                on_finished(self)

    def notify_merchant(
        self,
        *,
        tx: 'Transaction',
        refund_address: str,
        on_finished: Callable[['PaymentIdentifier'], None] = None,
    ):
        assert self._state == PaymentIdentifierState.MERCHANT_NOTIFY
        assert tx
        assert refund_address
        coro = self._do_notify_merchant(tx, refund_address, on_finished=on_finished)
        asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    @log_exceptions
    async def _do_notify_merchant(
        self,
        tx: 'Transaction',
        refund_address: str,
        *,
        on_finished: Callable[['PaymentIdentifier'], None] = None,
    ):
        try:
            if not self.bip70_data:
                self.set_state(PaymentIdentifierState.ERROR)
                return

            ack_status, ack_msg = await self.bip70_data.send_payment_and_receive_paymentack(tx.serialize(), refund_address)
            self.logger.info(f"Payment ACK: {ack_status}. Ack message: {ack_msg}")
            self.merchant_ack_status = ack_status
            self.merchant_ack_message = ack_msg
            self.set_state(PaymentIdentifierState.MERCHANT_ACK)
        except Exception as e:
            self.error = str(e)
            self.logger.error(f"_do_notify_merchant() got error: {e!r}")
            self.set_state(PaymentIdentifierState.MERCHANT_ERROR)
        finally:
            if on_finished:
                on_finished(self)

    def get_onchain_outputs(self, amount):
        if self.bip70:
            return self.bip70_data.get_outputs()
        elif self.multiline_outputs:
            return self.multiline_outputs
        elif self.spk:
            return [PartialTxOutput(scriptpubkey=self.spk, value=amount)]
        elif self.bip21:
            address = self.bip21.get('address')
            scriptpubkey, is_address = self.parse_output(address)
            assert is_address  # unlikely, but make sure it is an address, not a script
            return [PartialTxOutput(scriptpubkey=scriptpubkey, value=amount)]
        else:
            raise Exception('not onchain')

    def _parse_as_multiline(self, text: str):
        # filter out empty lines
        lines = text.split('\n')
        lines = [i for i in lines if i]
        is_multiline = len(lines) > 1
        outputs = []  # type: List[PartialTxOutput]
        errors = ''
        total = 0
        self._is_max = False
        for i, line in enumerate(lines):
            try:
                output = self.parse_address_and_amount(line)
                outputs.append(output)
                if parse_max_spend(output.value):
                    self._is_max = True
                else:
                    total += output.value
            except Exception as e:
                errors = f'{errors}line #{i}: {str(e)}\n'
                continue
        if is_multiline and errors:
            self.error = errors.strip() if errors else None
        self.logger.debug(f'multiline: {outputs!r}, {self.error}')
        return outputs

    def parse_address_and_amount(self, line: str) -> PartialTxOutput:
        try:
            x, y = line.split(',')
        except ValueError:
            raise Exception("expected two comma-separated values: (address, amount)") from None
        scriptpubkey, is_address = self.parse_output(x)
        if not scriptpubkey:
            raise Exception('Invalid address')
        amount = self.parse_amount(y)
        return PartialTxOutput(scriptpubkey=scriptpubkey, value=amount)

    def parse_output(self, x: str) -> Tuple[Optional[bytes], bool]:
        try:
            address = self.parse_address(x)
            return bitcoin.address_to_script(address), True
        except Exception as e:
            pass
        try:
            m = re.match('^' + RE_SCRIPT_FN + '$', x)
            script = self.parse_script(str(m.group(1)))
            return script, False
        except Exception as e:
            pass

        return None, False

    def parse_script(self, x: str) -> bytes:
        script = bytearray()
        for word in x.split():
            if word[0:3] == 'OP_':
                opcode_int = opcodes[word]
                script += construct_script([opcode_int])
            else:
                bytes.fromhex(word)  # to test it is hex data
                script += construct_script([word])
        return bytes(script)

    def parse_amount(self, x: str) -> Union[str, int]:
        x = x.strip()
        if not x:
            raise Exception("Amount is empty")
        if parse_max_spend(x):
            return x
        p = pow(10, self.config.get_decimal_point())
        try:
            return int(p * Decimal(x))
        except InvalidOperation:
            raise Exception("Invalid amount")

    def parse_address(self, line: str):
        r = line.strip()
        m = re.match('^' + RE_ALIAS + '$', r)
        address = str(m.group(2) if m else r)
        assert bitcoin.is_address(address)
        return address

    def _get_error_from_invoiceerror(self, e: 'InvoiceError') -> str:
        error = _("Error parsing Lightning invoice") + f":\n{e!r}"
        if e.args and len(e.args):
            arg = e.args[0]
            if isinstance(arg, LnInvoiceException):
                error = _("Error parsing Lightning invoice") + f":\n{e}"
            elif isinstance(arg, IncompatibleOrInsaneFeatures):
                error = _("Invoice requires unknown or incompatible Lightning feature") + f":\n{e!r}"
        return error

    def get_fields_for_GUI(self) -> FieldsForGUI:
        recipient = None
        amount = None
        description = None
        validated = None
        comment = None
        amount_range = None

        if (self.emaillike or self.domainlike) and self.openalias_data:
            key = self.emaillike if self.emaillike else self.domainlike
            address = self.openalias_data.get('address')
            name = self.openalias_data.get('name')
            description = name
            recipient = key + ' <' + address + '>'
            validated = self.openalias_data.get('validated')
            if not validated:
                self.warning = _('WARNING: the alias "{}" could not be validated via an additional '
                                 'security check, DNSSEC, and thus may not be correct.').format(key)

        elif self.bolt11:
            recipient, amount, description = self._get_bolt11_fields()

        elif self.lnurl and self.lnurl_data:
            domain = urllib.parse.urlparse(self.lnurl).netloc
            recipient = f"{self.lnurl_data.metadata_plaintext} <{domain}>"
            description = self.lnurl_data.metadata_plaintext
            if self.lnurl_data.comment_allowed:
                comment = self.lnurl_data.comment_allowed
            if self.lnurl_data.min_sendable_sat:
                amount = self.lnurl_data.min_sendable_sat
                if self.lnurl_data.min_sendable_sat != self.lnurl_data.max_sendable_sat:
                    amount_range = (self.lnurl_data.min_sendable_sat, self.lnurl_data.max_sendable_sat)

        elif self.bip70 and self.bip70_data:
            pr = self.bip70_data
            if pr.error:
                self.error = pr.error
            else:
                recipient = pr.get_requestor()
                amount = pr.get_amount()
                description = pr.get_memo()
                validated = not pr.has_expired()

        elif self.spk:
            pass

        elif self.multiline_outputs:
            pass

        elif self.bip21:
            label = self.bip21.get('label')
            address = self.bip21.get('address')
            recipient = f'{label} <{address}>' if label else address
            amount = self.bip21.get('amount')
            description = self.bip21.get('message')
            # TODO: use label as description? (not BIP21 compliant)
            # if label and not description:
            #     description = label

        return FieldsForGUI(recipient=recipient, amount=amount, description=description,
                            comment=comment, validated=validated, amount_range=amount_range)

    def _get_bolt11_fields(self):
        lnaddr = self.bolt11._lnaddr # TODO: improve access to lnaddr
        pubkey = lnaddr.pubkey.serialize().hex()
        for k, v in lnaddr.tags:
            if k == 'd':
                description = v
                break
        else:
            description = ''
        amount = lnaddr.get_amount_sat()
        return pubkey, amount, description

    async def resolve_openalias(self, key: str) -> Optional[dict]:
        # TODO: below check needed? we already matched RE_EMAIL/RE_DOMAIN
        # if not (('.' in key) and ('<' not in key) and (' ' not in key)):
        #     return None
        parts = key.split(sep=',')  # assuming single line
        if parts and len(parts) > 0 and bitcoin.is_address(parts[0]):
            return None
        try:
            data = self.contacts.resolve(key)  # TODO: don't use contacts as delegate to resolve openalias, separate.
            return data
        except AliasNotFoundException as e:
            self.logger.info(f'OpenAlias not found: {repr(e)}')
            return None
        except Exception as e:
            self.logger.info(f'error resolving address/alias: {repr(e)}')
            return None

    def has_expired(self):
        if self.bip70 and self.bip70_data:
            return self.bip70_data.has_expired()
        elif self.bolt11:
            return self.bolt11.has_expired()
        elif self.bip21:
            expires = self.bip21.get('exp') + self.bip21.get('time') if self.bip21.get('exp') else 0
            return bool(expires) and expires < time.time()
        return False


def invoice_from_payment_identifier(
    pi: 'PaymentIdentifier',
    wallet: 'Abstract_Wallet',
    amount_sat: Union[int, str],
    message: str = None
) -> Optional[Invoice]:
    assert pi.state in [PaymentIdentifierState.AVAILABLE, PaymentIdentifierState.MERCHANT_NOTIFY]
    assert pi.is_onchain() if amount_sat == '!' else True  # MAX should only be allowed if pi has onchain destination

    if pi.is_lightning() and not amount_sat == '!':
        invoice = pi.bolt11
        if not invoice:
            return
        if invoice.amount_msat is None:
            invoice.set_amount_msat(int(amount_sat * 1000))
        return invoice
    else:
        outputs = pi.get_onchain_outputs(amount_sat)
        message = pi.bip21.get('message') if pi.bip21 else message
        bip70_data = pi.bip70_data if pi.bip70 else None
        return wallet.create_invoice(
            outputs=outputs,
            message=message,
            pr=bip70_data,
            URI=pi.bip21)


# Note: this is only really used for bip70 to handle MECHANT_NOTIFY state from
# a saved bip70 invoice.
# TODO: reflect bip70-only in function name, or implement other types as well.
def payment_identifier_from_invoice(
    wallet: 'Abstract_Wallet',
    invoice: Invoice
) -> Optional[PaymentIdentifier]:
    if not invoice:
        return
    pi = PaymentIdentifier(wallet, '')
    if invoice.bip70:
        pi._type = PaymentIdentifierType.BIP70
        pi.bip70_data = paymentrequest.PaymentRequest(bytes.fromhex(invoice.bip70))
        pi.set_state(PaymentIdentifierState.MERCHANT_NOTIFY)
        return pi
    # else:
    #     if invoice.outputs:
    #         if len(invoice.outputs) > 1:
    #             pi._type = PaymentIdentifierType.MULTILINE
    #             pi.multiline_outputs = invoice.outputs
    #             pi.set_state(PaymentIdentifierState.AVAILABLE)
    #         else:
    #             pi._type = PaymentIdentifierType.BIP21
    #             params = {}
    #             if invoice.exp:
    #                 params['exp'] = str(invoice.exp)
    #             if invoice.time:
    #                 params['time'] = str(invoice.time)
    #             pi.bip21 = create_bip21_uri(invoice.outputs[0].address, invoice.get_amount_sat(), invoice.message,
    #                                         extra_query_params=params)
    #             pi.set_state(PaymentIdentifierState.AVAILABLE)
    #     elif invoice.is_lightning():
    #         pi._type = PaymentIdentifierType.BOLT11
    #         pi.bolt11 = invoice
    #         pi.set_state(PaymentIdentifierState.AVAILABLE)
    #     else:
    #         return None
    #     return pi
