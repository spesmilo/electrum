import asyncio
import time
import urllib
import re
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from typing import NamedTuple, Optional, Callable, List, TYPE_CHECKING

from . import bitcoin
from .contacts import AliasNotFoundException
from .i18n import _
from .logging import Logger
from .util import parse_max_spend, format_satoshis_plain
from .util import get_asyncio_loop, log_exceptions
from .transaction import PartialTxOutput
from .lnurl import decode_lnurl, request_lnurl, callback_lnurl, LNURLError, lightning_address_to_url
from .bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC, opcodes, construct_script
from .lnaddr import lndecode, LnDecodeException, LnInvoiceException
from .lnutil import IncompatibleOrInsaneFeatures

if TYPE_CHECKING:
    from .wallet import Abstract_Wallet


def maybe_extract_lightning_payment_identifier(data: str) -> Optional[str]:
    data = data.strip()  # whitespaces
    data = data.lower()
    if data.startswith(LIGHTNING_URI_SCHEME + ':ln'):
        cut_prefix = LIGHTNING_URI_SCHEME + ':'
        data = data[len(cut_prefix):]
    if data.startswith('ln'):
        return data
    return None

# URL decode
#_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
#urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)


# note: when checking against these, use .lower() to support case-insensitivity
BITCOIN_BIP21_URI_SCHEME = 'bitcoin'
LIGHTNING_URI_SCHEME = 'lightning'


class InvalidBitcoinURI(Exception):
    pass


def parse_bip21_URI(uri: str) -> dict:
    """Raises InvalidBitcoinURI on malformed URI."""

    if not isinstance(uri, str):
        raise InvalidBitcoinURI(f"expected string, not {repr(uri)}")

    if ':' not in uri:
        if not bitcoin.is_address(uri):
            raise InvalidBitcoinURI("Not a bitcoin address")
        return {'address': uri}

    u = urllib.parse.urlparse(uri)
    if u.scheme.lower() != BITCOIN_BIP21_URI_SCHEME:
        raise InvalidBitcoinURI("Not a bitcoin URI")
    address = u.path

    # python for android fails to parse query
    if address.find('?') > 0:
        address, query = u.path.split('?')
        pq = urllib.parse.parse_qs(query)
    else:
        pq = urllib.parse.parse_qs(u.query)

    for k, v in pq.items():
        if len(v) != 1:
            raise InvalidBitcoinURI(f'Duplicate Key: {repr(k)}')

    out = {k: v[0] for k, v in pq.items()}
    if address:
        if not bitcoin.is_address(address):
            raise InvalidBitcoinURI(f"Invalid bitcoin address: {address}")
        out['address'] = address
    if 'amount' in out:
        am = out['amount']
        try:
            m = re.match(r'([0-9.]+)X([0-9])', am)
            if m:
                k = int(m.group(2)) - 8
                amount = Decimal(m.group(1)) * pow(Decimal(10), k)
            else:
                amount = Decimal(am) * COIN
            if amount > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
                raise InvalidBitcoinURI(f"amount is out-of-bounds: {amount!r} BTC")
            out['amount'] = int(amount)
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'amount' field: {repr(e)}") from e
    if 'message' in out:
        out['message'] = out['message']
        out['memo'] = out['message']
    if 'time' in out:
        try:
            out['time'] = int(out['time'])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'time' field: {repr(e)}") from e
    if 'exp' in out:
        try:
            out['exp'] = int(out['exp'])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'exp' field: {repr(e)}") from e
    if 'sig' in out:
        try:
            out['sig'] = bitcoin.base_decode(out['sig'], base=58).hex()
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'sig' field: {repr(e)}") from e
    if 'lightning' in out:
        try:
            lnaddr = lndecode(out['lightning'])
        except LnDecodeException as e:
            raise InvalidBitcoinURI(f"Failed to decode 'lightning' field: {e!r}") from e
        amount_sat = out.get('amount')
        if amount_sat:
            # allow small leeway due to msat precision
            if abs(amount_sat - int(lnaddr.get_amount_sat())) > 1:
                raise InvalidBitcoinURI("Inconsistent lightning field in bip21: amount")
        address = out.get('address')
        ln_fallback_addr = lnaddr.get_fallback_address()
        if address and ln_fallback_addr:
            if ln_fallback_addr != address:
                raise InvalidBitcoinURI("Inconsistent lightning field in bip21: address")

    return out


def create_bip21_uri(addr, amount_sat: Optional[int], message: Optional[str],
                     *, extra_query_params: Optional[dict] = None) -> str:
    if not bitcoin.is_address(addr):
        return ""
    if extra_query_params is None:
        extra_query_params = {}
    query = []
    if amount_sat:
        query.append('amount=%s' % format_satoshis_plain(amount_sat))
    if message:
        query.append('message=%s' % urllib.parse.quote(message))
    for k, v in extra_query_params.items():
        if not isinstance(k, str) or k != urllib.parse.quote(k):
            raise Exception(f"illegal key for URI: {repr(k)}")
        v = urllib.parse.quote(v)
        query.append(f"{k}={v}")
    p = urllib.parse.ParseResult(
        scheme=BITCOIN_BIP21_URI_SCHEME,
        netloc='',
        path=addr,
        params='',
        query='&'.join(query),
        fragment=''
    )
    return str(urllib.parse.urlunparse(p))


def is_uri(data: str) -> bool:
    data = data.lower()
    if (data.startswith(LIGHTNING_URI_SCHEME + ":") or
            data.startswith(BITCOIN_BIP21_URI_SCHEME + ':')):
        return True
    return False


RE_ALIAS = r'(.*?)\s*\<([0-9A-Za-z]{1,})\>'
RE_EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'


class PaymentIdentifierState(IntEnum):
    EMPTY           = 0  # Initial state.
    INVALID         = 1  # Unrecognized PI
    AVAILABLE       = 2  # PI contains a payable destination
                         # payable means there's enough addressing information to submit to one
                         # of the channels Electrum supports (on-chain, lightning)
    NEED_RESOLVE    = 3  # PI contains a recognized destination format, but needs an online resolve step
    LNURLP_FINALIZE = 4  # PI contains a resolved LNURLp, but needs amount and comment to resolve to a bolt11
    MERCHANT_NOTIFY = 5  # PI contains a valid payment request and on-chain destination. It should notify
                         # the merchant payment processor of the tx after on-chain broadcast,
                         # and supply a refund address (bip70)
    MERCHANT_ACK    = 6  # PI notified merchant. nothing to be done.
    ERROR           = 50 # generic error
    NOT_FOUND       = 51 # PI contains a recognized destination format, but resolve step was unsuccesful
    MERCHANT_ERROR  = 52 # PI failed notifying the merchant after broadcasting onchain TX


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

    def __init__(self, wallet: 'Abstract_Wallet', text):
        Logger.__init__(self)
        self._state = PaymentIdentifierState.EMPTY
        self.wallet = wallet
        self.contacts = wallet.contacts if wallet is not None else None
        self.config = wallet.config if wallet is not None else None
        self.text = text.strip()
        self._type = None
        self.error = None    # if set, GUI should show error and stop
        self.warning = None  # if set, GUI should ask user if they want to proceed
        # more than one of those may be set
        self.multiline_outputs = None
        self._is_max = False
        self.bolt11 = None
        self.bip21 = None
        self.spk = None
        #
        self.emaillike = None
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
        self.logger.debug(f'PI state {self._state} -> {state}')
        self._state = state

    def is_state(self, state: 'PaymentIdentifierState'):
        return self._state == state

    def need_resolve(self):
        return self._state == PaymentIdentifierState.NEED_RESOLVE

    def need_finalize(self):
        return self._state == PaymentIdentifierState.LNURLP_FINALIZE

    def need_merchant_notify(self):
        return self._state == PaymentIdentifierState.MERCHANT_NOTIFY

    def is_valid(self):
        return self._state not in [PaymentIdentifierState.INVALID, PaymentIdentifierState.EMPTY]

    def is_lightning(self):
        return self.lnurl or self.bolt11

    def is_multiline(self):
        return bool(self.multiline_outputs)

    def is_multiline_max(self):
        return self.is_multiline() and self._is_max

    def is_amount_locked(self):
        if self._type == 'spk':
            return False
        elif self._type == 'bip21':
            return bool(self.bip21.get('amount'))
        elif self._type == 'bip70':
            return True  # TODO always given?
        elif self._type == 'bolt11':
            lnaddr = lndecode(self.bolt11)
            return bool(lnaddr.amount)
        elif self._type == 'lnurl' or self._type == 'lightningaddress':
            # amount limits known after resolve, might be specific amount or locked to range
            if self.need_resolve():
                return True
            if self.need_finalize():
                self.logger.debug(f'lnurl f {self.lnurl_data.min_sendable_sat}-{self.lnurl_data.max_sendable_sat}')
                return not (self.lnurl_data.min_sendable_sat < self.lnurl_data.max_sendable_sat)
            return True
        elif self._type == 'multiline':
            return True
        elif self._type == 'emaillike':
            return False
        elif self._type == 'openalias':
            return False

    def is_error(self) -> bool:
        return self._state >= PaymentIdentifierState.ERROR

    def get_error(self) -> str:
        return self.error

    def parse(self, text):
        # parse text, set self._type and self.error
        text = text.strip()
        if not text:
            return
        if outputs := self._parse_as_multiline(text):
            self._type = 'multiline'
            self.multiline_outputs = outputs
            if self.error:
                self.set_state(PaymentIdentifierState.INVALID)
            else:
                self.set_state(PaymentIdentifierState.AVAILABLE)
        elif invoice_or_lnurl := maybe_extract_lightning_payment_identifier(text):
            if invoice_or_lnurl.startswith('lnurl'):
                self._type = 'lnurl'
                try:
                    self.lnurl = decode_lnurl(invoice_or_lnurl)
                    self.set_state(PaymentIdentifierState.NEED_RESOLVE)
                except Exception as e:
                    self.error = _("Error parsing LNURL") + f":\n{e}"
                    self.set_state(PaymentIdentifierState.INVALID)
                    return
            else:
                self._type = 'bolt11'
                try:
                    lndecode(invoice_or_lnurl)
                except LnInvoiceException as e:
                    self.error = _("Error parsing Lightning invoice") + f":\n{e}"
                    self.set_state(PaymentIdentifierState.INVALID)
                    return
                except IncompatibleOrInsaneFeatures as e:
                    self.error = _("Invoice requires unknown or incompatible Lightning feature") + f":\n{e!r}"
                    self.set_state(PaymentIdentifierState.INVALID)
                    return
                self.bolt11 = invoice_or_lnurl
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
                self._type = 'bip70'
                self.set_state(PaymentIdentifierState.NEED_RESOLVE)
            else:
                self._type = 'bip21'
                # check optional lightning in bip21, set self.bolt11 if valid
                bolt11 = out.get('lightning')
                if bolt11:
                    try:
                        lndecode(bolt11)
                        # if we get here, we have a usable bolt11
                        self.bolt11 = bolt11
                    except LnInvoiceException as e:
                        self.logger.debug(_("Error parsing Lightning invoice") + f":\n{e}")
                    except IncompatibleOrInsaneFeatures as e:
                        self.logger.debug(_("Invoice requires unknown or incompatible Lightning feature") + f":\n{e!r}")
                self.set_state(PaymentIdentifierState.AVAILABLE)
        elif scriptpubkey := self.parse_output(text):
            self._type = 'spk'
            self.spk = scriptpubkey
            self.set_state(PaymentIdentifierState.AVAILABLE)
        elif re.match(RE_EMAIL, text):
            self._type = 'emaillike'
            self.emaillike = text
            self.set_state(PaymentIdentifierState.NEED_RESOLVE)
        elif self.error is None:
            truncated_text = f"{text[:100]}..." if len(text) > 100 else text
            self.error = f"Unknown payment identifier:\n{truncated_text}"
            self.set_state(PaymentIdentifierState.INVALID)

    def resolve(self, *, on_finished: 'Callable'):
        assert self._state == PaymentIdentifierState.NEED_RESOLVE
        coro = self._do_resolve(on_finished=on_finished)
        asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    @log_exceptions
    async def _do_resolve(self, *, on_finished=None):
        try:
            if self.emaillike:
                # TODO: parallel lookup?
                data = await self.resolve_openalias()
                if data:
                    self.openalias_data = data
                    self.logger.debug(f'OA: {data!r}')
                    name = data.get('name')
                    address = data.get('address')
                    self.contacts[self.emaillike] = ('openalias', name)
                    if not data.get('validated'):
                        self.warning = _(
                            'WARNING: the alias "{}" could not be validated via an additional '
                            'security check, DNSSEC, and thus may not be correct.').format(self.emaillike)
                    try:
                        scriptpubkey = self.parse_output(address)
                        self._type = 'openalias'
                        self.spk = scriptpubkey
                        self.set_state(PaymentIdentifierState.AVAILABLE)
                    except Exception as e:
                        self.error = str(e)
                        self.set_state(PaymentIdentifierState.NOT_FOUND)
                else:
                    lnurl = lightning_address_to_url(self.emaillike)
                    try:
                        data = await request_lnurl(lnurl)
                        self._type = 'lightningaddress'
                        self.lnurl = lnurl
                        self.lnurl_data = data
                        self.set_state(PaymentIdentifierState.LNURLP_FINALIZE)
                    except LNURLError as e:
                        self.set_state(PaymentIdentifierState.NOT_FOUND)
                    except Exception as e:
                        # NOTE: any other exception is swallowed here (e.g. DNS error)
                        # as the user may be typing and we have an incomplete emaillike
                        self.set_state(PaymentIdentifierState.NOT_FOUND)
            elif self.bip70:
                from . import paymentrequest
                data = await paymentrequest.get_payment_request(self.bip70)
                self.bip70_data = data
                self.set_state(PaymentIdentifierState.MERCHANT_NOTIFY)
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
            self.logger.error(repr(e))
            self.set_state(PaymentIdentifierState.ERROR)
        finally:
            if on_finished:
                on_finished(self)

    def finalize(self, *, amount_sat: int = 0, comment: str = None, on_finished: Callable = None):
        assert self._state == PaymentIdentifierState.LNURLP_FINALIZE
        coro = self._do_finalize(amount_sat, comment, on_finished=on_finished)
        asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    @log_exceptions
    async def _do_finalize(self, amount_sat: int = None, comment: str = None, on_finished: Callable = None):
        from .invoices import Invoice
        try:
            if not self.lnurl_data:
                raise Exception("Unexpected missing LNURL data")

            if not (self.lnurl_data.min_sendable_sat <= amount_sat <= self.lnurl_data.max_sendable_sat):
                self.error = _('Amount must be between %d and %d sat.') \
                    % (self.lnurl_data.min_sendable_sat, self.lnurl_data.max_sendable_sat)
                return
            if self.lnurl_data.comment_allowed == 0:
                comment = None
            params = {'amount': amount_sat * 1000}
            if comment:
                params['comment'] = comment
            try:
                invoice_data = await callback_lnurl(
                    self.lnurl_data.callback_url,
                    params=params,
                )
            except LNURLError as e:
                self.error = f"LNURL request encountered error: {e}"
                return
            bolt11_invoice = invoice_data.get('pr')
            #
            invoice = Invoice.from_bech32(bolt11_invoice)
            if invoice.get_amount_sat() != amount_sat:
                raise Exception("lnurl returned invoice with wrong amount")
            # this will change what is returned by get_fields_for_GUI
            self.bolt11 = bolt11_invoice
            self.set_state(PaymentIdentifierState.AVAILABLE)
        except Exception as e:
            self.error = str(e)
            self.logger.error(repr(e))
            self.set_state(PaymentIdentifierState.ERROR)
        finally:
            if on_finished:
                on_finished(self)

    def notify_merchant(self, *, tx: 'Transaction' = None, refund_address: str = None, on_finished: 'Callable' = None):
        assert self._state == PaymentIdentifierState.MERCHANT_NOTIFY
        assert tx
        coro = self._do_notify_merchant(tx, refund_address, on_finished=on_finished)
        asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    @log_exceptions
    async def _do_notify_merchant(self, tx, refund_address, *, on_finished: 'Callable'):
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
            self.logger.error(repr(e))
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
            scriptpubkey = self.parse_output(address)
            return [PartialTxOutput(scriptpubkey=scriptpubkey, value=amount)]
        else:
            raise Exception('not onchain')

    def _parse_as_multiline(self, text):
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

    def parse_address_and_amount(self, line) -> 'PartialTxOutput':
        try:
            x, y = line.split(',')
        except ValueError:
            raise Exception("expected two comma-separated values: (address, amount)") from None
        scriptpubkey = self.parse_output(x)
        if not scriptpubkey:
            raise Exception('Invalid address')
        amount = self.parse_amount(y)
        return PartialTxOutput(scriptpubkey=scriptpubkey, value=amount)

    def parse_output(self, x) -> bytes:
        try:
            address = self.parse_address(x)
            return bytes.fromhex(bitcoin.address_to_script(address))
        except Exception as e:
            pass
        try:
            script = self.parse_script(x)
            return bytes.fromhex(script)
        except Exception as e:
            pass

        # raise Exception("Invalid address or script.")

    def parse_script(self, x):
        script = ''
        for word in x.split():
            if word[0:3] == 'OP_':
                opcode_int = opcodes[word]
                script += construct_script([opcode_int])
            else:
                bytes.fromhex(word)  # to test it is hex data
                script += construct_script([word])
        return script

    def parse_amount(self, x):
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

    def parse_address(self, line):
        r = line.strip()
        m = re.match('^' + RE_ALIAS + '$', r)
        address = str(m.group(2) if m else r)
        assert bitcoin.is_address(address)
        return address

    def get_fields_for_GUI(self):
        recipient = None
        amount = None
        description = None
        validated = None
        comment = None

        if self.emaillike and self.openalias_data:
            address = self.openalias_data.get('address')
            name = self.openalias_data.get('name')
            recipient = self.emaillike + ' <' + address + '>'
            validated = self.openalias_data.get('validated')
            if not validated:
                self.warning = _('WARNING: the alias "{}" could not be validated via an additional '
                                 'security check, DNSSEC, and thus may not be correct.').format(self.emaillike)

        elif self.bolt11 and self.wallet.has_lightning():
            recipient, amount, description = self._get_bolt11_fields(self.bolt11)

        elif self.lnurl and self.lnurl_data:
            domain = urllib.parse.urlparse(self.lnurl).netloc
            recipient = f"{self.lnurl_data.metadata_plaintext} <{domain}>"
            amount = self.lnurl_data.min_sendable_sat if self.lnurl_data.min_sendable_sat else None
            description = self.lnurl_data.metadata_plaintext
            if self.lnurl_data.comment_allowed:
                comment = self.lnurl_data.comment_allowed

        elif self.bip70 and self.bip70_data:
            pr = self.bip70_data
            if pr.error:
                self.error = pr.error
                return
            recipient = pr.get_requestor()
            amount = pr.get_amount()
            description = pr.get_memo()
            validated = not pr.has_expired()
            # note: allow saving bip70 reqs, as we save them anyway when paying them
            #for btn in [self.send_button, self.clear_button, self.save_button]:
            #    btn.setEnabled(True)
            # signal to set fee
            #self.amount_e.textEdited.emit("")

        elif self.spk:
            pass

        elif self.multiline_outputs:
            pass

        elif self.bip21:
            recipient = self.bip21.get('address')
            amount = self.bip21.get('amount')
            label = self.bip21.get('label')
            description = self.bip21.get('message')
            # use label as description (not BIP21 compliant)
            if label and not description:
                description = label

        return recipient, amount, description, comment, validated

    def _get_bolt11_fields(self, bolt11_invoice):
        """Parse ln invoice, and prepare the send tab for it."""
        lnaddr = lndecode(bolt11_invoice) #
        pubkey = lnaddr.pubkey.serialize().hex()
        for k, v in lnaddr.tags:
            if k == 'd':
                description = v
                break
        else:
            description = ''
        amount = lnaddr.get_amount_sat()
        return pubkey, amount, description

    async def resolve_openalias(self) -> Optional[dict]:
        key = self.emaillike
        # TODO: below check needed? we already matched RE_EMAIL
        # if not (('.' in key) and ('<' not in key) and (' ' not in key)):
        #     return None
        parts = key.split(sep=',')  # assuming single line
        if parts and len(parts) > 0 and bitcoin.is_address(parts[0]):
            return None
        try:
            data = self.contacts.resolve(key) # TODO: don't use contacts as delegate to resolve openalias, separate.
            return data
        except AliasNotFoundException as e:
            self.logger.info(f'OpenAlias not found: {repr(e)}')
            return None
        except Exception as e:
            self.logger.info(f'error resolving address/alias: {repr(e)}')
            return None

    def has_expired(self):
        if self.bip70:
            return self.bip70_data.has_expired()
        elif self.bolt11:
            lnaddr = lndecode(self.bolt11)
            return lnaddr.is_expired()
        elif self.bip21:
            expires = self.bip21.get('exp') + self.bip21.get('time') if self.bip21.get('exp') else 0
            return bool(expires) and expires < time.time()
        return False

    def get_invoice(self, amount_sat, message):
        from .invoices import Invoice
        if self.is_lightning():
            invoice_str = self.bolt11
            if not invoice_str:
                return
            invoice = Invoice.from_bech32(invoice_str)
            if invoice.amount_msat is None:
                invoice.amount_msat = int(amount_sat * 1000)
            return invoice
        else:
            outputs = self.get_onchain_outputs(amount_sat)
            message = self.bip21.get('message') if self.bip21 else message
            bip70_data = self.bip70_data if self.bip70 else None
            return self.wallet.create_invoice(
                outputs=outputs,
                message=message,
                pr=bip70_data,
                URI=self.bip21)
