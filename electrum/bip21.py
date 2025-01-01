import urllib
import re
from decimal import Decimal
from typing import Optional

from . import bitcoin
from .util import format_satoshis_plain
from .bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from .lnaddr import lndecode, LnDecodeException

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
        if k.startswith('req-'):
            # we have no support for any req-* query parameters
            raise InvalidBitcoinURI(f'Unsupported Key: {repr(k)}')

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
            if amount > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN or amount <= 0:
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
            if lnaddr.get_amount_sat() is None or abs(amount_sat - int(lnaddr.get_amount_sat())) > 1:
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
