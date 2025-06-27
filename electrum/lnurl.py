"""Module for lnurl-related functionality."""
# https://github.com/sipa/bech32/tree/master/ref/python
# https://github.com/lnbits/lnurl

import asyncio
import json
from typing import Callable, Optional, NamedTuple, Any, TYPE_CHECKING
import re
import urllib.parse

import aiohttp.client_exceptions

from electrum import segwit_addr
from electrum.segwit_addr import bech32_decode, Encoding, convertbits, bech32_encode
from electrum.lnaddr import LnDecodeException, LnEncodeException
from electrum.network import Network
from electrum.logging import get_logger


_logger = get_logger(__name__)


class LNURLError(Exception):
    def __init__(self, message="", *args):
        # error messages are returned by the LNURL server, some services could try to trick
        # users into doing something by sending a malicious error message
        modified_message = f"[DO NOT TRUST THIS MESSAGE]:\n{message}"
        super().__init__(modified_message, *args)


def decode_lnurl(lnurl: str) -> str:
    """Converts bech32 encoded lnurl to url."""
    decoded_bech32 = bech32_decode(
        lnurl, ignore_long_length=True
    )
    hrp = decoded_bech32.hrp
    data = decoded_bech32.data
    if decoded_bech32.encoding is None:
        raise LnDecodeException("Bad bech32 checksum")
    if decoded_bech32.encoding != Encoding.BECH32:
        raise LnDecodeException("Bad bech32 encoding: must be using vanilla BECH32")
    if not hrp.startswith("lnurl"):
        raise LnDecodeException("Does not start with lnurl")
    data = convertbits(data, 5, 8, False)
    url = bytes(data).decode("utf-8")
    return url


def encode_lnurl(url: str) -> str:
    """Encode url to bech32 lnurl string."""
    try:
        url = url.encode("utf-8")
    except UnicodeError as e:
        raise LnEncodeException("invalid url") from e
    bech32_data = convertbits(url, 8, 5, True)
    assert bech32_data
    lnurl = bech32_encode(
        encoding=segwit_addr.Encoding.BECH32, hrp="lnurl", data=bech32_data)
    return lnurl.upper()


def _is_url_safe_enough_for_lnurl(url: str) -> bool:
    u = urllib.parse.urlparse(url)
    if u.scheme.lower() == "https":
        return True
    if u.netloc.endswith(".onion"):
        return True
    return False


def _parse_lnurl_response_callback_url(lnurl_response: dict) -> str:
    try:
        callback_url = lnurl_response['callback']
    except KeyError as e:
        raise LNURLError(f"Missing 'callback' field in lnurl response.") from e
    if not _is_url_safe_enough_for_lnurl(callback_url):
        raise LNURLError(
            f"This lnurl callback_url looks unsafe. It must use 'https://' or '.onion' (found: {callback_url[:10]}...)")
    return callback_url


# payRequest
# https://github.com/lnurl/luds/blob/227f850b701e9ba893c080103c683273e2feb521/06.md
class LNURL6Data(NamedTuple):
    callback_url: str
    max_sendable_sat: int
    min_sendable_sat: int
    metadata_plaintext: str
    comment_allowed: int
    #tag: str = "payRequest"

# withdrawRequest
# https://github.com/lnurl/luds/blob/227f850b701e9ba893c080103c683273e2feb521/03.md
class LNURL3Data(NamedTuple):
    # The URL which LN SERVICE would accept a withdrawal Lightning invoice as query parameter
    callback_url: str
    # Random or non-random string to identify the user's LN WALLET when using the callback URL
    k1: str
    # A default withdrawal invoice description
    default_description: str
    # Min amount the user can withdraw from LN SERVICE, or 0
    min_withdrawable_sat: int
    # Max amount the user can withdraw from LN SERVICE,
    # or equal to minWithdrawable if the user has no choice over the amounts
    max_withdrawable_sat: int

LNURLData = LNURL6Data | LNURL3Data


async def _request_lnurl(url: str) -> dict:
    """Requests payment data from a lnurl."""
    if not _is_url_safe_enough_for_lnurl(url):
        raise LNURLError(f"This lnurl looks unsafe. It must use 'https://' or '.onion' (found: {url[:10]}...)")
    try:
        response_raw = await Network.async_send_http_on_proxy("get", url, timeout=10)
    except asyncio.TimeoutError as e:
        raise LNURLError("LNURL server did not reply in time.") from e
    except aiohttp.client_exceptions.ClientError as e:
        raise LNURLError(f"Client error: {e}") from e
    try:
        response = json.loads(response_raw)
    except json.JSONDecodeError:
        raise LNURLError(f"Invalid response from LNURL server")

    status = response.get("status")
    if status and status == "ERROR":
        raise LNURLError(f"LNURL request encountered an error: {response.get('reason', '<missing reason>')}")
    return response


def _parse_lnurl6_response(lnurl_response: dict) -> LNURL6Data:
    # parse lnurl6 "metadata"
    metadata_plaintext = ""
    try:
        metadata_raw = lnurl_response["metadata"]
        metadata = json.loads(metadata_raw)
        for m in metadata:
            if m[0] == 'text/plain':
                metadata_plaintext = str(m[1])
    except Exception as e:
        raise LNURLError(
            f"Missing or malformed 'metadata' field in lnurl6 response. exc: {e!r}") from e
    # parse lnurl6 "callback"
    callback_url = _parse_lnurl_response_callback_url(lnurl_response)
    # parse lnurl6 "minSendable"/"maxSendable"
    try:
        max_sendable_sat = int(lnurl_response['maxSendable']) // 1000
        min_sendable_sat = int(lnurl_response['minSendable']) // 1000
    except Exception as e:
        raise LNURLError(
            f"Missing or malformed 'minSendable'/'maxSendable' field in lnurl6 response. {e=!r}") from e
    # parse lnurl6 "commentAllowed" (optional, described in lnurl-12)
    try:
        comment_allowed = int(lnurl_response['commentAllowed']) if 'commentAllowed' in lnurl_response else 0
    except Exception as e:
        raise LNURLError(f"Malformed 'commentAllowed' field in lnurl6 response. {e=!r}") from e
    data = LNURL6Data(
        callback_url=callback_url,
        max_sendable_sat=max_sendable_sat,
        min_sendable_sat=min_sendable_sat,
        metadata_plaintext=metadata_plaintext,
        comment_allowed=comment_allowed,
    )
    return data


def _parse_lnurl3_response(lnurl_response: dict) -> LNURL3Data:
    """Parses the server response received when requesting a LNURL-withdraw (lud3) request"""
    callback_url = _parse_lnurl_response_callback_url(lnurl_response)
    if not (k1 := lnurl_response.get('k1')):
        raise LNURLError(f"Missing k1 value in LNURL3 response: {lnurl_response=}")
    default_description = lnurl_response.get('defaultDescription', '')
    try:
        min_withdrawable_sat = int(lnurl_response['minWithdrawable']) // 1000
        max_withdrawable_sat = int(lnurl_response['maxWithdrawable']) // 1000
        assert max_withdrawable_sat >= min_withdrawable_sat, f"Invalid amounts: max < min amount"
        assert max_withdrawable_sat > 0, f"Invalid max amount: {max_withdrawable_sat} sat"
    except Exception as e:
        raise LNURLError(
            f"Missing or malformed 'minWithdrawable'/'minWithdrawable' field in lnurl3 response. {e=!r}") from e
    return LNURL3Data(
        callback_url=callback_url,
        k1=k1,
        default_description=default_description,
        min_withdrawable_sat=min_withdrawable_sat,
        max_withdrawable_sat=max_withdrawable_sat,
    )


async def request_lnurl(url: str) -> LNURLData:
    lnurl_dict = await _request_lnurl(url)
    tag = lnurl_dict.get('tag')
    if tag == 'payRequest':  # only LNURL6 is handled atm
        return _parse_lnurl6_response(lnurl_dict)
    elif tag == 'withdrawRequest':
        return _parse_lnurl3_response(lnurl_dict)
    raise LNURLError(f"Unknown subtype of lnurl. tag={tag}")


async def try_resolve_lnurlpay(lnurl: Optional[str]) -> Optional[LNURL6Data]:
    if lnurl:
        try:
            result = await request_lnurl(lnurl)
            assert isinstance(result, LNURL6Data), f"lnurl result is not LNURL-pay response: {result=}"
            return result
        except Exception as request_error:
            _logger.debug(f"Error resolving lnurl: {request_error!r}")
    return None

async def request_lnurl_withdraw_callback(callback_url: str, k1: str, bolt_11: str) -> None:
    assert bolt_11
    params = {
        "k1": k1,
        "pr": bolt_11,
    }
    await callback_lnurl(
        url=callback_url,
        params=params
    )

async def callback_lnurl(url: str, params: dict) -> dict:
    """Requests an invoice from a lnurl supporting server."""
    if not _is_url_safe_enough_for_lnurl(url):
        raise LNURLError(f"This lnurl looks unsafe. It must use 'https://' or '.onion' (found: {url[:10]}...)")
    try:
        response_raw = await Network.async_send_http_on_proxy("get", url, params=params)
    except asyncio.TimeoutError as e:
        raise LNURLError("LNURL server did not reply in time.") from e
    except aiohttp.client_exceptions.ClientError as e:
        raise LNURLError(f"Client error: {e}") from e
    try:
        response = json.loads(response_raw)
    except json.JSONDecodeError:
        raise LNURLError(f"Invalid response from LNURL server")

    status = response.get("status")
    if status and status == "ERROR":
        raise LNURLError(f"LNURL request encountered an error: {response.get('reason', '<missing reason>')}")
    # TODO: handling of specific errors (validate fields, e.g. for lnurl6)
    return response


def lightning_address_to_url(address: str) -> Optional[str]:
    """Converts an email-type lightning address to a decoded lnurl.
    see https://github.com/fiatjaf/lnurl-rfc/blob/luds/16.md
    """
    if re.match(r"^[^@]+@[^.@]+(\.[^.@]+)+$", address):
        username, domain = address.split("@")
        return f"https://{domain}/.well-known/lnurlp/{username}"
