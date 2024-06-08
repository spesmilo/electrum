"""Module for lnurl-related functionality."""
# https://github.com/sipa/bech32/tree/master/ref/python
# https://github.com/lnbits/lnurl

import asyncio
import json
from typing import Callable, Optional, NamedTuple, Any, TYPE_CHECKING
import re
import urllib.parse

import aiohttp.client_exceptions
from aiohttp import ClientResponse

from electrum import segwit_addr
from electrum.segwit_addr import bech32_decode, Encoding, convertbits, bech32_encode
from electrum.lnaddr import LnDecodeException, LnEncodeException
from electrum.network import Network
from electrum.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Coroutine


_logger = get_logger(__name__)


class LNURLError(Exception):
    pass


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


class LNURL6Data(NamedTuple):
    callback_url: str
    max_sendable_sat: int
    min_sendable_sat: int
    metadata_plaintext: str
    comment_allowed: int
    #tag: str = "payRequest"


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


async def request_lnurl(url: str) -> LNURL6Data:
    lnurl_dict = await _request_lnurl(url)
    tag = lnurl_dict.get('tag')
    if tag != 'payRequest':  # only LNURL6 is handled atm
        raise LNURLError(f"Unknown subtype of lnurl. tag={tag}")
    # parse lnurl6 "metadata"
    metadata_plaintext = ""
    try:
        metadata_raw = lnurl_dict["metadata"]
        metadata = json.loads(metadata_raw)
        for m in metadata:
            if m[0] == 'text/plain':
                metadata_plaintext = str(m[1])
    except Exception as e:
        raise LNURLError(f"Missing or malformed 'metadata' field in lnurl6 response. exc: {e!r}") from e
    # parse lnurl6 "callback"
    try:
        callback_url = lnurl_dict['callback']
    except KeyError as e:
        raise LNURLError(f"Missing 'callback' field in lnurl6 response.") from e
    if not _is_url_safe_enough_for_lnurl(callback_url):
        raise LNURLError(f"This lnurl callback_url looks unsafe. It must use 'https://' or '.onion' (found: {callback_url[:10]}...)")
    # parse lnurl6 "minSendable"/"maxSendable"
    try:
        max_sendable_sat = int(lnurl_dict['maxSendable']) // 1000
        min_sendable_sat = int(lnurl_dict['minSendable']) // 1000
    except Exception as e:
        raise LNURLError(f"Missing or malformed 'minSendable'/'maxSendable' field in lnurl6 response. {e=!r}") from e
    # parse lnurl6 "commentAllowed" (optional, described in lnurl-12)
    try:
        comment_allowed = int(lnurl_dict['commentAllowed']) if 'commentAllowed' in lnurl_dict else 0
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
