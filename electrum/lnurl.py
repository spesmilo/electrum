"""Module for lnurl-related functionality."""
# https://github.com/sipa/bech32/tree/master/ref/python
# https://github.com/lnbits/lnurl

import asyncio
import json
from typing import Callable, Optional, NamedTuple, Any, TYPE_CHECKING
import re

import aiohttp.client_exceptions
from aiohttp import ClientResponse

from electrum.segwit_addr import bech32_decode, Encoding, convertbits
from electrum.lnaddr import LnDecodeException
from electrum.network import Network

if TYPE_CHECKING:
    from collections.abc import Coroutine


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


class LNURL6Data(NamedTuple):
    callback_url: str
    max_sendable_sat: int
    min_sendable_sat: int
    metadata_plaintext: str
    comment_allowed: int
    #tag: str = "payRequest"


async def _request_lnurl(url: str) -> dict:
    """Requests payment data from a lnurl."""
    try:
        response = await Network.async_send_http_on_proxy("get", url, timeout=10)
        response = json.loads(response)
    except asyncio.TimeoutError as e:
        raise LNURLError("Server did not reply in time.") from e
    except aiohttp.client_exceptions.ClientError as e:
        raise LNURLError(f"Client error: {e}") from e
    except json.JSONDecodeError:
        raise LNURLError(f"Invalid response from server")
    # TODO: handling of specific client errors

    if "metadata" in response:
        response["metadata"] = json.loads(response["metadata"])
    status = response.get("status")
    if status and status == "ERROR":
        raise LNURLError(f"LNURL request encountered an error: {response['reason']}")
    return response


async def request_lnurl(url: str) -> LNURL6Data:
    lnurl_dict = await _request_lnurl(url)
    tag = lnurl_dict.get('tag')
    if tag != 'payRequest':  # only LNURL6 is handled atm
        raise LNURLError(f"Unknown subtype of lnurl. tag={tag}")
    metadata = lnurl_dict.get('metadata')
    metadata_plaintext = ""
    for m in metadata:
        if m[0] == 'text/plain':
            metadata_plaintext = str(m[1])
    data = LNURL6Data(
        callback_url=lnurl_dict['callback'],
        max_sendable_sat=int(lnurl_dict['maxSendable']) // 1000,
        min_sendable_sat=int(lnurl_dict['minSendable']) // 1000,
        metadata_plaintext=metadata_plaintext,
        comment_allowed=int(lnurl_dict['commentAllowed']) if 'commentAllowed' in lnurl_dict else 0
    )
    return data


async def callback_lnurl(url: str, params: dict) -> dict:
    """Requests an invoice from a lnurl supporting server."""
    try:
        response = await Network.async_send_http_on_proxy("get", url, params=params)
    except aiohttp.client_exceptions.ClientError as e:
        raise LNURLError(f"Client error: {e}") from e
    # TODO: handling of specific errors
    response = json.loads(response)
    status = response.get("status")
    if status and status == "ERROR":
        raise LNURLError(f"LNURL request encountered an error: {response['reason']}")
    return response


def lightning_address_to_url(address: str) -> Optional[str]:
    """Converts an email-type lightning address to a decoded lnurl.
    see https://github.com/fiatjaf/lnurl-rfc/blob/luds/16.md
    """
    if re.match(r"[^@]+@[^@]+\.[^@]+", address):
        username, domain = address.split("@")
        return f"https://{domain}/.well-known/lnurlp/{username}"
