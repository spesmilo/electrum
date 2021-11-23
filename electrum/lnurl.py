"""Module for lnurl-related functionality."""
# https://github.com/sipa/bech32/tree/master/ref/python
# https://github.com/lnbits/lnurl

import asyncio
import json
from typing import Callable, Optional
import re

import aiohttp.client_exceptions
from aiohttp import ClientResponse

from electrum.segwit_addr import bech32_decode, Encoding, convertbits
from electrum.lnaddr import LnDecodeException


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


def request_lnurl(url: str, request_over_proxy: Callable) -> dict:
    """Requests payment data from a lnurl."""
    try:
        response = request_over_proxy("get", url, timeout=2)
    except asyncio.TimeoutError as e:
        raise LNURLError("Server did not reply in time.") from e
    except aiohttp.client_exceptions.ClientError as e:
        raise LNURLError(f"Client error: {e}") from e
    # TODO: handling of specific client errors
    response = json.loads(response)
    if "metadata" in response:
        response["metadata"] = json.loads(response["metadata"])
    status = response.get("status")
    if status and status == "ERROR":
        raise LNURLError(f"LNURL request encountered an error: {response['reason']}")
    return response


def callback_lnurl(url: str, params: dict, request_over_proxy: Callable) -> dict:
    """Requests an invoice from a lnurl supporting server."""
    try:
        response = request_over_proxy("get", url, params=params)
    except aiohttp.client_exceptions.ClientError as e:
        raise LNURLError(f"Client error: {e}") from e
    # TODO: handling of specific errors
    response = json.loads(response)
    status = response.get("status")
    if status and status == "ERROR":
        raise LNURLError(f"LNURL request encountered an error: {response['reason']}")
    return response


def lightning_address_to_url(address: str) -> Optional[str]:
    """Converts an email-type lightning address to a decoded lnurl."""
    if re.match(r"[^@]+@[^@]+\.[^@]+", address):
        username, domain = address.split("@")
        return f"https://{domain}/.well-known/lnurlp/{username}"
