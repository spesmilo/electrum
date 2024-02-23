# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2023 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import io
import time

from . import lnmsg
from .segwit_addr import bech32_decode, DecodedBech32, convertbits


def is_offer(data: str):
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    if d == DecodedBech32(None, None, None):
        return False
    return d.hrp == 'lno'


def decode_offer(data):
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    d = bytes(convertbits(d.data, 5, 8))
    # we bomb on trailing 0, remove
    while d[-1] == 0:
        d = d[:-1]
    f = io.BytesIO(d)
    lns = lnmsg.LNSerializer()
    return lns.read_tlv_stream(fd=f, tlv_stream_name='offer')


def decode_invoice_request(data):
    # we bomb on trailing 0, remove
    while data[-1] == 0:
        data = data[:-1]
    f = io.BytesIO(data)
    lns = lnmsg.LNSerializer()
    return lns.read_tlv_stream(fd=f, tlv_stream_name='invoice_request')


def decode_invoice(data):
    # we bomb on trailing 0, remove
    while data[-1] == 0:
        data = data[:-1]
    f = io.BytesIO(data)
    lns = lnmsg.LNSerializer()
    return lns.read_tlv_stream(fd=f, tlv_stream_name='invoice')


async def request_invoice(bolt12_offer):
    time.sleep(5)
