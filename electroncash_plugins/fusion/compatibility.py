#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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
"""
Compatibility checking.
"""

# Please avoid introducing local imports here, as in future it would be
# nice if plugins could check compatibility in the plugins enable/disable menu
# (i.e. in the __init__.py)
from electroncash import schnorr
from google.protobuf.message import Message

def check():
    # Pure-python schnorr should't be used since fusion requires so many
    # curve ops, so that CPU usage can be quite high and can cause rounds to
    # fail due to slowed responses. This applies on both on server and client
    # side.
    if not schnorr.has_fast_sign() or not schnorr.has_fast_verify():
        raise RuntimeError("Fusion requires libsecp256k1")

    # Old versions of protobuf < 3.7.0 have missing API that we need in
    # validation.proto_strict_parse.
    # - .ParseFromString() may fail to return the length parsed. (It will
    #   actually work properly if the c++ backend is used.)
    # - .UnknownFields() missing.
    try:
        # This check works on >=3.7.0 and fails on <= 3.6.1, regardless of
        # backend.
        Message.UnknownFields
    except AttributeError:
        raise RuntimeError("Fusion requires python protobuf >= 3.7.0") from None
