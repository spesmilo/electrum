# Copyright (C) 2024 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import hashlib


def sha256(x: bytes) -> bytes:
    return bytes(hashlib.sha256(x).digest())


def bip340_tagged_hash(tag: bytes, msg: bytes) -> bytes:
    # note: _libsecp256k1.secp256k1_tagged_sha256 benchmarks about 70% slower than this (on my machine)
    return sha256(sha256(tag) + sha256(tag) + msg)

