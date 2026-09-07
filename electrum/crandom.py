# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# Cryptographically secure RNG.

import os
import secrets


def get_rand_bytes(nbytes: int) -> bytes:
    """Returns uniformly distributed bytes, of length nbytes."""
    assert nbytes >= 0, nbytes
    return os.urandom(nbytes)


def get_rand_below(upper_bound: int) -> int:
    """Return a uniformly distributed int in the range [0, upper_bound)."""
    assert upper_bound > 0, upper_bound
    return secrets.randbelow(upper_bound)

