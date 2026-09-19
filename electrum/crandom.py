# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# Cryptographically secure RNG.
#
# This mostly uses os.urandom, and extreme care should be taken here not to make things worse
# compared to just directly using that.
# We check os.urandom is not trivially broken (passes the zlib test), in which case we panic and runtime exit.
# However, os.urandom could still be subtly "broken" (undetected by us) and produce bad quality output.
# That's the motivation of all this code. We expect os.urandom to work well, BUT if it undetectably does not,
# hopefully mixing in other sources of entropy mitigates the situation somewhat.
#
# inspired by https://github.com/bitcoin/bitcoin/blob/67efced1fc83a0b7215cc1513e7c4754fee0f12f/src/random.h#L25
#
# The logic is split across two modules: crandom.py and crandom_env.py.
# - The core sensitive logic (RNG mixing, extracting random bytes) is in this module (crandom.py),
#   which is absolutely security critical and is kept concise to ease review.
# - crandom_env.py contains secondary sources of entropy and potentially platform-specific code.
#   Even if all the entropy sources listed in crandom_env.py are broken, assuming os.urandom()
#   produces high quality random, this module should never produce low-quality random output.

import hashlib
import os
import threading
import time
from typing import Callable
import zlib

from . import crandom_env
from .logging import Logger


# Check that os.urandom works
length = len(zlib.compress(os.urandom(1000)))
if length <= 900:
    raise ImportError("Broken PRNG. Refusing to continue. Exiting...")


def sha512(x: bytes) -> bytes:
    assert isinstance(x, bytes)
    return hashlib.sha512(x).digest()


CRANDOM_FEEDER_API = Callable[[bytes | str | int], None]


class RNGState(Logger):

    def __init__(self):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self._state = os.urandom(32)  # secret!  access needs lock.
        self._last_strengthened = 0
        self._last_dyn_refresh_slow = 0
        # gather ghetto-entropy:
        self.rand_add_refresh()  # clock
        crandom_env.rand_add_static_env(self.feed_entropy)
        self.rand_add_refresh()  # clock again

    def rand_add_refresh(self) -> None:
        """Gather dynamic environment data that changes over time and mix it in.
        This includes a high-precision clock.

        Never raises.
        """
        with self.lock:
            now = time.monotonic()
            incl_slow = False
            if now - self._last_dyn_refresh_slow > 60:  # been more than 1 minute
                self._last_dyn_refresh_slow = now
                incl_slow = True
        crandom_env.rand_add_dynamic_env(self.feed_entropy, include_slow_sources=incl_slow)

    def feed_entropy(self, data: bytes | str | int) -> None:
        """Mix in some data into our internal RNG state, in hopes of increasing entropy.

        We MUST be robust for given 'data' not to contain any randomness, it could even be static.
        Assuming our internal hash function is cryptographically secure, our internal state
        MUST not be left with less entropy than before the call.

        Never raises (assuming input type-checks).
        Matches CRANDOM_FEEDER_API.
        """
        if not data:
            return
        if isinstance(data, int):
            data = hex(data)
        if isinstance(data, str):
            # we must not raise UnicodeError, hence "backslashreplace"
            data = data.encode("utf-8", errors='backslashreplace')
        with self.lock:
            self._state = sha512(data + self._state)[0:32]
            assert len(self._state) == 32

    def _mix_extract(self) -> bytes:
        """Return 32 bytes of secure randomness.

        Mix in some new entropy from os.urandom first, and then extract 32 bytes.
        When mixing in new entropy, H = SHA512(new_entropy || old_rng_state) is computed, and
        the first 32 bytes of H are produced as output, while the last 32 bytes
        become the new RNG state.

        Never raises.
        """
        with self.lock:
            now = time.monotonic()
            if self._last_strengthened == 0:  # on first invocation, do some work
                self._last_strengthened = now
                self._strengthen(0.1)  # 100 ms
            elif now - self._last_strengthened > 60:  # been more than 1 minute
                self._last_strengthened = now
                self._strengthen(0)    # single hash-loop
            fresh_entropy = os.urandom(32)
            h = sha512(fresh_entropy + self._state)
            out, self._state = h[0:32], h[32:64]
            assert len(out) == 32
            assert len(self._state) == 32
            return out

    def get_rand_bytes(self, nbytes: int) -> bytes:
        """Returns uniformly distributed bytes, of length nbytes.

        Never raises.
        """
        assert nbytes >= 0, nbytes
        out = b""
        while len(out) < nbytes:
            out += self._mix_extract()
        return out[:nbytes]

    def _get_rand_bits(self, nbits: int) -> int:
        """Return a uniformly distributed int in the range [0, 2**nbits).

        Never raises.
        """
        assert nbits >= 0, nbits
        nbytes = nbits // 8 + (1 if nbits % 8 else 0)
        rb = self.get_rand_bytes(nbytes)
        ri = int.from_bytes(rb, byteorder="big", signed=False)
        # strip excess bits (we got up to 7 more than we asked for)
        extra_bits = 8 * nbytes - nbits
        assert 0 <= extra_bits < 8
        ri = ri >> extra_bits
        return ri

    def get_rand_below(self, upper_bound: int) -> int:
        """Return a uniformly distributed int in the range [0, upper_bound).

        Never raises.
        """
        assert upper_bound > 0, upper_bound
        nbits = upper_bound.bit_length()
        ri = upper_bound + 1
        # Keep generating random ints until we get one inside the requested range.
        # On average, we expect around 2 iterations.
        while ri >= upper_bound:
            ri = self._get_rand_bits(nbits)
        return ri

    def _strengthen(self, duration_sec: float | int) -> None:
        """Extract some random bytes, repeatedly hash it using SHA512, and then feed it back.

        This sort of mimics the iteration count of a KDF: an attacker trying to bruteforce/enumerate
        the possible internal states, e.g. due to broken (low-entropy) randomness,
        has to re-do this hashing for each attempt.

        Never raises.
        """
        self.logger.info(f"starting strengthen for {duration_sec} sec")
        self.rand_add_refresh()  # clock
        xhash = self._mix_extract()
        t0 = time.monotonic()
        cnt = 0
        while cnt == 0 or time.monotonic() - t0 < duration_sec:
            for _i in range(1000):
                cnt += 1
                xhash = sha512(xhash)
        self.rand_add_refresh()  # clock again
        self.feed_entropy(xhash)
        self.logger.info(f"finished strengthen. iter count: {cnt:_}")


_rng = RNGState()


########################################
# External API (thread-safe):

get_rand_bytes = _rng.get_rand_bytes
get_rand_below = _rng.get_rand_below
feed_entropy = _rng.feed_entropy
rand_add_refresh = _rng.rand_add_refresh
