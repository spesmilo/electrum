import hashlib
import time
from unittest import mock

from electrum import crandom

from . import ElectrumTestCase
from .test_wallet_vertical import UNICODE_HORROR

class TestCRandom(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        crandom._rng._last_strengthened = time.monotonic()  # disable periodic strengthen() calls

    def test_feed_entropy_naive(self):
        def run():
            datas = ["mystr1", 53, -866, b"\x01\x02\x03"]
            for data in datas:
                state = crandom._rng._state
                crandom.feed_entropy(data)
                self.assertNotEqual(state, crandom._rng._state)
        # internal state changes after feed_entropy():
        state1 = crandom._rng._state
        run()
        state2 = crandom._rng._state
        assert state1 != state2
        # feed_entropy() is deterministic, so given access to the secret internal state, I can predict it:
        crandom._rng._state = bytes(32)
        run()
        state3 = crandom._rng._state
        assert state2 != state3
        self.assertEqual(bytes.fromhex("a24e7c4c91c095226d254ad3fba5f3ef60a1dcf32fb769113bbc3d95d6160a6c"), state3)

    def test_feed_entropy_unicode(self):
        """This tests feed_entropy() does not raise on weird str inputs."""
        # feed in some vanilla unicode:
        state = crandom._rng._state
        crandom.feed_entropy(UNICODE_HORROR)
        self.assertNotEqual(state, crandom._rng._state)
        # feed in str that cannot be encoded as unicode in "strict" (default) mode:
        state = crandom._rng._state
        weird_string = ''.join(map(chr, range(0x110_000)))
        crandom.feed_entropy(weird_string)
        self.assertNotEqual(state, crandom._rng._state)

    def test_get_rand_bytes_api(self):
        # test output length:
        for nbytes in range(1000):
            self.assertEqual(nbytes, len(crandom.get_rand_bytes(nbytes)))
        # test internal state changes:
        state = crandom._rng._state
        r1 = crandom.get_rand_bytes(16)
        self.assertNotEqual(state, crandom._rng._state)
        # test output changes:
        self.assertNotEqual(r1, crandom.get_rand_bytes(16))

    def test_get_rand_bytes_os_urandom(self):
        # even if I have access to the secret internal state, I cannot predict the output,
        # as it depends on os.urandom:
        crandom._rng._state = bytes(32)
        r1 = crandom.get_rand_bytes(16)
        crandom._rng._state = bytes(32)
        r2 = crandom.get_rand_bytes(16)
        assert r1 != r2
        # but if os.urandom is broken, then the output can be predicted:
        with mock.patch('os.urandom', return_value=bytes(32)):
            crandom._rng._state = bytes(32)
            r3 = crandom.get_rand_bytes(16)
            self.assertEqual(bytes.fromhex("7be9fda48f4179e611c698a73cff09fa"), r3)

    def test_mix_extract(self):
        """Check mix_extract calls os.urandom(32) and it mixes in all those bytes."""
        #   h = sha512(os.urandom(32) + self._state)
        #   out, self._state = h[0:32], h[32:64]
        orig_state = b"state___" * 4
        osurandom_res = b"osurandom" * 4
        sha512res = hashlib.sha512(osurandom_res + orig_state).digest()
        assert sha512res == bytes.fromhex("e7a9e48bdcae23834fbc1bc35e61101eb9afd68c32473c250db9155cfa82018aec76a5ec216f7d4aad1bfb8aee012a1cab5869956327a39a2b1994366e899d0d")
        crandom._rng._state = orig_state
        with mock.patch('os.urandom', autospec=True) as mock_urandom:
            mock_urandom.return_value = osurandom_res
            extracted_bytes = crandom._rng._mix_extract()
        self.assertEqual(sha512res[:32], extracted_bytes)
        self.assertEqual(sha512res[32:], crandom._rng._state)
        mock_urandom.assert_called_once_with(32)  # os.urandom was asked for exactly 32 bytes

    def test_get_rand_below(self):
        self.assertEqual({0}, {crandom.get_rand_below(1) for i in range(128)})
        self.assertEqual({0, 1}, {crandom.get_rand_below(2) for i in range(128)})
        self.assertEqual({0, 1, 2}, {crandom.get_rand_below(3) for i in range(128)})
        self.assertEqual({0, 1, 2, 3}, {crandom.get_rand_below(4) for i in range(128)})

        upper_bound = 10000
        seen = set()
        for i in range(128):
            x = crandom.get_rand_below(upper_bound)
            assert 0 <= x < upper_bound
            seen.add(x)
        assert len(seen) >= 10, seen
        assert min(seen) < upper_bound // 2, seen
        assert max(seen) > upper_bound // 2, seen
        assert max(seen) - min(seen) > upper_bound // 2, seen

    def test_rand_add_refresh(self):
        state = crandom._rng._state
        crandom.rand_add_refresh()
        self.assertNotEqual(state, crandom._rng._state)
