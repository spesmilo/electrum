import unittest
from electrum_ltc import keystore
from electrum_ltc import mnemonic
from electrum_ltc import old_mnemonic
from electrum_ltc.util import bh2u

from . import SequentialTestCase


class Test_NewMnemonic(SequentialTestCase):

    def test_to_seed(self):
        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEqual(bh2u(seed),
                          '741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5b'
                          'b22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce')

    def test_random_seeds(self):
        iters = 10
        m = mnemonic.Mnemonic(lang='en')
        for _ in range(iters):
            seed = m.make_seed()
            i = m.mnemonic_decode(seed)
            self.assertEqual(m.mnemonic_encode(i), seed)


class Test_OldMnemonic(SequentialTestCase):

    def test(self):
        seed = '8edad31a95e7d59f8837667510d75a4d'
        result = old_mnemonic.mn_encode(seed)
        words = 'hardly point goal hallway patience key stone difference ready caught listen fact'
        self.assertEqual(result, words.split())
        self.assertEqual(old_mnemonic.mn_decode(result), seed)

class Test_BIP39Checksum(SequentialTestCase):

    def test(self):
        mnemonic = u'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
        is_checksum_valid, is_wordlist_valid = keystore.bip39_is_checksum_valid(mnemonic)
        self.assertTrue(is_wordlist_valid)
        self.assertTrue(is_checksum_valid)
