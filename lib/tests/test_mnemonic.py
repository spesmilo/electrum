import unittest
from lib import mnemonic
from lib import old_mnemonic

class Test_NewMnemonic(unittest.TestCase):

    def test_to_seed(self):
        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEquals(seed.encode('hex'),
                          '741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5b'
                          'b22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce')

    def test_random_seeds(self):
        iters = 10
        m = mnemonic.Mnemonic(lang='en')
        for _ in range(iters):
            seed = m.make_seed()
            i = m.mnemonic_decode(seed)
            self.assertEquals(m.mnemonic_encode(i), seed)


class Test_OldMnemonic(unittest.TestCase):

    def test(self):
        seed = '8edad31a95e7d59f8837667510d75a4d'
        result = old_mnemonic.mn_encode(seed)
        words = 'hardly point goal hallway patience key stone difference ready caught listen fact'
        self.assertEquals(result, words.split())
        self.assertEquals(old_mnemonic.mn_decode(result), seed)
