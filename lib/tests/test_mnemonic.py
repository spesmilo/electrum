import unittest
from lib import mnemonic

class Test_mnemonic(unittest.TestCase):

    def test_prepare_seed(self):
        seed = 'foo BAR Baz'
        self.assertEquals(mnemonic.prepare_seed(seed), 'foo bar baz')

    def test_mnemonic(self):
        m = mnemonic.Mnemonic(lang='en')
        seed = m.make_seed(randrange=lambda n: 44444444444444444444444444444444444444444)
        self.assertEquals(seed, 'trial shove mixed organ hamster rate page person whisper much cattle clap absurd')
        self.assertTrue(m.check_seed(seed, custom_entropy=1))

        i = m.mnemonic_decode(seed)
        self.assertEquals(i, 44444444444444444444444444444444444444481)
        self.assertEquals(m.mnemonic_encode(i), seed)

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
            self.assertTrue(m.check_seed(seed, custom_entropy=1))
            i = m.mnemonic_decode(seed)
            self.assertEquals(m.mnemonic_encode(i), seed)
