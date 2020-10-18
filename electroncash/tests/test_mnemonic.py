import unittest
from .. import keystore
from .. import mnemonic
from .. import old_mnemonic
from ..util import bh2u


class Test_NewMnemonic(unittest.TestCase):

    def test_to_seed(self):
        seed = mnemonic.Mnemonic_Electrum.mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEqual(bh2u(seed),
                          '741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5b'
                          'b22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce')

    def test_random_seeds(self):
        iters = 10
        m = mnemonic.Mnemonic_Electrum(lang='en')
        for _ in range(iters):
            seed = m.make_seed()
            i = m.mnemonic_decode(seed)
            self.assertEqual(m.mnemonic_encode(i), seed)


class Test_OldMnemonic(unittest.TestCase):

    def test(self):
        seed = '8edad31a95e7d59f8837667510d75a4d'
        result = old_mnemonic.mn_encode(seed)
        words = 'hardly point goal hallway patience key stone difference ready caught listen fact'
        self.assertEqual(result, words.split())
        self.assertEqual(old_mnemonic.mn_decode(result), seed)

class Test_BIP39Checksum(unittest.TestCase):

    def test(self):
        seed = u'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
        is_checksum_valid, is_wordlist_valid = mnemonic.Mnemonic().is_checksum_valid(seed)
        self.assertTrue(is_wordlist_valid)
        self.assertTrue(is_checksum_valid)

class Test_Seeds(unittest.TestCase):
    """ Test old and new seeds. """

    mnemonics = {
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze', 'old'),
        ('cell dumb heartbeat north boom tease ' * 4, 'old'),
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare badword', ''),
        ('cElL DuMb hEaRtBeAt nOrTh bOoM TeAsE ShIp bAbY BrIgHt kInGdOm rArE SqUeEzE', 'old'),
        ('   cElL  DuMb hEaRtBeAt nOrTh bOoM  TeAsE ShIp    bAbY BrIgHt kInGdOm rArE SqUeEzE   ', 'old'),
        # below seed is actually 'invalid old' as it maps to 33 hex chars
        ('hurry idiot prefer sunset mention mist jaw inhale impossible kingdom rare squeeze', 'old'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform able', 'electrum'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform', ''),
        ('ostrich security deer aunt climb inner alpha arm mutual marble solid task', 'electrum'),
        ('OSTRICH SECURITY DEER AUNT CLIMB INNER ALPHA ARM MUTUAL MARBLE SOLID TASK', 'electrum'),
        ('   oStRiCh sEcUrItY DeEr aUnT ClImB       InNeR AlPhA ArM MuTuAl mArBlE   SoLiD TaSk  ', 'electrum'),
        ('x8', 'electrum'),
        ('science dawn member doll dutch real ca brick knife deny drive list', ''),
        ('cook mushroom seminar deposit flash tuna deliver dog glove rug winner scout', 'bip39'),
    }

    def test_electrum_seed(self):
        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform able"
        self.assertTrue(mnemonic.is_electrum_seed(seed))

        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform"
        self.assertFalse(mnemonic.is_electrum_seed(seed))

    def test_old_seed(self):
        self.assertTrue(mnemonic.is_old_seed(" ".join(["like"] * 12)))
        self.assertFalse(mnemonic.is_old_seed(" ".join(["like"] * 18)))
        self.assertTrue(mnemonic.is_old_seed(" ".join(["like"] * 24)))
        self.assertFalse(mnemonic.is_old_seed("not a seed"))

        self.assertTrue(mnemonic.is_old_seed("0123456789ABCDEF" * 2))
        self.assertTrue(mnemonic.is_old_seed("0123456789ABCDEF" * 4))

    def test_seed_type(self):
        for seed_words, _type in self.mnemonics:
            self.assertEqual(_type, mnemonic.seed_type_name(seed_words), msg=seed_words)
