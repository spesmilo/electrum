from typing import NamedTuple, Optional

from electrum import keystore
from electrum import mnemonic
from electrum import old_mnemonic
from electrum.util import bh2u, bfh
from electrum.mnemonic import is_new_seed, is_old_seed, seed_type
from electrum.version import SEED_PREFIX_SW, SEED_PREFIX

from . import SequentialTestCase
from .test_wallet_vertical import UNICODE_HORROR, UNICODE_HORROR_HEX


class SeedTestCase(NamedTuple):
    words: str
    bip32_seed: str
    lang: Optional[str] = 'en'
    words_hex: Optional[str] = None
    entropy: Optional[int] = None
    passphrase: Optional[str] = None
    passphrase_hex: Optional[str] = None
    seed_version: str = SEED_PREFIX


SEED_TEST_CASES = {
    'english': SeedTestCase(
        words='wild father tree among universe such mobile favorite target dynamic credit identify',
        seed_version=SEED_PREFIX_SW,
        bip32_seed='aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756'),
    'english_with_passphrase': SeedTestCase(
        words='wild father tree among universe such mobile favorite target dynamic credit identify',
        seed_version=SEED_PREFIX_SW,
        passphrase='Did you ever hear the tragedy of Darth Plagueis the Wise?',
        bip32_seed='4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f'),
    'japanese': SeedTestCase(
        lang='ja',
        words='なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん',
        words_hex='e381aae381aee3818b20e381b2e3828de3818420e38197e381aae3829320e381bee381aae381b5e3829920e381a4e381b5e38299e3819920e38195e3818be38299e3819920e3818ae38197e38283e3828c20e3818be3828fe3818f20e3818ae38184e3818be38191e3828b20e38191e38195e3818d20e3818be38184e381a8e3818620e38195e3819fe38293',
        entropy=1938439226660562861250521787963972783469,
        bip32_seed='d3eaf0e44ddae3a5769cb08a26918e8b308258bcb057bb704c6f69713245c0b35cb92c03df9c9ece5eff826091b4e74041e010b701d44d610976ce8bfb66a8ad'),
    'japanese_with_passphrase': SeedTestCase(
        lang='ja',
        words='なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん',
        words_hex='e381aae381aee3818b20e381b2e3828de3818420e38197e381aae3829320e381bee381aae381b5e3829920e381a4e381b5e38299e3819920e38195e3818be38299e3819920e3818ae38197e38283e3828c20e3818be3828fe3818f20e3818ae38184e3818be38191e3828b20e38191e38195e3818d20e3818be38184e381a8e3818620e38195e3819fe38293',
        entropy=1938439226660562861250521787963972783469,
        passphrase=UNICODE_HORROR,
        passphrase_hex=UNICODE_HORROR_HEX,
        bip32_seed='251ee6b45b38ba0849e8f40794540f7e2c6d9d604c31d68d3ac50c034f8b64e4bc037c5e1e985a2fed8aad23560e690b03b120daf2e84dceb1d7857dda042457'),
    'chinese': SeedTestCase(
        lang='zh',
        words='眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬',
        words_hex='e79cbc20e682b220e58f9b20e694b920e88a8220e8b78320e8a1a120e5938d20e7968620e882a120e9818220e586ac',
        seed_version=SEED_PREFIX_SW,
        entropy=3083737086352778425940060465574397809099,
        bip32_seed='0b9077db7b5a50dbb6f61821e2d35e255068a5847e221138048a20e12d80b673ce306b6fe7ac174ebc6751e11b7037be6ee9f17db8040bb44f8466d519ce2abf'),
    'chinese_with_passphrase': SeedTestCase(
        lang='zh',
        words='眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬',
        words_hex='e79cbc20e682b220e58f9b20e694b920e88a8220e8b78320e8a1a120e5938d20e7968620e882a120e9818220e586ac',
        seed_version=SEED_PREFIX_SW,
        entropy=3083737086352778425940060465574397809099,
        passphrase='给我一些测试向量谷歌',
        passphrase_hex='e7bb99e68891e4b880e4ba9be6b58be8af95e59091e9878fe8b0b7e6ad8c',
        bip32_seed='6c03dd0615cf59963620c0af6840b52e867468cc64f20a1f4c8155705738e87b8edb0fc8a6cee4085776cb3a629ff88bb1a38f37085efdbf11ce9ec5a7fa5f71'),
    'spanish': SeedTestCase(
        lang='es',
        words='almíbar tibio superar vencer hacha peatón príncipe matar consejo polen vehículo odisea',
        words_hex='616c6d69cc8162617220746962696f20737570657261722076656e63657220686163686120706561746fcc816e20707269cc816e63697065206d6174617220636f6e73656a6f20706f6c656e2076656869cc8163756c6f206f6469736561',
        entropy=3423992296655289706780599506247192518735,
        bip32_seed='18bffd573a960cc775bbd80ed60b7dc00bc8796a186edebe7fc7cf1f316da0fe937852a969c5c79ded8255cdf54409537a16339fbe33fb9161af793ea47faa7a'),
    'spanish_with_passphrase': SeedTestCase(
        lang='es',
        words='almíbar tibio superar vencer hacha peatón príncipe matar consejo polen vehículo odisea',
        words_hex='616c6d69cc8162617220746962696f20737570657261722076656e63657220686163686120706561746fcc816e20707269cc816e63697065206d6174617220636f6e73656a6f20706f6c656e2076656869cc8163756c6f206f6469736561',
        entropy=3423992296655289706780599506247192518735,
        passphrase='araña difícil solución término cárcel',
        passphrase_hex='6172616ecc83612064696669cc8163696c20736f6c7563696fcc816e207465cc81726d696e6f206361cc817263656c',
        bip32_seed='363dec0e575b887cfccebee4c84fca5a3a6bed9d0e099c061fa6b85020b031f8fe3636d9af187bf432d451273c625e20f24f651ada41aae2c4ea62d87e9fa44c'),
    'spanish2': SeedTestCase(
        lang='es',
        words='equipo fiar auge langosta hacha calor trance cubrir carro pulmón oro áspero',
        words_hex='65717569706f20666961722061756765206c616e676f7374612068616368612063616c6f72207472616e63652063756272697220636172726f2070756c6d6fcc816e206f726f2061cc81737065726f',
        seed_version=SEED_PREFIX_SW,
        entropy=448346710104003081119421156750490206837,
        bip32_seed='001ebce6bfde5851f28a0d44aae5ae0c762b600daf3b33fc8fc630aee0d207646b6f98b18e17dfe3be0a5efe2753c7cdad95860adbbb62cecad4dedb88e02a64'),
    'spanish3': SeedTestCase(
        lang='es',
        words='vidrio jabón muestra pájaro capucha eludir feliz rotar fogata pez rezar oír',
        words_hex='76696472696f206a61626fcc816e206d756573747261207061cc816a61726f206361707563686120656c756469722066656c697a20726f74617220666f676174612070657a2072657a6172206f69cc8172',
        seed_version=SEED_PREFIX_SW,
        entropy=3444792611339130545499611089352232093648,
        passphrase='¡Viva España! repiten veinte pueblos y al hablar dan fe del ánimo español... ¡Marquen arado martillo y clarín',
        passphrase_hex='c2a1566976612045737061c3b16121207265706974656e207665696e746520707565626c6f73207920616c206861626c61722064616e2066652064656c20c3a16e696d6f2065737061c3b16f6c2e2e2e20c2a14d61727175656e20617261646f206d617274696c6c6f207920636c6172c3ad6e',
        bip32_seed='c274665e5453c72f82b8444e293e048d700c59bf000cacfba597629d202dcf3aab1cf9c00ba8d3456b7943428541fed714d01d8a0a4028fc3a9bb33d981cb49f'),
}


class Test_NewMnemonic(SequentialTestCase):

    def test_mnemonic_to_seed_basic(self):
        # note: not a valid electrum seed
        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEqual('741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5bb22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce',
                         bh2u(seed))

    def test_mnemonic_to_seed(self):
        for test_name, test in SEED_TEST_CASES.items():
            if test.words_hex is not None:
                self.assertEqual(test.words_hex, bh2u(test.words.encode('utf8')), msg=test_name)
            self.assertTrue(is_new_seed(test.words, prefix=test.seed_version), msg=test_name)
            m = mnemonic.Mnemonic(lang=test.lang)
            if test.entropy is not None:
                self.assertEqual(test.entropy, m.mnemonic_decode(test.words), msg=test_name)
            if test.passphrase_hex is not None:
                self.assertEqual(test.passphrase_hex, bh2u(test.passphrase.encode('utf8')), msg=test_name)
            seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic=test.words, passphrase=test.passphrase)
            self.assertEqual(test.bip32_seed, bh2u(seed), msg=test_name)

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


class Test_seeds(SequentialTestCase):
    """ Test old and new seeds. """

    mnemonics = {
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze', 'old'),
        ('cell dumb heartbeat north boom tease ' * 4, 'old'),
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare badword', ''),
        ('cElL DuMb hEaRtBeAt nOrTh bOoM TeAsE ShIp bAbY BrIgHt kInGdOm rArE SqUeEzE', 'old'),
        ('   cElL  DuMb hEaRtBeAt nOrTh bOoM  TeAsE ShIp    bAbY BrIgHt kInGdOm rArE SqUeEzE   ', 'old'),
        # below seed is actually 'invalid old' as it maps to 33 hex chars
        ('hurry idiot prefer sunset mention mist jaw inhale impossible kingdom rare squeeze', 'old'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform able', 'standard'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform', ''),
        ('ostrich security deer aunt climb inner alpha arm mutual marble solid task', 'standard'),
        ('OSTRICH SECURITY DEER AUNT CLIMB INNER ALPHA ARM MUTUAL MARBLE SOLID TASK', 'standard'),
        ('   oStRiCh sEcUrItY DeEr aUnT ClImB       InNeR AlPhA ArM MuTuAl mArBlE   SoLiD TaSk  ', 'standard'),
        ('x8', 'standard'),
        ('science dawn member doll dutch real can brick knife deny drive list', '2fa'),
        ('science dawn member doll dutch real ca brick knife deny drive list', ''),
        (' sCience dawn   member doll Dutch rEAl can brick knife deny drive  lisT', '2fa'),
        ('frost pig brisk excite novel report camera enlist axis nation novel desert', 'segwit'),
        ('  fRoSt pig brisk excIte novel rePort CamEra enlist axis nation nOVeL dEsert ', 'segwit'),
        ('9dk', 'segwit'),
    }

    def test_new_seed(self):
        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform able"
        self.assertTrue(is_new_seed(seed))

        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform"
        self.assertFalse(is_new_seed(seed))

    def test_old_seed(self):
        self.assertTrue(is_old_seed(" ".join(["like"] * 12)))
        self.assertFalse(is_old_seed(" ".join(["like"] * 18)))
        self.assertTrue(is_old_seed(" ".join(["like"] * 24)))
        self.assertFalse(is_old_seed("not a seed"))

        self.assertTrue(is_old_seed("0123456789ABCDEF" * 2))
        self.assertTrue(is_old_seed("0123456789ABCDEF" * 4))

    def test_seed_type(self):
        for seed_words, _type in self.mnemonics:
            self.assertEqual(_type, seed_type(seed_words), msg=seed_words)
