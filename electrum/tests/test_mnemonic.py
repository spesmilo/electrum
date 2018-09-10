from electrum import keystore
from electrum import mnemonic
from electrum import old_mnemonic
from electrum.util import bh2u, bfh
from electrum.bitcoin import is_new_seed
from electrum.version import SEED_PREFIX_SW

from . import SequentialTestCase
from .test_wallet_vertical import UNICODE_HORROR


SEED_WORDS_JAPANESE = 'なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん'
assert bh2u(SEED_WORDS_JAPANESE.encode('utf8')) == 'e381aae381aee3818b20e381b2e3828de3818420e38197e381aae3829320e381bee381aae381b5e3829920e381a4e381b5e38299e3819920e38195e3818be38299e3819920e3818ae38197e38283e3828c20e3818be3828fe3818f20e3818ae38184e3818be38191e3828b20e38191e38195e3818d20e3818be38184e381a8e3818620e38195e3819fe38293'

SEED_WORDS_CHINESE = '眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬'
assert bh2u(SEED_WORDS_CHINESE.encode('utf8')) == 'e79cbc20e682b220e58f9b20e694b920e88a8220e8b78320e8a1a120e5938d20e7968620e882a120e9818220e586ac'

PASSPHRASE_CHINESE = '给我一些测试向量谷歌'
assert bh2u(PASSPHRASE_CHINESE.encode('utf8')) == 'e7bb99e68891e4b880e4ba9be6b58be8af95e59091e9878fe8b0b7e6ad8c'


class Test_NewMnemonic(SequentialTestCase):

    def test_mnemonic_to_seed_basic(self):
        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEqual('741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5bb22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce',
                         bh2u(seed))

    def test_mnemonic_to_seed_japanese(self):
        words = SEED_WORDS_JAPANESE
        self.assertTrue(is_new_seed(words))

        m = mnemonic.Mnemonic(lang='ja')
        self.assertEqual(1938439226660562861250521787963972783469, m.mnemonic_decode(words))

        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic=words, passphrase='')
        self.assertEqual('d3eaf0e44ddae3a5769cb08a26918e8b308258bcb057bb704c6f69713245c0b35cb92c03df9c9ece5eff826091b4e74041e010b701d44d610976ce8bfb66a8ad',
                         bh2u(seed))

    def test_mnemonic_to_seed_japanese_with_unicode_horror(self):
        words = SEED_WORDS_JAPANESE
        self.assertTrue(is_new_seed(words))

        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic=words, passphrase=UNICODE_HORROR)
        self.assertEqual('251ee6b45b38ba0849e8f40794540f7e2c6d9d604c31d68d3ac50c034f8b64e4bc037c5e1e985a2fed8aad23560e690b03b120daf2e84dceb1d7857dda042457',
                         bh2u(seed))

    def test_mnemonic_to_seed_chinese(self):
        words = SEED_WORDS_CHINESE
        self.assertTrue(is_new_seed(words, prefix=SEED_PREFIX_SW))

        m = mnemonic.Mnemonic(lang='zh')
        self.assertEqual(3083737086352778425940060465574397809099, m.mnemonic_decode(words))

        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic=words, passphrase='')
        self.assertEqual('0b9077db7b5a50dbb6f61821e2d35e255068a5847e221138048a20e12d80b673ce306b6fe7ac174ebc6751e11b7037be6ee9f17db8040bb44f8466d519ce2abf',
                         bh2u(seed))

    def test_mnemonic_to_seed_chinese_with_passphrase(self):
        words = SEED_WORDS_CHINESE
        passphrase = PASSPHRASE_CHINESE
        self.assertTrue(is_new_seed(words, prefix=SEED_PREFIX_SW))
        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic=words, passphrase=passphrase)
        self.assertEqual('6c03dd0615cf59963620c0af6840b52e867468cc64f20a1f4c8155705738e87b8edb0fc8a6cee4085776cb3a629ff88bb1a38f37085efdbf11ce9ec5a7fa5f71',
                         bh2u(seed))

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
