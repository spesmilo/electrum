import unittest

from lib import account
from lib import wallet

class Test_Account(unittest.TestCase):

    def test_bip32_account(self):
        v = {
            'change': [
                '02d2967089cbcecf308f133cdec7e97eeeb53a1d8d76fc3656eaa55dac67b7694c',
                '023a667b846434d35fa76d5fe452c11a74504f5d6d551ad7fb9fe837041c3ef1de',
                '036df6df47ad3dae0594ff6f470daa4bded564d8d7ad9420ce077fa3ded949ffa9',
                '0211f0dce7457dc5f0a5ae4222552fea08f5fc587bff2fd2b9744c1cb5dc3a673e',
                '0239706f85ef5564ca95e9328cbc652bfc4295a1a6940d6b589f857332c2c8b29c',
                '030cf3e44121e753884d21daac49d3e47edc5fce1a2ad2f3c6ef296e349ca5d54b'
            ],
            'receiving': [
                '02f0eaac8dde84cf80ebdb3b136cb29d8c7954c869c6c8fdf9d72a82323a72a30e',
                '02a6f4acc94dc4496a78fad745897fec3b334b182a376ac7abe40975b9333ef67c',
                '03a47015d474ecc80fa20160d5b1bdb7696d020c6c220adeff51e616445aff1564',
                '030c7a3c94425e11dba07bb7bd147451f1b412b4b6659e467f2047383daf330e83',
                '026cc8f26926a4c86d12bb456f4d231c56b1fb3f4bd9f86f5e94f9cead5c28f09d',
                '0358ad542c97f2908458cd5d064e538b57d9ce9af35461e514388da16fba74344f',
                '029dae6d94528de02c51d1f61c48c1e5cd36399735a1de10e1beddd561f0938bca',
                '0354c030301461884e7728e12374b98bb85a82f199676f0c222be7fa8b157a72c8',
                '03d9c693eb4e9ce9b9d8ffebec8ac0c4dbcaf928f39fb838474143f171734e5789',
                '03765cfe701e03dcb9be91d4b40fb6b0717a53000aabdbdea275290bddb627921e',
                '0224104233a86b5f6381e12f2aea3121bc817029526440cdfcf83d6f5d7b7c11fb',
                '03aa93f028c330e00b5b95c790672beab4d654b06b73b5d06b8eb1a1373ada76de',
                '0223d0ffeebd7d081c7d62206f1b57a02323712d90e4b1e4444647e9946b6dedfe',
                '032b1bfc1a500eed050c7ba946827d048d4bef7230a327916d33edf68eff43cf37',
                '039bebf87a2dba3e2e842f7e56c131c843cacc1e4ca827d479cc87aba8ac74e38d',
                '028de15894751cbe5916ebd38c1c22129983560a5b1cc95b6e215661ae0bb193e4',
                '02ecb390d1a92af7193dce256b18af2b65def1398069eed58291d9d467421a54ff',
                '029538f295c5ab4225f15ac5e35299eb56cb84ee13e28371ac50409a140f8834f2',
                '029482ac8185bda04d771c008ca6979d8cb786d4f47398752826908e46c9cc33ab',
                '02624a80408fc39db86848bb6995bdc52ccc9591cff4633a4536a60f270d502cd4'
            ],
            'xpub': 'xpub661MyMwAqRbcF8M4CH68NvHEc6TUNaVhXwmGrsagNjrCja49H9L4ziJGe8YmaSBPbY4ZmQPQeW5CK6fiwx2EH6VxQab3zwDzZVWVApDSVNh'
        }
        a = account.BIP32_Account(v)
        self.assertEquals(a.dump(), v)
        self.assertEquals(a.get_master_pubkeys(), [v['xpub']])
        self.assertEquals(a.first_address(),
                          ('1EtJphMVpes4UKm8bYu5D1fGvNoTSJM3ZL', v['receiving'][0]))

        xprv = 'xprv9s21ZrQH143K2eGb6FZ81nLW44cyy7mrAiqg4VB4pQKDrmizjc1pSuynnpeiaMPdZxvrfvdBi5oqFi9hmsV7MrsVquKkruQ7TJPCfVuPSdw'
        storage = dict(
            master_public_keys={0: a.xpub},
            master_private_keys={0: xprv},
            wallet_type='standard'
        )
        w = wallet.BIP32_Wallet(storage)
        self.assertEquals(a.get_private_key(sequence=[0, 0], wallet=w, password=None),
                          ['KxuBFG13CPUBwPAUWvZSQ3mjNNjHoDghfxnax6RbwS3Rw8tqSzCk'])

        for for_change in [0, 1]:
            for n in range(6):
                label = ['receiving', 'change'][for_change]
                expected = v[label][n]
                self.assertEquals(expected, a.derive_pubkey_from_xpub(a.xpub, for_change, n))
                self.assertEquals(expected, a.get_pubkey_from_xpub(a.xpub, for_change, n))
                self.assertEquals(expected, a.derive_pubkeys(for_change, n))

                pubkey, = a.get_xpubkeys(for_change, n)
                xpub, seq = a.parse_xpubkey(pubkey)
                self.assertEquals(xpub, a.xpub)
                self.assertEquals(seq, [for_change, n])
