"""Test for Elcash wallets which by default are bip39 mnemonic with segwit (bech32) addresses"""
import tempfile
from enum import Enum
from unittest import TestCase
from unittest.mock import patch

from electrum import keystore, SimpleConfig
from electrum.constants import set_elcash_mainnet, set_elcash_testnet
from electrum.tests.test_wallet_vertical import WalletIntegrityHelper
from electrum.wallet import Abstract_Wallet

MNEMONIC = 'patch rabbit try vehicle quick image attract payment report truly nest carry'
# this mnemonic is used in MulitiSig wallet tests
MNEMONIC_COSIGNER = 'voyage work slush run impact blossom offer double erupt shoe inherit puzzle'


class SeedType(Enum):
    LEGACY = 'standard'
    SEGWIT = 'segwit'


def _derive_pubkey(keystore: keystore, change_index: int, index: int):
    return keystore.derive_pubkey(
        for_change=change_index,
        n=index,
    ).hex()


def _get_keystore(seed_type: SeedType, is_p2sh):
    return keystore.from_seed(
        seed=MNEMONIC,
        passphrase='',
        is_p2sh=is_p2sh,
        seed_type_=seed_type.value,
    )


def _get_cosigner_keystore(seed_type: SeedType):
    return keystore.from_seed(
        seed=MNEMONIC_COSIGNER,
        passphrase='',
        is_p2sh=True,
        seed_type_=seed_type.value
    )


class TestUtilsMixin():
    def _test_receive_pubkeys(self, key_store):
        self.assertTrue(self.RECEIVE_KEYS)
        for i, pubkey in enumerate(self.RECEIVE_KEYS.values()):
            with self.subTest(pubkey):
                self.assertEqual(
                    _derive_pubkey(key_store, 0, i),
                    pubkey
                )

    def _test_change_pubkeys(self, key_store):
        self.assertTrue(self.CHANGE_KEYS)
        for i, pubkey in enumerate(self.CHANGE_KEYS.values()):
            with self.subTest(pubkey):
                self.assertEqual(
                    _derive_pubkey(key_store, 1, i),
                    pubkey
                )

    def _test_addresses(self, key_store, addresses, is_change_address):
        with tempfile.NamedTemporaryFile() as file, patch.object(Abstract_Wallet, 'gap_limit_for_change', self.GAP_LIMIT):
            config = SimpleConfig({
                'electrum_path': file.name,
            })
            if isinstance(key_store, list):
                wallet = WalletIntegrityHelper.create_multisig_wallet(
                    keystores=key_store,
                    multisig_type='2of2',
                    config=config,
                    gap_limit=self.GAP_LIMIT,
                )
            else:
                wallet = WalletIntegrityHelper.create_standard_wallet(
                    key_store,
                    config=config,
                    gap_limit=self.GAP_LIMIT,
                )
            # test gap limits
            self.assertEqual(
                wallet.gap_limit,
                self.GAP_LIMIT
            )
            self.assertEqual(
                wallet.gap_limit_for_change,
                self.GAP_LIMIT
            )

            # test addresses saved in wallet db
            db_saved_addresses = wallet.db.get_change_addresses() if is_change_address else wallet.db.get_receiving_addresses()
            for i, address in enumerate(addresses[:self.GAP_LIMIT]):
                with self.subTest(address):
                    self.assertEqual(
                        db_saved_addresses[i],
                        address
                    )

            # test rest of the addresses
            for i, address in enumerate(addresses[self.GAP_LIMIT:]):
                with self.subTest(address):
                    self.assertEqual(
                        wallet.derive_address(
                            for_change=1 if is_change_address else 0,
                            n=i + self.GAP_LIMIT
                        ),
                        address
                    )
                    self.assertEqual(
                        wallet.create_new_address(for_change=is_change_address),
                        address,
                    )


class TestElCashStandardLegacyWallet(TestCase, TestUtilsMixin):
    # 10 first keys
    # keys in format private_key: public_key
    RECEIVE_KEYS = {
        '40a78ce6601eff1eced05d4d7c3227d1ff3013aa216e2ac136c98d6583791361': '0264352f6cd0531a2191c4e53d99b8db11b3f94074f87e4580abc4cea9b38cb59c',
        '9d5e28df2fc26e1e0060909db6bbada2699a87b124432590c415c620e7c286da': '03c1b8dfee31fb10cf90909dd3803b79c050d14edb8d652dbd4e13099bb8bd6d7b',
        '95b8e56ce38769cc8ec707eae25da2abedf5870fb2a9ba9cfea740e7ae3f5e76': '02e481c87ab8ab00f4c0f3f92da6dbac980fd473511d3ffb0503a265b7924f9641',
        '1754164d4c761b88209a5e9243864e94223d6439c6392d579378f10556ceb5f8': '03174ab6f6ae42c55da4612313a56a04279768171899484bf5fd87ba63c6f8a329',
        'bd5e1d0710d8618fa56bd94bc0b68eff620e32b2264a52de53aa8f2eeb10cd5b': '038d531e80a56665909d014e19d487c17ea8105b9f4cf216d0d77950111422929a',
        'e301a4f75954261c227651989d7029f3967c9a012ecba701023a1d1d9ac30465': '02d8359bbe7913e24a77dd33484a6920c031cd69a98faa0e389a3a0d4cedbbaf3b',
        '4cb8af7aaddd1a6f4c1356ced36269235acb039b7a8739685530f9f3675a81a2': '0262f8826c998a7b5bffdc0b9650e0c5ef08ced807b498388c94ff835fc723078b',
        'a36ae8e380be9d6ee26f94d9de2673490bcfbb841a565d3bc041a03ae2d8c99c': '03cfebda3d244974fbf5adbe1e25b28795015bc39b549a99c4a6cae25128c33148',
        'b17c847491c520f0557c49a4350414c6ce3ab4e672974ee9ae89ad1b63d39236': '02f55897ac30d6fa9d7960221be1ca4671ce1577da996ca66e988ebded697b9e86',
        'a018d0357ee77ef8c78e6605200afdf6705ded2af84cb2cc4c7bd2438624107e': '02eab7d1e089b3e10ad2c9017e25c6a9daf7c4ae4155eb9ff9f32b740dcfcaa384',
    }
    CHANGE_KEYS = {
        'fd8ea21c184b1c3052c041efb96ba025782d0c9a700306a5159cd272d5baaac0': '035abbdd098318d1e1579ffb56e0d86fb5258ecd9dfb322702333c0038c30d703c',
        '25a0fa2afb09c5f89176862ce3701d0c633cf556b9ea7166a708c4bfdf5878c6': '02aa8d5cca8519ef60bfc5b78dabc12306fb33aa2abfe58c5761e7ebab504c8c83',
        'fc354858d27f432fecd8ae03df502c14c8301c891a68843ae6664782ff906756': '0205ff0c3471a43f16e465e75f4ebf4758a218a0e8404b4eade779a61a10950c03',
        '9b7edca5814ecfc30625fa0aaefab49cfb618cdc94fb4a3ea33b68fec8694ed5': '036cbc6fe1fd9277041228976eae57bff7f0e0842c184476b08712313c0304a49f',
        '91cd09b1f362103b3ffce886d1bd5b16f9fd5c7411084997e1068f90a0262926': '02df3c941a56f461d7d6e07c96917a2c72ba4ed75c193a8e187d1810ccc4a51981',
        'e19daac24e61183cc05ba749c23a0c87c6959545bcdb7a83d83a9bf5a8d7012d': '02bf4096115a460f1e8f7bb4048e7bb35421084b57b34096da947bc002a38a11d1',
        '4028e67f30d92454c7eda657988e97c94127c1e40c2263d5c94ffcfadb8050e1': '025042dc07903ca052499e22e5f7d03f669b30336f2f938b7fd8c5e89a54076a4e',
        'f418f64382d289b2196185b7ca7b131988d795fb464d7a4961c715c354d8acb5': '0325890dcd0c175a9b34a1ce4cbc3cce9430e2b5b015590eda059365c567a41e5b',
        'f557dad91133784adc2ff2dfc450a0e76b84681e7054b37aee25bcaada9b3f6e': '033878a6fe42528ea2ff62a4db35ffddc74e14cf8b72be5e0360f9ae8c373be7fc',
        '923139d13c7ffd6e7a626632c1624bb566c049da174698820073504a508a917c': '0306dcd854f810dcf4d1135cbf5a319e3da060314e237842b1e254550897adce46',
    }
    GAP_LIMIT = 2

    def test_derivation_path(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self.assertEqual(
            key_store.get_derivation_prefix(),
            "m/44'/2137'/0'"
        )

    def test_receive_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self._test_receive_pubkeys(key_store)

    def test_change_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self._test_change_pubkeys(key_store)

    def test_testnet_receive_addresses(self):
        addresses = (
            'TVnLdDeav7Q8fEFXWsP4e4TxGRerFtESJb',
            'TLvuDqR1fQkrucuihfr7Y6BgyJvdJXap2o',
            'TQjnrbx4wxkL29pFHDH1meH3iXeFYPvm2P',
            'TKipKX3ATrJaLC2XQggms1j5Te51TKUGMi',
            'TDA1o7kTZMw575LVPL2wXyUrKth8hihND9',
            'TFkhXGR7z44L2XrVLNXeMgWuwKnsfnHuSk',
            'TRGwfGKPsjPXDyYAHqNAR71SwjXSTn8HnN',
            'TBis3JCtYt32BVunr5WRYFDsQr866Z8Czf',
            'TMQ2Fv9kChyp5cQ1NgD3AJtV8vzcpcKJgm',
            'TUL984mZ9xExKh1p5Z45GEKxeu9WZ1gZNR',
        )
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=False,
        )

    def test_testnet_change_addresses(self):
        addresses = (
            'TDwNHhuyrRXZ3LGy6NKMK8v6pMkRtbtjiy',
            'TQ22wSVAfosGakW3vupnrk6a3KBFMm4ugt',
            'TXJKiGd3ajVMa5YYBcDanNWczUaGCA9S8R',
            'TFFDH6KJcnMu7WbLAF2U4dp5YzCsstpZS4',
            'TVcbpDGCfkUJo9pfZGCLgA2Uke6jiyFiwn',
            'TUcyfDnNTa5idkMYEkaQQj9RBmnXbfFqGo',
            'TSXHvX5jn6Ew4AzAJttYDWuDc9LSMaFinp',
            'THE5MJhuF1dEY4ciGxVEASdo2RaFrVw4XG',
            'TLms47L7fEoszxvKzr5zP9CeMCp1AXkydL',
            'TPwwKbeqhpWxkpj4fRQ5fZKM4uypAsFDSz',
        )
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=True,
        )

    def test_mainnet_receive_addresses(self):
        addresses = (
            'Ecy37k7NCLa6VMnkjSis83kn8HQfYp7yBC',
            'EU7biMsnwdvpjkSwvFBv25UWqAgSZ9TiQV',
            'EXvVM8QrEBvHrHMUVncpFdZsaPQ4qEJre4',
            'ESuWp3Vwk5UYAKZkdG2aM11uKVppkZNyMA',
            'ELLiHeDEqb72wCsibuNk1xmgBkSwxnLsWm',
            'ENwQ1nsuGHEHrfPiYwsSqfojoBYgv2NZTh',
            'EYTe9nnB9xZV475PWQhxu6JGobHFk6JkEt',
            'EJuZXpffq7Cz1dT24erE2EWhGhsuLxz1XV',
            'EUaikScXUw9mujwEbFYqeJBJznkS3k1QMi',
            'EbWqcbELSBQv9pZ3J8PskDcnWkuKqWa5tx',
        )
        set_elcash_mainnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=False,
        )

    def test_mainnet_change_addresses(self):
        addresses = (
            'EM84nENm8ehWsTpCJwf9o8CvgDWF93PYvX',
            'EXCjRxwwx33EQt3H9VAbLjPPuAw4bs5NHj',
            'EeV2Co5prxfKQD5mQBZPGMoSrLL5UfjFpQ',
            'ENRumcn5u1Xrwe8ZNpNGYd6uQqxhBvraCq',
            'EcoJJjiywyeGdHMtmqY9A9KJcVrYuip7Tg',
            'Ebog9kF9joFgTstmTKvCtiSF3dYLrCZ8LW',
            'EZhzR3YX4KQttJXPXUELhWC3U16FbNjAUA',
            'EQQmqqAgXEoCNC9wVXq2eRvctHL549xTCX',
            'ETxZYdntwTyqq6TZDRRns8VUD4ZpPfTfBq',
            'EX8dp87cz3gvaxGHszjt9YcAvmjdQxWxaM',
        )
        set_elcash_mainnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=True,
        )


class TestElCashStandardSegwitWallet(TestCase, TestUtilsMixin):
    # 10 first keys
    # keys in format private_key: public_key
    RECEIVE_KEYS = {
        '4d8b01626eeed82a8a967a3f5244e2c16c012b5168e379db3529daf4a56133f1': '0381151a69fb57f543e2c79c835a73f2ac99ad6e0ee347019066ce9a8a052b24e9',
        'a93b21be8cb793a9107db4027bf28e4ca2d54a4c18e43db6320a7e50011dab82': '027f6796b005d857df23953be84510246f626e7f51fae561c20bc02d0d98fd99b9',
        'aefcf33b184a9795bd4bac6d6c41191039350324c1dfd5994349bf383861e5ff': '03d3f1a4c43e4992c4bf7d75976b2ba11e4cab66fc5e0b8760329140cff0d7306d',
        '73a7739a467d34c22ac639e0d3e1992b1b2f10cc8cc8c7aef24247d3800460c7': '02a74c997f646cd45f03e3d4e87baa35d1d3b83b9e2e30e54f370c3e630afc97a2',
        '2e170e1533bab0174233444b647fe473c659dec1cfe3e4f7a1b723a31e8e2430': '03cb13a48f281f01bbc71086d936cd89387a085555cb7b76c3aa437d21ec4fb95c',
        'c04a100ad601e095d4f597fa76d01bd8618b5e00ad9ffe5967fc754f7faf47d1': '029dacc8c1cbae2c70d6837d91837d9f28a45d59040c5db18a6dc4b2b201259d47',
        '94cb81202bad11467b1b08104fad8d1df416331cd2cd477366d4ef1d81bae564': '02d1c8760d0b436d8fbdadee00a8f75fd1c9d8cc66b1edb95b814d9d08a239853f',
        '283df4b043a2585dee6a06d9664b8cd8ff411fefae26ddd661a3718b3b76da43': '03c293f934723a50a640a9c7699a90f97c86abd285f41dfca49472e85889d7b1d0',
        'a01668dcd223de0135008534f8dacbf61b60ab6ad2f847bad83b938ed2e8c8db': '0345a969720fdf2d44b1bfe9c4e1c64a84c8be3bb56fbe60bbcbc63442a5132931',
        '80e0c0ea9acc3318586b1eaf70b496680a8ec35b7209a01009a8edf5233d8d83': '036e38a09d2598909f9234c52a5abaffe10754d32d1dca7514228225ee2f3f9688',
    }
    CHANGE_KEYS = {
        '0d99c1a47f1871aa55d990f2f30e32d57850df66c19e2bf87b6f8269cde3bcba': '027c3b345cd9db6964313849eec702d1bff33f3508ca4a775430d8342d0344dd57',
        '1d4018da3202083d0a01fa98af3d744fcac84d9a428ea70ae780483d70cb5ea4': '02ed12ec848f1524a2a7e7b5f35c77c098017bc4dd2a3579ab4521567fe572863f',
        'dd698cf163f3ba9320568d89c6beb1044daf4e63a98b878fcf76ae48f62f4c71': '03e92543138ff2ab82c7ae39e624fafd322339532488e7734415c4a1f219d3d877',
        '0be64430f96693bbaf9de7f932dbcaa9986e85b79d4448fd630b4dc4e7a8b5fe': '020d7b9cd3fa74eeb5e640eedfc87bd5bb9ad167f3b3a0a42e2c3ca032eaabbd85',
        '8a24946b0e5703aac882a826f2532e9349c0c13930f5fb9ba5bd333a7908db3d': '020b90281b968db4c01681bb51a18059fe2cd5558545305c9e831f81fce6f3033e',
        '7014b14013246c37d5c56d76f39d72e733830441648d9b0aaabe0f7f7959d5c7': '021e34a1b03cfa9d90d564f47fba80efdccef412a8f3f35a2ae2ccd017afe55701',
        '3cbd912ad2e99365065db7d6d50c760cef25d1697667191321c9441ece44c7b8': '0202f8260d94266cabdb9dcc9c79699c82ed93484e71dd80b5073d241cce3d767a',
        'c48db4b8fcb45b2a21ff8b7dc76a9002468dab31124dfd15251e09b8cbc86d52': '02fe7d7ea7fb8a656a4ce61e34be74449c6c42c79f6aaf242731e713dcb022726c',
        '432cc7b6577c62d5ea668b9d4dba02e64fad30c00c92a11c3e63093166e9cee5': '039046427f714ae13b3420b0d193b8ec94bb12e7dc9bd88611600243fd3be0f570',
        'e4750c41109a1da6ef807a75c62dbb2fe76c94c964a92b75466f75bc480f462a': '03645847de8246c57f613daf73372a1bc880d6eea537c2d215137e2da95ff68e9c',
    }
    GAP_LIMIT = 2

    def test_derivation_path(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self.assertEqual(
            key_store.get_derivation_prefix(),
            "m/84'/2137'/0'"
        )

    def test_receive_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self._test_receive_pubkeys(key_store)

    def test_change_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self._test_change_pubkeys(key_store)

    def test_testnet_receive_addresses(self):
        addresses = (
            'telcash1qv9cks2mwhcmfyskqyf88l7h4xd2xsv5tajlh4p',
            'telcash1qr39yrr0sy2jzglsjh8unpur0j5t252k8erp2c4',
            'telcash1qdw722dd9w0uwtj40frpvasjchnz76nqh7zsy46',
            'telcash1qz80yf3u7re8f8c82ccaztsmm0jr0yx534mq5e3',
            'telcash1q5mjgr3cse050rx5srgrcxkudf8jchtpd95ffhs',
            'telcash1q9lpu9x3m595cntperxwy7u68u3v9wt5ml00f9a',
            'telcash1qmnz3ah3vu8t222ll2kd603n9nhurpusmcj88rk',
            'telcash1qja3qe7hegq5vcgl5epq2s9azlj9s9p6kjnrntx',
            'telcash1q6vt8xxaufyzwwmyy0st85qmr7x4q5a6dup5auj',
            'telcash1qn85zgqy5d4qcfnvecrvd6ly9pgupzlsvvtd55l',
        )
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=False,
        )

    def test_testnet_change_addresses(self):
        addresses = (
            'telcash1q0k6tf278s7cupegf5pc58jl6p684mfgarzrhcd',
            'telcash1qn4pqr37s7kt7465m0pwvkqtnqet5dnlc8vnkks',
            'telcash1qn8cx9vnc3e65xtf6ldclgzfc7x3t90g63lrkau',
            'telcash1qtw7q8z4f0wcp2h8tmtlz5t0kml0waxxzed9dun',
            'telcash1qzrhh8hlfmnrl0a0fq6wwf5wew2kmw0wuzagxtq',
            'telcash1q9w3gxkp5xecqu4srwwww2lelydm989u7g6225v',
            'telcash1q7y042vm8hldqvg5yhh8hjzz44kpjyfw94vp832',
            'telcash1qz5tmwd2q8slkyg0me6h3kp2l0e6fn2l8r3mh2x',
            'telcash1qzydzf5sfptuvt64aq5ux0lmg5qctjrgpd060ua',
            'telcash1qvlwu64jxs7f37ccrp6u8hq7uzeghvy5kjvnwjd',
        )
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=True,
        )

    def test_mainnet_receive_addresses(self):
        addresses = (
            'elcash1qv9cks2mwhcmfyskqyf88l7h4xd2xsv5td8jkjm',
            'elcash1qr39yrr0sy2jzglsjh8unpur0j5t252k8fkvtl0',
            'elcash1qdw722dd9w0uwtj40frpvasjchnz76nqhwha9jq',
            'elcash1qz80yf3u7re8f8c82ccaztsmm0jr0yx539wd47t',
            'elcash1q5mjgr3cse050rx5srgrcxkudf8jchtpd4pygs2',
            'elcash1q9lpu9x3m595cntperxwy7u68u3v9wt5m06zgz8',
            'elcash1qmnz3ah3vu8t222ll2kd603n9nhurpusmg82xyv',
            'elcash1qja3qe7hegq5vcgl5epq2s9azlj9s9p6kzxwjvu',
            'elcash1q6vt8xxaufyzwwmyy0st85qmr7x4q5a6dv5eumg',
            'elcash1qn85zgqy5d4qcfnvecrvd6ly9pgupzlsvu7q4n9',
        )
        set_elcash_mainnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=False,
        )

    def test_mainnet_change_addresses(self):
        addresses = (
            'elcash1q0k6tf278s7cupegf5pc58jl6p684mfganhwklh',
            'elcash1qn4pqr37s7kt7465m0pwvkqtnqet5dnlche7h32',
            'elcash1qn8cx9vnc3e65xtf6ldclgzfc7x3t90g6p2wh6x',
            'elcash1qtw7q8z4f0wcp2h8tmtlz5t0kml0waxxzfcgvmf',
            'elcash1qzrhh8hlfmnrl0a0fq6wwf5wew2kmw0wujg98v6',
            'elcash1q9w3gxkp5xecqu4srwwww2lelydm989u7c08tnk',
            'elcash1q7y042vm8hldqvg5yhh8hjzz44kpjyfw99evxks',
            'elcash1qz5tmwd2q8slkyg0me6h3kp2l0e6fn2l8nykkdu',
            'elcash1qzydzf5sfptuvt64aq5ux0lmg5qctjrgpa6hwm8',
            'elcash1qvlwu64jxs7f37ccrp6u8hq7uzeghvy5kze704h',
        )
        set_elcash_mainnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=False)
        self._test_addresses(
            key_store=key_store,
            addresses=addresses,
            is_change_address=True,
        )


class TestElCashMultiSigLegacyWallet(TestCase, TestUtilsMixin):
    # 10 first keys
    # keys in format private_key: public_key
    RECEIVE_KEYS = {
        '5545c67e1c58441d3ff2af3dd8a0485f8b0c01b74789bbc6483cbaebe8d12c3e': '03684aa8d2ce4c578e503cc0bdf0b9a95d2baa4112fe6fbdfc74990749d8b2734e',
        '0c5304a021b94063e69b08ccf8135494cc21ab05f0289c73b0860e14758d4776': '026322b67863d92f0df08510842e5d4f5c4082884ef8c12d122f51f9cba474ce3d',
        '9c7f9bb43da1d5ca7f7ac48c584b65f1c8da31841f820da268be548ff5e073c7': '02b52de7df001eb70383514c9621616de2d93975bfae5cadb1f183b81f57a4ecb4',
        '4289202d1844797cd666cf4cf9f9846a4de9e46f90a375e090a72f920210b2da': '020e3c7d7bf3ee00de3024f3552120c1f1713fceee282d31c5038102c9301c02ca',
        'c3093e8e200eb9b1802d84b90495b6ee983299eefd7d011ce3dc88ee6735bbce': '024202ebdf568684f99c9c6db4e2a278a306d2b3d93de96dc5d81353cc71612dd8',
        'bf4240d191a49177b2711651725f0f9a5d1bb01d7b04c6eb1b816c6b14943d8d': '033de74d564694c7f574a0906b1afa9c90cef3e2156d70d5389529c9f3fd88c59c',
        '07afbb43b6c9ed1a4d0c579ead18fb3f4e255bed4ad6a74199380e1dc3824421': '0361c453668b7a30f044889300d2e3cafc8d7c65ffff0a8f08623ef4a2469a1569',
        '359e8df68d3b794f469928ee7de2c895f7a6b5ef9b64c96bfb3a22939c3eb7ca': '02b223766a49ebd82cd05a98aef5cc19536a9eacb9fe6cd6adc88c2f9c296123d7',
        '920ae9415c027b7354f69d4f63f6b2ccb8a33fe6dcc883918f7fcf226a40fc3d': '0271d9cfec8175f31ea9042bb99c432b8f548fac0c4932cdba25461e5537405509',
        '75402a95e34697a01604bc486406b2c0bfbc7c599da26856496d016c6b9f1a67': '029022069a124e9b67dc834dfe0c594857270abeaa7de9f5f5707e5cd40abaca0f',
    }
    CHANGE_KEYS = {
        '84ef772495a986f55abc241a6cc29b096a96e1ddfa2ef803493ab69d93467817': '0248d589537c4ec9d2f8d033aeb4ffed547e9f47194b675dacc4676a341d8eb6ed',
        '6bd0f1bf8612a09e6890fa5540e3dc50192232794c2bb5b86a981eb9ac6a2877': '0338c1fd498cf60d3a87712441e3c956ffe8e76ee8791890b060f58d402a795e0b',
        '027ea9b14b3af02655167b361459b4a701665cc8eab593e1842f613753877fe4': '03873fb26f200e05f7870399a74e850a721a41c33fb117a79c1f43fddb6c0d8bdc',
        '1590ded2933d3e5091a3cc2a9394a6078f150da4804a2f087f8d132182598ed3': '021f629fc1d8a0769ebbc67b39e0b62175ed89e4d580acb2171deddc253f04cdee',
        '5601b19dd1b44aae33b79255b3a0474ba2b3c2db2cf38267e208a9c9df5dc472': '03088d2fef3de2da39ae4e74555e90ce0430ea57cc0679a396f83a1384eccd7c05',
        'ed6b77f22605077152df916b96dd4d3f1c1d77c134430f0c264df50b656ececd': '02a9d15f23ee3d9b5fc003e03c7c3eaab473afc79fe00fb264d678df66df848921',
        '1c773dd4fe6ca51b3cf5a49752afae9009c8b6c50bb5de26af6ce8134f5db3e7': '0365e15c8e5c48c48f1c0e4cbb26b1006378b685ace56285c3b025539288958261',
        'c40abec5a0efcf338532c1e7246e847107ebf2ecfb2e1483b5a0b6563f3f666f': '03036907bcf01322ea619e355b79587c3099ed14ab3e23925b47ebefaf4f681f63',
        '1c66b7749f3781ea3513a703fd7c1f946e683136c88bbd4cac2d78298f3e1200': '03eccef78666e2997fce4d7dffde92d4f0ca05eeb339b69c9ccf0231eb3d0df1d1',
        'd4cebf6fcad2f8d4de2ba18fc9bfdaa97eecfb0689247eb020f3ac103628a62b': '036eae1e13d5d8914ddc60801b0c1a1cd886ca41140837b07ffde5e3be901392d1',
    }
    GAP_LIMIT = 2

    def test_derivation_path(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=True)
        self.assertEqual(
            key_store.get_derivation_prefix(),
            "m/48'/2137'/0'/3'"
        )

    def test_receive_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=True)
        self._test_receive_pubkeys(key_store)

    def test_change_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.LEGACY, is_p2sh=True)
        self._test_change_pubkeys(key_store)

    def test_testnet_receive_addresses(self):
        addresses = (
            'e5nmZb8rpJR2vxeD9fpi6ZsxwqVLiqHv6W',
            'e7PxkLBdRKcrJNjGV6vNWgBS8D7mmoHhYa',
            'eFQm4enDmzfz6WbE2kC4s2zF5o85k7FB7H',
            'e3MU6NnSoxpYDhMBdkgtDYgdkq1pMYYrKJ',
            'eHQifdBT6rS7wBxkaEw8i9XbB8ZvjX3VGn',
            'eCiawtbiiFxhgGyQxgYeivzJtw8RRAgz6W',
            'eCi6qkhKkcUYtSNv62xFyFh3wyxP1nTAtr',
            'eD2ZvgfCNez7HKedrgpNUC5oYbWXtJ5fZp',
            'eDcacsYP4N5qTzgXWQEP3rbwDsEBF9kRN3',
            'eL1vpc39txMTABPNiYrLVVdvJGRDU5i9fH',
        )
        set_elcash_testnet()
        seed_type = SeedType.LEGACY
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=False,
        )

    def test_testnet_change_addresses(self):
        addresses = (
            'e5CdLgBF1Tdaovi6Upzqnfu4z9UgYP5dCi',
            'e3n2xJ5i6iY6Ly6igmeXDfdY9CgC9cNkKt',
            'eCHFHaDf9bhWPgAY3WB6JLaEx1VWGyUbD5',
            'e6AqRjk9nNbtSvuuFVCkXJCDYi1uWEJrP5',
            'e8uXCRQKp5uHTkyx8Dc75M5HYPjDZNHqMw',
            'eBdJ3Deq3KRLREbzJVW9uYwhk3cL6UD48S',
            'e6UTvcuY4etTnSrnqtHgBV8cJ9zaYFgDkz',
            'eFDBNxdKZAKmcirLHkcX5KZdTfP8iNo6iq',
            'eFACammzjrsUF5rC9SBpq6XFoLUnHwWXdo',
            'eHKR3ZPuMo9zCxnqEJ8K9uVbmnYDyCjrdq',
        )
        set_elcash_testnet()
        seed_type = SeedType.LEGACY
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=True,
        )

    def test_mainnet_receive_addresses(self):
        addresses = (
            'c56ke3eRGQ6eqnwn2aA7fwX2oKCdAm8QYp',
            'c6hwpnhBsRJUDD2qN1Fn63pVygq4AY5TXN',
            'cEik97HnE6Mc1LtnueXUSQdJwGqNGUes6R',
            'c2fTAqJ1G4WA8XekWf2HnvKhcJj6q51dz6',
            'cGihk5h1Yx7jr2GKT9GYHXAf2cHDCjg5Yp',
            'cC2a2M7HAMeKb7Gyqat4JJdNkQqhwBh9DX',
            'cC25vDCtCiAAoGgUxwHfYdL7oTffRgpU6Z',
            'cCLZ19AkpkfjC9xCjb9n3ZisQ5DpLcisnY',
            'cCvZhL3wWTmTNpz6PJZndEF15LwTgJ13Wp',
            'cKKuu4YiM43551gwbTBk4sGz9k8Vx43eVQ',
        )
        set_elcash_mainnet()
        seed_type = SeedType.LEGACY
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=False,
        )

    def test_mainnet_change_addresses(self):
        addresses = (
            'c4WcR8goTZKCim1fMjLFN3Y8qdBxzK1P3U',
            'c3622kbGYpDiFoQHZfyvo3GbzgPUbC1Wiy',
            'cBbEN2jDbhP8JWU6vQWVsiDJoVCnj5Ndnp',
            'c5UpWCFiEUHWMmDU8PYA6fqHQBjBw6ToeA',
            'c8DWGsutGBauNbHX17wWeiiMPsSVxwjPcA',
            'cAwH7gAPVR6xL4uZBPqZUvambXKcZnradf',
            'c5nT15R6Wka5hHAMind5krmg9dhruBCXX5',
            'cEXATR8t1G1PXZ9uAewvehChK96RBDKkHK',
            'cEUBfEHZBxZ69v9m2LXEQUAKepC4hQVQzq',
            'cGdQ81uTotqc7o6Q7CTijH8fdGFWLZZFdt',
        )
        set_elcash_mainnet()
        seed_type = SeedType.LEGACY
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=True,
        )


class TestElCashMultiSigSegwitWallet(TestCase, TestUtilsMixin):
    # 10 first keys
    # keys in format private_key: public_key
    RECEIVE_KEYS = {
        '5d49fc20ca9641f7eb10b9d20b377d25ea472b78d706aadcca3c9a7f023e49c1': '039ed31e44da6a45fca6484a3682f0b461a488ed72102d69f31dc8ec0d2525b825',
        'bf348973a4d0c03fc2525f76593327521ba101ccf9a12cec4e91408f9767b60c': '02f8c35eea5cbc5c8786d9f157db05a0e7d95b7d74b9027b514035112967d11275',
        'bd18aeaa28ec8a85e04648521b0c9c1d14aad2972a16f9487a51c8d2b303bf22': '03cb5bb24dabf9c67b6b1e52381051d732d4ddc26d2b618fba7d34f0b7eb7b4b15',
        '0d85feb8051d8b314ca0a15fb4709908149bacaeaab53aafb1cb19463cc1c3db': '03471976b4f331ca745386d4654cab09babad5710d455bc3ba79497802a3461a29',
        '9b06eed1fbe21dcb97ed3fabf9431742822fd22dc7c520215f9f4a34d087c4fc': '02d7a383672800179df1aa5e0ab3a4769ab0379e73c4c84ca2b06da339801bf1a5',
        'a9e2c235cccc55597fb8bc171e5512265243b15f322dd4ee6d480d7868a01bab': '02ce5e7d59843355ad49d8786b4078a014399b35a5b183e6b9ffa2a703d51aad8b',
        'f5c60ec85fdab8ad74ba1176665eb74c184152d60efb20c48a9adec77c7d7c10': '03449fcd05d25a90ee11ae65b48249223430ae42c51da5e60296e64397f1ce0b28',
        'cc2be51c5a237464c81cefc08a1b6ff1d2dfd240a712e7632c97be47a5f8220c': '0254dfa579ace6430c9437472f623e9adb4e4277c1c3e76d35317495d1f18a6fbc',
        'a71dc1687bac8a61a85e9cee11d2d97c995f1026afd0510f5cae44a1220ec250': '03f97efd2b5dabd1d05a90c9a2127b332f9d3f5d2483203bfb2cd561110ee1a1a5',
        '555505d9304771e73d8764b96def3ee61f3ab890c99a229c804c0773dcb0f53d': '0283eb3bfc310a6c1924a4859538ce64cc1afe121b8195c500424ea957f3028651',
    }
    CHANGE_KEYS = {
        'b5dbb23f0c909ca1fb19d8773a1986ffe7d22ebd3628c1aa12afbf4b762e1703': '0214b0ce7762d9dccc96965af62e47122ba1efe1f302a1f6a8fc08e249645b1df5',
        '0282bc9ba2a4bda52d2364853d486e01622bc2da89af15cb05d4c11da964e883': '03c22a645929d9e43b5876870078eb38958885226e17ba06c38d6098186901bbd5',
        '71c9e364e4b952997726fa14b6e82467d9f3459ddf5f59cb44476d4e44260569': '02fc83a3a1bd4778f2db317e82d573dd6942eff2b05026f06f20c48e24dbcdb248',
        '318591be4d66e9fcee682f2b4e6b8661d3b1f99e4ccec2730638f2d9053da1f4': '03d6e7074e09ce6788986cea7bd7a3f4f885ed5c87201fc428eab3fb4b87121746',
        'a6e3d168d4814fb0b5c9849530b710aaaaf0a43b42023b5858c3868d95f5b0b6': '03a47efef02dc764db06d4fb4d76cb040bd6e461da2487d6b69b8bc2d2a3bf9c6d',
        '966b8d68e64c1b772e2637c6cda3b79c84fb3aef8a4031fa1c7756d02ae38771': '02841e92ea7446ee93aa5a8c25ba1ff395b5abc25e3864746ee588b7959e8cad0a',
        '90d7f041e5d59658f533d4b3684f719eec36ab06aa3ec2490f82726dcfccd5ae': '02075f04d702d53f9e5a1009b04dd886a54cc22492ddebae33c94fad1509c3051c',
        '469b54e47cb2ca6eeaa1271f83a1c1e02a60d7b6d1dab5a6ac6827f0b72f6167': '02abb80c26c7c72d893df8580f386582c5261d80bde77c52a4bfcb8e1b6ff8be10',
        'ff2950efc740b5255a3dfa76aa7a666deccd9af2186d5344b14746ef58ffc6ed': '02121b573681d1ce9dc294829b04d6524ebcafced8f8ee9405a6d54cbee6d900b3',
        'cd84717b274ff5e74e88fd02e8b7a76fb716e6d05832d95abb63659db7fd4098': '02e88f773682f129852c0ae098a6d699f62dfc23fc8ab98d83721b5c1643cbda90',
    }
    GAP_LIMIT = 2

    def test_derivation_path(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=True)
        self.assertEqual(
            key_store.get_derivation_prefix(),
            "m/48'/2137'/0'/2'"
        )

    def test_receive_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=True)
        self._test_receive_pubkeys(key_store)

    def test_change_pubkeys(self):
        set_elcash_testnet()
        key_store = _get_keystore(SeedType.SEGWIT, is_p2sh=True)
        self._test_change_pubkeys(key_store)

    def test_testnet_receive_addresses(self):
        addresses = (
            'telcash1q0d64evf6jyu0vkjns22t6e69hu75qxvu84ahcn2auv9axgfxm3xqw43paj',
            'telcash1qjrhwl3zhxyp56zjv0zzmcgx474vq3rvm5muvsu70ylyvegn27mls35csga',
            'telcash1qlst770ldhecv5l87np4g32cg0kc2estxu2f8c3v3dxvsx8sl0tlq8r0p2e',
            'telcash1qjl8hk8erl3ukx79x9gv0wjyk46tz0302x0g3kfefjck7a9slgrlq9uh5dp',
            'telcash1qs5ewg9mh3wlqac7gyekv5p64g6m6uu3pd3xquku76v927xx2l5esepcwcr',
            'telcash1qc8w79563srjpf966xpwhf2r6sr7jqq3c8s2kt2tcg0rr04rncdmq3y4vr6',
            'telcash1qnnhgtxza5jrd9rtwllg6c946jhsk3sms3r7cmsaelzejqx20p7zqcm2kq4',
            'telcash1qm6yneet4f3ddh4l3n6suflxys9lr536l44mq308p62zlur53hguqkt9s9y',
            'telcash1qxx8jwl0lq0zwn64g43v94phah3aav90rx5kj8e8nnuvwtecm6pzsapd8t8',
            'telcash1qzht4caw6lq8jv55vaacwz27t0jhuxyw5hgh2fzzhnmay4zp3njvqzadnh5',
        )
        set_elcash_testnet()
        seed_type = SeedType.SEGWIT
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=False,
        )

    def test_testnet_change_addresses(self):
        addresses = (
            'telcash1qzhd37etus2mh62s0wkasxl0zwmnrjcm65hgkcq2zj7a349jeassq7zrep0',
            'telcash1q9fhpegvqsj0scd92ep62wueckz5deenjxujyrm8sdz2w5hq5hcuq35m8ry',
            'telcash1qm6cxq0lyyvnyvnklp9e42hj8htmgkx6g3hv3v2g29y0zs7sl64ksfynedk',
            'telcash1q2c7quy3wmzcle0q4qjmz6mjhgahck0ktqtchn89d2edxff264yxqq35jgc',
            'telcash1q7nes7dr02yldq788h7yvrp8ska95ff2k5s375afdklgxw2htr39qvqp6g7',
            'telcash1qgcyqxqnx9u090jaxnwmanecf0rhz54rsncqj2tmh84eekekaq8gqqm9lhl',
            'telcash1qx8etau3njvdcqj6wd8lfx2az8z0gamqnfetrvvq6zcyl460ypj4sqdttp9',
            'telcash1qhee5uwyvw0g2nxww5y8v8pgx0swkrd300nkxmv2pf2sqesnghxmqdhlj4t',
            'telcash1qj7qvw0yxx8ylerms56pmc759e6w88dknc5fjq3tazcvecxc7qekqrccwz9',
            'telcash1qgkcu9qrx9pw82kf3j2rypmaplyh9uptx8nkdwnh8rhwlklje4vasj94f68',
        )
        set_elcash_testnet()
        seed_type = SeedType.SEGWIT
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=True,
        )

    def test_mainnet_receive_addresses(self):
        addresses = (
            'elcash1q0d64evf6jyu0vkjns22t6e69hu75qxvu84ahcn2auv9axgfxm3xq46g33t',
            'elcash1qjrhwl3zhxyp56zjv0zzmcgx474vq3rvm5muvsu70ylyvegn27mls2mpqyy',
            'elcash1qlst770ldhecv5l87np4g32cg0kc2estxu2f8c3v3dxvsx8sl0tlquvk3xq',
            'elcash1qjl8hk8erl3ukx79x9gv0wjyk46tz0302x0g3kfefjck7a9slgrlq7nwypc',
            'elcash1qs5ewg9mh3wlqac7gyekv5p64g6m6uu3pd3xquku76v927xx2l5eszwp756',
            'elcash1qc8w79563srjpf966xpwhf2r6sr7jqq3c8s2kt2tcg0rr04rncdmq2tvu0r',
            'elcash1qnnhgtxza5jrd9rtwllg6c946jhsk3sms3r7cmsaelzejqx20p7zqr5nxvv',
            'elcash1qm6yneet4f3ddh4l3n6suflxys9lr536l44mq308p62zlur53hguqdyuqfa',
            'elcash1qxx8jwl0lq0zwn64g43v94phah3aav90rx5kj8e8nnuvwtecm6pzsxw5h87',
            'elcash1qzht4caw6lq8jv55vaacwz27t0jhuxyw5hgh2fzzhnmay4zp3njvqej5rmd',
        )
        set_elcash_mainnet()
        seed_type = SeedType.SEGWIT
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=False,
        )

    def test_mainnet_change_addresses(self):
        addresses = (
            'elcash1qzhd37etus2mh62s0wkasxl0zwmnrjcm65hgkcq2zj7a349jeassq9d6fdk',
            'elcash1q9fhpegvqsj0scd92ep62wueckz5deenjxujyrm8sdz2w5hq5hcuq2mzh0a',
            'elcash1qm6cxq0lyyvnyvnklp9e42hj8htmgkx6g3hv3v2g29y0zs7sl64ksjt2fp0',
            'elcash1q2c7quy3wmzcle0q4qjmz6mjhgahck0ktqtchn89d2edxff264yxqm7dzyp',
            'elcash1q7nes7dr02yldq788h7yvrp8ska95ff2k5s375afdklgxw2htr39qh0c2y8',
            'elcash1qgcyqxqnx9u090jaxnwmanecf0rhz54rsncqj2tmh84eekekaq8gqm5u0mx',
            'elcash1qx8etau3njvdcqj6wd8lfx2az8z0gamqnfetrvvq6zcyl460ypj4smzjmdu',
            'elcash1qhee5uwyvw0g2nxww5y8v8pgx0swkrd300nkxmv2pf2sqesnghxmqkcxzej',
            'elcash1qj7qvw0yxx8ylerms56pmc759e6w88dknc5fjq3tazcvecxc7qekqchp7wu',
            'elcash1qgkcu9qrx9pw82kf3j2rypmaplyh9uptx8nkdwnh8rhwlklje4vasf2vek7',
        )
        set_elcash_mainnet()
        seed_type = SeedType.SEGWIT
        key_stores = [
            _get_keystore(seed_type, is_p2sh=True),
            _get_cosigner_keystore(seed_type)
        ]
        self._test_addresses(
            key_store=key_stores,
            addresses=addresses,
            is_change_address=True,
        )
