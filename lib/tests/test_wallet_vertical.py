import unittest
from unittest import mock

import lib.bitcoin as bitcoin
import lib.keystore as keystore
import lib.storage as storage
import lib.wallet as wallet


# TODO: 2fa
class TestWalletKeystoreAddressIntegrity(unittest.TestCase):

    gap_limit = 1  # make tests run faster

    def _check_seeded_keystore_sanity(self, ks):
        self.assertTrue (ks.is_deterministic())
        self.assertFalse(ks.is_watching_only())
        self.assertFalse(ks.can_import())
        self.assertTrue (ks.has_seed())

    def _check_xpub_keystore_sanity(self, ks):
        self.assertTrue (ks.is_deterministic())
        self.assertTrue (ks.is_watching_only())
        self.assertFalse(ks.can_import())
        self.assertFalse(ks.has_seed())

    def _create_standard_wallet(self, ks):
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        store.put('keystore', ks.dump())
        store.put('gap_limit', self.gap_limit)
        w = wallet.Standard_Wallet(store)
        w.synchronize()
        return w

    def _create_multisig_wallet(self, ks1, ks2):
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        multisig_type = "%dof%d" % (2, 2)
        store.put('wallet_type', multisig_type)
        store.put('x%d/' % 1, ks1.dump())
        store.put('x%d/' % 2, ks2.dump())
        store.put('gap_limit', self.gap_limit)
        w = wallet.Multisig_Wallet(store)
        w.synchronize()
        return w

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_standard(self, mock_write):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xq1voqNse7SRu45ADCKVJEoDw1z5G95wZNqCSyheM9vwPTnYWuNyuN6m1MdcJ91ZoFgCuyba5THD2J9rnyhXfS5Qe7qnJEWLvsFMiYDDzBnepvx')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], '717CgQx3VSyY5u8iQG5ZngR4P1eV5H1PRQ')
        self.assertEqual(w.get_change_addresses()[0], '6xB6n4Xj6pqnHKYhb3gmfTMguD62gRhjwC')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_segwit(self, mock_write):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'fc1q3g5tmkmlvxryhh843v4dz026avatc0zze79tag')
        self.assertEqual(w.get_change_addresses()[0], 'fc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzjr6pu2q')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_old(self, mock_write):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(bitcoin.seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], '6t2g1hJkduqsSvyf6DSJpsSJnUsCUoz8tR')
        self.assertEqual(w.get_change_addresses()[0], '6x9wvLT8Dmmq9C5Mq6VZSz8wavUy4od4WS')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip44_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xq1voxdCgdGjwcKKVtabawSDLQhnjTVRxQ1dXGW3MY1UhnMTQ9GJ3VvZCZdk4Fp5JTuXjnzM4iBxAGcb3GtfzUXdfCbap3CvMzgnHyKETsnX32g')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], '6jTZ1Mv5Vfhtuh96dUrx8LBRnCxfcwvN4P')
        self.assertEqual(w.get_change_addresses()[0], '6tzXP1pYchJLya4Wg5VAfPp5DdoGoVTwyi')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip49_p2sh_segwit(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], '35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W')
        self.assertEqual(w.get_change_addresses()[0], '3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_standard(self, mock_write):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xq1voqNse7SRu45AE3kBtmVQxZeJ1UFoYKxCLmhpcBEjffRtQdJbEohAqDi52zwgm89z7hmjtngf5NyVJximE42T5srjEecUgvTxQ5AzNUbifRg')

        ks2 = keystore.from_xpub('xq1voqNse7SRu45AELiBEUg6Lodbeh7rDafkvyfQz3r7VhmQaZrAuXBVuuPFX7QXgGcKpWjsikvAKngnDSbMUd1baPFuQyVbCZeXrHh3s5ZRqxs')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], '32ji3QkAgXNz6oFoRfakyD3ys1XXiERQYN')
        self.assertEqual(w.get_change_addresses()[0], '36XWwEHrrVCLnhjK5MrVVGmUHghr9oWTN1')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_segwit(self, mock_write):
        seed_words = 'snow nest raise royal more walk demise rotate smooth spirit canyon gun'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'Zpub6xwgqLvc42wXB1wEELTdALD9iXwStMUkGqBgxkJFYumaL2dWgNvUkjEDWyDFZD3fZuDWDzd1KQJ4NwVHS7hs6H6QkpNYSShfNiUZsgMdtNg')

        ks2 = keystore.from_xpub('Zpub6ymNkfdyhypEoqQNNGAUz9gXeiWJsW8AWx8Aa6PnDdeL76UC9b1UPGmEvwWzzkVVghVQuDBry7CK7wCBBdysRQgFFmdDSqi5kWoZ3A4cBuA')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], 'fc1qlf9cr48pj5zheqedla0eucpzhufl7kp2nd0a0evsz529gdx7jgnsfu6rd6')
        self.assertEqual(w.get_change_addresses()[0], 'fc1q89s4j4k3ghdmscjz0pklz2fl24mc9ptvwyg38xgqyw8f5vk29ccsjt9dq7')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_bip45_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xq1vouL6LEZp1paM6EEUZo9pp4HisFYF4paRMHUnEsQK6LagTnhBNhdG2GN5jdFtzpmLsjg1JV7oR78Mih9FyYiEqHyd55rZqo1F1WK5nsMK3sx')

        ks2 = keystore.from_xpub('xq1vovzJpgMwrmKvS8DvBTitKs5ABtRcKqRhnQNurX8FNMtKcxevmj7vFqJk4tWusMQwwYuK3kG5iW5CRsAmzY6mVgDQRtqTfnNXkXms2Ukm6s3')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], '3H3iyACDTLJGD2RMjwKZcCwpdYZLwEZzKb')
        self.assertEqual(w.get_change_addresses()[0], '31hyfHrkhNjiPZp1t7oky5CGNYqSqDAVM9')

