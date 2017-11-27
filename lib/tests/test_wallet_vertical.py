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

        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWrnppLtf')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'FrYULoWP7RAp5SCcwVQaTSQNE7KEdkjxRd')
        self.assertEqual(w.get_change_addresses()[0], 'FocNST64io34Grcc8H1nLDLzkJknNpoXpF')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_segwit(self, mock_write):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVF7CfyG')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'grs1q3g5tmkmlvxryhh843v4dz026avatc0zz7ttsyg')
        self.assertEqual(w.get_change_addresses()[0], 'grs1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzjy008nq')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_old(self, mock_write):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(bitcoin.seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'FjTwg5s6Ft39SU3ZdSmKVdRcdaXx9XAVQX')
        self.assertEqual(w.get_change_addresses()[0], 'FobDaj1Tqjy78j9GNKpa7k8FS29ijX3Cnu')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip44_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLZ6mWs9')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'FatpfkUR7duAuED1AiBxo6AjdJdRLTQuiS')
        self.assertEqual(w.get_change_addresses()[0], 'FkRo3QNtEfVcy78RDJpBL9oP4jU2RDUTJL')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip49_p2sh_segwit(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbM3NdVgT')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], '35ohQTdNykjkF1Mn9nAVEFjupyAtrJyzdK')
        self.assertEqual(w.get_change_addresses()[0], '3KaBTcviBLEJajTEMstsA2GWjYoPxX6T8z')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_standard(self, mock_write):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHF9MZ76m')

        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDbenT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjoVjze9')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], '32ji3QkAgXNz6oFoRfakyD3ys1XXfjymjf')
        self.assertEqual(w.get_change_addresses()[0], '36XWwEHrrVCLnhjK5MrVVGmUHghrBWAwNJ')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_segwit(self, mock_write):
        seed_words = 'snow nest raise royal more walk demise rotate smooth spirit canyon gun'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'Zpub6xwgqLvc42wXB1wEELTdALD9iXwStMUkGqBgxkJFYumaL2dWgNvUkjEDWyDFZD3fZuDWDzd1KQJ4NwVHS7hs6H6QkpNYSShfNiUZsh9UCBk')

        ks2 = keystore.from_xpub('Zpub6ymNkfdyhypEoqQNNGAUz9gXeiWJsW8AWx8Aa6PnDdeL76UC9b1UPGmEvwWzzkVVghVQuDBry7CK7wCBBdysRQgFFmdDSqi5kWoZ3B2MoJR')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], 'grs1qlf9cr48pj5zheqedla0eucpzhufl7kp2nd0a0evsz529gdx7jgnszwctgy')
        self.assertEqual(w.get_change_addresses()[0], 'grs1q89s4j4k3ghdmscjz0pklz2fl24mc9ptvwyg38xgqyw8f5vk29ccsee899q')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_bip45_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub69xafV4YxC6o8Yiga5EiGLAtqR7rgNgNUGiYgw3S9g9pp6XYUne1KxdcfYtxwmA3eBrzMFuYcNQKfqsXCygCo4GxQFHfywxpUbKNfafEvEU')

        ks2 = keystore.from_xpub('xpub6Bco9vrgo8rNUSi8Bjomn8xLA41DwPXeuPcgJamNRhTTyGVHsp8fZXaGzp9ypHoei16J6X3pumMAP1u3Dy4jTSWjm4GZowL7Dcn9u445kWg')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], '3H3iyACDTLJGD2RMjwKZcCwpdYZLuL8ZDm')
        self.assertEqual(w.get_change_addresses()[0], '31hyfHrkhNjiPZp1t7oky5CGNYqSqRrRMw')

