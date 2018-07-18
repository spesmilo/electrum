import unittest
from unittest import mock
import shutil
import tempfile
from typing import Sequence

from electrum_ltc import storage, bitcoin, keystore, constants
from electrum_ltc import Transaction
from electrum_ltc import SimpleConfig
from electrum_ltc.address_synchronizer import TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT
from electrum_ltc.wallet import sweep, Multisig_Wallet, Standard_Wallet, Imported_Wallet
from electrum_ltc.util import bfh, bh2u

from . import TestCaseForTestnet
from . import SequentialTestCase
from .test_bitcoin import needs_test_with_all_ecc_implementations


_UNICODE_HORROR_HEX = 'e282bf20f09f988020f09f98882020202020e3818620e38191e3819fe381be20e3828fe3828b2077cda2cda2cd9d68cda16fcda2cda120ccb8cda26bccb5cd9f6eccb4cd98c7ab77ccb8cc9b73cd9820cc80cc8177cd98cda2e1b8a9ccb561d289cca1cda27420cca7cc9568cc816fccb572cd8fccb5726f7273cca120ccb6cda1cda06cc4afccb665cd9fcd9f20ccb6cd9d696ecda220cd8f74cc9568ccb7cca1cd9f6520cd9fcd9f64cc9b61cd9c72cc95cda16bcca2cca820cda168ccb465cd8f61ccb7cca2cca17274cc81cd8f20ccb4ccb7cda0c3b2ccb5ccb666ccb82075cca7cd986ec3adcc9bcd9c63cda2cd8f6fccb7cd8f64ccb8cda265cca1cd9d3fcd9e'
UNICODE_HORROR = bfh(_UNICODE_HORROR_HEX).decode('utf-8')
# '₿ 😀 😈     う けたま わる w͢͢͝h͡o͢͡ ̸͢k̵͟n̴͘ǫw̸̛s͘ ̀́w͘͢ḩ̵a҉̡͢t ̧̕h́o̵r͏̵rors̡ ̶͡͠lį̶e͟͟ ̶͝in͢ ͏t̕h̷̡͟e ͟͟d̛a͜r̕͡k̢̨ ͡h̴e͏a̷̢̡rt́͏ ̴̷͠ò̵̶f̸ u̧͘ní̛͜c͢͏o̷͏d̸͢e̡͝?͞'


class WalletIntegrityHelper:

    gap_limit = 1  # make tests run faster

    @classmethod
    def check_seeded_keystore_sanity(cls, test_obj, ks):
        test_obj.assertTrue(ks.is_deterministic())
        test_obj.assertFalse(ks.is_watching_only())
        test_obj.assertFalse(ks.can_import())
        test_obj.assertTrue(ks.has_seed())

    @classmethod
    def check_xpub_keystore_sanity(cls, test_obj, ks):
        test_obj.assertTrue(ks.is_deterministic())
        test_obj.assertTrue(ks.is_watching_only())
        test_obj.assertFalse(ks.can_import())
        test_obj.assertFalse(ks.has_seed())

    @classmethod
    def create_standard_wallet(cls, ks, gap_limit=None):
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        store.put('keystore', ks.dump())
        store.put('gap_limit', gap_limit or cls.gap_limit)
        w = Standard_Wallet(store)
        w.synchronize()
        return w

    @classmethod
    def create_imported_wallet(cls, privkeys=False):
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        if privkeys:
            k = keystore.Imported_KeyStore({})
            store.put('keystore', k.dump())
        w = Imported_Wallet(store)
        return w

    @classmethod
    def create_multisig_wallet(cls, keystores: Sequence, multisig_type: str, gap_limit=None):
        """Creates a multisig wallet."""
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        for i, ks in enumerate(keystores):
            cosigner_index = i + 1
            store.put('x%d/' % cosigner_index, ks.dump())
        store.put('wallet_type', multisig_type)
        store.put('gap_limit', gap_limit or cls.gap_limit)
        w = Multisig_Wallet(store)
        w.synchronize()
        return w


class TestWalletKeystoreAddressIntegrityForMainnet(SequentialTestCase):

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_standard(self, mock_write):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks = keystore.from_seed(seed_words, '', False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6')
        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'LgbiA75qdajKtdsfEXQQGwfonAQZEEEbjS')
        self.assertEqual(w.get_change_addresses()[0], 'LdfcFkfXExba64HeRK1c9icSJMr6tMKyfv')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_segwit(self, mock_write):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, '', False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2')
        self.assertEqual(ks.xpub, 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1q3g5tmkmlvxryhh843v4dz026avatc0zz8xd49e')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzjazfzj3')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_segwit_passphrase(self, mock_write):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, UNICODE_HORROR, False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAZDmEQiCLUcZXPfrBXoksCD2R6RMAzAre7SUyBotibisy9c7vGhLYvHaP3d9rYU12DKAWdZfscPNA7qEPgTkCDqX5sE93ryAJAQvkDbfLxU')
        self.assertEqual(ks.xpub, 'zpub6nD7dvF6ArArjskKHZLmEL9ky8FqaSti1LN5maDWGwFrqwwGTp1b6ic4EHwciFNaYDmCXcQYxXSiF9BjcLCMPcaYkVN2nQD6QjYQ8vpSR3Z')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1qx94dutas7ysn2my645cyttujrms5d9p564qe9t')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1qcywwsy87sdp8vz5rfjh3sxdv6rt95kujfu64lc')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_old(self, mock_write):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(bitcoin.seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, '', False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'LZXBVPSYn3bfFfibvUm9K8h4BddGhUE4Fe')
        self.assertEqual(w.get_change_addresses()[0], 'LdeTQ2avMuXcwvpJfMpPwFPgz5F3Fnbsdu')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip44_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9zGLcNEb3cHUKizLVBz6RYeE9bEZAVPjH2pD1DEzCnPcsemWc3d3xTao8sfhfUmDLMq6e3RcEMEvJG1Et8dvfL8DV4h7mwm9J6AJsW9WXQD')
        self.assertEqual(ks.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'LQx4V43sdoTgiRt3TkBncbSBBMijtP3jg3')
        self.assertEqual(w.get_change_addresses()[0], 'LaV2rhxLkq48nJoTWLp19f4pcnZLtJeLoB')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip44_standard_passphrase(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, UNICODE_HORROR, "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9z8izheguGnLopSqkY7GcGFrP2Gu6rzBvvHo6uB9B8DWJhsows6WDZAsbBTaP3ncP2AVbTQphyEQkahrB9s1L7ihZtfz5WGQPMbXwsUtSik')
        self.assertEqual(ks.xpub, 'xpub6D85QDBajeLe2JXJrZeGyQCaw47PWKi3J9DPuHakjTkVBWCxVQQkmMVMSSfnw39tj9FntbozpRtb1AJ8ubjeVSBhyK4M5mzdvsXZzKPwodT')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'LZM5wF6QG1wGRvWhS2sgnHUT5Bxr9CJYdR')
        self.assertEqual(w.get_change_addresses()[0], 'LbHMUEAW7eeMKHS4LdJ9MfZmsSiQeoRyng')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip49_p2sh_segwit(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'yprvAJEYHeNEPcyBoQYM7sGCxDiNCTX65u4ANgZuSGTrKN5YCC9MP84SBayrgaMyZV7zvkHrr3HVPTK853s2SPk4EttPazBZBmz6QfDkXeE8Zr7')
        self.assertEqual(ks.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2wpkh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], 'MC1qiM3LvsbB3WdgFf9q3tzK9fmLrX1SQs')
        self.assertEqual(w.get_change_addresses()[0], 'MRnKmWLg8T5jPEj8TktCyfWv4FPqyFBS3V')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip84_native_segwit(self, mock_write):
        # test case from bip84
        seed_words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/84'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
        self.assertEqual(ks.xpub, 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')

        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1qcr8te4kr609gcawutmrza0j4xv80jy8z4nqduv')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_standard(self, mock_write):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '', True)
        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9s21ZrQH143K3t9vo23J3hajRbzvkRLJ6Y1zFrUFAfU3t8oooMPfb7f87cn5KntgqZs5nipZkCiBFo5ZtaSD2eDo7j7CMuFV8Zu6GYLTpY6')
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHFBUrq4c')

        # electrum seed: ghost into match ivory badge robot record tackle radar elbow traffic loud
        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDbenT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2')
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], 'M8wrMJA8deEQuJXhXYa6nrJPBi7yiLnCN5')
        self.assertEqual(w.get_change_addresses()[0], 'MCjfF7hpoc3mbD1DBEqqJv1scPJJDhtoMG')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_segwit(self, mock_write):
        seed_words = 'snow nest raise royal more walk demise rotate smooth spirit canyon gun'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks1 = keystore.from_seed(seed_words, '', True)
        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'ZprvAjxLRqPiDfPDxXrm8JvcoCGRAW6xUtktucG6AMtdzaEbTEJN8qcECvujfhtDU3jLJ9g3Dr3Gz5m1ypfMs8iSUh62gWyHZ73bYLRWyeHf6y4')
        self.assertEqual(ks1.xpub, 'Zpub6xwgqLvc42wXB1wEELTdALD9iXwStMUkGqBgxkJFYumaL2dWgNvUkjEDWyDFZD3fZuDWDzd1KQJ4NwVHS7hs6H6QkpNYSShfNiUZsgMdtNg')

        # electrum seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        ks2 = keystore.from_xpub('Zpub6y4oYeETXAbzLNg45wcFDGwEG3vpgsyMJybiAfi2pJtNF3i3fJVxK2BeZJaw7VeKZm192QHvXP3uHDNpNmNDbQft9FiMzkKUhNXQafUMYUY')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2')
        self.assertEqual(w.txin_type, 'p2wsh')

        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1qvzezdcv6vs5h45ugkavp896e0nde5c5lg5h0fwe2xyfhnpkxq6gqa9a79a')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1qxqf840dqswcmu7a8v82fj6ej0msx08flvuy6kngr7axstjcaq6usxndfdg')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_bip45_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9vyEFyXf7pYVv4eDU3hhuCEAHPHNGuxX73nwtYdpbLcqwJCPwFKknAK8pHWuHHBirCzAPDZ7UJHrYdhLfn1NkGp9rk3rVz2aEqrT93qKRD9')
        self.assertEqual(ks1.xpub, 'xpub69xafV4YxC6o8Yiga5EiGLAtqR7rgNgNUGiYgw3S9g9pp6XYUne1KxdcfYtxwmA3eBrzMFuYcNQKfqsXCygCo4GxQFHfywxpUbKNfYvGJka')

        # bip39 seed: tray machine cook badge night page project uncover ritual toward person enact
        # der: m/45'/0
        ks2 = keystore.from_xpub('xpub6B26nSWddbWv7J3qQn9FbwPPQktSBdPQfLfHhRK4375QoZq8fvM8rQey1koGSTxC5xVoMzNMaBETMUmCqmXzjc8HyAbN7LqrvE4ovGRwNGg')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2')
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], 'MQbbhvCgqcowyoHsoEdZkvMENhhvktToCi')
        self.assertEqual(w.get_change_addresses()[0], 'MMV7XoNeRLdTcwqYBq9e6fDtG9E9uHciwz')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_p2sh_segwit(self, mock_write):
        # bip39 seed: pulse mixture jazz invite dune enrich minor weapon mosquito flight fly vapor
        # der: m/49'/0'/0'
        # NOTE: there is currently no bip43 standard derivation path for p2wsh-p2sh
        ks1 = keystore.from_xprv('YprvAUXFReVvDjrPerocC3FxVH748sJUTvYjkAhtKop5VnnzVzMEHr1CHrYQKZwfJn1As3X4LYMav6upxd5nDiLb6SCjRZrBH76EFvyQAG4cn79')
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'Ypub6hWbqA2p47QgsLt5J4nxrR3ngu8xsPGb7PdV8CDh48KyNngNqPKSqertAqYhQ4umELu1UsZUCYfj9XPA6AdSMZWDZQobwF7EJ8uNrECaZg1')

        # bip39 seed: slab mixture skin evoke harsh tattoo rare crew sphere extend balcony frost
        # der: m/49'/0'/0'
        ks2 = keystore.from_xpub('Ypub6iNDhL4WWq5kFZcdFqHHwX4YTH4rYGp8xbndpRrY7WNZFFRfogSrL7wRTajmVHgR46AT1cqUG1mrcRd7h1WXwBsgX2QvT3zFbBCDiSDLkau')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2')
        self.assertEqual(w.txin_type, 'p2wsh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], 'MBYnVwVNdKM5EK7uzBCSAMU5iJa3ATHxCK')
        self.assertEqual(w.get_change_addresses()[0], 'MFdrC72fZDa7aTMo5gi7XSyeeiA3P9VtUM')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip32_extended_version_bytes(self, mock_write):
        seed_words = 'crouch dumb relax small truck age shine pink invite spatial object tenant'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))
        bip32_seed = keystore.bip39_to_seed(seed_words, '')
        self.assertEqual('0df68c16e522eea9c1d8e090cfb2139c3b3a2abed78cbcb3e20be2c29185d3b8df4e8ce4e52a1206a688aeb88bfee249585b41a7444673d1f16c0d45755fa8b9',
                         bh2u(bip32_seed))

        def create_keystore_from_bip32seed(xtype):
            ks = keystore.BIP32_KeyStore({})
            ks.add_xprv_from_seed(bip32_seed, xtype=xtype, derivation='m/')
            return ks

        ks = create_keystore_from_bip32seed(xtype='standard')
        self.assertEqual('033a05ec7ae9a9833b0696eb285a762f17379fa208b3dc28df1c501cf84fe415d0', ks.derive_pubkey(0, 0))
        self.assertEqual('02bf27f41683d84183e4e930e66d64fc8af5508b4b5bf3c473c505e4dbddaeed80', ks.derive_pubkey(1, 0))

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2pkh
        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(ks.xprv, 'xprv9s21ZrQH143K3nyWMZVjzGL4KKAE1zahmhTHuV5pdw4eK3o3igC5QywgQG7UTRe6TGBniPDpPFWzXMeMUFbBj8uYsfXGjyMmF54wdNt8QBm')
        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcGH3yTb2kMQGnsLziRTJZ8vNthsVSCGbdBr8CGDWKxnGAFYgyKTzBtwvPPmfVAWJuFmxRXjSbUTg87wDkWQ5GmzpfUcN9t8Z')
        self.assertEqual(w.get_receiving_addresses()[0], 'LTtTVhtMvLYJWaoTiWqQ5w2jwnLL6Rra9S')
        self.assertEqual(w.get_change_addresses()[0], 'LYTUNqss6W2gonLUojLPN6znCrSxkzEmkb')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh-p2sh')
        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(ks.xprv, 'yprvABrGsX5C9janu6AdBvHNCMRZVHJfxcaCgoyWgsyi1wSXN9cGyLMe33bpRU54TLJ1ruJbTrpNqusYQeFvBx1CXNb9k1DhKtBFWo8b1sLbXhN')
        self.assertEqual(ks.xpub, 'ypub6QqdH2c5z7967aF6HwpNZVNJ3K9AN5J442u7VGPKaGyWEwwRWsftaqvJGkeZKNe7Jb3C9FG3dAfT94ZzFRrcGhMizGvB6Jtm3itJsEFhxMC')
        self.assertEqual(w.get_receiving_addresses()[0], 'MAeJky6ECCKzzCyLf1pajZCxFFd4fEVs16')
        self.assertEqual(w.get_change_addresses()[0], 'MF7vnDyYc1HhEqC83zKCjPwYKTipPQkVBo')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh')
        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(ks.xprv, 'zprvAWgYBBk7JR8GkPMk2H4zQSX4fFT7uEZhbvVjUGsbPwpQRFRWDzXCf7FxSg2eTEwwGYRQDLQwJaE6HvsUueRDKcGkcLv7unzjnXCEQVWhrF9')
        self.assertEqual(ks.xpub, 'zpub6jftahH18ngZxsSD8JbzmaToDHHcJhHYy9RLGfHCxHMPJ3kemXqTCuaSHxc9KHJ2iE9ztirc5q212MBYy8Gd4w3KrccbgDiFKSwxFpYKEH6')
        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1qtuynwzd0d6wptvyqmc6ehkm70zcamxpsncccvf')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1qjy5zunxh6hjysele86qqywfa437z4xwmm96rkx')

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2sh
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1')
        self.assertEqual(ks.xprv, 'xprv9s21ZrQH143K3nyWMZVjzGL4KKAE1zahmhTHuV5pdw4eK3o3igC5QywgQG7UTRe6TGBniPDpPFWzXMeMUFbBj8uYsfXGjyMmF54wdNt8QBm')
        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcGH3yTb2kMQGnsLziRTJZ8vNthsVSCGbdBr8CGDWKxnGAFYgyKTzBtwvPPmfVAWJuFmxRXjSbUTg87wDkWQ5GmzpfUcN9t8Z')
        self.assertEqual(w.get_receiving_addresses()[0], 'MMGw51usjhyCm1CjoMNMrmdx1Ld9oJsKgE')
        self.assertEqual(w.get_change_addresses()[0], 'MULtECgjv7Li2t3zGwyoTD8SgrCDSqzVmi')

        ks = create_keystore_from_bip32seed(xtype='p2wsh-p2sh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1')
        self.assertEqual(ks.xprv, 'YprvANkMzkodih9AKfL18akM2RmND5LwAyFo15dBc9FFPiGvzLBBjjjv8ATkEB2Y1mWv6NNaLSpVj8G3XosgVBA9frhpaUL6jHeFQXQTbqVPcv2')
        self.assertEqual(ks.xpub, 'Ypub6bjiQGLXZ4hTY9QUEcHMPZi6m7BRaRyeNJYnQXerx3ous8WLHH4AfxnE5Tc2sos1Y47B1qGAWP3xGEBkYf1ZRBUPpk2aViMkwTABT6qoiBb')
        self.assertEqual(w.get_receiving_addresses()[0], 'MSDLGDk8PPAeqiguxnqvLQJ6taHiCKq6Cd')
        self.assertEqual(w.get_change_addresses()[0], 'MURQvUyTUag1D1hbpnUjeB7nCmGUCdw8p4')

        ks = create_keystore_from_bip32seed(xtype='p2wsh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1')
        self.assertEqual(ks.xprv, 'ZprvAhadJRUYsNgeAxX7xwXyEWrsP3VP7bFHvC9QPY98miep3RzQzPuUkE7tFNz81gAqW1VP5vR4BncbR6VFCsaAU6PRSp2XKCTjgFU6zRpk6Xp')
        self.assertEqual(ks.xpub, 'Zpub6vZyhw1ShkEwPSbb4y4ybeobw5KsX3y9HR51BvYkL4BnvEKZXwDjJ2SN6fZcsiWvwhDymJriy3QW9WoKGMRaDR9zh5j15dBFDBDpqjK1ekQ')
        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1q84x0yrztvcjg88qef4d6978zccxulcmc9y88xcg4ghjdau999x7qaxz66u')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1q0fj5mra96hhnum80kllklc52zqn6kppt3hyzr49yhr3ecr42z3tsqjxpj4')


class TestWalletKeystoreAddressIntegrityForTestnet(TestCaseForTestnet):

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_p2sh_segwit_testnet(self, mock_write):
        # bip39 seed: finish seminar arrange erosion sunny coil insane together pretty lunch lunch rose
        # der: m/49'/1'/0'
        # NOTE: there is currently no bip43 standard derivation path for p2wsh-p2sh
        ks1 = keystore.from_xprv('Uprv9BEixD3As2LK5h6G2SNT3cTqbZpsWYPceKTSuVAm1yuSybxSvQz2MV1o8cHTtctQmj4HAenb3eh5YJv4YRZjv35i8fofVnNbs4Dd2B4i5je')
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'Upub5QE5Mia4hPtcJBAj8TuTQkQa9bfMv17U1YP3hsaNaKSRrQHbTxJGuHLGyv3MbKZixuPyjfXGUdbTjE4KwyFcX8YD7PX5ybTDbP11UT8UpZR')

        # bip39 seed: square page wood spy oil story rebel give milk screen slide shuffle
        # der: m/49'/1'/0'
        ks2 = keystore.from_xpub('Upub5QRzUGRJuWJe5MxGzwgQAeyJjzcdGTXkkq77w6EfBkCyf5iWppSaZ4caY2MgWcU9LP4a4uE5apUFN4wLoENoe9tpu26mrUxeGsH84dN3JFh')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2')
        self.assertEqual(w.txin_type, 'p2wsh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], 'QUERagKWpsSWvprWNivNrVfAEjPbK3GA2c')
        self.assertEqual(w.get_change_addresses()[0], 'QjAv49kqZeSEhpo12vgZFzrB6S8RMCegug')

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip32_extended_version_bytes(self, mock_write):
        seed_words = 'crouch dumb relax small truck age shine pink invite spatial object tenant'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))
        bip32_seed = keystore.bip39_to_seed(seed_words, '')
        self.assertEqual('0df68c16e522eea9c1d8e090cfb2139c3b3a2abed78cbcb3e20be2c29185d3b8df4e8ce4e52a1206a688aeb88bfee249585b41a7444673d1f16c0d45755fa8b9',
                         bh2u(bip32_seed))

        def create_keystore_from_bip32seed(xtype):
            ks = keystore.BIP32_KeyStore({})
            ks.add_xprv_from_seed(bip32_seed, xtype=xtype, derivation='m/')
            return ks

        ks = create_keystore_from_bip32seed(xtype='standard')
        self.assertEqual('033a05ec7ae9a9833b0696eb285a762f17379fa208b3dc28df1c501cf84fe415d0', ks.derive_pubkey(0, 0))
        self.assertEqual('02bf27f41683d84183e4e930e66d64fc8af5508b4b5bf3c473c505e4dbddaeed80', ks.derive_pubkey(1, 0))

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2pkh
        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(ks.xprv, 'tprv8ZgxMBicQKsPecD328MF9ux3dSaSFWci7FNQmuWH7uZ86eY8i3XpvjK8KSH8To2QphiZiUqaYc6nzDC6bTw8YCB9QJjaQL5pAApN4z7vh2B')
        self.assertEqual(ks.xpub, 'tpubD6NzVbkrYhZ4Y5Epun1qZKcACU6NQqocgYyC4RYaYBMWw8nuLSMR7DvzVamkqxwRgrTJ1MBMhc8wwxT2vbHqMu8RBXy4BvjWMxR5EdZroxE')
        self.assertEqual(w.get_receiving_addresses()[0], 'mpBTXYfWehjW2tavFwpUdqBJbZZkup13k2')
        self.assertEqual(w.get_change_addresses()[0], 'mtkUQgf1psDtL67wMAKTv19LrdgPWy6GDQ')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh-p2sh')
        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(ks.xprv, 'uprv8tXDerPXZ1QsVuQ9rV8sN13YoQitC8cD2MtdZJQAVuw19kMMxhhPYnyGLeEiThgLELqNTxS91GTLsVofKAM9LRrkGeRzzEuJRtt1Tcostr7')
        self.assertEqual(ks.xpub, 'upub57Wa4MvRPNyAiPUcxWfsj8zHMSZNbbL4PapEMgon4FTz2YgWWF1e6bHkBvpDKk2Rg2Zy9LsonXFFbv7jNeCZ5kdKWv8UkfcoxpdjJrZuBX6')
        self.assertEqual(w.get_receiving_addresses()[0], 'QPM8dqUXse31Xg62rNV8cZPFHHgcLu6vLw')
        self.assertEqual(w.get_change_addresses()[0], 'QTpkf6MrHSzhnJJpFLykcQ7qMVnN9LUuCe')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh')
        w = WalletIntegrityHelper.create_standard_wallet(ks)
        self.assertEqual(ks.xprv, 'vprv9DMUxX4ShgxMMCbGgqvVa693yNsL8kbhwUQrLhJ3svJtCrAbDMrxArdQMrCJTcLFdyxBDS2hTvotknRE2rmA8fYM8z8Ra9inhcwerEsG6Ev')
        self.assertEqual(ks.xpub, 'vpub5SLqN2bLY4WeZgfjnsTVwE5nXQhpYDKZJhLT95hfSFqs5eVjkuBCiewtD8moKegM5fgmtpUNFBboVCjJ6LcZszJvPFpuLaSJEYhNhUAnrCS')
        self.assertEqual(w.get_receiving_addresses()[0], 'tltc1qtuynwzd0d6wptvyqmc6ehkm70zcamxpsy2m3lr')
        self.assertEqual(w.get_change_addresses()[0], 'tltc1qjy5zunxh6hjysele86qqywfa437z4xwmvhe29v')

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2sh
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1')
        self.assertEqual(ks.xprv, 'tprv8ZgxMBicQKsPecD328MF9ux3dSaSFWci7FNQmuWH7uZ86eY8i3XpvjK8KSH8To2QphiZiUqaYc6nzDC6bTw8YCB9QJjaQL5pAApN4z7vh2B')
        self.assertEqual(ks.xpub, 'tpubD6NzVbkrYhZ4Y5Epun1qZKcACU6NQqocgYyC4RYaYBMWw8nuLSMR7DvzVamkqxwRgrTJ1MBMhc8wwxT2vbHqMu8RBXy4BvjWMxR5EdZroxE')
        self.assertEqual(w.get_receiving_addresses()[0], 'QZykwtJBR9gDJUKRzi2ujmpF3NghQtKC4x')
        self.assertEqual(w.get_change_addresses()[0], 'Qh3i7553bZ3iaMAgUJeMLDJjitFm8zYwhv')

        ks = create_keystore_from_bip32seed(xtype='p2wsh-p2sh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1')
        self.assertEqual(ks.xprv, 'Uprv95RJn67y7xyEvUZXo9brC5PMXCm9QVHoLdYJUZfhsgmQmvvGj75fduqC9MCC28uETouMLYSFtUqqzfRRcPW6UuyR77YQPeNJKd9t3XutF8b')
        self.assertEqual(ks.xpub, 'Upub5JQfBberxLXY8xdzuB8rZDL65Ebdox1ehrTuGx5KS2JPejFRGePvBi9fzdmgtBFKuVdx1vsvfjdkj5jVfsMWEEjzMPEtA55orYubtrCZmRr')
        self.assertEqual(w.get_receiving_addresses()[0], 'QevA968S4psfPBocA9WUDQUPvcMFwq7ZdA')
        self.assertEqual(w.get_change_addresses()[0], 'Qh8EoMMmA2P1kUpJ299HXBJ5EoL1xrrTLT')

        ks = create_keystore_from_bip32seed(xtype='p2wsh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1')
        self.assertEqual(ks.xprv, 'Vprv16YtLrHXxePM6noKqtFtMtmUgBE9bEpF3fPLmpvuPksssLostujtdHBwqhEeVuzESz22UY8hyPx9ed684SQpCmUKSVhpxPFbvVNY7qnviNR')
        self.assertEqual(ks.xpub, 'Vpub5dEvVGKn7251zFq7jXvUmJRbFCk5ka19cxz84LyCp2gGhq4eXJZUomop1qjGt5uFK8kkmQUV8PzJcNM4PZmX2URbDiwJjyuJ8GyFHRrEmmG')
        self.assertEqual(w.get_receiving_addresses()[0], 'tltc1q84x0yrztvcjg88qef4d6978zccxulcmc9y88xcg4ghjdau999x7qkfxy9f')
        self.assertEqual(w.get_change_addresses()[0], 'tltc1q0fj5mra96hhnum80kllklc52zqn6kppt3hyzr49yhr3ecr42z3tstazldq')


class TestWalletSending(TestCaseForTestnet):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.electrum_path = tempfile.mkdtemp()
        cls.config = SimpleConfig({'electrum_path': cls.electrum_path})

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.electrum_path)

    def create_standard_wallet_from_seed(self, seed_words):
        ks = keystore.from_seed(seed_words, '', False)
        return WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=2)

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_between_p2wpkh_and_compressed_p2pkh(self, mock_write):
        wallet1 = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver')
        wallet2 = self.create_standard_wallet_from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song')

        # bootstrap wallet1
        funding_tx = Transaction('01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000')
        funding_txid = funding_tx.txid()
        funding_output_value = 1000000
        self.assertEqual('add2535aedcbb5ba79cc2260868bb9e57f328738ca192937f2c92e0e94c19203', funding_txid)
        wallet1.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [(bitcoin.TYPE_ADDRESS, wallet2.get_receiving_address(), 250000)]
        tx = wallet1.mktx(outputs=outputs, password=None, config=self.config, fee=5000)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet1.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet1.is_mine(wallet1.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('010000000001010392c1940e2ec9f2372919ca3887327fe5b98b866022cc79bab5cbed5a53d2ad0000000000feffffff0290d00300000000001976a914ea7804a2c266063572cc009a63dc25dcc0e9d9b588ac285e0b0000000000160014690b59a8140602fb23cc2904ece9cc4daf361052024730440220608a5339ca894592da82119e1e4a1d09335d70a552c683687223b8ed724465e902201b3f0feccf391b1b6257e4b18970ae57d7ca060af2dae519b3690baad2b2a34e0121030faee9b4a25b7db82023ca989192712cdd4cb53d3d9338591c7909e581ae1c0c00000000',
                         str(tx_copy))
        self.assertEqual('3c06ae4d9be8226a472b3e7f7c127c7e3016f525d658d26106b80b4c7e3228e2', tx_copy.txid())
        self.assertEqual('d8d930ae91dce73118c3fffabbdfcfb87f5d91673fb4c7dfd0fbe7cf03bf426b', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)  # TX_HEIGHT_UNCONF_PARENT but nvm
        wallet2.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [(bitcoin.TYPE_ADDRESS, wallet1.get_receiving_address(), 100000)]
        tx = wallet2.mktx(outputs=outputs, password=None, config=self.config, fee=5000)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet2.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet2.is_mine(wallet2.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('0100000001e228327e4c0bb80661d258d625f516307e7c127c7f3e2b476a22e89b4dae063c000000006b483045022100d3895b31e7c9766987c6f53794c7394f534f4acecefda5479d963236f9703d0b022026dd4e40700ceb788f136faf54bf85b966648dc7c2a608d8110604f2d22d59070121030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cffeffffff02a0860100000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c4268360200000000001976a914ca4c60999c46c2108326590b125aefd476dcb11888ac00000000',
                         str(tx_copy))
        self.assertEqual('5f25707571eb776bdf14142f9966bf2a681906e0a79501edbb99a972c2ceb972', tx_copy.txid())
        self.assertEqual('5f25707571eb776bdf14142f9966bf2a681906e0a79501edbb99a972c2ceb972', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 250000 - 5000 + 100000, 0), wallet1.get_balance())
        self.assertEqual((0, 250000 - 5000 - 100000, 0), wallet2.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_between_p2sh_2of3_and_uncompressed_p2pkh(self, mock_write):
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure', '', True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4XJzYkhsCbDCcZRmDAKSD7bXi9mdCni7acVt45fxbTVZyU6jRGh29ULKTjoapkfFsSJvQHitcVKbQgzgkkYsAmaovcro7Mhf')
            ],
            '2of3', gap_limit=2
        )
        wallet1b = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song', '', True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YARFMEZPckrqJkw59GZD1PXtQnw14ukvWDofR7Z1HMeSCxfYEZVvg4VdZ8zGok5VxHwdrLqew5cMdQntWc5mT7mh1CSgrnX')
            ],
            '2of3', gap_limit=2
        )
        # ^ third seed: ghost into match ivory badge robot record tackle radar elbow traffic loud
        wallet2 = self.create_standard_wallet_from_seed('powerful random nobody notice nothing important anyway look away hidden message over')

        # bootstrap wallet1
        funding_tx = Transaction('010000000001014121f99dc02f0364d2dab3d08905ff4c36fc76c55437fd90b769c35cc18618280100000000fdffffff02d4c22d00000000001600143fd1bc5d32245850c8cb5be5b09c73ccbb9a0f75001bb7000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887024830450221008781c78df0c9d4b5ea057333195d5d76bc29494d773f14fa80e27d2f288b2c360220762531614799b6f0fb8d539b18cb5232ab4253dd4385435157b28a44ff63810d0121033de77d21926e09efd04047ae2d39dbd3fb9db446e8b7ed53e0f70f9c9478f735dac11300')
        funding_txid = funding_tx.txid()
        funding_output_value = 12000000
        self.assertEqual('b25cd55687c9e528c2cfd546054f35fb6741f7cf32d600f07dfecdf2e1d42071', funding_txid)
        wallet1a.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [(bitcoin.TYPE_ADDRESS, wallet2.get_receiving_address(), 370000)]
        tx = wallet1a.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx = Transaction(tx.serialize())  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())
        wallet1b.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet1a.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet1a.is_mine(wallet1a.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000017120d4e1f2cdfe7df000d632cff74167fb354f0546d5cfc228e5c98756d55cb201000000fdfe0000483045022100f9ce5616683e613ae14b98d56436454b003348a8172e2ed598018e3d206e57d7022030c65c6551e839f9e9409812be624dbb4e36bd4152c9ed9b0988c10fd8201d1401483045022100d5cb94d4d1dcf01bb9e9280e8178a7e9ada3ad14378ca543afcc9f5667b27cb2022018e76b74800a21934e73b226b34cbbe45c877fba64693da8a20d3cb330f2eafd014c69522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53aefeffffff0250a50500000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac2862b1000000000017a9142e517854aa54668128c0e9a3fdd4dec13ad571368700000000',
                         str(tx_copy))
        self.assertEqual('26f3bdd0402e1cff19126244ebe3d32722cef0db507c7229ca8754f5e06ef25d', tx_copy.txid())
        self.assertEqual('26f3bdd0402e1cff19126244ebe3d32722cef0db507c7229ca8754f5e06ef25d', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [(bitcoin.TYPE_ADDRESS, wallet1a.get_receiving_address(), 100000)]
        tx = wallet2.mktx(outputs=outputs, password=None, config=self.config, fee=5000)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet2.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet2.is_mine(wallet2.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000015df26ee0f55487ca29727c50dbf0ce2227d3e3eb44621219ff1c2e40d0bdf326000000008b483045022100bd9f61ba82507d3a28922fb8be129e14699dfa54ddd03cc9494f696d38ac4121022071afca6fad5bc5c09b0a675e6444be3e97dbbdbc283764ee5f4e27a032d933d80141045f7ba332df2a7b4f5d13f246e307c9174cfa9b8b05f3b83410a3c23ef8958d610be285963d67c7bc1feb082f168fa9877c25999963ff8b56b242a852b23e25edfeffffff02a08601000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887280b0400000000001976a914ca14915184a2662b5d1505ce7142c8ca066c70e288ac00000000',
                         str(tx_copy))
        self.assertEqual('c573b3f8464a4ed40dfc79d0889a780f44e917beef7a75883b2427c2987f3e95', tx_copy.txid())
        self.assertEqual('c573b3f8464a4ed40dfc79d0889a780f44e917beef7a75883b2427c2987f3e95', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 370000 - 5000 + 100000, 0), wallet1a.get_balance())
        self.assertEqual((0, 370000 - 5000 - 100000, 0), wallet2.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_between_p2wsh_2of3_and_p2wsh_p2sh_2of2(self, mock_write):
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', '', True),
                keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra')
            ],
            '2of3', gap_limit=2
        )
        wallet1b = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('snow nest raise royal more walk demise rotate smooth spirit canyon gun', '', True),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra'),
                keystore.from_xpub('Vpub5gSKXzxK7FeKQedu2q1z9oJWxqvX72AArW3HSWpEhc8othDH8xMDu28gr7gf17sp492BuJod8Tn7anjvJrKpETwqnQqX7CS8fcYyUtedEMk')
            ],
            '2of3', gap_limit=2
        )
        # ^ third seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        wallet2a = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: finish seminar arrange erosion sunny coil insane together pretty lunch lunch rose, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9CvELvByqm8k2dpecJVjgLMX1z5DufEjY4fBC5YvdGF5WjGCa7GVJJ2fYni1tyuF7Hw83E6W2ZBjAhaFLZv2ri3rEsubkCd5avg4EHKoDBN'),
                keystore.from_xpub('Upub5Qb8ik4Cnu8g97KLXKgVXHqY6tH8emQvqtBncjSKsyfTZuorPtTZgX7ovKKZHuuVGBVd1MTTBkWez1XXt2weN1sWBz6SfgRPQYEkNgz81QF')
            ],
            '2of2', gap_limit=2
        )
        wallet2b = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: square page wood spy oil story rebel give milk screen slide shuffle, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9BbnKEXJxXaNvdEsRJ9VA9toYrSeFJh5UfGBpM2iKe8Uh7UhrM9K8ioL53s8gvCoGfirHHaqpABDAE7VUNw8LNU1DMJKVoWyeNKu9XcDC19'),
                keystore.from_xpub('Upub5RuakRisg8h3F7u7iL2k3UJFa1uiK7xauHamzTxYBbn4PXbM7eajr6M9Q2VCr6cVGhfhqWQqxnABvtSATuVM1xzxk4nA189jJwzaMn1QX7V')
            ],
            '2of2', gap_limit=2
        )

        # bootstrap wallet1
        funding_tx = Transaction('01000000000101a41aae475d026c9255200082c7fad26dc47771275b0afba238dccda98a597bd20000000000fdffffff02400d0300000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c9dcd410000000000160014824626055515f3ed1d2cfc9152d2e70685c71e8f02483045022100b9f39fad57d07ce1e18251424034f21f10f20e59931041b5167ae343ce973cf602200fefb727fa0ffd25b353f1bcdae2395898fe407b692c62f5885afbf52fa06f5701210301a28f68511ace43114b674371257bb599fd2c686c4b19544870b1799c954b40e9c11300')
        funding_txid = funding_tx.txid()
        funding_output_value = 200000
        self.assertEqual('d2bd6c9d332db8e2c50aa521cd50f963fba214645aab2f7556e061a412103e21', funding_txid)
        wallet1a.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [(bitcoin.TYPE_ADDRESS, wallet2a.get_receiving_address(), 165000)]
        tx = wallet1a.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        txid = tx.txid()
        tx = Transaction(tx.serialize())  # simulates moving partial txn between cosigners
        self.assertEqual(txid, tx.txid())
        self.assertFalse(tx.is_complete())
        wallet1b.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet1a.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet1a.is_mine(wallet1a.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000000101213e1012a461e056752fab5a6414a2fb63f950cd21a50ac5e2b82d339d6cbdd20000000000feffffff023075000000000000220020cc5e4cc05a76d0648cd0742768556317e9f8cc729aed077134287909035dba88888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf8743870400483045022100ea2fbd3d8681cfafdcae1bdaaa64f92fb9872fb8f6bf03a2b7effcf7390b66c8022021a79eff7975479934f958f3766d6ac61d708c79b785e398b3bcd84b1039e9b501483045022100dbc4f1ec18f0e0deb4ff88d7d5b3d3b7b500a80d0c0f33efbd3262f0c8689095022074fd226c0b52e3716ad907d14cba9c79aca482a8f4a51662ca83a5b9db49e15b016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae00000000',
                         str(tx_copy))
        self.assertEqual('6e9c3cd8788bdb970a124ea06136d52bc01cec4f9b1e217627d5e90ebe77d049', tx_copy.txid())
        self.assertEqual('c58650fb77d04577fccb3e201deecbf691ab52ffb61cd2e57996c4d51f7e980b', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual(txid, tx_copy.txid())

        wallet1a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [(bitcoin.TYPE_ADDRESS, wallet1a.get_receiving_address(), 100000)]
        tx = wallet2a.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        txid = tx.txid()
        tx = Transaction(tx.serialize())  # simulates moving partial txn between cosigners
        self.assertEqual(txid, tx.txid())
        self.assertFalse(tx.is_complete())
        wallet2b.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet2a.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet2a.is_mine(wallet2a.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('0100000000010149d077be0ee9d52776211e9b4fec1cc02bd53661a04e120a97db8b78d83c9c6e01000000232200204311edae835c7a5aa712c8ca644180f13a3b2f3b420fa879b181474724d6163cfeffffff0260ea00000000000017a9143025051b6b5ccd4baf30dfe2de8aa84f0dd567ed87a0860100000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c0400483045022100c254468bbe6b8bd1c8c01b6a223e46cc5c6b56fbba87d59575385ad249133b0e02207139688f8d6ae8076c92a266d98454d25c040d04c8e513a37bf7c32dad3e48210147304402204af5edbab2d674f6a9edef8c97b2f7fdf8ababedc7b287710cc7a64d4699358b022064e2d07f4bb32373be31b2003dc56b7b831a7c01419326efb3011c64b898b3f00147522102119f899075a131d4d519d4cdcf5de5907dc2df3b93d54b53ded852211d2b6cb12102fdb0f6775d4b6619257c43343ba5e7807b0164f1eb3f00f2b594ab9e53ab812652ae00000000',
                         str(tx_copy))
        self.assertEqual('84b0dcb43022385f7a10e2710e5625a2be3cd6e390387b6100b55500d5eea8f6', tx_copy.txid())
        self.assertEqual('7e561e25da843326e61fd20a40b72fcaeb8690176fc7c3fcbadb3a0146c8396c', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual(txid, tx_copy.txid())

        wallet1a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 165000 - 5000 + 100000, 0), wallet1a.get_balance())
        self.assertEqual((0, 165000 - 5000 - 100000, 0), wallet2a.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_between_p2sh_1of2_and_p2wpkh_p2sh(self, mock_write):
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('phone guilt ancient scan defy gasp off rotate approve ill word exchange', '', True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YPZ3ntVjqSCxiUUv2jikrUBU73Q3iJ7Y8iR41oYf991L5fanv7ciHjbjokdK2bjYqg1BzEUDxucU9qM5WRdBiY738wmgLP4')
            ],
            '1of2', gap_limit=2
        )
        # ^ second seed: kingdom now gift initial age right velvet exotic harbor enforce kingdom kick
        wallet2 = WalletIntegrityHelper.create_standard_wallet(
            # bip39: uniform tank success logic lesson awesome stove elegant regular desert drip device, der: m/49'/1'/0'
            keystore.from_xprv('uprv91HGbrNZTK4x8u22nbdYGzEuWPxjaHMREUi7CNhY64KsG5ZGnVM99uCa16EMSfrnaPTFxjbRdBZ2WiBkokoM8anzAy3Vpc52o88WPkitnxi'),
            gap_limit=2
        )

        # bootstrap wallet1
        funding_tx = Transaction('010000000001027e20990282eb29588375ad04936e1e991af3bc5b9c6f1ab62eca8c25becaef6a01000000171600140e6a17fadc8bafba830f3467a889f6b211d69a00fdffffff51847fd6bcbdfd1d1ea2c2d95c2d8de1e34c5f2bd9493e88a96a4e229f564e800100000017160014ecdf9fa06856f9643b1a73144bc76c24c67774a6fdffffff021e8501000000000017a91451991bfa68fbcb1e28aa0b1e060b7d24003352e38700093d000000000017a914b0b9f31bace76cdfae2c14abc03e223403d7dc4b870247304402205e19721b92c6afd70cd932acb50815a36ee32ab46a934147d62f02c13aeacf4702207289c4a4131ef86e27058ff70b6cb6bf0e8e81c6cbab6dddd7b0a9bc732960e4012103fe504411c21f7663caa0bbf28931f03fae7e0def7bc54851e0194dfb1e2c85ef02483045022100e969b65096fba4f8b24eb5bc622d2282076241621f3efe922cc2067f7a8a6be702203ec4047dd2a71b9c83eb6a0875a6d66b4d65864637576c06ed029d3d1a8654b0012102bbc8100dca67ba0297aba51296a4184d714204a5fc2eda34708360f37019a3dccfcc1300')
        funding_txid = funding_tx.txid()
        funding_output_value = 4000000
        self.assertEqual('1137c12de4ce0f5b08de8846ba14c0814351a7f0f31457c8ea51a5d4b3c891a3', funding_txid)
        wallet1a.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [(bitcoin.TYPE_ADDRESS, wallet2.get_receiving_address(), 1000000)]
        tx = wallet1a.mktx(outputs=outputs, password=None, config=self.config, fee=5000)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet1a.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet1a.is_mine(wallet1a.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('0100000001a391c8b3d4a551eac85714f3f0a7514381c014ba4688de085b0fcee42dc13711010000009200483045022100fcf03aeb97b66791372c18aa0dd651817cf458d941dd628c966f0305a023360f022016c534530e267b6a52f90e62aa9fb50ace609ffb21e472d3ba7b29db9b30050e014751210245c90e040d4f9d1fc136b3d4d6b7535bbb5df2bd27666c21977042cc1e05b5b02103c9a6bebfce6294488315e58137a279b2efe09f1f528ecf93b40675ded3cf0e5f52aefeffffff0240420f000000000017a9149573eb50f3136dff141ac304190f41c8becc92ce8738b32d000000000017a914b815d1b430ae9b632e3834ed537f7956325ee2a98700000000',
                         str(tx_copy))
        self.assertEqual('1b7e94860b9681d4e371928d40fdbd4641e991aa74f1a211f239c887047e4a2a', tx_copy.txid())
        self.assertEqual('1b7e94860b9681d4e371928d40fdbd4641e991aa74f1a211f239c887047e4a2a', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [(bitcoin.TYPE_ADDRESS, wallet1a.get_receiving_address(), 300000)]
        tx = wallet2.mktx(outputs=outputs, password=None, config=self.config, fee=5000)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(wallet2.txin_type, tx.inputs()[0]['type'])
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet2.is_mine(wallet2.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('010000000001012a4a7e0487c839f211a2f174aa91e94146bdfd408d9271e3d481960b86947e1b00000000171600149fad840ed174584ee054bd26f3e411817338c5edfeffffff02e09304000000000017a914b0b9f31bace76cdfae2c14abc03e223403d7dc4b87d89a0a000000000017a9148ccd0efb2be5b412c4033715f560ed8f446c8ceb87024830450221009c816c3e0c40b37085244f0976f65635b8d711952bad9843c5f51e386fd37cc402202c34a4a7227182742d9f93e9f28c4bd30ded6514550f39614cb5ad00e46690070121038362bbf0b4918b37e9d7c75930ed3a78e3d445724cb5c37ade4a59b6e411fe4e00000000',
                         str(tx_copy))
        self.assertEqual('f65edb0843ff44436dc5964fb6b298e157502b9b4a83dac6b82dd2d2a3247d0a', tx_copy.txid())
        self.assertEqual('63efc09db4c7445eaaca9a5e7732202f42aec81a53b05d819f1918ce0cf3b84d', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 1000000 - 5000 + 300000, 0), wallet1a.get_balance())
        self.assertEqual((0, 1000000 - 5000 - 300000, 0), wallet2.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bump_fee_p2pkh(self, mock_write):
        wallet = self.create_standard_wallet_from_seed('fold object utility erase deputy output stadium feed stereo usage modify bean')

        # bootstrap wallet
        funding_tx = Transaction('010000000001011f4db0ecd81f4388db316bc16efb4e9daf874cf4950d54ecb4c0fb372433d68500000000171600143d57fd9e88ef0e70cddb0d8b75ef86698cab0d44fdffffff0280969800000000001976a91472e34cebab371967b038ce41d0e8fa1fb983795e88ac86a0ae020000000017a9149188bc82bdcae077060ebb4f02201b73c806edc887024830450221008e0725d531bd7dee4d8d38a0f921d7b1213e5b16c05312a80464ecc2b649598d0220596d309cf66d5f47cb3df558dbb43c5023a7796a80f5a88b023287e45a4db6b9012102c34d61ceafa8c216f01e05707672354f8119334610f7933a3f80dd7fb6290296bd391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('03052739fcfa2ead5f8e57e26021b0c2c546bcd3d74c6e708d5046dc58d90762', funding_txid)
        wallet.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'QUrDUN7qA7VNHd8TnrV94qFKXU6P9djYPn', 2500000)]
        coins = wallet.get_spendable_coins(domain=None, config=self.config)
        tx = wallet.make_unsigned_transaction(coins, outputs, config=self.config, fixed_fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325501
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc39270503000000006b483045022100df74e6a88085be1ff3a3fd96cf2ef03b5e33fa06788f56aa71649f0177d1bfc402206e36a7e6124863ac746d5288d6d47c1d1eac5d4ac3818e561a7a0f2c0a269429012102a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587afdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d7200000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbd391400',
                         str(tx_copy))
        self.assertEqual('44e6dd9529a253181112fc40cadd8ebb4c4359aacb91aa24c45556a1d00839b0', tx_copy.txid())
        self.assertEqual('44e6dd9529a253181112fc40cadd8ebb4c4359aacb91aa24c45556a1d00839b0', tx_copy.wtxid())

        wallet.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 5000, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=Transaction(tx.serialize()), delta=5000)
        tx.locktime = 1325501
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        tx_copy = Transaction(tx.serialize())
        self.assertEqual('01000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc39270503000000006a473044022055b7e6b7e89a55740f7aa2ad1ffcd4b5c913f0de63cf512438921534bc9c3a8d022043b3b27bdc2da4cc6265e4cc9673a3780ccd5cd6f0ee2eaedb51720c15b7a00a012102a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587afdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987d0497200000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbd391400',
                         str(tx_copy))
        self.assertEqual('f26edcf20991dccedf16058adbee923db7057c9b102db660156b8142b6a59bc7', tx_copy.txid())
        self.assertEqual('f26edcf20991dccedf16058adbee923db7057c9b102db660156b8142b6a59bc7', tx_copy.wtxid())

        wallet.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 10000, 0), wallet.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_cpfp_p2pkh(self, mock_write):
        wallet = self.create_standard_wallet_from_seed('fold object utility erase deputy output stadium feed stereo usage modify bean')

        # bootstrap wallet
        funding_tx = Transaction('010000000001010f40064d66d766144e17bb3276d96042fd5aee2196bcce7e415f839e55a83de800000000171600147b6d7c7763b9185b95f367cf28e4dc6d09441e73fdffffff02404b4c00000000001976a9141df43441a3a3ee563e560d3ddc7e07cc9f9c3cdb88ac009871000000000017a9143873281796131b1996d2f94ab265327ee5e9d6e28702473044022029c124e5a1e2c6fa12e45ccdbdddb45fec53f33b982389455b110fdb3fe4173102203b3b7656bca07e4eae3554900aa66200f46fec0af10e83daaa51d9e4e62a26f4012103c8f0460c245c954ef563df3b1743ea23b965f98b120497ac53bd6b8e8e9e0f9bbe391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 5000000
        self.assertEqual('9973bf8918afa349b63934432386f585613b51034db6c8628b61ba2feb8a3668', funding_txid)
        wallet.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # cpfp tx
        tx = wallet.cpfp(funding_tx, fee=50000)
        tx.set_rbf(True)
        tx.locktime = 1325502
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('010000000168368aeb2fba618b62c8b64d03513b6185f58623433439b649a3af1889bf7399000000006a47304402203a0b369e46c5fbacb83044b7ab9d69ff7998774041d6870993504915bc495d210220272833b870d8abca516adb7dc4cb27892b1b6e4b52fbfeb592a72c3e795eb213012102a7536f0bfbc60c5a8e86e2b9df26431fc062f9f454016dbc26f2467e0bc98b3ffdffffff01f0874b00000000001976a9141df43441a3a3ee563e560d3ddc7e07cc9f9c3cdb88acbe391400',
                         str(tx_copy))
        self.assertEqual('47500a425518b5542d94db1157f473b8cf322d31ea97a1a642fec19386cdb761', tx_copy.txid())
        self.assertEqual('47500a425518b5542d94db1157f473b8cf322d31ea97a1a642fec19386cdb761', tx_copy.wtxid())

        wallet.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 50000, 0), wallet.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bump_fee_p2wpkh(self, mock_write):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage')

        # bootstrap wallet
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid)
        wallet.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'QUrDUN7qA7VNHd8TnrV94qFKXU6P9djYPn', 2500000)]
        coins = wallet.get_spendable_coins(domain=None, config=self.config)
        tx = wallet.make_unsigned_transaction(coins, outputs, config=self.config, fixed_fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402205442705e988abe74bf391b293bb1b886674284a92ed0788c33024f9336d60aef022013a93049d3bed693254cd31a704d70bb988a36750f0b74d0a5b4d9e29c54ca9d0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('b019bbad45a46ed25365e46e4cae6428fb12ae425977eb93011ffb294cb4977e', tx_copy.txid())
        self.assertEqual('ba87313e2b3b42f1cc478843d4d53c72d6e06f6c66ac8cfbe2a59cdac2fd532d', tx_copy.wtxid())

        wallet.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 5000, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=Transaction(tx.serialize()), delta=5000)
        tx.locktime = 1325500
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = Transaction(tx.serialize())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987d049720000000000160014f0fe5c1867a174a12e70165e728a072619455ed5024730440220517fed3a902b5b41fa718ffd5f229b835b8ed26f23433c4ea437d24eff66d15b0220526854a6ebcd351ab2373d0e7c4e20f17c420520b5d570c2df7ca1d773d6a55d0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bc391400',
                         str(tx_copy))
        self.assertEqual('9a1c0ef7e871798b86074c7f8dd1e81b6d9a758ff07e0059eee31dc6fbf4f438', tx_copy.txid())
        self.assertEqual('59144d30c911ac33359b0a32d5a3fdd2ca806982c85838e193eb95f5d315e813', tx_copy.wtxid())

        wallet.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 10000, 0), wallet.get_balance())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_cpfp_p2wpkh(self, mock_write):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage')

        # bootstrap wallet
        funding_tx = Transaction('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 5000000
        self.assertEqual('c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a', funding_txid)
        wallet.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # cpfp tx
        tx = wallet.cpfp(funding_tx, fee=50000)
        tx.set_rbf(True)
        tx.locktime = 1325501
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('010000000001014a5d2593658f7feb9fadcf70dced3bc18db8c90bf77495e608f14dd51c6e6ac30100000000fdffffff01f0874b000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab900248304502210098fbe458a9f1c595d6bf63962fad00300a7b60c6dd8b2e7625f3804a3bf1086602204bc8a46fb162be8f85a23644eccf9f4223fa092f5c861144676a34dc83a7c39d012102a6ff1ffc189b4776b78e20edca969cc45da3e610cc0cc79925604be43fee469fbd391400',
                         str(tx_copy))
        self.assertEqual('38a21c67336232c88ae15311f329197c69ee70e872f8acb5bc9c2b6417c35ad8', tx_copy.txid())
        self.assertEqual('b5b8264ed5f3e03d48ef82fa2a25278cd9c0563fa78e557f370b7e0558293172', tx_copy.wtxid())

        wallet.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 50000, 0), wallet.get_balance())

    @needs_test_with_all_ecc_implementations
    def test_sweep_p2pk(self):

        class NetworkMock:
            relay_fee = 1000
            def get_local_height(self): return 1325785
            def listunspent_for_scripthash(self, scripthash):
                if scripthash == '460e4fb540b657d775d84ff4955c9b13bd954c2adc26a6b998331343f85b6a45':
                    return [{'tx_hash': 'ac24de8b58e826f60bd7b9ba31670bdfc3e8aedb2f28d0e91599d741569e3429', 'tx_pos': 1, 'height': 1325785, 'value': 1000000}]
                else:
                    return []

        privkeys = ['93NQ7CFbwTPyKDJLXe97jczw33fiLijam2SCZL3Uinz1NSbHrTu', ]
        network = NetworkMock()
        dest_addr = 'tltc1q3ws2p0qjk5vrravv065xqlnkckvzcpcl0k88vr'
        tx = sweep(privkeys, network, config=None, recipient=dest_addr, fee=5000)

        tx_copy = Transaction(tx.serialize())
        self.assertEqual('010000000129349e5641d79915e9d0282fdbaee8c3df0b6731bab9d70bf626e8588bde24ac010000004847304402206bf0d0a93abae0d5873a62ebf277a5dd2f33837821e8b93e74d04e19d71b578002201a6d729bc159941ef5c4c9e5fe13ece9fc544351ba531b00f68ba549c8b38a9a01fdffffff01b82e0f00000000001600148ba0a0bc12b51831f58c7ea8607e76c5982c071fd93a1400',
                         str(tx_copy))
        self.assertEqual('7f827fc5256c274fd1094eb7e020c8ded0baf820356f61aa4f14a9093b0ea0ee', tx_copy.txid())
        self.assertEqual('7f827fc5256c274fd1094eb7e020c8ded0baf820356f61aa4f14a9093b0ea0ee', tx_copy.wtxid())


class TestWalletOfflineSigning(TestCaseForTestnet):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.electrum_path = tempfile.mkdtemp()
        cls.config = SimpleConfig({'electrum_path': cls.electrum_path})

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.electrum_path)

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_xprv_online_xpub_p2pkh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/44'/1'/0'
            keystore.from_xprv('tprv8gfKwjuAaqtHgqxMh1tosAQ28XvBMkcY5NeFRA3pZMpz6MR4H4YZ3MJM4fvNPnRKeXR1Td2vQGgjorNXfo94WvT5CYDsPAqjHxSn436G1Eu'),
            gap_limit=4
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('tpubDDMN69wQjDZxaJz9afZQGa48hZS7X5oSegF2hg67yddNvqfpuTN9DqvDEp7YyVf7AzXnqBqHdLhzTAStHvsoMDDb8WoJQzNrcHgDJHVYgQF'),
            gap_limit=4
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1qp0mv2sxsyxxfj5gl0332f9uyez93su9cszcqyh', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual('d9c21696eca80321933e7444ca928aaf25eeda81aaa2f4e5c085d4d0a9cf7aa7', tx.txid())
        self.assertEqual('d9c21696eca80321933e7444ca928aaf25eeda81aaa2f4e5c085d4d0a9cf7aa7', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_xprv_online_xpub_p2wpkh_p2sh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/49'/1'/0'
            keystore.from_xprv('uprv8zHHrMQMQ26utWwNJ5MK2SXpB9hbmy7pbPaneii69xT8cZTyFpxQFxkknGWKP8dxBTZhzy7yP6cCnLrRCQjzJDk3G61SjZpxhFQuB2NR8a5'),
            gap_limit=4
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('upub5DGeFrwFEPfD711qQ6tKPaUYjBY6BRqfxcWPT77hiHz7VMo7oNGeom5EdXoKXEazePyoN3ueJMqHBfp3MwmsaD8k9dFHoa8KGeVXev7Pbg2'),
            gap_limit=4
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1qp0mv2sxsyxxfj5gl0332f9uyez93su9cszcqyh', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325341

        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('3f0d188519237478258ad2bf881643618635d11c2bb95512e830fcf2eda3c522', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('3f0d188519237478258ad2bf881643618635d11c2bb95512e830fcf2eda3c522', tx.txid())
        self.assertEqual('27b78ec072a403b0545258e7a1a8d494e4b6fd48bf77f4251a12160c92207cbc', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_xprv_online_xpub_p2wpkh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/84'/1'/0'
            keystore.from_xprv('vprv9K9hbuA23Bidgj1KRSHUZMa59jJLeZBpXPVn4RP7sBLArNhZxJjw4AX7aQmVTErDt4YFC11ptMLjbwxgrsH8GLQ1cx77KggWeVPeDBjr9xM'),
            gap_limit=4
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('vpub5Y941QgusZGvuD5nXTpUvVWohm8q41uftcRNronjRWs9jB2iVr4BbxqbRfAoQjWHgJtDCQEXChgfsPbEuBnidtkFztZSD3zDKTrtwXa2LCa'),
            gap_limit=4
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1qp0mv2sxsyxxfj5gl0332f9uyez93su9cszcqyh', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325341

        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('ee76c0c6da87f0eb5ab4d1ae05d3942512dcd3c4c42518f9d3619e74400cfc1f', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('ee76c0c6da87f0eb5ab4d1ae05d3942512dcd3c4c42518f9d3619e74400cfc1f', tx.txid())
        self.assertEqual('729c2e40a2fccd6b731407c01ed304119c1ac329bdf9baae5b642d916c5f3272', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_wif_online_addr_p2pkh(self, mock_write):  # compressed pubkey
        wallet_offline = WalletIntegrityHelper.create_imported_wallet(privkeys=True)
        wallet_offline.import_private_key('p2pkh:cQDxbmQfwRV3vP1mdnVHq37nJekHLsuD3wdSQseBRA2ct4MFk5Pq', pw=None)
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('mg2jk6S5WGDhUPA8mLSxDLWpUoQnX1zzoG')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtj48k8j', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.txid())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_wif_online_addr_p2wpkh_p2sh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_imported_wallet(privkeys=True)
        wallet_offline.import_private_key('p2wpkh-p2sh:cU9hVzhpvfn91u2zTVn8uqF2ymS7ucYH8V5TmsTDmuyMHgRk9WsJ', pw=None)
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('QdP4iVMZ8PKbcP583dUWSzJBprz54Yyhd7')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtj48k8j', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('7642816d051aa3b333b6564bb6e44fe3a5885bfe7db9860dfbc9973a5c9a6562', tx.txid())
        self.assertEqual('9bb9949974954613945756c48ca5525cd5cba1b667ccb10c7a53e1ed076a1117', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_wif_online_addr_p2wpkh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_imported_wallet(privkeys=True)
        wallet_offline.import_private_key('p2wpkh:cPuQzcNEgbeYZ5at9VdGkCwkPA9r34gvEVJjuoz384rTfYpahfe7', pw=None)
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('tltc1qm2eh4787lwanrzr6pf0ekf5c7jnmghm2ad526v')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtj48k8j', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('f8039bd85279f2b5698f15d47f2e338d067d09af391bd8a19467aa94d03f280c', tx.txid())
        self.assertEqual('3b7cc3c3352bbb43ddc086487ac696e09f2863c3d9e8636721851b8008a83ffa', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_xprv_online_addr_p2pkh(self, mock_write):  # compressed pubkey
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/44'/1'/0'
            keystore.from_xprv('tprv8gfKwjuAaqtHgqxMh1tosAQ28XvBMkcY5NeFRA3pZMpz6MR4H4YZ3MJM4fvNPnRKeXR1Td2vQGgjorNXfo94WvT5CYDsPAqjHxSn436G1Eu'),
            gap_limit=4
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('mg2jk6S5WGDhUPA8mLSxDLWpUoQnX1zzoG')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtj48k8j', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.txid())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_xprv_online_addr_p2wpkh_p2sh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/49'/1'/0'
            keystore.from_xprv('uprv8zHHrMQMQ26utWwNJ5MK2SXpB9hbmy7pbPaneii69xT8cZTyFpxQFxkknGWKP8dxBTZhzy7yP6cCnLrRCQjzJDk3G61SjZpxhFQuB2NR8a5'),
            gap_limit=4
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('QdP4iVMZ8PKbcP583dUWSzJBprz54Yyhd7')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtj48k8j', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('7642816d051aa3b333b6564bb6e44fe3a5885bfe7db9860dfbc9973a5c9a6562', tx.txid())
        self.assertEqual('9bb9949974954613945756c48ca5525cd5cba1b667ccb10c7a53e1ed076a1117', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_xprv_online_addr_p2wpkh(self, mock_write):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/84'/1'/0'
            keystore.from_xprv('vprv9K9hbuA23Bidgj1KRSHUZMa59jJLeZBpXPVn4RP7sBLArNhZxJjw4AX7aQmVTErDt4YFC11ptMLjbwxgrsH8GLQ1cx77KggWeVPeDBjr9xM'),
            gap_limit=4
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('tltc1qm2eh4787lwanrzr6pf0ekf5c7jnmghm2ad526v')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'tltc1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtj48k8j', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325340

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('f8039bd85279f2b5698f15d47f2e338d067d09af391bd8a19467aa94d03f280c', tx.txid())
        self.assertEqual('3b7cc3c3352bbb43ddc086487ac696e09f2863c3d9e8636721851b8008a83ffa', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_hd_multisig_online_addr_p2sh(self, mock_write):
        # 2-of-3 legacy p2sh multisig
        wallet_offline1 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure', '', True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4XJzYkhsCbDCcZRmDAKSD7bXi9mdCni7acVt45fxbTVZyU6jRGh29ULKTjoapkfFsSJvQHitcVKbQgzgkkYsAmaovcro7Mhf')
            ],
            '2of3', gap_limit=2
        )
        wallet_offline2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song', '', True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YARFMEZPckrqJkw59GZD1PXtQnw14ukvWDofR7Z1HMeSCxfYEZVvg4VdZ8zGok5VxHwdrLqew5cMdQntWc5mT7mh1CSgrnX')
            ],
            '2of3', gap_limit=2
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('QYLoFfKZdcWevrfipJhT4EKxejnccnR14w')

        # bootstrap wallet_online
        funding_tx = Transaction('010000000001016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc3927050301000000171600147a4fc8cdc1c2cf7abbcd88ef6d880e59269797acfdffffff02809698000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e48870d0916020000000017a914703f83ef20f3a52d908475dcad00c5144164d5a2870247304402203b1a5cb48cadeee14fa6c7bbf2bc581ca63104762ec5c37c703df778884cc5b702203233fa53a2a0bfbd85617c636e415da72214e359282cce409019319d031766c50121021112c01a48cc7ea13cba70493c6bffebb3e805df10ff4611d2bf559d26e25c04bf391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('c59913a1fa9b1ef1f6928f0db490be67eeb9d7cb05aa565ee647e859642f3532', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'QNZAXJAcoxb5ZBftHaEgFdcAYEGo81An8z', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325503

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx - first
        tx = wallet_offline1.sign_transaction(tx_copy, password=None)
        self.assertFalse(tx.is_complete())
        tx = Transaction(tx.serialize())

        # sign tx - second
        tx = wallet_offline2.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        tx = Transaction(tx.serialize())

        self.assertEqual('010000000132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c500000000fdfe0000483045022100cfe41e783629a2ad0b1f17cd2dbd69db05763fa7a22691131fa321ba3140d7cb02203fbda2ccc6212315464cd814d4e909b4f80a2361e3af0f9deda06478f91a0f3901483045022100b84fd63e957f2409558f63962fc91ba58334efde8b88ff53ca71da3d0fe7219702206001c6caeb30e18a7525fc72de0003e12646bf815b12fb132c1aadd6ffa1989c014c69522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53aefdffffff02a02526000000000017a9141567b2578f300fa618ef0033611fd67087aff6d187585d72000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887bf391400',
                         str(tx))
        self.assertEqual('bb4c28af28b970522c56ff0482cd98c2b78a90bec578bcede8a9e5cbec6ef5e7', tx.txid())
        self.assertEqual('bb4c28af28b970522c56ff0482cd98c2b78a90bec578bcede8a9e5cbec6ef5e7', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_hd_multisig_online_addr_p2wsh_p2sh(self, mock_write):
        # 2-of-2 p2sh-embedded segwit multisig
        wallet_offline1 = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: finish seminar arrange erosion sunny coil insane together pretty lunch lunch rose, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9CvELvByqm8k2dpecJVjgLMX1z5DufEjY4fBC5YvdGF5WjGCa7GVJJ2fYni1tyuF7Hw83E6W2ZBjAhaFLZv2ri3rEsubkCd5avg4EHKoDBN'),
                keystore.from_xpub('Upub5Qb8ik4Cnu8g97KLXKgVXHqY6tH8emQvqtBncjSKsyfTZuorPtTZgX7ovKKZHuuVGBVd1MTTBkWez1XXt2weN1sWBz6SfgRPQYEkNgz81QF')
            ],
            '2of2', gap_limit=2
        )
        wallet_offline2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: square page wood spy oil story rebel give milk screen slide shuffle, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9BbnKEXJxXaNvdEsRJ9VA9toYrSeFJh5UfGBpM2iKe8Uh7UhrM9K8ioL53s8gvCoGfirHHaqpABDAE7VUNw8LNU1DMJKVoWyeNKu9XcDC19'),
                keystore.from_xpub('Upub5RuakRisg8h3F7u7iL2k3UJFa1uiK7xauHamzTxYBbn4PXbM7eajr6M9Q2VCr6cVGhfhqWQqxnABvtSATuVM1xzxk4nA189jJwzaMn1QX7V')
            ],
            '2of2', gap_limit=2
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('QLeAYmt4Pp9b1xHb44aNgtu4YHZMXpcZvS')

        # bootstrap wallet_online
        funding_tx = Transaction('0100000000010118d494d28e5c3bf61566ca0313e22c3b561b888a317d689cc8b47b947adebd440000000017160014aec84704ea8508ddb94a3c6e53f0992d33a2a529fdffffff020f0925000000000017a91409f7aae0265787a02de22839d41e9c927768230287809698000000000017a91400698bd11c38f887f17c99846d9be96321fbf989870247304402206b906369f4075ebcfc149f7429dcfc34e11e1b7bbfc85d1185d5e9c324be0d3702203ce7fc12fd3131920fbcbb733250f05dbf7d03e18a4656232ee69d5c54dd46bd0121028a4b697a37f3f57f6e53f90db077fa9696095b277454fda839c211d640d48649c0391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('54356de9e156b85c8516fd4d51bdb68b5513f58b4a6147483978ae254627ee3e', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'QbZeRSpCc8KHiuGZFYKMdyimwxQttFDEYp', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325504

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx - first
        tx = wallet_offline1.sign_transaction(tx_copy, password=None)
        self.assertFalse(tx.is_complete())
        self.assertEqual('6a58a51591142429203b62b6ddf6b799a6926882efac229998c51bee6c3573eb', tx.txid())
        tx = Transaction(tx.serialize())

        # sign tx - second
        tx = wallet_offline2.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        tx = Transaction(tx.serialize())

        self.assertEqual('010000000001013eee274625ae78394847614a8bf513558bb6bd514dfd16855cb856e1e96d355401000000232200206ee8d4bb1277b7dbe1d4e49b880993aa993f417a9101cb23865c7c7258732704fdffffff02a02526000000000017a914a4189ef02c95cfe36f8e880c6cb54dff0837b22687585d72000000000017a91400698bd11c38f887f17c99846d9be96321fbf98987040047304402205a9dd9eb5676196893fb08f60079a2e9f567ee39614075d8c5d9fab0f11cbbc7022039640855188ebb7bccd9e3f00b397a888766d42d00d006f1ca7457c15449285f014730440220234f6648c5741eb195f0f4cd645298a10ce02f6ef557d05df93331e21c4f58cb022058ce2af0de1c238c4a8dd3b3c7a9a0da6e381ddad7593cddfc0480f9fe5baadf0147522102975c00f6af579f9a1d283f1e5a43032deadbab2308aef30fb307c0cfe54777462102d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c52aec0391400',
                         str(tx))
        self.assertEqual('6a58a51591142429203b62b6ddf6b799a6926882efac229998c51bee6c3573eb', tx.txid())
        self.assertEqual('96d0bca1001778c54e4c3a07929fab5562c5b5a23fd1ca3aa3870cc5df2bf97d', tx.wtxid())

    @needs_test_with_all_ecc_implementations
    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sending_offline_hd_multisig_online_addr_p2wsh(self, mock_write):
        # 2-of-3 p2wsh multisig
        wallet_offline1 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', '', True),
                keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra')
            ],
            '2of3', gap_limit=2
        )
        wallet_offline2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('snow nest raise royal more walk demise rotate smooth spirit canyon gun', '', True),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra'),
                keystore.from_xpub('Vpub5gSKXzxK7FeKQedu2q1z9oJWxqvX72AArW3HSWpEhc8othDH8xMDu28gr7gf17sp492BuJod8Tn7anjvJrKpETwqnQqX7CS8fcYyUtedEMk')
            ],
            '2of3', gap_limit=2
        )
        # ^ third seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False)
        wallet_online.import_address('tltc1q83p6eqxkuvq4eumcha46crpzg4nj84s9p0hnynkxg8nhvfzqcc7q26lnr9')

        # bootstrap wallet_online
        funding_tx = Transaction('0100000000010132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c501000000171600142e5d579693b2a7679622935df94d9f3c84909b24fdffffff0280969800000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c83717d010000000017a91441b772909ad301b41b76f4a3c5058888a7fe6f9a8702483045022100de54689f74b8efcce7fdc91e40761084686003bcd56c886ee97e75a7e803526102204dea51ae5e7d01bd56a8c336c64841f7fe02a8b101fa892e13f2d079bb14e6bf012102024e2f73d632c49f4b821ccd3b6da66b155427b1e5b1c4688cefd5a4b4bfa404c1391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('643a7ab9083d0227dd9df314ce56b18d279e6018ff975079dfaab82cd7a66fa3', funding_txid)
        wallet_online.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [(bitcoin.TYPE_ADDRESS, 'QTAKcyzh2zCA7XY1x1AEThtCjuNctXioJ9', 2500000)]
        tx = wallet_online.mktx(outputs=outputs, password=None, config=self.config, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325505

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = Transaction(tx.serialize())
        self.assertTrue(wallet_online.is_mine(wallet_online.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx - first
        tx = wallet_offline1.sign_transaction(tx_copy, password=None)
        self.assertFalse(tx.is_complete())
        self.assertEqual('32e946761b4e718c1fa8d044db9e72d5831f6395eb284faf2fb5c4af0743e501', tx.txid())
        tx = Transaction(tx.serialize())

        # sign tx - second
        tx = wallet_offline2.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        tx = Transaction(tx.serialize())

        self.assertEqual('01000000000101a36fa6d72cb8aadf795097ff18609e278db156ce14f39ddd27023d08b97a3a640000000000fdffffff02a02526000000000017a91447ee5a659f6ffb53f7e3afc1681b6415f3c00fa187585d7200000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c04004730440220629d89626585f563202e6b38ceddc26ccd00737e0b7ee4239b9266ef9174ea2f02200b74828399a2e35ed46c9b484af4817438d5fea890606ebb201b821944db1fdc0147304402205d1a59c84c419992069e9764a7992abca6a812cc5dfd4f0d6515d4283e660ce802202597a38899f31545aaf305629bd488f36bf54e4a05fe983932cafbb3906efb8f016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153aec1391400',
                         str(tx))
        self.assertEqual('32e946761b4e718c1fa8d044db9e72d5831f6395eb284faf2fb5c4af0743e501', tx.txid())
        self.assertEqual('4376fa5f1f6cb37b1f3956175d3bd4ef6882169294802b250a3c672f3ff431c1', tx.wtxid())


class TestWalletHistory_SimpleRandomOrder(TestCaseForTestnet):
    transactions = {
        "0f4972c84974b908a58dda2614b68cf037e6c03e8291898c719766f213217b67": "01000000029d1bdbe67f0bd0d7bd700463f5c29302057c7b52d47de9e2ca5069761e139da2000000008b483045022100a146a2078a318c1266e42265a369a8eef8993750cb3faa8dd80754d8d541d5d202207a6ab8864986919fd1a7fd5854f1e18a8a0431df924d7a878ec3dc283e3d75340141045f7ba332df2a7b4f5d13f246e307c9174cfa9b8b05f3b83410a3c23ef8958d610be285963d67c7bc1feb082f168fa9877c25999963ff8b56b242a852b23e25edfeffffff9d1bdbe67f0bd0d7bd700463f5c29302057c7b52d47de9e2ca5069761e139da2010000008a47304402201c7fa37b74a915668b0244c01f14a9756bbbec1031fb69390bcba236148ab37e02206151581f9aa0e6758b503064c1e661a726d75c6be3364a5a121a8c12cf618f64014104dc28da82e141416aaf771eb78128d00a55fdcbd13622afcbb7a3b911e58baa6a99841bfb7b99bcb7e1d47904fda5d13fdf9675cdbbe73e44efcc08165f49bac6feffffff02b0183101000000001976a914ca14915184a2662b5d1505ce7142c8ca066c70e288ac005a6202000000001976a9145eb4eeaefcf9a709f8671444933243fbd05366a388ac54c51200",
        "2791cdc98570cc2b6d9d5b197dc2d002221b074101e3becb19fab4b79150446d": "010000000132201ff125888a326635a2fc6e971cd774c4d0c1a757d742d0f6b5b020f7203a050000006a47304402201d20bb5629a35b84ff9dd54788b98e265623022894f12152ac0e6158042550fe02204e98969e1f7043261912dd0660d3da64e15acf5435577fc02a00eccfe76b323f012103a336ad86546ab66b6184238fe63bb2955314be118b32fa45dd6bd9c4c5875167fdffffff0254959800000000001976a9148d2db0eb25b691829a47503006370070bc67400588ac80969800000000001976a914f96669095e6df76cfdf5c7e49a1909f002e123d088ace8ca1200",
        "2d216451b20b6501e927d85244bcc1c7c70598332717df91bb571359c358affd": "010000000001036cdf8d2226c57d7cc8485636d8e823c14790d5f24e6cf38ba9323babc7f6db2901000000171600143fc0dbdc2f939c322aed5a9c3544468ec17f5c3efdffffff507dce91b2a8731636e058ccf252f02b5599489b624e003435a29b9862ccc38c0200000017160014c50ff91aa2a790b99aa98af039ae1b156e053375fdffffff6254162cf8ace3ddfb3ec242b8eade155fa91412c5bde7f55decfac5793743c1010000008b483045022100de9599dcd7764ca8d4fcbe39230602e130db296c310d4abb7f7ae4d139c4d46402200fbfd8e6dc94d90afa05b0c0eab3b84feb465754db3f984fbf059447282771c30141045eecefd39fabba7b0098c3d9e85794e652bdbf094f3f85a3de97a249b98b9948857ea1e8209ee4f196a6bbcfbad103a38698ee58766321ba1cdee0cbfb60e7b2fdffffff01e85af70100000000160014e8d29f07cd5f813317bec4defbef337942d85d74024730440220218049aee7bbd34a7fa17f972a8d24a0469b0131d943ef3e30860401eaa2247402203495973f006e6ee6ae74a83228623029f238f37390ee4b587d95cdb1d1aaee9901210392ba263f3a2b260826943ff0df25e9ca4ef603b98b0a916242c947ae0626575f02473044022002603e5ceabb4406d11aedc0cccbf654dd391ce68b6b2228a40e51cf8129310d0220533743120d93be8b6c1453973935b911b0a2322e74708d23e8b5f90e74b0f192012103221b4ee0f508ba595fc1b9c2252ed9d03e99c73b97344dae93263c68834f034800ed161300",
        "31494e7e9f42f4bd736769b07cc602e2a1019617b2c72a03ec945b667aada78f": "0100000000010454022b1b4d3b45e7fcac468de2d6df890a9f41050c05d80e68d4b083f728e76a000000008b483045022100ea8fe74db2aba23ad36ac66aaa481bad2b4d1b3c331869c1d60a28ce8cfad43c02206fa817281b33fbf74a6dd7352bdc5aa1d6d7966118a4ad5b7e153f37205f1ae80141045f7ba332df2a7b4f5d13f246e307c9174cfa9b8b05f3b83410a3c23ef8958d610be285963d67c7bc1feb082f168fa9877c25999963ff8b56b242a852b23e25edfdffffff54022b1b4d3b45e7fcac468de2d6df890a9f41050c05d80e68d4b083f728e76a01000000171600146dfe07e12af3db7c715bf1c455f8517e19c361e7fdffffff54022b1b4d3b45e7fcac468de2d6df890a9f41050c05d80e68d4b083f728e76a020000006a47304402200b1fb89e9a772a8519294acd61a53a29473ce76077165447f49a686f1718db5902207466e2e8290f84114dc9d6c56419cb79a138f03d7af8756de02c810f19e4e03301210222bfebe09c2638cfa5aa8223fb422fe636ba9675c5e2f53c27a5d10514f49051fdffffff54022b1b4d3b45e7fcac468de2d6df890a9f41050c05d80e68d4b083f728e76a0300000000fdffffff018793140d000000001600144b3e27ddf4fc5f367421ee193da5332ef351b700000247304402207ba52959938a3853bcfd942d8a7e6a181349069cde3ea73dbde43fa9669b8d5302207a686b92073863203305cb5d5550d88bdab0d21b9e9761ba4a106ea3970e08d901210265c1e014112ed19c9f754143fb6a2ff89f8630d62b33eb5ae708c9ea576e61b50002473044022029e868a905aa3ecae6eafcbd5959aefff0e5f39c1fc7a131a174828806e74e5202202f0aaa7c3cb3d9a9d526e5428ce37c0f0af0d774aa30b09ded8bc2230e7ffaf2012102fe0104455dc52b1689bba130664e452642180eb865217acfc6997260b7d946ae22c71200",
        "336eee749da7d1c537fd5679157fae63005bfd4bb8cf47ae73600999cbc9beaa": "0100000000010232201ff125888a326635a2fc6e971cd774c4d0c1a757d742d0f6b5b020f7203a020000006a4730440220198c0ba2b2aefa78d8cca01401d408ecdebea5ac05affce36f079f6e5c8405ca02200eabb1b9a01ff62180cf061dfacedba6b2e07355841b9308de2d37d83489c7b80121031c663e5534fe2a6de816aded6bb9afca09b9e540695c23301f772acb29c64a05fdfffffffb28ff16811d3027a2405be68154be8fdaff77284dbce7a2314c4107c2c941600000000000fdffffff015e104f01000000001976a9146dfd56a0b5d0c9450d590ad21598ecfeaa438bd788ac000247304402207d6dc521e3a4577685535f098e5bac4601aa03658b924f30bf7afef1850e437e022045b76771d8b6ca1939352d6b759fca31029e5b2edffa44dc747fe49770e746cd012102c7f36d4ceed353b90594ebaf3907972b6d73289bdf4707e120de31ec4e1eb11679f31200",
        "3a6ed17d34c49dfdf413398e113cf5f71710d59e9f4050bbc601d513a77eb308": "010000000168091e76227e99b098ef8d6d5f7c1bb2a154dd49103b93d7b8d7408d49f07be0000000008a47304402202f683a63af571f405825066bd971945a35e7142a75c9a5255d364b25b7115d5602206c59a7214ae729a519757e45fdc87061d357813217848cf94df74125221267ac014104aecb9d427e10f0c370c32210fe75b6e72ccc4f415076cf1a6318fbed5537388862c914b29269751ab3a04962df06d96f5f4f54e393a0afcbfa44b590385ae61afdffffff0240420f00000000001976a9145f917fd451ca6448978ebb2734d2798274daf00b88aca8063d00000000001976a914e1232622a96a04f5e5a24ca0792bb9c28b089d6e88ace9ca1200",
        "475c149be20c8a73596fad6cb8861a5af46d4fcf8e26a9dbf6cedff7ff80b70d": "01000000013a7e6f19a963adc7437d2f3eb0936f1fc9ef4ba7e083e19802eb1111525a59c2000000008b483045022100958d3931051306489d48fe69b32561e0a16e82a2447c07be9d1069317084b5e502202f70c2d9be8248276d334d07f08f934ffeea83977ad241f9c2de954a2d577f94014104d950039cec15ad10ad4fb658873bc746148bc861323959e0c84bf10f8633104aa90b64ce9f80916ab0a4238e025dcddf885b9a2dd6e901fe043a433731db8ab4fdffffff02a086010000000000160014bbfab2cc3267cea2df1b68c392cb3f0294978ca922940d00000000001976a914760f657c67273a06cad5b1d757a95f4ed79f5a4b88ac4c8d1300",
        "56a65810186f82132cea35357819499468e4e376fca685c023700c75dc3bd216": "01000000000101614b142aeeb827d35d2b77a5b11f16655b6776110ddd9f34424ff49d85706cf90200000000fdffffff02784a4c00000000001600148464f47f35cbcda2e4e5968c5a3a862c43df65a1404b4c00000000001976a914c9efecf0ecba8b42dce0ae2b28e3ea0573d351c988ac0247304402207d8e559ed1f56cb2d02c4cb6c95b95c470f4b3cb3ce97696c3a58e39e55cd9b2022005c9c6f66a7154032a0bb2edc1af1f6c8f488bec52b6581a3a780312fb55681b0121024f83b87ac3440e9b30cec707b7e1461ecc411c2f45520b45a644655528b0a68ae9ca1200",
        "6ae728f783b0d4680ed8050c05419f0a89dfd6e28d46acfce7453b4d1b2b0254": "0100000000010496941b9f18710b39bacde890e39a7fa401e6bf49985857cb7adfb8a45147ef1e000000001716001441aec99157d762708339d7faf7a63a8c479ed84cfdffffff96941b9f18710b39bacde890e39a7fa401e6bf49985857cb7adfb8a45147ef1e0100000000fdffffff1a5d1e4ca513983635b0df49fd4f515c66dd26d7bff045cfbd4773aa5d93197f000000006a4730440220652145460092ef42452437b942cb3f563bf15ad90d572d0b31d9f28449b7a8dd022052aae24f58b8f76bd2c9cf165cc98623f22870ccdbef1661b6dbe01c0ef9010f01210375b63dd8e93634bbf162d88b25d6110b5f5a9638f6fe080c85f8b21c2199a1fdfdffffff1a5d1e4ca513983635b0df49fd4f515c66dd26d7bff045cfbd4773aa5d93197f010000008a47304402207517c52b241e6638a84b05385e0b3df806478c2e444f671ca34921f6232ee2e70220624af63d357b83e3abe7cdf03d680705df0049ec02f02918ee371170e3b4a73d014104de408e142c00615294813233cdfe9e7774615ae25d18ba4a1e3b70420bb6666d711464518457f8b947034076038c6f0cfc8940d85d3de0386e0ad88614885c7cfdffffff0480969800000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac809698000000000017a914f2a76207d7b54bd34282281205923841341d9e1f87002d3101000000001976a914b8d4651937cd7db5bcf5fc98e6d2d8cfa131e85088ac743db20a00000000160014c7d0df09e03173170aed0247243874c6872748ed02483045022100b932cda0aeb029922e126568a48c05d79317747dcd77e61dce44e190e140822002202d13f84338bb272c531c4086277ac11e166c59612f4aefa6e20f78455bdc09970121028e6808a8ac1e9ede621aaabfcad6f86662dbe0ace0236f078eb23c24bc88bd5e02483045022100d74a253262e3898626c12361ba9bb5866f9303b42eec0a55ced0578829e2e61e022059c08e61d90cd63c84de61c796c9d1bc1e2f8217892a7c07b383af357ddd7a730121028641e89822127336fc12ff99b1089eb1a124847639a0e98d17ff03a135ad578b000020c71200",
        "72419d187c61cfc67a011095566b374dc2c01f5397e36eafe68e40fc44474112": "0100000002677b2113f26697718c8991823ec0e637f08cb61426da8da508b97449c872490f000000008b4830450221009c50c0f56f34781dfa7b3d540ac724436c67ffdc2e5b2d5a395c9ebf72116ef802205a94a490ea14e4824f36f1658a384aeaecadd54839600141eb20375a49d476d1014104c291245c2ee3babb2a35c39389df56540867f93794215f743b9aa97f5ba114c4cdee8d49d877966728b76bc649bb349efd73adef1d77452a9aac26f8c51ae1ddfdffffff677b2113f26697718c8991823ec0e637f08cb61426da8da508b97449c872490f010000008b483045022100ae0b286493491732e7d3f91ab4ac4cebf8fe8a3397e979cb689e62d350fdcf2802206cf7adf8b29159dd797905351da23a5f6dab9b9dbf5028611e86ccef9ff9012e014104c62c4c4201d5c6597e5999f297427139003fdb82e97c2112e84452d1cfdef31f92dd95e00e4d31a6f5f9af0dadede7f6f4284b84144e912ff15531f36358bda7fdffffff019f7093030000000022002027ce908c4ee5f5b76b4722775f23e20c5474f459619b94040258290395b88afb6ec51200",
        "76bcf540b27e75488d95913d0950624511900ae291a37247c22d996bb7cde0b4": "0100000001f4ba9948cdc4face8315c7f0819c76643e813093ffe9fbcf83d798523c7965db000000006a473044022061df431a168483d144d4cffe1c5e860c0a431c19fc56f313a899feb5296a677c02200208474cc1d11ad89b9bebec5ec00b1e0af0adaba0e8b7f28eed4aaf8d409afb0121039742bf6ab70f12f6353e9455da6ed88f028257950450139209b6030e89927997fdffffff01d4f84b00000000001976a9140b93db89b6bf67b5c2db3370b73d806f458b3d0488ac0a171300",
        "7f19935daa7347bdcf45f0bfd726dd665c514ffd49dfb035369813a54c1e5d1a": "01000000000102681b6a8dd3a406ee10e4e4aece3c2e69f6680c02f53157be6374c5c98322823a00000000232200209adfa712053a06cc944237148bcefbc48b16eb1dbdc43d1377809bcef1bea9affdffffff681b6a8dd3a406ee10e4e4aece3c2e69f6680c02f53157be6374c5c98322823a0100000023220020f40ed2e3fbffd150e5b74f162c3ce5dae0dfeba008a7f0f8271cf1cf58bfb442fdffffff02801d2c04000000001976a9140cc01e19090785d629cdcc98316f328df554de4f88ac6d455d05000000001976a914b9e828990a8731af4527bcb6d0cddf8d5ffe90ce88ac040047304402206eb65bd302eefae24eea05781e8317503e68584067d35af028a377f0751bb55b0220226453d00db341a4373f1bcac2391f886d3a6e4c30dd15133d1438018d2aad24014730440220343e578591fab0236d28fb361582002180d82cb1ba79eec9139a7a9519fca4260220723784bd708b4a8ed17bb4b83a5fd2e667895078e80eec55119015beb3592fd2016952210222eca5665ed166d090a5241d9a1eb27a92f85f125aaf8df510b2b5f701f3f534210227bca514c22353a7ae15c61506522872afecf10df75e599aabe4d562d0834fce2103601d7d49bada5a57a4832eafe4d1f1096d7b0b051de4a29cd5fc8ad62865e0a553ae0400483045022100b15ea9daacd809eb4d783a1449b7eb33e2965d4229e1a698db10869299dddc670220128871ffd27037a3e9dac6748ce30c14b145dd7f9d56cc9dcde482461fb6882601483045022100cb659e1de65f8b87f64d1b9e62929a5d565bbd13f73a1e6e9dd5f4efa024b6560220667b13ce2e1a3af2afdcedbe83e2120a6e8341198a79efb855b8bc5f93b4729f0169522102d038600af253cf5019f9d5637ca86763eca6827ed7b2b7f8cc6326dffab5eb68210315cdb32b7267e9b366fb93efe29d29705da3db966e8c8feae0c8eb51a7cf48e82103f0335f730b9414acddad5b3ee405da53961796efd8c003e76e5cd306fcc8600c53ae1fc71200",
        "9de08bcafc602a3d2270c46cbad1be0ef2e96930bec3944739089f960652e7cb": "010000000001013409c10fd732d9e4b3a9a1c4beb511fa5eb32bc51fd169102a21aa8519618f800000000000fdffffff0640420f00000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac40420f00000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac40420f00000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac80841e00000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac64064a000000000016001469825d422ca80f2a5438add92d741c7df45211f280969800000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac02483045022100b4369b18bccb74d72b6a38bd6db59122a9e8af3356890a5ecd84bdb8c7ffe317022076a5aa2b817be7b3637d179106fccebb91acbc34011343c8e8177acc2da4882e0121033c8112bbf60855f4c3ae489954500c4b8f3408665d8e1f63cf3216a76125c69865281300",
        "a29d131e766950cae2e97dd4527b7c050293c2f5630470bdd7d00b7fe6db1b9d": "010000000400899af3606e93106a5d0f470e4e2e480dfc2fd56a7257a1f0f4d16fd5961a0f000000006a47304402205b32a834956da303f6d124e1626c7c48a30b8624e33f87a2ae04503c87946691022068aa7f936591fb4b3272046634cf526e4f8a018771c38aff2432a021eea243b70121034bb61618c932b948b9593d1b506092286d9eb70ea7814becef06c3dfcc277d67fdffffff4bc2dcc375abfc7f97d8e8c482f4c7b8bc275384f5271678a32c35d955170753000000006b483045022100de775a580c6cb47061d5a00c6739033f468420c5719f9851f32c6992610abd3902204e6b296e812bb84a60c18c966f6166718922780e6344f243917d7840398eb3db0121025d7317c6910ad2ad3d29a748c7796ddf01e4a8bc5e3bf2a98032f0a20223e4aafdffffff4bc2dcc375abfc7f97d8e8c482f4c7b8bc275384f5271678a32c35d955170753010000006a4730440220615a26f38bf6eb7043794c08fb81f273896b25783346332bec4de8dfaf7ed4d202201c2bc4515fc9b07ded5479d5be452c61ce785099f5e33715e9abd4dbec410e11012103caa46fcb1a6f2505bf66c17901320cc2378057c99e35f0630c41693e97ebb7cffdffffff4bc2dcc375abfc7f97d8e8c482f4c7b8bc275384f5271678a32c35d955170753030000006b483045022100c8fba762dc50041ee3d5c7259c01763ed913063019eefec66678fb8603624faa02200727783ccbdbda8537a6201c63e30c0b2eb9afd0e26cb568d885e6151ef2a8540121027254a862a288cfd98853161f575c49ec0b38f79c3ef0bf1fb89986a3c36a8906fdffffff0240787d01000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac3bfc1502000000001976a914c30f2af6a79296b6531bf34dba14c8419be8fb7d88ac52c51200",
        "c1433779c5faec5df5e7bdc51214a95f15deeab842c23efbdde3acf82c165462": "0100000003aabec9cb99096073ae47cfb84bfd5b0063ae7f157956fd37c5d1a79d74ee6e33000000008b4830450221008136fc880d5e24fdd9d2a43f5085f374fef013b814f625d44a8075104981d92a0220744526ec8fc7887c586968f22403f0180d54c9b7ff8db9b553a3c4497982e8250141047b8b4c91c5a93a1f2f171c619ca41770427aa07d6de5130c3ba23204b05510b3bd58b7a1b35b9c4409104cfe05e1677fc8b51c03eac98b206e5d6851b31d2368fdffffff16d23bdc750c7023c085a6fc76e3e468944919783535ea2c13826f181058a656010000008a47304402204148410f2d796b1bb976b83904167d28b65dcd7c21b3876022b4fa70abc86280022039ea474245c3dc8cd7e5a572a155df7a6a54496e50c73d9fed28e76a1cf998c00141044702781daed201e35aa07e74d7bda7069e487757a71e3334dc238144ad78819de4120d262e8488068e16c13eea6092e3ab2f729c13ef9a8c42136d6365820f7dfdffffff68091e76227e99b098ef8d6d5f7c1bb2a154dd49103b93d7b8d7408d49f07be0010000008b4830450221008228af51b61a4ee09f58b4a97f204a639c9c9d9787f79b2fc64ea54402c8547902201ed81fca828391d83df5fbd01a3fa5dd87168c455ed7451ba8ccb5bf06942c3b0141046fcdfab26ac08c827e68328dbbf417bbe7577a2baaa5acc29d3e33b3cc0c6366df34455a9f1754cb0952c48461f71ca296b379a574e33bcdbb5ed26bad31220bfdffffff0210791c00000000001976a914a4b991e7c72996c424fe0215f70be6aa7fcae22c88ac80c3c901000000001976a914b0f6e64ea993466f84050becc101062bb502b4e488ac7af31200",
        "c2595a521111eb0298e183e0a74befc91f6f93b03e2f7d43c7ad63a9196f7e3a": "01000000018557003cb450f53922f63740f0f77db892ef27e15b2614b56309bfcee96a0ad3010000006a473044022041923c905ae4b5ed9a21aa94c60b7dbcb8176d58d1eb1506d9fb1e293b65ce01022015d6e9d2e696925c6ad46ce97cc23dec455defa6309b839abf979effc83b8b160121029332bf6bed07dcca4be8a5a9d60648526e205d60c75a21291bffcdefccafdac3fdffffff01c01c0f00000000001976a914a2185918aa1006f96ed47897b8fb620f28a1b09988ac01171300",
        "e07bf0498d40d7b8d7933b1049dd54a1b21b7c5f6d8def98b0997e22761e0968": "01000000016d445091b7b4fa19cbbee30141071b2202d0c27d195b9d6d2bcc7085c9cd9127010000008b483045022100daf671b52393af79487667eddc92ebcc657e8ae743c387b25d1c1a2e19c7a4e7022015ef2a52ea7e94695de8898821f9da539815775516f18329896e5fc52a3563b30141041704a3daafaace77c8e6e54cf35ed27d0bf9bb8bcd54d1b955735ff63ec54fe82a80862d455c12e739108b345d585014bf6aa0cbd403817c89efa18b3c06d6b5fdffffff02144a4c00000000001976a9148942ac692ace81019176c4fb0ac408b18b49237f88ac404b4c00000000001976a914dd36d773acb68ac1041bc31b8a40ee504b164b2e88ace9ca1200",
        "e453e7346693b507561691b5ea73f8eba60bfc8998056226df55b2fac88ba306": "010000000125af87b0c2ebb9539d644e97e6159ccb8e1aa80fe986d01f60d2f3f37f207ae8010000008b483045022100baed0747099f7b28a5624005d50adf1069120356ac68c471a56c511a5bf6972b022046fbf8ec6950a307c3c18ca32ad2955c559b0d9bbd9ec25b64f4806f78cadf770141041ea9afa5231dc4d65a2667789ebf6806829b6cf88bfe443228f95263730b7b70fb8b00b2b33777e168bcc7ad8e0afa5c7828842794ce3814c901e24193700f6cfdffffff02a0860100000000001976a914ade907333744c953140355ff60d341cedf7609fd88ac68830a00000000001976a9145d48feae4c97677e4ca7dcd73b0d9fd1399c962b88acc9cc1300",
        "e87a207ff3f3d2601fd086e90fa81a8ecb9c15e6974e649d53b9ebc2b087af25": "01000000010db780fff7dfcef6dba9268ecf4f6df45a1a86b86cad6f59738a0ce29b145c47010000008a47304402202887ec6ec200e4e2b4178112633011cbdbc999e66d398b1ff3998e23f7c5541802204964bd07c0f18c48b7b9c00fbe34c7bc035efc479e21a4fa196027743f06095f0141044f1714ed25332bb2f74be169784577d0838aa66f2374f5d8cbbf216063626822d536411d13cbfcef1ff3cc1d58499578bc4a3c4a0be2e5184b2dd7963ef67713fdffffff02a0860100000000001600145bbdf3ba178f517d4812d286a40c436a9088076e6a0b0c00000000001976a9143fc16bef782f6856ff6638b1b99e4d3f863581d388acfbcb1300"
    }
    txid_list = sorted(list(transactions))

    @classmethod
    def create_old_wallet(cls):
        ks = keystore.from_old_mpk('e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')
        # seed words: powerful random nobody notice nothing important anyway look away hidden message over
        w = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=20)
        # some txns are beyond gap limit:
        w.create_new_address(for_change=True)
        return w

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_restoring_old_wallet_txorder1(self, mock_write):
        w = self.create_old_wallet()
        for i in [2, 12, 7, 9, 11, 10, 16, 6, 17, 1, 13, 15, 5, 8, 4, 0, 14, 18, 3]:
            tx = Transaction(self.transactions[self.txid_list[i]])
            w.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(27633300, sum(w.get_balance()))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_restoring_old_wallet_txorder2(self, mock_write):
        w = self.create_old_wallet()
        for i in [9, 18, 2, 0, 13, 3, 1, 11, 4, 17, 7, 14, 12, 15, 10, 8, 5, 6, 16]:
            tx = Transaction(self.transactions[self.txid_list[i]])
            w.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(27633300, sum(w.get_balance()))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_restoring_old_wallet_txorder3(self, mock_write):
        w = self.create_old_wallet()
        for i in [5, 8, 17, 0, 9, 10, 12, 3, 15, 18, 2, 11, 14, 7, 16, 1, 4, 6, 13]:
            tx = Transaction(self.transactions[self.txid_list[i]])
            w.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(27633300, sum(w.get_balance()))


class TestWalletHistory_EvilGapLimit(TestCaseForTestnet):
    transactions = {
        # txn A:
        "511a35e240f4c8855de4c548dad932d03611a37e94e9203fdb6fc79911fe1dd4": "010000000001018aacc3c8f98964232ebb74e379d8ff4e800991eecfcf64bd1793954f5e50a8790100000000fdffffff0340420f0000000000160014dbf321e905d544b54b86a2f3ed95b0ac66a3ddb0ff0514000000000016001474f1c130d3db22894efb3b7612b2c924628d0d7e80841e000000000016001488492707677190c073b6555fb08d37e91bbb75d802483045022100cf2904e09ea9d2670367eccc184d92fcb8a9b9c79a12e4efe81df161077945db02203530276a3401d944cf7a292e0660f36ee1df4a1c92c131d2c0d31d267d52524901210215f523a412a5262612e1a5ef9842dc864b0d73dc61fb4c6bfd480a867bebb1632e181400",
        # txn B:
        "fde0b68938709c4979827caa576e9455ded148537fdb798fd05680da64dc1b4f": "01000000000101a317998ac6cc717de17213804e1459900fe257b9f4a3b9b9edd29806728277530100000000fdffffff03c0c62d00000000001600149543301687b1ca2c67718d55fbe10413c73ddec200093d00000000001600141bc12094a4475dcfbf24f9920dafddf9104ca95b3e4a4c0000000000160014b226a59f2609aa7da4026fe2c231b5ae7be12ac302483045022100f1082386d2ce81612a3957e2801803938f6c0066d76cfbd853918d4119f396df022077d05a2b482b89707a8a600013cb08448cf211218a462f2a23c2c0d80a8a0ca7012103f4aac7e189de53d95e0cb2e45d3c0b2be18e93420734934c61a6a5ad88dd541033181400",
        # txn C:
        "268fce617aaaa4847835c2212b984d7b7741fdab65de22813288341819bc5656": "010000000001014f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0100000000fdffffff0260e316000000000016001445e9879cf7cd5b4a15df7ddcaf5c6dca0e1508bacc242600000000001600141bc12094a4475dcfbf24f9920dafddf9104ca95b02483045022100ae3618912f341fefee11b67e0047c47c88c4fa031561c3fafe993259dd14d846022056fa0a5b5d8a65942fa68bcc2f848fd71fa455ba42bc2d421b67eb49ba62aa4e01210394d8f4f06c2ea9c569eb050c897737a7315e7f2104d9b536b49968cc89a1f11033181400",
    }

    @classmethod
    def create_wallet(cls):
        ks = keystore.from_xpub('vpub5Vhmk4dEJKanDTTw6immKXa3thw45u3gbd1rPYjREB6viP13sVTWcH6kvbR2YeLtGjradr6SFLVt9PxWDBSrvw1Dc1nmd3oko3m24CQbfaJ')
        # seed words: nephew work weather maze pyramid employ check permit garment scene kiwi smooth
        w = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=20)
        return w

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_restoring_wallet_txorder1(self, mock_write):
        w = self.create_wallet()
        w.storage.put('stored_height', 1316917 + 100)
        for txid in self.transactions:
            tx = Transaction(self.transactions[txid])
            w.transactions[tx.txid()] = tx
        # txn A is an external incoming txn paying to addr (3) and (15)
        # txn B is an external incoming txn paying to addr (4) and (25)
        # txn C is an internal transfer txn from addr (25) -- to -- (1) and (25)
        w.receive_history_callback('tltc1qgh5c088he4d559wl0hw27hrdeg8p2z96c3td9f',  # HD index 1
                                   [('268fce617aaaa4847835c2212b984d7b7741fdab65de22813288341819bc5656', 1316917)],
                                   {})
        w.synchronize()
        w.receive_history_callback('tltc1qm0ejr6g964zt2jux5te7m9ds43n28hds528z0k',  # HD index 3
                                   [('511a35e240f4c8855de4c548dad932d03611a37e94e9203fdb6fc79911fe1dd4', 1316912)],
                                   {})
        w.synchronize()
        w.receive_history_callback('tltc1qj4pnq958k89zcem3342lhcgyz0rnmhkzxjy3gk',  # HD index 4
                                   [('fde0b68938709c4979827caa576e9455ded148537fdb798fd05680da64dc1b4f', 1316917)],
                                   {})
        w.synchronize()
        w.receive_history_callback('tltc1q3pyjwpm8wxgvquak240mprfhaydmkawcfhg2zs',  # HD index 15
                                   [('511a35e240f4c8855de4c548dad932d03611a37e94e9203fdb6fc79911fe1dd4', 1316912)],
                                   {})
        w.synchronize()
        w.receive_history_callback('tltc1qr0qjp99ygawul0eylxfqmt7alygye22mtenjfm',  # HD index 25
                                   [('fde0b68938709c4979827caa576e9455ded148537fdb798fd05680da64dc1b4f', 1316917),
                                    ('268fce617aaaa4847835c2212b984d7b7741fdab65de22813288341819bc5656', 1316917)],
                                   {})
        w.synchronize()
        self.assertEqual(9999788, sum(w.get_balance()))
