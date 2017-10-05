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

        ks = keystore.from_seed(seed_words, '')

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'LgbiA75qdajKtdsfEXQQGwfonAQZEEEbjS')
        self.assertEqual(w.get_change_addresses()[0], 'LdfcFkfXExba64HeRK1c9icSJMr6tMKyfv')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_segwit(self, mock_write):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, '')

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'zpub6jftahH18ngZyLeqfLBFAm7YaWFVttE9pku5pNMX2qPzTjoq1FVgZMmhjecyB2nqFb31gHE9vNvbaggU6vvWpNZbXEWLLUjYjFqG95LNyT8')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1qtt5msqvcqyvuu7hq7urwgraqqyq2yhtux3m2q9')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1q9wlrynvj7qz7x4fs29d8dnje0zdevj5vl9f0pn')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_seed_old(self, mock_write):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(bitcoin.seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, '')

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'LZXBVPSYn3bfFfibvUm9K8h4BddGhUE4Fe')
        self.assertEqual(w.get_change_addresses()[0], 'LdeTQ2avMuXcwvpJfMpPwFPgz5F3Fnbsdu')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip44_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'LQx4V43sdoTgiRt3TkBncbSBBMijtP3jg3')
        self.assertEqual(w.get_change_addresses()[0], 'LaV2rhxLkq48nJoTWLp19f4pcnZLtJeLoB')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_seed_bip49_p2sh_segwit(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0], 'MC1qiM3LvsbB3WdgFf9q3tzK9fmLrX1SQs')
        self.assertEqual(w.get_change_addresses()[0], 'MRnKmWLg8T5jPEj8TktCyfWv4FPqyFBS3V')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_standard(self, mock_write):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(bitcoin.seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '')
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHFBUrq4c')

        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDbenT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], 'M8wrMJA8deEQuJXhXYa6nrJPBi7yiLnCN5')
        self.assertEqual(w.get_change_addresses()[0], 'MCjfF7hpoc3mbD1DBEqqJv1scPJJDhtoMG')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_electrum_multisig_seed_segwit(self, mock_write):
        seed_words = 'snow nest raise royal more walk demise rotate smooth spirit canyon gun'
        self.assertEqual(bitcoin.seed_type(seed_words), 'segwit')

        ks1 = keystore.from_seed(seed_words, '')
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'zpub6jftahH18ngZxwy83eiaWSH1ynYTbA4Ta5MR6JQb4TZCJLCbEzY15f6BCpiDtQeFkzni3v4tT5x6x6Lanvg1YbMZ7ePQmjqtbznPUcYA6mK')

        ks2 = keystore.from_xpub('zpub6jftahH18ngZxE47EYpJWzwTF71AhtNW8ToREBZB7mu3BMdud8aG1tw5TtSqY4qPrhFK1NpKvYwJi9mnhLE8p57nx6929YguJ1Sf2VB8VGt')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], 'ltc1qnvks7gfdu72de8qv6q6rhkkzu70fqz4wpjzuxjf6aydsx7wxfwcqsmgvk5')
        self.assertEqual(w.get_change_addresses()[0], 'ltc1qsvfq6ekp0paugjhfey38pt3nqyvs3tcxu5l00v56j3g6g5la004qd3rptc')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_bip44_standard(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        ks2 = keystore.from_xpub('xpub6D9mmC1euHjT6dVrsfwSeNRPF2oi3cTifXwgnhzAay7RiCmZTtzAPCGPcyYP9NwTn5QvoyYsx7DxSQYc82872dk3pWv1P5om1EC1jAr5jGT')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], 'MBuxL7kbT7iUkkPWMasFYJjYcVZjjuLraf')
        self.assertEqual(w.get_change_addresses()[0], 'MFYWFqFWu4yxGsUmDvEjwg2mVuRM2TQxTr')

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_bip39_multisig_seed_bip49_p2sh_segwit(self, mock_write):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/49'/0'/0'")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4')

        ks2 = keystore.from_xpub('ypub6WnnkE8TGSfWMb6QUVYoVsDRwpCUR98xUg7JnSoVuK7w41UGNViztuCCd8f4mHi6KkUahrh5CnZex1PJNi3oKcSCZ9Lni4huF5FAGouGkuz')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], 'M9v59KeYadS8XdnNh3c99tRdqt1ugksorH')
        self.assertEqual(w.get_change_addresses()[0], 'MFex2cX9XVcdvYu3UQEMqmJHASBXYToe6q')
