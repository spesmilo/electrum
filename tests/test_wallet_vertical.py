import unittest
from unittest import mock
import shutil
import tempfile
from typing import Sequence
import asyncio
import copy

from electrum import storage, bitcoin, keystore, bip32, slip39, wallet
from electrum import Transaction
from electrum import SimpleConfig
from electrum import util
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT
from electrum.wallet import (sweep, Multisig_Wallet, Standard_Wallet, Imported_Wallet,
                             restore_wallet_from_text, Abstract_Wallet, CannotBumpFee, BumpFeeStrategy,
                             TransactionPotentiallyDangerousException, TransactionDangerousException,
                             TxSighashRiskLevel)
from electrum.util import bfh, NotEnoughFunds, UnrelatedTransactionException, UserFacingException
from electrum.transaction import Transaction, PartialTxOutput, tx_from_any, Sighash
from electrum.mnemonic import calc_seed_type
from electrum.network import Network

from electrum.plugins.trustedcoin import trustedcoin

from . import ElectrumTestCase


UNICODE_HORROR_HEX = 'e282bf20f09f988020f09f98882020202020e3818620e38191e3819fe381be20e3828fe3828b2077cda2cda2cd9d68cda16fcda2cda120ccb8cda26bccb5cd9f6eccb4cd98c7ab77ccb8cc9b73cd9820cc80cc8177cd98cda2e1b8a9ccb561d289cca1cda27420cca7cc9568cc816fccb572cd8fccb5726f7273cca120ccb6cda1cda06cc4afccb665cd9fcd9f20ccb6cd9d696ecda220cd8f74cc9568ccb7cca1cd9f6520cd9fcd9f64cc9b61cd9c72cc95cda16bcca2cca820cda168ccb465cd8f61ccb7cca2cca17274cc81cd8f20ccb4ccb7cda0c3b2ccb5ccb666ccb82075cca7cd986ec3adcc9bcd9c63cda2cd8f6fccb7cd8f64ccb8cda265cca1cd9d3fcd9e'
UNICODE_HORROR = bfh(UNICODE_HORROR_HEX).decode('utf-8')
assert UNICODE_HORROR == '₿ 😀 😈     う けたま わる w͢͢͝h͡o͢͡ ̸͢k̵͟n̴͘ǫw̸̛s͘ ̀́w͘͢ḩ̵a҉̡͢t ̧̕h́o̵r͏̵rors̡ ̶͡͠lį̶e͟͟ ̶͝in͢ ͏t̕h̷̡͟e ͟͟d̛a͜r̕͡k̢̨ ͡h̴e͏a̷̢̡rt́͏ ̴̷͠ò̵̶f̸ u̧͘ní̛͜c͢͏o̷͏d̸͢e̡͝?͞'


class WalletIntegrityHelper:

    gap_limit = 1  # make tests run faster
    # TODO also use short gap limit for change addrs, for performance

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
    def create_standard_wallet(cls, ks, *, config: SimpleConfig, gap_limit=None):
        db = storage.WalletDB('', storage=None, upgrade=True)
        db.put('keystore', ks.dump())
        db.put('gap_limit', gap_limit or cls.gap_limit)
        w = Standard_Wallet(db, config=config)
        w.synchronize()
        return w

    @classmethod
    def create_imported_wallet(cls, *, config: SimpleConfig, privkeys: bool):
        db = storage.WalletDB('', storage=None, upgrade=True)
        if privkeys:
            k = keystore.Imported_KeyStore({})
            db.put('keystore', k.dump())
        w = Imported_Wallet(db, config=config)
        return w

    @classmethod
    def create_multisig_wallet(cls, keystores: Sequence, multisig_type: str, *,
                               config: SimpleConfig, gap_limit=None):
        """Creates a multisig wallet."""
        db = storage.WalletDB('', storage=None, upgrade=False)
        for i, ks in enumerate(keystores):
            cosigner_index = i + 1
            db.put('x%d' % cosigner_index, ks.dump())
        db.put('wallet_type', multisig_type)
        db.put('gap_limit', gap_limit or cls.gap_limit)
        w = Multisig_Wallet(db, config=config)
        w.synchronize()
        return w


class TestWalletKeystoreAddressIntegrityForMainnet(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_standard(self, mock_save_db):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(calc_seed_type(seed_words), 'standard')

        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6')
        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf')
        self.assertEqual(w.get_change_addresses()[0], '1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_segwit(self, mock_save_db):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(calc_seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2')
        self.assertEqual(ks.xpub, 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p')

        self.assertEqual('zprvAabC4ncjU4qVMNbpYZ5G4XqmKJoJN3EA4TVCodaPwyvEatrZpVYmWVHfKwS1fdq2uCdPyCmbjAjQ5FzeqHFSGv9KUmUFptTMAcyKzHiUM6Q',
                         ks.get_lightning_xprv(None))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_segwit_passphrase(self, mock_save_db):
        seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        self.assertEqual(calc_seed_type(seed_words), 'segwit')

        ks = keystore.from_seed(seed_words, passphrase=UNICODE_HORROR, for_multisig=False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAZDmEQiCLUcZXPfrBXoksCD2R6RMAzAre7SUyBotibisy9c7vGhLYvHaP3d9rYU12DKAWdZfscPNA7qEPgTkCDqX5sE93ryAJAQvkDbfLxU')
        self.assertEqual(ks.xpub, 'zpub6nD7dvF6ArArjskKHZLmEL9ky8FqaSti1LN5maDWGwFrqwwGTp1b6ic4EHwciFNaYDmCXcQYxXSiF9BjcLCMPcaYkVN2nQD6QjYQ8vpSR3Z')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qx94dutas7ysn2my645cyttujrms5d9p57f6aam')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qcywwsy87sdp8vz5rfjh3sxdv6rt95kujdqq38g')

        self.assertEqual('zprvAaoTFrze53KLvVYL8yL5H4sxoBFto98dgfTxFxcBepBPaEWStxpsdYqvNGxskGMTgX11bUtPiVj3aCe2jXFkAJQMi9RmksGBgFVwFM85Gir',
                         ks.get_lightning_xprv(None))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_old(self, mock_save_db):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(calc_seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)

        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], '1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo')
        self.assertEqual(w.get_change_addresses()[0], '1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_2fa_legacy_pre27_25words(self, mock_save_db):
        # pre-version-2.7 2fa seed, containing 25 words
        seed_words = 'bind clever room kidney crucial sausage spy edit canvas soul liquid ribbon slam open alpha suffer gate relax voice carpet law hill woman tonight abstract'
        assert len(seed_words.split()) == 25
        self.assertEqual(calc_seed_type(seed_words), '2fa')

        xprv1, xpub1, xprv2, xpub2 = trustedcoin.TrustedCoinPlugin.xkeys_from_seed(seed_words, '')

        ks1 = keystore.from_xprv(xprv1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9s21ZrQH143K2TsDemiaPqaTuBkW3gns4sGi9f65pWtg27nmmmAut6fErgaHFxj3d4rHgyFKjhvtAUafqF3wwU8Bkou8LefQgBtRWjUKN3V')
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcEwwgkoFakyXCTDazT9WiS6CJx3VhNrRetv7vKJVARtyihwCVatSsUtVsEYcvdxhvDtkSk8qKV3VVtcL3csz6sQTbGzmEckd')
        self.assertEqual(ks1.xpub, xpub1)

        ks2 = keystore.from_xprv(xprv2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))
        self.assertEqual(ks2.xprv, 'xprv9s21ZrQH143K3r6H1h91TqRECE7tmDB5PYGZDKPuSjefTzNbDMauUMUnjsUSv8X8nuzQsrtGmtCuA51CNz7XimRj2HPYxUxXGGf4KB7M74y')
        self.assertEqual(ks2.xpub, 'xpub661MyMwAqRbcGLAk7ig1pyMxkFxPAftvkmCA1hoX15BeLnhjktuA29oGb7bh9opQgNERu6iWhwcY6b5bZX57dYsGo7zYjwXTNCryfKuPfek')
        self.assertEqual(ks2.xpub, xpub2)

        long_user_id, short_id = trustedcoin.get_user_id(
            {'x1': {'xpub': xpub1},
             'x2': {'xpub': xpub2}})
        xtype = bip32.xpub_type(xpub1)
        xpub3 = trustedcoin.make_xpub(trustedcoin.get_signing_xpub(xtype), long_user_id)
        ks3 = keystore.from_xpub(xpub3)
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks3)
        self.assertTrue(isinstance(ks3, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2, ks3], '2of3', config=self.config)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '3Bw5jczNModhFAbvfwvUHbdGrC2Lh2qRQp')
        self.assertEqual(w.get_change_addresses()[0], '3Ke6pKrmtSyyQaMob1ES4pk8siAAkRmst9')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_2fa_legacy_pre27_24words(self, mock_save_db):
        # pre-version-2.7 2fa seed, containing 24 words
        seed_words = 'sibling leg cable timber patient foot occur plate travel finger chef scale radio citizen promote immune must chef fluid sea sphere common acid lab'
        assert len(seed_words.split()) == 24
        self.assertEqual(calc_seed_type(seed_words), '2fa')

        xprv1, xpub1, xprv2, xpub2 = trustedcoin.TrustedCoinPlugin.xkeys_from_seed(seed_words, '')

        ks1 = keystore.from_xprv(xprv1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9s21ZrQH143K37iqjPnsBm27cRgrg6TiKNwhCYg7Uk46yLKB5s4N1Knzo7rTkYvjojh9Z6KkGTMi6CV5h4kEcWYLmHjcTW8kK5bnMVXvEvp')
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcFboJqRKsYtxrATXM5ZBZgbsHzw5j35b5r8eKdQNcZ87UeR24LDSn2RxspwL9s7yM3KqtPFq5dwP5csmQ2Xb1dgaQztrNGyP')
        self.assertEqual(ks1.xpub, xpub1)

        ks2 = keystore.from_xprv(xprv2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))
        self.assertEqual(ks2.xprv, 'xprv9s21ZrQH143K2qJ6sVTs5bXnrw7CPEpYTkefvW6Xj9fMuskny5t3TaLMAvZtSkYwT68asJdrEaay8q4ntmXvYCuQL3ULdEziFCB9KyZhuDX')
        self.assertEqual(ks2.xpub, 'xpub661MyMwAqRbcFKNZyWzsSjUXQxwgnhYPpyaGitW9HVCLng5wWdCJ1Neq2DLV3717ED1RG3aTGLJVVBt5CJEXmCzMLBjqXtK4MEvRXiYSvnJ')
        self.assertEqual(ks2.xpub, xpub2)

        long_user_id, short_id = trustedcoin.get_user_id(
            {'x1': {'xpub': xpub1},
             'x2': {'xpub': xpub2}})
        xtype = bip32.xpub_type(xpub1)
        xpub3 = trustedcoin.make_xpub(trustedcoin.get_signing_xpub(xtype), long_user_id)
        ks3 = keystore.from_xpub(xpub3)
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks3)
        self.assertTrue(isinstance(ks3, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2, ks3], '2of3', config=self.config)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '39XK9VBGiK4bqNJYrajfKE8C1ky4gYA5Zy')
        self.assertEqual(w.get_change_addresses()[0], '3PKtHrjiKdsZ73ULZ4Sf1vDBnrUoAEtLDe')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_2fa_legacy_post27(self, mock_save_db):
        # post-version-2.7 2fa seed
        seed_words = 'kiss live scene rude gate step hip quarter bunker oxygen motor glove'
        self.assertEqual(calc_seed_type(seed_words), '2fa')

        xprv1, xpub1, xprv2, xpub2 = trustedcoin.TrustedCoinPlugin.xkeys_from_seed(seed_words, '')

        ks1 = keystore.from_xprv(xprv1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9uraXy9F3HP7i8QDqwNTBiD8Jf4bPD4Epif8cS8qbUbgeidUesyZpKmzfcSeHutsGfFnjgih7kzwTB5UQVRNB5LoXaNc8pFusKYx3KVVvYR')
        self.assertEqual(ks1.xpub, 'xpub68qvwUg8sewQvcUgwxuTYr9rrgu5nfn6BwajQpYT9p8fXWxdCRHpN86UWruWJAD1ede8Sv8ERrTa22Gyc4SBfm7zFpcyoVWVBKCVwnw6s1J')
        self.assertEqual(ks1.xpub, xpub1)

        ks2 = keystore.from_xprv(xprv2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))
        self.assertEqual(ks2.xprv, 'xprv9uraXy9F3HP7kKSiRAvLV7Nrjj7YzspDys7dvGLLu4tLZT49CEBxPWp88dHhVxvZ69SHrPQMUCWjj4Ka2z9kNvs1HAeEf3extGGeSWqEVqf')
        self.assertEqual(ks2.xpub, 'xpub68qvwUg8sewQxoXBXCTLrFKbHkx3QLY5M63EiejxTQRKSFPHjmWCwK8byvZMM2wZNYA3SmxXoma3M1zxhGESHZwtB7SwrxRgKXAG8dCD2eS')
        self.assertEqual(ks2.xpub, xpub2)

        long_user_id, short_id = trustedcoin.get_user_id(
            {'x1': {'xpub': xpub1},
             'x2': {'xpub': xpub2}})
        xtype = bip32.xpub_type(xpub1)
        xpub3 = trustedcoin.make_xpub(trustedcoin.get_signing_xpub(xtype), long_user_id)
        ks3 = keystore.from_xpub(xpub3)
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks3)
        self.assertTrue(isinstance(ks3, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2, ks3], '2of3', config=self.config)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '35L8XmCDoEBKeaWRjvmZvoZvhp8BXMMMPV')
        self.assertEqual(w.get_change_addresses()[0], '3PeZEcumRqHSPNN43hd4yskGEBdzXgY8Cy')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_seed_2fa_segwit(self, mock_save_db):
        seed_words = 'universe topic remind silver february ranch shine worth innocent cattle enhance wise'
        self.assertEqual(calc_seed_type(seed_words), '2fa_segwit')

        xprv1, xpub1, xprv2, xpub2 = trustedcoin.TrustedCoinPlugin.xkeys_from_seed(seed_words, '')

        ks1 = keystore.from_xprv(xprv1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'ZprvAm1R3RZMrkSLYKZer8QECGoc8oA1RQuKfsztHkBTmi2yF8RhmN1JRb7Ag69mMrL88sP67WiaegaSSDnKndorWEpFr7a5B2QgrD7TkERSYX6')
        self.assertEqual(ks1.xpub, 'Zpub6yzmSw6Fh7zdkoe7x9wEZQkLgpzVpsdB36vV68b5L3Zx7vkrJuKYyPReXMSjBegmtUjFBxP2uZEdL87cYvtTtGaVuwtRRCTSFUsoAdKZMge')
        self.assertEqual(ks1.xpub, xpub1)

        ks2 = keystore.from_xprv(xprv2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))
        self.assertEqual(ks2.xprv, 'ZprvAm1R3RZMrkSLab4jVKTwuroBgKEfnsmK9CQa1ErkuRzpsPauYuv9z2UzhDNn9YgbLHcmXpmxbNq4MdDRAUM5B2N9Wr3Uq9yp2c4AtTJDFdi')
        self.assertEqual(ks2.xpub, 'Zpub6yzmSw6Fh7zdo59CbLzxGzjvEM5ACLVAWRLAodGNTmXokBv46TEQXpoUYUaoxPCeynysxg7APfScikCQ2jhCfM3NcNEk46BCVfSSrdrSkbR')
        self.assertEqual(ks2.xpub, xpub2)

        long_user_id, short_id = trustedcoin.get_user_id(
            {'x1': {'xpub': xpub1},
             'x2': {'xpub': xpub2}})
        xtype = bip32.xpub_type(xpub1)
        xpub3 = trustedcoin.make_xpub(trustedcoin.get_signing_xpub(xtype), long_user_id)
        ks3 = keystore.from_xpub(xpub3)
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks3)
        self.assertTrue(isinstance(ks3, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2, ks3], '2of3', config=self.config)
        self.assertEqual(w.txin_type, 'p2wsh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qpmufh0zjp5prfsrk2yskcy82sa26srqkd97j0457andc6m0gh5asw7kqd2')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qd4q50nft7kxm9yglfnpup9ed2ukj3tkxp793y0zya8dc9m39jcwq308dxz')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_seed_bip44_standard(self, mock_save_db):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        root_seed = keystore.bip39_to_seed(seed_words, passphrase='')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9zGLcNEb3cHUKizLVBz6RYeE9bEZAVPjH2pD1DEzCnPcsemWc3d3xTao8sfhfUmDLMq6e3RcEMEvJG1Et8dvfL8DV4h7mwm9J6AJsW9WXQD')
        self.assertEqual(ks.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], '16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo')
        self.assertEqual(w.get_change_addresses()[0], '1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_seed_bip44_standard_passphrase(self, mock_save_db):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        root_seed = keystore.bip39_to_seed(seed_words, passphrase=UNICODE_HORROR)
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9z8izheguGnLopSqkY7GcGFrP2Gu6rzBvvHo6uB9B8DWJhsows6WDZAsbBTaP3ncP2AVbTQphyEQkahrB9s1L7ihZtfz5WGQPMbXwsUtSik')
        self.assertEqual(ks.xpub, 'xpub6D85QDBajeLe2JXJrZeGyQCaw47PWKi3J9DPuHakjTkVBWCxVQQkmMVMSSfnw39tj9FntbozpRtb1AJ8ubjeVSBhyK4M5mzdvsXZzKPwodT')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], '1F88g2naBMhDB7pYFttPWGQgryba3hPevM')
        self.assertEqual(w.get_change_addresses()[0], '1H4QD1rg2zQJ4UjuAVJr5eW1fEM8WMqyxh')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_seed_bip49_p2sh_segwit(self, mock_save_db):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        root_seed = keystore.bip39_to_seed(seed_words, passphrase='')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'yprvAJEYHeNEPcyBoQYM7sGCxDiNCTX65u4ANgZuSGTrKN5YCC9MP84SBayrgaMyZV7zvkHrr3HVPTK853s2SPk4EttPazBZBmz6QfDkXeE8Zr7')
        self.assertEqual(ks.xpub, 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '35ohQTdNykjkF1Mn9nAVEFjupyAtsPAK1W')
        self.assertEqual(w.get_change_addresses()[0], '3KaBTcviBLEJajTEMstsA2GWjYoPzPK7Y7')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_seed_bip84_native_segwit(self, mock_save_db):
        # test case from bip84
        seed_words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        root_seed = keystore.bip39_to_seed(seed_words, passphrase='')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/84'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
        self.assertEqual(ks.xpub, 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
        self.assertEqual(w.get_change_addresses()[0], 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_multisig_seed_standard(self, mock_save_db):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(calc_seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, passphrase='', for_multisig=True)
        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9s21ZrQH143K3t9vo23J3hajRbzvkRLJ6Y1zFrUFAfU3t8oooMPfb7f87cn5KntgqZs5nipZkCiBFo5ZtaSD2eDo7j7CMuFV8Zu6GYLTpY6')
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHFBUrq4c')

        # electrum seed: ghost into match ivory badge robot record tackle radar elbow traffic loud
        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDbenT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2', config=self.config)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '32ji3QkAgXNz6oFoRfakyD3ys1XXiERQYN')
        self.assertEqual(w.get_change_addresses()[0], '36XWwEHrrVCLnhjK5MrVVGmUHghr9oWTN1')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_electrum_multisig_seed_segwit(self, mock_save_db):
        seed_words = 'snow nest raise royal more walk demise rotate smooth spirit canyon gun'
        self.assertEqual(calc_seed_type(seed_words), 'segwit')

        ks1 = keystore.from_seed(seed_words, passphrase='', for_multisig=True)
        WalletIntegrityHelper.check_seeded_keystore_sanity(self, ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'ZprvAjxLRqPiDfPDxXrm8JvcoCGRAW6xUtktucG6AMtdzaEbTEJN8qcECvujfhtDU3jLJ9g3Dr3Gz5m1ypfMs8iSUh62gWyHZ73bYLRWyeHf6y4')
        self.assertEqual(ks1.xpub, 'Zpub6xwgqLvc42wXB1wEELTdALD9iXwStMUkGqBgxkJFYumaL2dWgNvUkjEDWyDFZD3fZuDWDzd1KQJ4NwVHS7hs6H6QkpNYSShfNiUZsgMdtNg')

        # electrum seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        ks2 = keystore.from_xpub('Zpub6y4oYeETXAbzLNg45wcFDGwEG3vpgsyMJybiAfi2pJtNF3i3fJVxK2BeZJaw7VeKZm192QHvXP3uHDNpNmNDbQft9FiMzkKUhNXQafUMYUY')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2', config=self.config)
        self.assertEqual(w.txin_type, 'p2wsh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qvzezdcv6vs5h45ugkavp896e0nde5c5lg5h0fwe2xyfhnpkxq6gq7pnwlc')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qxqf840dqswcmu7a8v82fj6ej0msx08flvuy6kngr7axstjcaq6us9hrehd')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_multisig_seed_bip45_standard(self, mock_save_db):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        root_seed = keystore.bip39_to_seed(seed_words, passphrase='')
        ks1 = keystore.from_bip43_rootseed(root_seed, derivation="m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xprv, 'xprv9vyEFyXf7pYVv4eDU3hhuCEAHPHNGuxX73nwtYdpbLcqwJCPwFKknAK8pHWuHHBirCzAPDZ7UJHrYdhLfn1NkGp9rk3rVz2aEqrT93qKRD9')
        self.assertEqual(ks1.xpub, 'xpub69xafV4YxC6o8Yiga5EiGLAtqR7rgNgNUGiYgw3S9g9pp6XYUne1KxdcfYtxwmA3eBrzMFuYcNQKfqsXCygCo4GxQFHfywxpUbKNfYvGJka')

        # bip39 seed: tray machine cook badge night page project uncover ritual toward person enact
        # der: m/45'/0
        ks2 = keystore.from_xpub('xpub6B26nSWddbWv7J3qQn9FbwPPQktSBdPQfLfHhRK4375QoZq8fvM8rQey1koGSTxC5xVoMzNMaBETMUmCqmXzjc8HyAbN7LqrvE4ovGRwNGg')
        WalletIntegrityHelper.check_xpub_keystore_sanity(self, ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2', config=self.config)
        self.assertEqual(w.txin_type, 'p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '3JPTQ2nitVxXBJ1yhMeDwH6q417UifE3bN')
        self.assertEqual(w.get_change_addresses()[0], '3FGyDuxgUDn2pSZe5xAJH1yUwSdhzDMyEE')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_multisig_seed_p2sh_segwit(self, mock_save_db):
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

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2', config=self.config)
        self.assertEqual(w.txin_type, 'p2wsh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '35LeC45QgCVeRor1tJD6LiDgPbybBXisns')
        self.assertEqual(w.get_change_addresses()[0], '39RhtDchc6igmx5tyoimhojFL1ZbQBrXa6')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip32_extended_version_bytes(self, mock_save_db):
        seed_words = 'crouch dumb relax small truck age shine pink invite spatial object tenant'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))
        bip32_seed = keystore.bip39_to_seed(seed_words, passphrase='')
        self.assertEqual('0df68c16e522eea9c1d8e090cfb2139c3b3a2abed78cbcb3e20be2c29185d3b8df4e8ce4e52a1206a688aeb88bfee249585b41a7444673d1f16c0d45755fa8b9',
                         bip32_seed.hex())

        def create_keystore_from_bip32seed(xtype):
            ks = keystore.BIP32_KeyStore({})
            ks.add_xprv_from_seed(bip32_seed, xtype=xtype, derivation='m/')
            return ks

        ks = create_keystore_from_bip32seed(xtype='standard')
        self.assertEqual('033a05ec7ae9a9833b0696eb285a762f17379fa208b3dc28df1c501cf84fe415d0', ks.derive_pubkey(0, 0).hex())
        self.assertEqual('02bf27f41683d84183e4e930e66d64fc8af5508b4b5bf3c473c505e4dbddaeed80', ks.derive_pubkey(1, 0).hex())

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2pkh
        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(ks.xprv, 'xprv9s21ZrQH143K3nyWMZVjzGL4KKAE1zahmhTHuV5pdw4eK3o3igC5QywgQG7UTRe6TGBniPDpPFWzXMeMUFbBj8uYsfXGjyMmF54wdNt8QBm')
        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcGH3yTb2kMQGnsLziRTJZ8vNthsVSCGbdBr8CGDWKxnGAFYgyKTzBtwvPPmfVAWJuFmxRXjSbUTg87wDkWQ5GmzpfUcN9t8Z')
        self.assertEqual(w.get_receiving_addresses()[0], '19fWEVaXqgJFFn7JYNr6ouxyjZy3uK7CdK')
        self.assertEqual(w.get_change_addresses()[0], '1EEX7da31qndYyeKdbM665w1ze5gbkkAZZ')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh-p2sh')
        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(ks.xprv, 'yprvABrGsX5C9janu6AdBvHNCMRZVHJfxcaCgoyWgsyi1wSXN9cGyLMe33bpRU54TLJ1ruJbTrpNqusYQeFvBx1CXNb9k1DhKtBFWo8b1sLbXhN')
        self.assertEqual(ks.xpub, 'ypub6QqdH2c5z7967aF6HwpNZVNJ3K9AN5J442u7VGPKaGyWEwwRWsftaqvJGkeZKNe7Jb3C9FG3dAfT94ZzFRrcGhMizGvB6Jtm3itJsEFhxMC')
        self.assertEqual(w.get_receiving_addresses()[0], '34SAT5gGF5UaBhhSZ8qEuuxYvZ2cm7Zi23')
        self.assertEqual(w.get_change_addresses()[0], '38unULZaetSGSKvDx7Krukh8zm8NQnxGiA')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh')
        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(ks.xprv, 'zprvAWgYBBk7JR8GkPMk2H4zQSX4fFT7uEZhbvVjUGsbPwpQRFRWDzXCf7FxSg2eTEwwGYRQDLQwJaE6HvsUueRDKcGkcLv7unzjnXCEQVWhrF9')
        self.assertEqual(ks.xpub, 'zpub6jftahH18ngZxsSD8JbzmaToDHHcJhHYy9RLGfHCxHMPJ3kemXqTCuaSHxc9KHJ2iE9ztirc5q212MBYy8Gd4w3KrccbgDiFKSwxFpYKEH6')
        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qtuynwzd0d6wptvyqmc6ehkm70zcamxpshyzu5e')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qjy5zunxh6hjysele86qqywfa437z4xwmleq8wk')

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2sh
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1', config=self.config)
        self.assertEqual(ks.xprv, 'xprv9s21ZrQH143K3nyWMZVjzGL4KKAE1zahmhTHuV5pdw4eK3o3igC5QywgQG7UTRe6TGBniPDpPFWzXMeMUFbBj8uYsfXGjyMmF54wdNt8QBm')
        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcGH3yTb2kMQGnsLziRTJZ8vNthsVSCGbdBr8CGDWKxnGAFYgyKTzBtwvPPmfVAWJuFmxRXjSbUTg87wDkWQ5GmzpfUcN9t8Z')
        self.assertEqual(w.get_receiving_addresses()[0], '3F4nm8Vunb7mxVvqhUP238PYge2hpU5qYv')
        self.assertEqual(w.get_change_addresses()[0], '3N8jvKGmxzVHENn6B4zTdZt3N9bmRKjj96')

        ks = create_keystore_from_bip32seed(xtype='p2wsh-p2sh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1', config=self.config)
        self.assertEqual(ks.xprv, 'YprvANkMzkodih9AKfL18akM2RmND5LwAyFo15dBc9FFPiGvzLBBjjjv8ATkEB2Y1mWv6NNaLSpVj8G3XosgVBA9frhpaUL6jHeFQXQTbqVPcv2')
        self.assertEqual(ks.xpub, 'Ypub6bjiQGLXZ4hTY9QUEcHMPZi6m7BRaRyeNJYnQXerx3ous8WLHH4AfxnE5Tc2sos1Y47B1qGAWP3xGEBkYf1ZRBUPpk2aViMkwTABT6qoiBb')
        self.assertEqual(w.get_receiving_addresses()[0], '3L1BxLLASGKE3DR1ruraWm3hZshGCKqcJx')
        self.assertEqual(w.get_change_addresses()[0], '3NDGcbZVXTpaQWRhiuVPpXsNt4g2JiCX4E')

        ks = create_keystore_from_bip32seed(xtype='p2wsh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1', config=self.config)
        self.assertEqual(ks.xprv, 'ZprvAhadJRUYsNgeAxX7xwXyEWrsP3VP7bFHvC9QPY98miep3RzQzPuUkE7tFNz81gAqW1VP5vR4BncbR6VFCsaAU6PRSp2XKCTjgFU6zRpk6Xp')
        self.assertEqual(ks.xpub, 'Zpub6vZyhw1ShkEwPSbb4y4ybeobw5KsX3y9HR51BvYkL4BnvEKZXwDjJ2SN6fZcsiWvwhDymJriy3QW9WoKGMRaDR9zh5j15dBFDBDpqjK1ekQ')
        self.assertEqual(w.get_receiving_addresses()[0], 'bc1q84x0yrztvcjg88qef4d6978zccxulcmc9y88xcg4ghjdau999x7q7zv2qe')
        self.assertEqual(w.get_change_addresses()[0], 'bc1q0fj5mra96hhnum80kllklc52zqn6kppt3hyzr49yhr3ecr42z3tsrkg3gs')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_non_extendable_basic_3of6_bip44_standard(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        xprv9s21ZrQH143K2pMWi8jrTawHaj16uKk4CSbvo4Zt61tcrmuUDMx2o1Byzcr3saXNGNvHP8zZgXVdJHsXVdzYFPavxvCyaGyGr1WkAYG83ce
        """
        mnemonics = [
            "extra extend academic bishop cricket bundle tofu goat apart victim enlarge program behavior permit course armed jerky faint language modern",
            "extra extend academic acne away best indicate impact square oasis prospect painting voting guest either argue username racism enemy eclipse",
            "extra extend academic arcade born dive legal hush gross briefing talent drug much home firefly toxic analysis idea umbrella slice",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9yELEwkzJkSUHXz4hX6iv1SkhKeEhNtgoRDqm8whrymd3f3W2Abdpx6MjRmdEAERNeGauGx1u5djsExCT8qE6e4fGNeetfWtp45rSJu7kNW')
        self.assertEqual(ks.xpub, 'xpub6CDgeTHt97zmW24XoYdjH9PVFMUj6qcYAe9SZXMKRKJbvTNeZhutNkQqajLyZrQ9DCqdnGenKhBD6UTrT1nHnoLCfFHkdeX8hDsZx1je6b2')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], '1NomKAUNnbASwbPuGHmkSVmnrJS5tZeVce')
        self.assertEqual(w.get_change_addresses()[0], '1Aw4wpXsAyEHSgMZqPdyewoAtJqH9Jaso3')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_non_extendable_basic_2of5_bip49_p2sh_segwit(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        xprv9s21ZrQH143K2o6EXEHpVy8TCYoMmkBnDCCESLdR2ieKwmcNG48ck2XJQY4waS7RUQcXqR9N7HnQbUVEDMWYyREdF1idQqxFHuCfK7fqFni
        """
        mnemonics = [
            "hobo romp academic axis august founder knife legal recover alien expect emphasis loan kitchen involve teacher capture rebuild trial numb spider forward ladle lying voter typical security quantity hawk legs idle leaves gasoline",
            "hobo romp academic agency ancestor industry argue sister scene midst graduate profile numb paid headset airport daisy flame express scene usual welcome quick silent downtown oral critical step remove says rhythm venture aunt",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'yprvAK7DoEDitppjkdf6LrveZUBjB1SFQ54mTy8pqyb1wDyTjNkzNnFC1PEeGyBLfEAjxv3RmtusmBco7LF5DPxtV94mP7qa8t4dP4mmiDrnZF2')
        self.assertEqual(ks.xpub, 'ypub6Y6aCjkcjCP2y7jZStTevc8Tj3GjoXncqC4ReMzdVZWScB68vKZSZBZ88ENvuPUXXBBR58JXkuz1UrwLnCFvnFTUEpzu5yQabeYBRyd7Edf')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '3GCgNoWWVqVdhBxWxrnWQHgwLtffGSYn7D')
        self.assertEqual(w.get_change_addresses()[0], '3FVvdRhR7racZhmcvrGAqX9eJoP8Sw3ypp')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_non_extendable_groups_128bit_bip84_native_segwit(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV
        """

        # SLIP39 shares (128 bits, 2 groups from 1 of 1, 1 of 1, 3 of 5, 2 of 6)
        mnemonics = [
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
            "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
            "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
            "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/84'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAdskBk5s8FxC4hq9PVU1nSRRzotSzUy9vTwv5hscqr3ANM52mtJJT5cdfHTJnfd2cPFKWXpm4WhB9ruQCEC8KWkSeziMEZjbheNp4xUUTTG')
        self.assertEqual(ks.xpub, 'zpub6rs6bFckxdWVHBucVX129aNAYqiwPwh1HgsWt6HEQBa9F9QBKRcYzsw7WZR7rPSCWKmRVTUaEgrGrHStx2LSTpbgAEerbnrh4XxkRXbUUZF')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qaggygkqgqjjpt58zrmhvjz5m9dj8mjshw0lpgu')
        self.assertEqual(w.get_change_addresses()[0], 'bc1q8l6hcvlczu4mtjcnlwhczw7vdxnvwccpjl3cwz')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_non_extendable_groups_256bit_bip49_p2sh_segwit(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c
        """

        # SLIP39 shares (256 bits, 2 groups from 1 of 1, 1 of 1, 3 of 5, 2 of 6):
        mnemonics = [
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
            "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'yprvAHiJ72E8kJU1XQ2adZcUv8Buffr48bik1F3EHCSDDafScwLdfJ5oDgENm1cAAxNPeXMCBxmm7rmyoKua5LfjnrmgxqP5sYtAVDYngxF2zsB')
        self.assertEqual(ks.xpub, 'ypub6WheWXm2ag2Jjt73jb9VHG8eDhgYY4SbNTxq5aqpmvCRVjfnCqQ3mUYrcGiBR5qvbhJap5hjSiN2eoXBFLGuipWLRAgf11bRThSJLoGrBag')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '3FoqkcrEHgkKQ3iXStantygCetRGSRMMNE')
        self.assertEqual(w.get_change_addresses()[0], '32tvTmBLfLofu8ps4SWpUJC4fS699jiWvC')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_extendable_basic_3of6_bip44_standard(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        xprv9yba7duYBT5g7SbaN1oCX43xeDtjKXNUZ2uSmJ3efHsWYaLkqzdjg2bjLYYzQ9rmXdNzDHYWXv5m9aBCqbFbZzAoGcAceH1K8cPYVDpsJLH
        """
        mnemonics = [
            "judicial dramatic academic agree craft physics memory born prize academic black listen elder station premium dance sympathy flip always kitchen",
            "judicial dramatic academic arcade clogs timber taught recover burning judicial desktop square ecology budget nervous overall tidy knife fused knit",
            "judicial dramatic academic axle destroy justice username elegant filter seafood device ranked behavior pecan infant lunar answer identify hour enjoy",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        self.assertEqual("255415e2b20ad13cef7adca1e336eaec", root_seed.hex())
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'xprv9yba7duYBT5g7SbaN1oCX43xeDtjKXNUZ2uSmJ3efHsWYaLkqzdjg2bjLYYzQ9rmXdNzDHYWXv5m9aBCqbFbZzAoGcAceH1K8cPYVDpsJLH')
        self.assertEqual(ks.xpub, 'xpub6CavX9SS1pdyKvg3U3LCtBzhCFjDiz6KvFq3ZgTGDdQVRNfuPXwzDpvDBqbg1kEsDgEeHo6uWeYsZWALRejoJMVCq4rprrHkbw8Jyu3uaMb')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2pkh')

        self.assertEqual(w.get_receiving_addresses()[0], '1N4hqJRTVqUbwT5WCbbsQSwKRPPPzG1TSo')
        self.assertEqual(w.get_change_addresses()[0], '1FW3QQzbYRSUoNDDYGWPvSCoom8fBhPC9k')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_extendable_basic_2of5_bip49_p2sh_segwit(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        yprvAJP391MZiYGpkDnSkAfHBGrEKNxpkFVbx9hap59M2hxD1i7kmnaBUC2yo8tzz5AwxSv3ekJRrSGYWA8ec7XmQGLvX4xkWwCRqiadT5fuTfh
        """
        mnemonics = [
            "station type academic acid away gather venture pupal speak treat ruler pecan soldier cowboy paces wavy review similar born moment",
            "station type academic aquatic bundle mineral twice temple miracle ruin earth olympic system dining inform alive branch false easy manual",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'yprvAJP391MZiYGpkDnSkAfHBGrEKNxpkFVbx9hap59M2hxD1i7kmnaBUC2yo8tzz5AwxSv3ekJRrSGYWA8ec7XmQGLvX4xkWwCRqiadT5fuTfh')
        self.assertEqual(ks.xpub, 'ypub6XNPYWtTYuq7xhrurCCHYQnxsQoK9iDTKNdBcTYxb3VBtWSuKKtS1zMTeQTDeVe1Y8mzGue1oDYyvjczspnPznLmyruzxVTU785W2QpbTW9')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '38diDMcH7japAtpJjVKviBroQfTdvgpdqX')
        self.assertEqual(w.get_change_addresses()[0], '36Hd2PnEvJpN9pUdhpZWh3aQccbRp46FVc')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_extendable_groups_128bit_bip84_native_segwit(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        zprvAe6okUFoH5tieuTJJxN84xjPCvWkhFiiP87myHqTNmfux4wY8XnLG7DxezL5Dt2jXu5FrsMc4wEPhAJovAGhH1cAPjmkhh3KcSCMRyuQghd
        """

        # SLIP39 shares (128 bits, 2 groups from 1 of 1, 1 of 1, 3 of 5, 2 of 6)
        mnemonics = [
            "fact else acrobat romp analysis usher havoc vitamins analysis garden prevent romantic silent dramatic adjust priority mailman plains vintage else",
            "fact else ceramic round craft lips snake faint adorn square bucket deadline violence guitar greatest academic stadium snake frequent memory",
            "fact else ceramic scatter counter remove club forbid busy cause taxi forecast prayer uncover living type training forward software pumps",
            "fact else ceramic shaft clock crowd detect cleanup wildlife depict include trip profile isolate express category wealthy advance garden mixture",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/84'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'zprvAe6okUFoH5tieuTJJxN84xjPCvWkhFiiP87myHqTNmfux4wY8XnLG7DxezL5Dt2jXu5FrsMc4wEPhAJovAGhH1cAPjmkhh3KcSCMRyuQghd')
        self.assertEqual(ks.xpub, 'zpub6s6A9ynh7TT1sPXmQyu8S6g7kxMF6iSZkM3NmgF4w7CtpsGgg56aouYSWHgAoMy186a8FRT8zkmhcwV5SWKFFQfMpvV8C9Ft4woWSzD5sXz')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh')

        self.assertEqual(w.get_receiving_addresses()[0], 'bc1qs2svwhfz47qv9qju2waa6prxzv5f522fc4p06t')
        self.assertEqual(w.get_change_addresses()[0], 'bc1qmjq5nenac3vjwltldk5qsq4yd8mttw2dpkmx06')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_slip39_extendable_groups_256bit_bip49_p2sh_segwit(self, mock_save_db):
        """
        BIP32 Root Key for passphrase "TREZOR":
        yprvAJbhup8ey3hmPhgVsXKySTS54BfywUZR6SvQ2jrjdsUgNd4P8B5HR7ute93zXVTXKUvrmvnav1spLzEkDuT7Cy3bf3hWtYoH6A5p8vNzbEC
        """

        # SLIP39 shares (256 bits, 2 groups from 1 of 1, 1 of 1, 3 of 5, 2 of 6):
        mnemonics = [
            "smart surprise acrobat romp deal omit pupal capacity invasion should glen smear segment frost surprise ancestor plan frost cultural herd",
            "smart surprise beard romp closet antenna pencil rapids goat artwork race industry segment parcel briefing glad voice camera priority satoshi",
        ]

        encrypted_seed = slip39.recover_ems(mnemonics)
        root_seed = encrypted_seed.decrypt('TREZOR')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/49'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xprv, 'yprvAJbhup8ey3hmPhgVsXKySTS54BfywUZR6SvQ2jrjdsUgNd4P8B5HR7ute93zXVTXKUvrmvnav1spLzEkDuT7Cy3bf3hWtYoH6A5p8vNzbEC')
        self.assertEqual(ks.xpub, 'ypub6Xb4KKfYoRG4cBkxyYryobNocDWULwHGTfqzq8GMCD1fFRPXfiPXxvENVQYVbi64BJzdPnPUiJ4iY37X5BA594dqxyE4FwccHdhydU9RhPJ')

        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(w.txin_type, 'p2wpkh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '3JDN4wF5BphZqcJFFYuDA7N1apzfPYyJLG')
        self.assertEqual(w.get_change_addresses()[0], '3J8zNvhJndqzBcuPuarzUn1kWs9N4ZY7HS')

class TestWalletKeystoreAddressIntegrityForTestnet(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip39_multisig_seed_p2sh_segwit_testnet(self, mock_save_db):
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

        w = WalletIntegrityHelper.create_multisig_wallet([ks1, ks2], '2of2', config=self.config)
        self.assertEqual(w.txin_type, 'p2wsh-p2sh')

        self.assertEqual(w.get_receiving_addresses()[0], '2MzsfTfTGomPRne6TkctMmoDj6LwmVkDrMt')
        self.assertEqual(w.get_change_addresses()[0], '2NFp9w8tbYYP9Ze2xQpeYBJQjx3gbXymHX7')

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bip32_extended_version_bytes(self, mock_save_db):
        seed_words = 'crouch dumb relax small truck age shine pink invite spatial object tenant'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))
        bip32_seed = keystore.bip39_to_seed(seed_words, passphrase='')
        self.assertEqual('0df68c16e522eea9c1d8e090cfb2139c3b3a2abed78cbcb3e20be2c29185d3b8df4e8ce4e52a1206a688aeb88bfee249585b41a7444673d1f16c0d45755fa8b9',
                         bip32_seed.hex())

        def create_keystore_from_bip32seed(xtype):
            ks = keystore.BIP32_KeyStore({})
            ks.add_xprv_from_seed(bip32_seed, xtype=xtype, derivation='m/')
            return ks

        ks = create_keystore_from_bip32seed(xtype='standard')
        self.assertEqual('033a05ec7ae9a9833b0696eb285a762f17379fa208b3dc28df1c501cf84fe415d0', ks.derive_pubkey(0, 0).hex())
        self.assertEqual('02bf27f41683d84183e4e930e66d64fc8af5508b4b5bf3c473c505e4dbddaeed80', ks.derive_pubkey(1, 0).hex())

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2pkh
        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(ks.xprv, 'tprv8ZgxMBicQKsPecD328MF9ux3dSaSFWci7FNQmuWH7uZ86eY8i3XpvjK8KSH8To2QphiZiUqaYc6nzDC6bTw8YCB9QJjaQL5pAApN4z7vh2B')
        self.assertEqual(ks.xpub, 'tpubD6NzVbkrYhZ4Y5Epun1qZKcACU6NQqocgYyC4RYaYBMWw8nuLSMR7DvzVamkqxwRgrTJ1MBMhc8wwxT2vbHqMu8RBXy4BvjWMxR5EdZroxE')
        self.assertEqual(w.get_receiving_addresses()[0], 'mpBTXYfWehjW2tavFwpUdqBJbZZkup13k2')
        self.assertEqual(w.get_change_addresses()[0], 'mtkUQgf1psDtL67wMAKTv19LrdgPWy6GDQ')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh-p2sh')
        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(ks.xprv, 'uprv8tXDerPXZ1QsVuQ9rV8sN13YoQitC8cD2MtdZJQAVuw19kMMxhhPYnyGLeEiThgLELqNTxS91GTLsVofKAM9LRrkGeRzzEuJRtt1Tcostr7')
        self.assertEqual(ks.xpub, 'upub57Wa4MvRPNyAiPUcxWfsj8zHMSZNbbL4PapEMgon4FTz2YgWWF1e6bHkBvpDKk2Rg2Zy9LsonXFFbv7jNeCZ5kdKWv8UkfcoxpdjJrZuBX6')
        self.assertEqual(w.get_receiving_addresses()[0], '2MuzNWpcHrXyvPVKzEGT7Xrwp8uEnXXjWnK')
        self.assertEqual(w.get_change_addresses()[0], '2MzTzY5VcGLwce7YmdEwjXhgQD7LYEKLJTm')

        ks = create_keystore_from_bip32seed(xtype='p2wpkh')
        w = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        self.assertEqual(ks.xprv, 'vprv9DMUxX4ShgxMMCbGgqvVa693yNsL8kbhwUQrLhJ3svJtCrAbDMrxArdQMrCJTcLFdyxBDS2hTvotknRE2rmA8fYM8z8Ra9inhcwerEsG6Ev')
        self.assertEqual(ks.xpub, 'vpub5SLqN2bLY4WeZgfjnsTVwE5nXQhpYDKZJhLT95hfSFqs5eVjkuBCiewtD8moKegM5fgmtpUNFBboVCjJ6LcZszJvPFpuLaSJEYhNhUAnrCS')
        self.assertEqual(w.get_receiving_addresses()[0], 'tb1qtuynwzd0d6wptvyqmc6ehkm70zcamxpsaze002')
        self.assertEqual(w.get_change_addresses()[0], 'tb1qjy5zunxh6hjysele86qqywfa437z4xwm4lm549')

        ks = create_keystore_from_bip32seed(xtype='standard')  # p2sh
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1', config=self.config)
        self.assertEqual(ks.xprv, 'tprv8ZgxMBicQKsPecD328MF9ux3dSaSFWci7FNQmuWH7uZ86eY8i3XpvjK8KSH8To2QphiZiUqaYc6nzDC6bTw8YCB9QJjaQL5pAApN4z7vh2B')
        self.assertEqual(ks.xpub, 'tpubD6NzVbkrYhZ4Y5Epun1qZKcACU6NQqocgYyC4RYaYBMWw8nuLSMR7DvzVamkqxwRgrTJ1MBMhc8wwxT2vbHqMu8RBXy4BvjWMxR5EdZroxE')
        self.assertEqual(w.get_receiving_addresses()[0], '2N6czpsRwQ3d8AHZPNbztf5NotzEsaZmVQ8')
        self.assertEqual(w.get_change_addresses()[0], '2NDgwz4CoaSzdSAQdrCcLFWsJaVowCNgiPA')

        ks = create_keystore_from_bip32seed(xtype='p2wsh-p2sh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1', config=self.config)
        self.assertEqual(ks.xprv, 'Uprv95RJn67y7xyEvUZXo9brC5PMXCm9QVHoLdYJUZfhsgmQmvvGj75fduqC9MCC28uETouMLYSFtUqqzfRRcPW6UuyR77YQPeNJKd9t3XutF8b')
        self.assertEqual(ks.xpub, 'Upub5JQfBberxLXY8xdzuB8rZDL65Ebdox1ehrTuGx5KS2JPejFRGePvBi9fzdmgtBFKuVdx1vsvfjdkj5jVfsMWEEjzMPEtA55orYubtrCZmRr')
        self.assertEqual(w.get_receiving_addresses()[0], '2NBZQ25GC3ipaF13ZY3UT8i2xnDuS17pJqx')
        self.assertEqual(w.get_change_addresses()[0], '2NDmUgLVX8vKvcJ4FQ37GSUre6QtBzKkb6k')

        ks = create_keystore_from_bip32seed(xtype='p2wsh')
        w = WalletIntegrityHelper.create_multisig_wallet([ks], '1of1', config=self.config)
        self.assertEqual(ks.xprv, 'Vprv16YtLrHXxePM6noKqtFtMtmUgBE9bEpF3fPLmpvuPksssLostujtdHBwqhEeVuzESz22UY8hyPx9ed684SQpCmUKSVhpxPFbvVNY7qnviNR')
        self.assertEqual(ks.xpub, 'Vpub5dEvVGKn7251zFq7jXvUmJRbFCk5ka19cxz84LyCp2gGhq4eXJZUomop1qjGt5uFK8kkmQUV8PzJcNM4PZmX2URbDiwJjyuJ8GyFHRrEmmG')
        self.assertEqual(w.get_receiving_addresses()[0], 'tb1q84x0yrztvcjg88qef4d6978zccxulcmc9y88xcg4ghjdau999x7qf2696k')
        self.assertEqual(w.get_change_addresses()[0], 'tb1q0fj5mra96hhnum80kllklc52zqn6kppt3hyzr49yhr3ecr42z3ts5777jl')


class TestWalletSending(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def create_standard_wallet_from_seed(self, seed_words, *, config=None, gap_limit=2):
        if config is None:
            config = self.config
        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)
        return WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=gap_limit, config=config)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_between_p2wpkh_and_compressed_p2pkh(self, mock_save_db):
        wallet1 = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver')
        wallet2 = self.create_standard_wallet_from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song')

        # bootstrap wallet1
        funding_tx = Transaction('01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000')
        funding_txid = funding_tx.txid()
        funding_output_value = 1000000
        self.assertEqual('add2535aedcbb5ba79cc2260868bb9e57f328738ca192937f2c92e0e94c19203', funding_txid)
        wallet1.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [PartialTxOutput.from_address_and_value(wallet2.get_receiving_address(), 250000)]
        tx = wallet1.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet1.is_mine(wallet1.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('010000000001010392c1940e2ec9f2372919ca3887327fe5b98b866022cc79bab5cbed5a53d2ad0000000000feffffff0290d00300000000001976a914ea7804a2c266063572cc009a63dc25dcc0e9d9b588ac285e0b0000000000160014690b59a8140602fb23cc2904ece9cc4daf361052024730440220608a5339ca894592da82119e1e4a1d09335d70a552c683687223b8ed724465e902201b3f0feccf391b1b6257e4b18970ae57d7ca060af2dae519b3690baad2b2a34e0121030faee9b4a25b7db82023ca989192712cdd4cb53d3d9338591c7909e581ae1c0c00000000',
                         str(tx_copy))
        self.assertEqual('3c06ae4d9be8226a472b3e7f7c127c7e3016f525d658d26106b80b4c7e3228e2', tx_copy.txid())
        self.assertEqual('d8d930ae91dce73118c3fffabbdfcfb87f5d91673fb4c7dfd0fbe7cf03bf426b', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)  # TX_HEIGHT_UNCONF_PARENT but nvm
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [PartialTxOutput.from_address_and_value(wallet1.get_receiving_address(), 100000)]
        tx = wallet2.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet2.is_mine(wallet2.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('0100000001e228327e4c0bb80661d258d625f516307e7c127c7f3e2b476a22e89b4dae063c000000006a47304402200c7b06ff882db5ffe9d6e2a3cc2cabf5cd1b4224f1453d1e3dadd13b3d391e2c02201d23fde8482b05837f27d43021d17a1be2ee619dfc889ee80d4c2761e7c7ffb20121030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cffeffffff02a086010000000000160014284520c815980d426264766d8d930013dd20aa6068360200000000001976a914ca4c60999c46c2108326590b125aefd476dcb11888ac00000000',
                         str(tx_copy))
        self.assertEqual('4ff22c31dd884dedbb905fae275508d1f7bb4948c1c979d2567132848fdff24a', tx_copy.txid())
        self.assertEqual('4ff22c31dd884dedbb905fae275508d1f7bb4948c1c979d2567132848fdff24a', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 250000 - 5000 + 100000, 0), wallet1.get_balance())
        self.assertEqual((0, 250000 - 5000 - 100000, 0), wallet2.get_balance())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_between_p2sh_2of3_and_uncompressed_p2pkh(self, mock_save_db):
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure', passphrase='', for_multisig=True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4XJzYkhsCbDCcZRmDAKSD7bXi9mdCni7acVt45fxbTVZyU6jRGh29ULKTjoapkfFsSJvQHitcVKbQgzgkkYsAmaovcro7Mhf')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        wallet1b = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song', passphrase='', for_multisig=True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YARFMEZPckrqJkw59GZD1PXtQnw14ukvWDofR7Z1HMeSCxfYEZVvg4VdZ8zGok5VxHwdrLqew5cMdQntWc5mT7mh1CSgrnX')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        # ^ third seed: ghost into match ivory badge robot record tackle radar elbow traffic loud
        wallet2 = self.create_standard_wallet_from_seed('powerful random nobody notice nothing important anyway look away hidden message over')

        # bootstrap wallet1
        funding_tx = Transaction('010000000001014121f99dc02f0364d2dab3d08905ff4c36fc76c55437fd90b769c35cc18618280100000000fdffffff02d4c22d00000000001600143fd1bc5d32245850c8cb5be5b09c73ccbb9a0f75001bb7000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887024830450221008781c78df0c9d4b5ea057333195d5d76bc29494d773f14fa80e27d2f288b2c360220762531614799b6f0fb8d539b18cb5232ab4253dd4385435157b28a44ff63810d0121033de77d21926e09efd04047ae2d39dbd3fb9db446e8b7ed53e0f70f9c9478f735dac11300')
        funding_txid = funding_tx.txid()
        funding_output_value = 12000000
        self.assertEqual('b25cd55687c9e528c2cfd546054f35fb6741f7cf32d600f07dfecdf2e1d42071', funding_txid)
        wallet1a.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [PartialTxOutput.from_address_and_value(wallet2.get_receiving_address(), 370000)]
        tx = wallet1a.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007501000000017120d4e1f2cdfe7df000d632cff74167fb354f0546d5cfc228e5c98756d55cb20100000000feffffff0250a50500000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac2862b1000000000017a9142e517854aa54668128c0e9a3fdd4dec13ad571368700000000000100e0010000000001014121f99dc02f0364d2dab3d08905ff4c36fc76c55437fd90b769c35cc18618280100000000fdffffff02d4c22d00000000001600143fd1bc5d32245850c8cb5be5b09c73ccbb9a0f75001bb7000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887024830450221008781c78df0c9d4b5ea057333195d5d76bc29494d773f14fa80e27d2f288b2c360220762531614799b6f0fb8d539b18cb5232ab4253dd4385435157b28a44ff63810d0121033de77d21926e09efd04047ae2d39dbd3fb9db446e8b7ed53e0f70f9c9478f735dac11300220202afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f284730440220751ee3599e59debb8b2aeef61bb5f574f26379cd961caf382d711a507bc632390220598d53e62557c4a5ab8cfb2f8948f37cca06a861714b55c781baf2c3d7a580b501010469522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53ae220602afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f280c0036e9ac00000000000000002206030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf0c48adc7a00000000000000000220603e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce0cdb692427000000000000000000000100695221022ec6f62b0f3b7c2446f44346bff0a6f06b5fdbc27368be8a36478e0287fe47be21024238f21f90527dc87e945f389f3d1711943b06f0a738d5baab573fc0ab6c98582102b7139e93747d7c77f62af5a38b8a2b009f3456aa94dea9bf21f73a6298c867a253ae2202022ec6f62b0f3b7c2446f44346bff0a6f06b5fdbc27368be8a36478e0287fe47be0cdb69242701000000000000002202024238f21f90527dc87e945f389f3d1711943b06f0a738d5baab573fc0ab6c98580c0036e9ac0100000000000000220202b7139e93747d7c77f62af5a38b8a2b009f3456aa94dea9bf21f73a6298c867a20c48adc7a0010000000000000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())
        wallet1b.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet1a.is_mine(wallet1a.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000017120d4e1f2cdfe7df000d632cff74167fb354f0546d5cfc228e5c98756d55cb201000000fc004730440220751ee3599e59debb8b2aeef61bb5f574f26379cd961caf382d711a507bc632390220598d53e62557c4a5ab8cfb2f8948f37cca06a861714b55c781baf2c3d7a580b501473044022023b55c679397bdf3a04d545adc6193eabc11b3a28850d3d46049a51a30c6732402205dbfdade5620e9072ae4aa7577c5f0fd294f59a6b0064cc7105093c0fe7a6d24014c69522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53aefeffffff0250a50500000000001976a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac2862b1000000000017a9142e517854aa54668128c0e9a3fdd4dec13ad571368700000000',
                         str(tx_copy))
        self.assertEqual('b508ee1908181e55d2a18a5b2a3904dffbc7cb6b6320bbfba4433578d0f7831e', tx_copy.txid())
        self.assertEqual('b508ee1908181e55d2a18a5b2a3904dffbc7cb6b6320bbfba4433578d0f7831e', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [PartialTxOutput.from_address_and_value(wallet1a.get_receiving_address(), 100000)]
        tx = wallet2.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False, sign=False)
        self.assertEqual(
            "pkh(045f7ba332df2a7b4f5d13f246e307c9174cfa9b8b05f3b83410a3c23ef8958d610be285963d67c7bc1feb082f168fa9877c25999963ff8b56b242a852b23e25ed)",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        wallet2.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet2.is_mine(wallet2.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000011e83f7d0783543a4fbbb20636bcbc7fbdf04392a5b8aa1d2551e180819ee08b5000000008a473044022007569f938b5d7a7f529ceccc413363d84325c11d589c1897660bebfd5fd1cc4302203ef71fa42f9b31bb1e816af13b0bf725c493a0405433390c783cd9374713c5880141045f7ba332df2a7b4f5d13f246e307c9174cfa9b8b05f3b83410a3c23ef8958d610be285963d67c7bc1feb082f168fa9877c25999963ff8b56b242a852b23e25edfeffffff02a08601000000000017a914efe136b8275f49bc0f9871eebb9a48d0516229fd87280b0400000000001976a914ca14915184a2662b5d1505ce7142c8ca066c70e288ac00000000',
                         str(tx_copy))
        self.assertEqual('30f6eec4db5e6b1dfe572dfbc7077661df9a15a2a1b7701612b906d3e1bee3d8', tx_copy.txid())
        self.assertEqual('30f6eec4db5e6b1dfe572dfbc7077661df9a15a2a1b7701612b906d3e1bee3d8', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 370000 - 5000 + 100000, 0), wallet1a.get_balance())
        self.assertEqual((0, 370000 - 5000 - 100000, 0), wallet2.get_balance())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_between_p2wsh_2of3_and_p2wsh_p2sh_2of2(self, mock_save_db):
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        wallet1b = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('snow nest raise royal more walk demise rotate smooth spirit canyon gun', passphrase='', for_multisig=True),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra'),
                keystore.from_xpub('Vpub5gSKXzxK7FeKQedu2q1z9oJWxqvX72AArW3HSWpEhc8othDH8xMDu28gr7gf17sp492BuJod8Tn7anjvJrKpETwqnQqX7CS8fcYyUtedEMk')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        # ^ third seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        wallet2a = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: finish seminar arrange erosion sunny coil insane together pretty lunch lunch rose, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9CvELvByqm8k2dpecJVjgLMX1z5DufEjY4fBC5YvdGF5WjGCa7GVJJ2fYni1tyuF7Hw83E6W2ZBjAhaFLZv2ri3rEsubkCd5avg4EHKoDBN'),
                keystore.from_xpub('Upub5Qb8ik4Cnu8g97KLXKgVXHqY6tH8emQvqtBncjSKsyfTZuorPtTZgX7ovKKZHuuVGBVd1MTTBkWez1XXt2weN1sWBz6SfgRPQYEkNgz81QF')
            ],
            '2of2', gap_limit=2,
            config=self.config
        )
        wallet2b = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: square page wood spy oil story rebel give milk screen slide shuffle, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9BbnKEXJxXaNvdEsRJ9VA9toYrSeFJh5UfGBpM2iKe8Uh7UhrM9K8ioL53s8gvCoGfirHHaqpABDAE7VUNw8LNU1DMJKVoWyeNKu9XcDC19'),
                keystore.from_xpub('Upub5RuakRisg8h3F7u7iL2k3UJFa1uiK7xauHamzTxYBbn4PXbM7eajr6M9Q2VCr6cVGhfhqWQqxnABvtSATuVM1xzxk4nA189jJwzaMn1QX7V')
            ],
            '2of2', gap_limit=2,
            config=self.config
        )

        # bootstrap wallet1
        funding_tx = Transaction('01000000000101a41aae475d026c9255200082c7fad26dc47771275b0afba238dccda98a597bd20000000000fdffffff02400d0300000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c9dcd410000000000160014824626055515f3ed1d2cfc9152d2e70685c71e8f02483045022100b9f39fad57d07ce1e18251424034f21f10f20e59931041b5167ae343ce973cf602200fefb727fa0ffd25b353f1bcdae2395898fe407b692c62f5885afbf52fa06f5701210301a28f68511ace43114b674371257bb599fd2c686c4b19544870b1799c954b40e9c11300')
        funding_txid = funding_tx.txid()
        funding_output_value = 200000
        self.assertEqual('d2bd6c9d332db8e2c50aa521cd50f963fba214645aab2f7556e061a412103e21', funding_txid)
        wallet1a.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [PartialTxOutput.from_address_and_value(wallet2a.get_receiving_address(), 165000)]
        tx = wallet1a.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False, sign=False)
        self.assertEqual((0, 2), tx.signature_count())
        self.assertEqual(
            "wsh(sortedmulti(2,[b2e35a7d/1h]tpubD9aPYLPPYw8MxU3cD57LwpV5v7GomHxdv62MSbPcRkp47zwXx69ACUFsKrj8xzuzRrij9FWVhfvkvNqtqsr8ZtefkDsGZ9GLuHzoS6bXyk1/0/0,[53b77ddb/1h]tpubD8spLJysN7v7V1KHvkZ7AwjnXShKafopi7Vu3Ahs2S46FxBPTode8DgGxDo55k4pJvETGScZFwnM5f2Y31EUjteJdhxR73sjr9ieydgah2U/0/0,[43067d63/1h]tpubD8khd1g1tzFeKeaU59QV811hyvhwn9KDfy5sqFJ5m2wJLw6rUt4AZviqutRPXTUAK4SpU2we3y2WBP916Ma8Em4qFGcbYkFvXVfpGYV3oZR/0/0))",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        wallet1a.sign_transaction(tx, password=None)
        self.assertEqual((1, 2), tx.signature_count())
        txid = tx.txid()
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007e0100000001213e1012a461e056752fab5a6414a2fb63f950cd21a50ac5e2b82d339d6cbdd20000000000feffffff023075000000000000220020cc5e4cc05a76d0648cd0742768556317e9f8cc729aed077134287909035dba88888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf874387000000000001012b400d0300000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c0100eb01000000000101a41aae475d026c9255200082c7fad26dc47771275b0afba238dccda98a597bd20000000000fdffffff02400d0300000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c9dcd410000000000160014824626055515f3ed1d2cfc9152d2e70685c71e8f02483045022100b9f39fad57d07ce1e18251424034f21f10f20e59931041b5167ae343ce973cf602200fefb727fa0ffd25b353f1bcdae2395898fe407b692c62f5885afbf52fa06f5701210301a28f68511ace43114b674371257bb599fd2c686c4b19544870b1799c954b40e9c1130022020223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa473044022055cb04fa71c4b5955724d7ac5da90436d75212e7847fc121cb588f54bcdffdc4022064eca1ad639b7c748101059dc69f2893abb3b396bcf9c13f670415076f93ddbf0101056952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae22060223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa10b2e35a7d01000080000000000000000022060273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e1053b77ddb010000800000000000000000220602aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae9411043067d6301000080000000000000000000010169522102174696a58a8dcd6c6455bd25e0749e9a6fc7d84ee09e192ab37b0d0b18c2de1a2102c807a19ca6783261f8c198ffcc437622e7ecba8d6c5692f3a5e7f1e45af53fd52102eee40c7e24d89639182db32f5e9188613e4bc212da2ee9b4ccc85d9b82e1a98053ae220202174696a58a8dcd6c6455bd25e0749e9a6fc7d84ee09e192ab37b0d0b18c2de1a1053b77ddb010000800100000000000000220202c807a19ca6783261f8c198ffcc437622e7ecba8d6c5692f3a5e7f1e45af53fd51043067d63010000800100000000000000220202eee40c7e24d89639182db32f5e9188613e4bc212da2ee9b4ccc85d9b82e1a98010b2e35a7d0100008001000000000000000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertEqual(txid, tx.txid())
        self.assertFalse(tx.is_complete())
        wallet1b.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertEqual((2, 2), tx.signature_count())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet1a.is_mine(wallet1a.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000000101213e1012a461e056752fab5a6414a2fb63f950cd21a50ac5e2b82d339d6cbdd20000000000feffffff023075000000000000220020cc5e4cc05a76d0648cd0742768556317e9f8cc729aed077134287909035dba88888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf8743870400473044022055cb04fa71c4b5955724d7ac5da90436d75212e7847fc121cb588f54bcdffdc4022064eca1ad639b7c748101059dc69f2893abb3b396bcf9c13f670415076f93ddbf01473044022009230e456724f2a4c10d886c836eeec599b21db0bf078aa8fc8c95868b8920ec02200dfda835a66acb5af50f0d95fcc4b76c6e8f4789a7184c182275b087d1efe556016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae00000000',
                         str(tx_copy))
        self.assertEqual('6e9c3cd8788bdb970a124ea06136d52bc01cec4f9b1e217627d5e90ebe77d049', tx_copy.txid())
        self.assertEqual('dfd568f4fe0d41f8679b665d2d65e514315bcd5ac3ff63ef1b1596e5313740a3', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual(txid, tx_copy.txid())

        wallet1a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [PartialTxOutput.from_address_and_value(wallet1a.get_receiving_address(), 100000)]
        tx = wallet2a.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)
        self.assertEqual((1, 2), tx.signature_count())
        self.assertEqual(
            "sh(wsh(sortedmulti(2,[d1dbcc21]tpubDDsv4RpsGViZeEVwivuj3aaKhFQSv1kYsz64mwRoHkqBfw8qBSYEmc8TtyVGotJb44V3pviGzefP9m9hidRg9dPPaDWL2yoRpMW3hdje3Rk/0/0,[17cea914]tpubDCZU2kACPGACYDvAXvZUXQ7cE7msFfCtpah5QCuaz8iarKMLTgR4c2u8RGKdFhbb3YJxzmktDd1rCtF58ksyVgFw28pchY55uwkDiXjY9hU/0/0)))",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        txid = tx.txid()
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007e010000000149d077be0ee9d52776211e9b4fec1cc02bd53661a04e120a97db8b78d83c9c6e0100000000feffffff0260ea00000000000017a9143025051b6b5ccd4baf30dfe2de8aa84f0dd567ed87a086010000000000220020f7b6b30c3073ae2680a7e90c589bbfec5303331be68bbab843eed5d51ba012390000000000010120888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf8743870100fd7c0101000000000101213e1012a461e056752fab5a6414a2fb63f950cd21a50ac5e2b82d339d6cbdd20000000000feffffff023075000000000000220020cc5e4cc05a76d0648cd0742768556317e9f8cc729aed077134287909035dba88888402000000000017a914187842cea9c15989a51ce7ca889a08b824bf8743870400473044022055cb04fa71c4b5955724d7ac5da90436d75212e7847fc121cb588f54bcdffdc4022064eca1ad639b7c748101059dc69f2893abb3b396bcf9c13f670415076f93ddbf01473044022009230e456724f2a4c10d886c836eeec599b21db0bf078aa8fc8c95868b8920ec02200dfda835a66acb5af50f0d95fcc4b76c6e8f4789a7184c182275b087d1efe556016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae00000000220202119f899075a131d4d519d4cdcf5de5907dc2df3b93d54b53ded852211d2b6cb14730440220091ea67af7c1131f51f62fe9596dff0a60c8b45bfc5be675389e193912e8a71802201bf813bbf83933a35ecc46e2d5b0442bd8758fa82e0f8ed16392c10d51f7f7660101042200204311edae835c7a5aa712c8ca644180f13a3b2f3b420fa879b181474724d6163c010547522102119f899075a131d4d519d4cdcf5de5907dc2df3b93d54b53ded852211d2b6cb12102fdb0f6775d4b6619257c43343ba5e7807b0164f1eb3f00f2b594ab9e53ab812652ae220602119f899075a131d4d519d4cdcf5de5907dc2df3b93d54b53ded852211d2b6cb10cd1dbcc210000000000000000220602fdb0f6775d4b6619257c43343ba5e7807b0164f1eb3f00f2b594ab9e53ab81260c17cea9140000000000000000000100220020717ab7037b81797cb3e192a8a1b4d88083444bbfcd26934cadf3bcf890f14e05010147522102987c184fcd8ace2e2a314250e04a15a4b8c885fb4eb778ab82c45838bcbcbdde21034084c4a0493c248783e60d8415cd30b3ba2c3b7a79201e38b953adea2bc44f9952ae220202987c184fcd8ace2e2a314250e04a15a4b8c885fb4eb778ab82c45838bcbcbdde0c17cea91401000000000000002202034084c4a0493c248783e60d8415cd30b3ba2c3b7a79201e38b953adea2bc44f990cd1dbcc2101000000000000000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertEqual(txid, tx.txid())
        self.assertFalse(tx.is_complete())
        wallet2b.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertEqual((2, 2), tx.signature_count())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet2a.is_mine(wallet2a.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('0100000000010149d077be0ee9d52776211e9b4fec1cc02bd53661a04e120a97db8b78d83c9c6e01000000232200204311edae835c7a5aa712c8ca644180f13a3b2f3b420fa879b181474724d6163cfeffffff0260ea00000000000017a9143025051b6b5ccd4baf30dfe2de8aa84f0dd567ed87a086010000000000220020f7b6b30c3073ae2680a7e90c589bbfec5303331be68bbab843eed5d51ba0123904004730440220091ea67af7c1131f51f62fe9596dff0a60c8b45bfc5be675389e193912e8a71802201bf813bbf83933a35ecc46e2d5b0442bd8758fa82e0f8ed16392c10d51f7f7660147304402203ecf75b0316a449dd31bc549251b687dc904194aa551941bd5e8c67603661bdb02204ed58b3a6b070ec138d2127093bebcc6581495818fa611583e1c81cd9b2cf5ee0147522102119f899075a131d4d519d4cdcf5de5907dc2df3b93d54b53ded852211d2b6cb12102fdb0f6775d4b6619257c43343ba5e7807b0164f1eb3f00f2b594ab9e53ab812652ae00000000',
                         str(tx_copy))
        self.assertEqual('df92f0179b2bd4d0845472a8492edcaa3c24883ec4c7816dcd634183e0f89f29', tx_copy.txid())
        self.assertEqual('614a3c2d908229e5421364b5ac9802eb4636ead08c080cae3c7ca6ba4ad5f3cf', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual(txid, tx_copy.txid())

        wallet1a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 165000 - 5000 + 100000, 0), wallet1a.get_balance())
        self.assertEqual((0, 165000 - 5000 - 100000, 0), wallet2a.get_balance())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_between_p2sh_1of2_and_p2wpkh_p2sh(self, mock_save_db):
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('phone guilt ancient scan defy gasp off rotate approve ill word exchange', passphrase='', for_multisig=True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YPZ3ntVjqSCxiUUv2jikrUBU73Q3iJ7Y8iR41oYf991L5fanv7ciHjbjokdK2bjYqg1BzEUDxucU9qM5WRdBiY738wmgLP4')
            ],
            '1of2', gap_limit=2,
            config=self.config
        )
        # ^ second seed: kingdom now gift initial age right velvet exotic harbor enforce kingdom kick
        wallet2 = WalletIntegrityHelper.create_standard_wallet(
            # bip39: uniform tank success logic lesson awesome stove elegant regular desert drip device, der: m/49'/1'/0'
            keystore.from_xprv('uprv91HGbrNZTK4x8u22nbdYGzEuWPxjaHMREUi7CNhY64KsG5ZGnVM99uCa16EMSfrnaPTFxjbRdBZ2WiBkokoM8anzAy3Vpc52o88WPkitnxi'),
            gap_limit=2,
            config=self.config
        )

        # bootstrap wallet1
        funding_tx = Transaction('010000000001027e20990282eb29588375ad04936e1e991af3bc5b9c6f1ab62eca8c25becaef6a01000000171600140e6a17fadc8bafba830f3467a889f6b211d69a00fdffffff51847fd6bcbdfd1d1ea2c2d95c2d8de1e34c5f2bd9493e88a96a4e229f564e800100000017160014ecdf9fa06856f9643b1a73144bc76c24c67774a6fdffffff021e8501000000000017a91451991bfa68fbcb1e28aa0b1e060b7d24003352e38700093d000000000017a914b0b9f31bace76cdfae2c14abc03e223403d7dc4b870247304402205e19721b92c6afd70cd932acb50815a36ee32ab46a934147d62f02c13aeacf4702207289c4a4131ef86e27058ff70b6cb6bf0e8e81c6cbab6dddd7b0a9bc732960e4012103fe504411c21f7663caa0bbf28931f03fae7e0def7bc54851e0194dfb1e2c85ef02483045022100e969b65096fba4f8b24eb5bc622d2282076241621f3efe922cc2067f7a8a6be702203ec4047dd2a71b9c83eb6a0875a6d66b4d65864637576c06ed029d3d1a8654b0012102bbc8100dca67ba0297aba51296a4184d714204a5fc2eda34708360f37019a3dccfcc1300')
        funding_txid = funding_tx.txid()
        funding_output_value = 4000000
        self.assertEqual('1137c12de4ce0f5b08de8846ba14c0814351a7f0f31457c8ea51a5d4b3c891a3', funding_txid)
        wallet1a.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> wallet2
        outputs = [PartialTxOutput.from_address_and_value(wallet2.get_receiving_address(), 1000000)]
        tx = wallet1a.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet1a.is_mine(wallet1a.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('0100000001a391c8b3d4a551eac85714f3f0a7514381c014ba4688de085b0fcee42dc1371101000000910047304402204f1e1821b93b80a2033d3045325fe5c123d7ef54c2050aa356712eb32111ee670220039825c63cfe5879e808bf95aa365967d06a5f4072154955448becb65b8c5926014751210245c90e040d4f9d1fc136b3d4d6b7535bbb5df2bd27666c21977042cc1e05b5b02103c9a6bebfce6294488315e58137a279b2efe09f1f528ecf93b40675ded3cf0e5f52aefeffffff0240420f000000000017a9149573eb50f3136dff141ac304190f41c8becc92ce8738b32d000000000017a914b815d1b430ae9b632e3834ed537f7956325ee2a98700000000',
                         str(tx_copy))
        self.assertEqual('4649d6b6f8f967a84309de15c6d7403e628aa92ecb4f4d6d21299156fddff9e6', tx_copy.txid())
        self.assertEqual('4649d6b6f8f967a84309de15c6d7403e628aa92ecb4f4d6d21299156fddff9e6', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet2 -> wallet1
        outputs = [PartialTxOutput.from_address_and_value(wallet1a.get_receiving_address(), 300000)]
        tx = wallet2.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet2.is_mine(wallet2.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('01000000000101e6f9dffd569129216d4d4fcb2ea98a623e40d7c615de0943a867f9f8b6d6494600000000171600149fad840ed174584ee054bd26f3e411817338c5edfeffffff02e09304000000000017a9145ae3933a6e13100f301f23227b98b0bdb5d16b8487d89a0a000000000017a9148ccd0efb2be5b412c4033715f560ed8f446c8ceb8702473044022020a3c46886b72f4ec561c5983a789098202307eae9679ff74fcb0879f65fff1d0220242ec3bfa747c513ef31874670d9c68ad235892588be55564696dd6690952e5a0121038362bbf0b4918b37e9d7c75930ed3a78e3d445724cb5c37ade4a59b6e411fe4e00000000',
                         str(tx_copy))
        self.assertEqual('ae5dcacdf9e3067e18fcfd33582c24f60f844730e7872049bb627796929879ee', tx_copy.txid())
        self.assertEqual('f70bce6418fc44dcab41cbd466086aea54283821487189e4d15c4d1e2d1e267d', tx_copy.wtxid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())

        wallet1a.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, funding_output_value - 1000000 - 5000 + 300000, 0), wallet1a.get_balance())
        self.assertEqual((0, 1000000 - 5000 - 300000, 0), wallet2.get_balance())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_rbf(self, mock_save_db):
        self.maxDiff = None

        class TmpConfig(tempfile.TemporaryDirectory):  # to avoid sub-tests side-effecting each other
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.config = SimpleConfig({'electrum_path': self.name})
                self.config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = False
            def __enter__(self):
                return self.config

        for simulate_moving_txs in (False, True):
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2pkh_when_there_is_a_change_address", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2pkh_when_there_is_a_change_address(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2wpkh_when_there_is_a_change_address", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2wpkh_when_there_is_a_change_address(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2pkh_when_there_are_two_ismine_outs_one_change_one_recv", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2pkh_when_there_are_two_ismine_outs_one_change_one_recv(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_when_user_sends_max", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_when_user_sends_max(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_when_new_inputs_need_to_be_added", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_when_new_inputs_need_to_be_added(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2wpkh_when_there_is_only_a_single_output_and_that_is_a_change_address", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2wpkh_when_there_is_only_a_single_output_and_that_is_a_change_address(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_rbf_batching", simulate_moving_txs=simulate_moving_txs):
                    await self._rbf_batching(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_when_not_all_inputs_are_ismine_subcase_some_outputs_are_ismine_but_not_all", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_when_not_all_inputs_are_ismine_subcase_some_outputs_are_ismine_but_not_all(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_when_not_all_inputs_are_ismine_subcase_all_outputs_are_ismine", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_when_not_all_inputs_are_ismine_subcase_all_outputs_are_ismine(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2wpkh_decrease_payment", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2wpkh_decrease_payment(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2wpkh_decrease_payment_batch", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2wpkh_decrease_payment_batch(
                        simulate_moving_txs=simulate_moving_txs,
                        config=config)
            with TmpConfig() as config:
                with self.subTest(msg="_bump_fee_p2wpkh_insane_high_target_fee", simulate_moving_txs=simulate_moving_txs):
                    await self._bump_fee_p2wpkh_insane_high_target_fee(config=config)

    async def _bump_fee_p2pkh_when_there_is_a_change_address(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('fold object utility erase deputy output stadium feed stereo usage modify bean',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('010000000001011f4db0ecd81f4388db316bc16efb4e9daf874cf4950d54ecb4c0fb372433d68500000000171600143d57fd9e88ef0e70cddb0d8b75ef86698cab0d44fdffffff0280969800000000001976a91472e34cebab371967b038ce41d0e8fa1fb983795e88ac86a0ae020000000017a9149188bc82bdcae077060ebb4f02201b73c806edc887024830450221008e0725d531bd7dee4d8d38a0f921d7b1213e5b16c05312a80464ecc2b649598d0220596d309cf66d5f47cb3df558dbb43c5023a7796a80f5a88b023287e45a4db6b9012102c34d61ceafa8c216f01e05707672354f8119334610f7933a3f80dd7fb6290296bd391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('03052739fcfa2ead5f8e57e26021b0c2c546bcd3d74c6e708d5046dc58d90762', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', 2500000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325501
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff01007501000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc392705030000000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d7200000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbd391400000100fa010000000001011f4db0ecd81f4388db316bc16efb4e9daf874cf4950d54ecb4c0fb372433d68500000000171600143d57fd9e88ef0e70cddb0d8b75ef86698cab0d44fdffffff0280969800000000001976a91472e34cebab371967b038ce41d0e8fa1fb983795e88ac86a0ae020000000017a9149188bc82bdcae077060ebb4f02201b73c806edc887024830450221008e0725d531bd7dee4d8d38a0f921d7b1213e5b16c05312a80464ecc2b649598d0220596d309cf66d5f47cb3df558dbb43c5023a7796a80f5a88b023287e45a4db6b9012102c34d61ceafa8c216f01e05707672354f8119334610f7933a3f80dd7fb6290296bd391400220602a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587a0c8296e57100000000000000000000220203aa6a5d43c6de66d60f50942cf34f20e02c2c6f55349548fbf2cde5dd5d69b9180c8296e571010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc39270503000000006a473044022003660461e018c78c2cc73e12c367062a51f71c79b5123b1508765980cbe131bd02205c09bf00e629ea166e2b810a220a20bf4327b4479fb8d841e0c9bca0f843a009012102a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587afdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d7200000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbd391400',
                         str(tx_copy))
        self.assertEqual('212cd9aca604cfb4f2c43161b94e32c1a6bc9773fced360e5d4dda98e84b168d', tx_copy.txid())
        self.assertEqual('212cd9aca604cfb4f2c43161b94e32c1a6bc9773fced360e5d4dda98e84b168d', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 5000, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=tx_from_any(tx.serialize()), new_fee_rate=70.0)
        tx.locktime = 1325501
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff01007501000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc392705030000000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987a0337200000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbd391400000100fa010000000001011f4db0ecd81f4388db316bc16efb4e9daf874cf4950d54ecb4c0fb372433d68500000000171600143d57fd9e88ef0e70cddb0d8b75ef86698cab0d44fdffffff0280969800000000001976a91472e34cebab371967b038ce41d0e8fa1fb983795e88ac86a0ae020000000017a9149188bc82bdcae077060ebb4f02201b73c806edc887024830450221008e0725d531bd7dee4d8d38a0f921d7b1213e5b16c05312a80464ecc2b649598d0220596d309cf66d5f47cb3df558dbb43c5023a7796a80f5a88b023287e45a4db6b9012102c34d61ceafa8c216f01e05707672354f8119334610f7933a3f80dd7fb6290296bd391400220602a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587a0c8296e57100000000000000000000220203aa6a5d43c6de66d60f50942cf34f20e02c2c6f55349548fbf2cde5dd5d69b9180c8296e571010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('01000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc39270503000000006a4730440220228deafd10b344371cb828eda507707f0b01f8b421feae5b079396aef72fa08f02205c63a540ac54b483cb59275ff191c89997be02fcf548a216ed1b1045c5d21041012102a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587afdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987a0337200000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbd391400',
                         str(tx_copy))
        self.assertEqual('fa1eba447d88bd84c6ceca16f2767232c488c73a25b51989b2fc6aacaa05d16f', tx_copy.txid())
        self.assertEqual('fa1eba447d88bd84c6ceca16f2767232c488c73a25b51989b2fc6aacaa05d16f', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 7484320, 0), wallet.get_balance())

    async def _bump_fee_p2pkh_when_there_are_two_ismine_outs_one_change_one_recv(self, *, simulate_moving_txs, config):
        """This tests a regression where sometimes we created a replacement tx
        that spent from the original (which is clearly invalid).
        """
        wallet = self.create_standard_wallet_from_seed('amazing vapor slab rib chat cousin east float plug baby session weird',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('02000000000101a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080100000000fdffffff0220a10700000000001976a9143decc30f4f7eec45c5775347050b85a43ac7ee0b88ac203c3500000000001600149d91f0053172fab394d277ae27e9fa5c5a4921090247304402207a2b4abe2c4128fe80db297d636b81487feda2ee3c51a95bc670b7b377b09ca402205147bc550dfdff72e9159554c19045111daf6d95f556a4f4dc370c90aa37a3e0012102cccad56b36e7bd1ae44c37d69019d006d8911b43071725d6dcbbdfcade05650313f71c00')
        funding_txid = funding_tx.txid()
        self.assertEqual('0d98d8615f7b711beff2efcd4cf6b9f7ecd3b16a53fb9374e6a81d852492674e', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('02000000014e679224851da8e67493fb536ab1d3ecf7b9f64ccdeff2ef1b717b5f61d8980d000000006a4730440220361b332f0488501e0605b9a5385edda762e761c00f95195f308e2baea5e12f9d0220051be1c834f0de69ecf084b0311abf541687436cb34311a002efa4f104a722a3012103d4ce4ba5be0b861d2ee7c715b84ab0e791ccd36530bd8652babae37eda693c39fdffffff02bc020000000000001976a914093107975170d4416bd2dad961414ac0a5c9b3de88ac389d0700000000001976a914ac55156f62fa9085c114fc6496aee5ab153cb22888ac13f71c00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('2bce74c17a2b4c1f57b454604c87006173716e92028de60463182c344f3e2180', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        # bump tx
        tx = wallet.bump_fee(tx=tx_from_any(orig_rbf_tx.serialize()), new_fee_rate=200)
        self.assertTrue(not any([txin for txin in tx.inputs() if txin.prevout.txid.hex() == orig_rbf_txid]))
        tx.locktime = 1898260
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff01005502000000014e679224851da8e67493fb536ab1d3ecf7b9f64ccdeff2ef1b717b5f61d8980d0000000000fdffffff01200b0700000000001976a914ac55156f62fa9085c114fc6496aee5ab153cb22888ac14f71c00000100e102000000000101a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080100000000fdffffff0220a10700000000001976a9143decc30f4f7eec45c5775347050b85a43ac7ee0b88ac203c3500000000001600149d91f0053172fab394d277ae27e9fa5c5a4921090247304402207a2b4abe2c4128fe80db297d636b81487feda2ee3c51a95bc670b7b377b09ca402205147bc550dfdff72e9159554c19045111daf6d95f556a4f4dc370c90aa37a3e0012102cccad56b36e7bd1ae44c37d69019d006d8911b43071725d6dcbbdfcade05650313f71c00220603d4ce4ba5be0b861d2ee7c715b84ab0e791ccd36530bd8652babae37eda693c390c11aad9ae000000000000000000220203feceda5212994b3552847c93288c47490404784d90f1966b7d02e009ba40680e0c11aad9ae000000000100000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000014e679224851da8e67493fb536ab1d3ecf7b9f64ccdeff2ef1b717b5f61d8980d000000006a473044022043b34ed26822f120a2454aa9dd271400883e5c7133d3cd58ac018ddfa8ba4648022010394ca68edaf75df31217d3097f1171a87c846facfd963e49618fb1af89b66d012103d4ce4ba5be0b861d2ee7c715b84ab0e791ccd36530bd8652babae37eda693c39fdffffff01200b0700000000001976a914ac55156f62fa9085c114fc6496aee5ab153cb22888ac14f71c00',
                         str(tx_copy))
        self.assertEqual('9599a45a566251a5949b4f4b4a5f8d9a34c9e38e1ead9337c8338e34ea5bcd6e', tx_copy.txid())
        self.assertEqual('9599a45a566251a5949b4f4b4a5f8d9a34c9e38e1ead9337c8338e34ea5bcd6e', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 461600, 0), wallet.get_balance())

    async def _bump_fee_p2wpkh_decrease_payment(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('leader company camera enlist crash sleep insane aware anger hole hammer label',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('020000000001022ea8f7940c2e4bca2f34f21ba15a5c8d5e3c93d9c6deb17983412feefa0f1f6d0100000000fdffffff9d4ba5ab41951d506a7fa8272ef999ce3df166fe28f6f885aa791f012a0924cf0000000000fdffffff027485010000000000160014f80e86af4246960a24cd21c275a8e8842973fbcaa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400247304402203bf6dd875a775f356d4bb8c4e295a2cd506338c100767518f2b31fb85db71c1302204dc4ebca5584fc1cc08bd7f7171135d1b67ca6c8812c3723cd332eccaa7b848101210360bdbd16d9ef390fd3e804c421e6f30e6b065ac314f4d2b9a80d2f0682ad1431024730440220126b442d7988c5883ca17c2429f51ce770e3a57895524c8dfe07b539e483019e02200b50feed4f42f0035c9a9ddd044820607281e45e29e41a29233c2b8be6080bac01210245d47d08915816a5ecc934cff1b17e00071ca06172f51d632ba95392e8aad4fdd38a1d00')
        funding_txid = funding_tx.txid()
        self.assertEqual('dd0bf0d1563cd588b4c93cc1a9623c051ddb1c4f4581cf8ef43cfd27f031f246', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('0200000000010146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff02c8af000000000000160014999a95482213a896c72a251b6cc9f3d137b0a45850c3000000000000160014ea76d391236726af7d7a9c10abe600129154eb5a02473044022076d298537b524a926a8fadad0e9ded5868c8f4cf29246048f76f00eb4afa56310220739ad9e0417e97ce03fad98a454b4977972c2805cef37bfa822c6d6c56737c870121024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af4d48a1d00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('db2f77709a4a04417b3a45838c21470877fe7c182a4f81005a21ce1315c6a5e6', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        # bump tx
        tx = wallet.bump_fee(
            tx=tx_from_any(orig_rbf_tx.serialize()),
            new_fee_rate=60,
            strategy=BumpFeeStrategy.DECREASE_PAYMENT,
        )
        tx.locktime = 1936085
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff010071020000000146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff02c8af000000000000160014999a95482213a896c72a251b6cc9f3d137b0a458ccb5000000000000160014ea76d391236726af7d7a9c10abe600129154eb5ad58a1d000001011fa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400100fd7201020000000001022ea8f7940c2e4bca2f34f21ba15a5c8d5e3c93d9c6deb17983412feefa0f1f6d0100000000fdffffff9d4ba5ab41951d506a7fa8272ef999ce3df166fe28f6f885aa791f012a0924cf0000000000fdffffff027485010000000000160014f80e86af4246960a24cd21c275a8e8842973fbcaa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400247304402203bf6dd875a775f356d4bb8c4e295a2cd506338c100767518f2b31fb85db71c1302204dc4ebca5584fc1cc08bd7f7171135d1b67ca6c8812c3723cd332eccaa7b848101210360bdbd16d9ef390fd3e804c421e6f30e6b065ac314f4d2b9a80d2f0682ad1431024730440220126b442d7988c5883ca17c2429f51ce770e3a57895524c8dfe07b539e483019e02200b50feed4f42f0035c9a9ddd044820607281e45e29e41a29233c2b8be6080bac01210245d47d08915816a5ecc934cff1b17e00071ca06172f51d632ba95392e8aad4fdd38a1d002206024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af410ce2dd7cb00000080000000000000000000220203ecb63cc22d200c96225671b88a51a71deb053c6445dbd4694f61166e3e5bd05910ce2dd7cb0000008001000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('0200000000010146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff02c8af000000000000160014999a95482213a896c72a251b6cc9f3d137b0a458ccb5000000000000160014ea76d391236726af7d7a9c10abe600129154eb5a024730440220063a2d330f0d659b3f686cc291722a87cc37371d3520c946e74da8dbbd4c57e00220604b0f387754988f71af47db78263698a513173e8ce3b27a696b9e3954ba757b0121024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af4d58a1d00',
                         str(tx_copy))
        self.assertEqual('6b03c00f47cb145ffb632c3ce54dece29b9a980949ef5c574321f7fc83fa2238', tx_copy.txid())
        self.assertEqual('cb1f123231a3de5b02babddb43208f0273cb0df8addd4275583234eb50c7a87d', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 45000, 0), wallet.get_balance())

    async def _bump_fee_p2wpkh_decrease_payment_batch(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('leader company camera enlist crash sleep insane aware anger hole hammer label',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('020000000001022ea8f7940c2e4bca2f34f21ba15a5c8d5e3c93d9c6deb17983412feefa0f1f6d0100000000fdffffff9d4ba5ab41951d506a7fa8272ef999ce3df166fe28f6f885aa791f012a0924cf0000000000fdffffff027485010000000000160014f80e86af4246960a24cd21c275a8e8842973fbcaa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400247304402203bf6dd875a775f356d4bb8c4e295a2cd506338c100767518f2b31fb85db71c1302204dc4ebca5584fc1cc08bd7f7171135d1b67ca6c8812c3723cd332eccaa7b848101210360bdbd16d9ef390fd3e804c421e6f30e6b065ac314f4d2b9a80d2f0682ad1431024730440220126b442d7988c5883ca17c2429f51ce770e3a57895524c8dfe07b539e483019e02200b50feed4f42f0035c9a9ddd044820607281e45e29e41a29233c2b8be6080bac01210245d47d08915816a5ecc934cff1b17e00071ca06172f51d632ba95392e8aad4fdd38a1d00')
        funding_txid = funding_tx.txid()
        self.assertEqual('dd0bf0d1563cd588b4c93cc1a9623c051ddb1c4f4581cf8ef43cfd27f031f246', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('0200000000010146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff05e803000000000000160014a01f6b2a4bdaf3fb61f2a45e5eac92fcc58daee3881300000000000016001470fcde1ed0159ba5af97baec085ceb857098cedb0c49000000000000160014999a95482213a896c72a251b6cc9f3d137b0a458a86100000000000016001440c234c451fbd9ddf7824d6b8f0dc968a220946450c3000000000000160014ea76d391236726af7d7a9c10abe600129154eb5a024730440220782fb75f2398997ac77cd1b5c0d78f30a66b83df1d2d21c7a06cb03eb592d91702200540cf329c4b21e26aaba79a0c0ebdf465c4befb76a61e4eec924bc482cbf2930121024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af4a58a1d00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('9e0c7d890053c47c7cd653be984bc4b9a5dab8acf9a6ae075a00113d3077ad74', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        # bump tx
        tx = wallet.bump_fee(
            tx=tx_from_any(orig_rbf_tx.serialize()),
            new_fee_rate=60,
            strategy=BumpFeeStrategy.DECREASE_PAYMENT,
        )
        tx.locktime = 1936095
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100af020000000146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff045d0500000000000016001470fcde1ed0159ba5af97baec085ceb857098cedb0c49000000000000160014999a95482213a896c72a251b6cc9f3d137b0a4587d5300000000000016001440c234c451fbd9ddf7824d6b8f0dc968a220946425b5000000000000160014ea76d391236726af7d7a9c10abe600129154eb5adf8a1d000001011fa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400100fd7201020000000001022ea8f7940c2e4bca2f34f21ba15a5c8d5e3c93d9c6deb17983412feefa0f1f6d0100000000fdffffff9d4ba5ab41951d506a7fa8272ef999ce3df166fe28f6f885aa791f012a0924cf0000000000fdffffff027485010000000000160014f80e86af4246960a24cd21c275a8e8842973fbcaa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400247304402203bf6dd875a775f356d4bb8c4e295a2cd506338c100767518f2b31fb85db71c1302204dc4ebca5584fc1cc08bd7f7171135d1b67ca6c8812c3723cd332eccaa7b848101210360bdbd16d9ef390fd3e804c421e6f30e6b065ac314f4d2b9a80d2f0682ad1431024730440220126b442d7988c5883ca17c2429f51ce770e3a57895524c8dfe07b539e483019e02200b50feed4f42f0035c9a9ddd044820607281e45e29e41a29233c2b8be6080bac01210245d47d08915816a5ecc934cff1b17e00071ca06172f51d632ba95392e8aad4fdd38a1d002206024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af410ce2dd7cb0000008000000000000000000000220203ecb63cc22d200c96225671b88a51a71deb053c6445dbd4694f61166e3e5bd05910ce2dd7cb000000800100000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('0200000000010146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff045d0500000000000016001470fcde1ed0159ba5af97baec085ceb857098cedb0c49000000000000160014999a95482213a896c72a251b6cc9f3d137b0a4587d5300000000000016001440c234c451fbd9ddf7824d6b8f0dc968a220946425b5000000000000160014ea76d391236726af7d7a9c10abe600129154eb5a024730440220477ff315d3ac58de3bc1ec0b44b90a90da9bc09c440982fd9a1563eae98df0dc0220574033b0e306d388edcc77e4c2b39338fc8f182c747014aef3ce2c99cf9e5e960121024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af4df8a1d00',
                         str(tx_copy))
        self.assertEqual('bc86f4f14fea5305b197c02ae7b0d6b04c5f49144d9ad37c9f64ec0ec6d34594', tx_copy.txid())
        self.assertEqual('368e4c0429b38e66ac64ac9dbb66145c9f28dfaf2fad60f6424db32c379a12da', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 18700, 0), wallet.get_balance())

    async def _bump_fee_p2wpkh_insane_high_target_fee(self, *, config):
        wallet = self.create_standard_wallet_from_seed('leader company camera enlist crash sleep insane aware anger hole hammer label',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('020000000001022ea8f7940c2e4bca2f34f21ba15a5c8d5e3c93d9c6deb17983412feefa0f1f6d0100000000fdffffff9d4ba5ab41951d506a7fa8272ef999ce3df166fe28f6f885aa791f012a0924cf0000000000fdffffff027485010000000000160014f80e86af4246960a24cd21c275a8e8842973fbcaa0860100000000001600149c6b743752604b98d30f1a5d27a5d5ce8919f4400247304402203bf6dd875a775f356d4bb8c4e295a2cd506338c100767518f2b31fb85db71c1302204dc4ebca5584fc1cc08bd7f7171135d1b67ca6c8812c3723cd332eccaa7b848101210360bdbd16d9ef390fd3e804c421e6f30e6b065ac314f4d2b9a80d2f0682ad1431024730440220126b442d7988c5883ca17c2429f51ce770e3a57895524c8dfe07b539e483019e02200b50feed4f42f0035c9a9ddd044820607281e45e29e41a29233c2b8be6080bac01210245d47d08915816a5ecc934cff1b17e00071ca06172f51d632ba95392e8aad4fdd38a1d00')
        funding_txid = funding_tx.txid()
        self.assertEqual('dd0bf0d1563cd588b4c93cc1a9623c051ddb1c4f4581cf8ef43cfd27f031f246', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('0200000000010146f231f027fd3cf48ecf81454f1cdb1d053c62a9c13cc9b488d53c56d1f00bdd0100000000fdffffff02c8af000000000000160014999a95482213a896c72a251b6cc9f3d137b0a45850c3000000000000160014ea76d391236726af7d7a9c10abe600129154eb5a02473044022076d298537b524a926a8fadad0e9ded5868c8f4cf29246048f76f00eb4afa56310220739ad9e0417e97ce03fad98a454b4977972c2805cef37bfa822c6d6c56737c870121024196fb7b766ac987a08b69a5e108feae8513b7e72bc9e47899e27b36100f2af4d48a1d00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('db2f77709a4a04417b3a45838c21470877fe7c182a4f81005a21ce1315c6a5e6', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        with self.assertRaises(CannotBumpFee):
            tx = wallet.bump_fee(
                tx=tx_from_any(orig_rbf_tx.serialize()),
                new_fee_rate=99999,
                strategy=BumpFeeStrategy.DECREASE_PAYMENT,
            )
        with self.assertRaises(CannotBumpFee):
            tx = wallet.bump_fee(
                tx=tx_from_any(orig_rbf_tx.serialize()),
                new_fee_rate=99999,
                strategy=BumpFeeStrategy.PRESERVE_PAYMENT,
            )

        tx = wallet.bump_fee(
            tx=tx_from_any(orig_rbf_tx.serialize()),
            new_fee_rate=60,
            strategy=BumpFeeStrategy.DECREASE_PAYMENT,
        )
        tx.locktime = 1936085
        tx.version = 2
        self.assertEqual('6b03c00f47cb145ffb632c3ce54dece29b9a980949ef5c574321f7fc83fa2238', tx.txid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_cpfp_p2pkh(self, mock_save_db):
        wallet = self.create_standard_wallet_from_seed('fold object utility erase deputy output stadium feed stereo usage modify bean')

        # bootstrap wallet
        funding_tx = Transaction('010000000001010f40064d66d766144e17bb3276d96042fd5aee2196bcce7e415f839e55a83de800000000171600147b6d7c7763b9185b95f367cf28e4dc6d09441e73fdffffff02404b4c00000000001976a9141df43441a3a3ee563e560d3ddc7e07cc9f9c3cdb88ac009871000000000017a9143873281796131b1996d2f94ab265327ee5e9d6e28702473044022029c124e5a1e2c6fa12e45ccdbdddb45fec53f33b982389455b110fdb3fe4173102203b3b7656bca07e4eae3554900aa66200f46fec0af10e83daaa51d9e4e62a26f4012103c8f0460c245c954ef563df3b1743ea23b965f98b120497ac53bd6b8e8e9e0f9bbe391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 5000000
        self.assertEqual('9973bf8918afa349b63934432386f585613b51034db6c8628b61ba2feb8a3668', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # cpfp tx
        tx = wallet.cpfp(funding_tx, fee=50000)
        tx.set_rbf(True)
        tx.locktime = 1325502
        tx.version = 1
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('010000000168368aeb2fba618b62c8b64d03513b6185f58623433439b649a3af1889bf7399000000006a473044022014139c4c8dd4148851c1306c4901b759799e87a22885a3c23f6a6472a3c580dd02205df8037a19261a80157143ee61d24b64b8f60c3cb196e36e758920669f88eb56012102a7536f0bfbc60c5a8e86e2b9df26431fc062f9f454016dbc26f2467e0bc98b3ffdffffff01f0874b00000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88acbe391400',
                         str(tx_copy))
        self.assertEqual('c064c0dd89077de615f0ff8a626d4a62092c02649ed8266ed4c54302918e87d5', tx_copy.txid())
        self.assertEqual('c064c0dd89077de615f0ff8a626d4a62092c02649ed8266ed4c54302918e87d5', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 50000, 0), wallet.get_balance())

    async def _bump_fee_p2wpkh_when_there_is_a_change_address(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', 2500000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100720100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402205442705e988abe74bf391b293bb1b886674284a92ed0788c33024f9336d60aef022013a93049d3bed693254cd31a704d70bb988a36750f0b74d0a5b4d9e29c54ca9d0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('b019bbad45a46ed25365e46e4cae6428fb12ae425977eb93011ffb294cb4977e', tx_copy.txid())
        self.assertEqual('ba87313e2b3b42f1cc478843d4d53c72d6e06f6c66ac8cfbe2a59cdac2fd532d', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 5000, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=tx_from_any(tx.serialize()), new_fee_rate=70.0)
        tx.locktime = 1325500
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100720100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f9870c4a720000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bc3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f9870c4a720000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402202a7e412d37f7a54f7ede0f85e58c7f9dc0f7244d222a4f50a90f87b05badeed40220788d4a4a13f660de7d5464dce5e79419361fdd5d1853c7da65469cd32f7981a90121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bc391400',
                         str(tx_copy))
        self.assertEqual('dad75ab7078b9ce9698a83e7a954c1c38b235d3a4ab79bcb340245e3d9b62b93', tx_copy.txid())
        self.assertEqual('05a484c64a094724b1c58a15463c8c772a98f084cc23ee636204ad9c4d9e5b51', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 7490060, 0), wallet.get_balance())

    async def _bump_fee_when_not_all_inputs_are_ismine_subcase_some_outputs_are_ismine_but_not_all(self, *, simulate_moving_txs, config):
        class NetworkMock:
            relay_fee = 1000
            async def get_transaction(self, txid, timeout=None):
                if txid == "597098f9077cd2a7bf5bb2a03c9ae5fcd9d1f07c0891cb42cbb129cf9eaf57fd":
                    return "02000000000102a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540000000000fdffffffbdeb0175b1c51c96843d1952f7e1c49c1703717d7d020048d4de0a8eed94dad50000000000fdffffff03b2a00700000000001600140cd6c9f8ce0aa73d77fcf7f156c74f5cbec6906bb2a00700000000001600146435504ddc95e6019a90bb7dfc7ca81a88a8633106d790000000000016001444bd3017ee214370abf683abaa7f6204c9f40210024730440220652a04a2a301d9a031a034f3ae48174e204e17acf7bfc27f0dcab14243f73e2202207b29e964c434dfb2c515232d36566a40dccd4dd93ccb7fd15260ecbda10f0d9801210231994e564a0530068d17a9b0f85bec58d1352517a2861ea99e5b3070d2c5dbda02473044022072186473874919019da0e3d92b6e0aa4f88cba448ed5434615e5a3c8e2b7c42a02203ec05cef66960d5bc45d0f3d25675190cf8035b11a05ed4b719fd9c3a894899b012102f5fdca8c4e30ba0a1babf9cf9ebe62519b08aead351c349ed1ffc8316c24f542d7f61c00"
                else:
                    raise Exception("unexpected txid")
            def has_internet_connection(self):
                return True
            run_from_another_thread = Network.run_from_another_thread
            def get_local_height(self):
                return 0
            def blockchain(self):
                class BlockchainMock:
                    def is_tip_stale(self):
                        return True
                return BlockchainMock()

        wallet = self.create_standard_wallet_from_seed('mix total present junior leader live state athlete mistake crack wall valve',
                                                       config=config)
        wallet.network = NetworkMock()

        # bootstrap wallet
        funding_tx = Transaction('02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c00')
        funding_txid = funding_tx.txid()
        self.assertEqual('08557327673db61cc921e1a30826608599b86457836be3021105c13940d9a9a3', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('02000000000102a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdfffffffd57af9ecf29b1cb42cb91087cf0d1d9fce59a3ca0b25bbfa7d27c07f99870590200000000fdffffff03b2a00700000000001600145dc80fd43eb70fd21a6c4446e3ce043df94f100cb2a00700000000001600147db4ab480b7d2218fba561ff304178f4afcbc972be358900000000001600149d91f0053172fab394d277ae27e9fa5c5a49210902473044022003999f03be8b9e299b2cd3bc7bce05e273d5d9ce24fc47af8754f26a7a13e13f022004e668499a67061789f6ebd2932c969ece74417ae3f2307bf696428bbed4fe36012102a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb0247304402207121358a66c0e716e2ba2be928076736261c691b4fbf89ea8d255449a4f5837b022042cadf9fe1b4f3c03ede3cef6783b42f0ba319f2e0273b624009cd023488c4c1012103a5ba95fb1e0043428ed70680fc17db254b3f701dfccf91e48090aa17c1b7ea40fef61c00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('6057690010ddac93a371629e1f41866400623e13a9cd336d280fc3239086a983', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        # bump tx
        orig_rbf_tx = tx_from_any(orig_rbf_tx.serialize())
        orig_rbf_tx.add_info_from_wallet(wallet=wallet)
        await orig_rbf_tx.add_info_from_network(network=wallet.network)
        tx = wallet.bump_fee(tx=orig_rbf_tx, new_fee_rate=70)
        tx.locktime = 1898268
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100b90200000002a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdfffffffd57af9ecf29b1cb42cb91087cf0d1d9fce59a3ca0b25bbfa7d27c07f99870590200000000fdffffff031660070000000000160014a36590fb127d05cf17a07a84a17f2f2d6cc90a7bb2a00700000000001600147db4ab480b7d2218fba561ff304178f4afcbc972be358900000000001600149d91f0053172fab394d277ae27e9fa5c5a4921091cf71c000001011f20a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec7270100de02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c00220602a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb109c9fff98000000800000000000000000000100fd910102000000000102a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540000000000fdffffffbdeb0175b1c51c96843d1952f7e1c49c1703717d7d020048d4de0a8eed94dad50000000000fdffffff03b2a00700000000001600140cd6c9f8ce0aa73d77fcf7f156c74f5cbec6906bb2a00700000000001600146435504ddc95e6019a90bb7dfc7ca81a88a8633106d790000000000016001444bd3017ee214370abf683abaa7f6204c9f40210024730440220652a04a2a301d9a031a034f3ae48174e204e17acf7bfc27f0dcab14243f73e2202207b29e964c434dfb2c515232d36566a40dccd4dd93ccb7fd15260ecbda10f0d9801210231994e564a0530068d17a9b0f85bec58d1352517a2861ea99e5b3070d2c5dbda02473044022072186473874919019da0e3d92b6e0aa4f88cba448ed5434615e5a3c8e2b7c42a02203ec05cef66960d5bc45d0f3d25675190cf8035b11a05ed4b719fd9c3a894899b012102f5fdca8c4e30ba0a1babf9cf9ebe62519b08aead351c349ed1ffc8316c24f542d7f61c0000220203b1b437d6d3366441e63e387594ffacb80676d7d518971d1d284b775cd7d8c38b109c9fff98000000800100000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('70736274ff0100b90200000002a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdfffffffd57af9ecf29b1cb42cb91087cf0d1d9fce59a3ca0b25bbfa7d27c07f99870590200000000fdffffff031660070000000000160014a36590fb127d05cf17a07a84a17f2f2d6cc90a7bb2a00700000000001600147db4ab480b7d2218fba561ff304178f4afcbc972be358900000000001600149d91f0053172fab394d277ae27e9fa5c5a4921091cf71c000001011f20a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec7270100de02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c0001070001086b0247304402201f5ea643f6bc59c96ab8f1a3935b455e8f9395a67b74d618d121d16ae76f7b440220574d05df88740f915798e7993158c08e544801a044d19ef140574da19c1937d7012102a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb000100fd910102000000000102a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540000000000fdffffffbdeb0175b1c51c96843d1952f7e1c49c1703717d7d020048d4de0a8eed94dad50000000000fdffffff03b2a00700000000001600140cd6c9f8ce0aa73d77fcf7f156c74f5cbec6906bb2a00700000000001600146435504ddc95e6019a90bb7dfc7ca81a88a8633106d790000000000016001444bd3017ee214370abf683abaa7f6204c9f40210024730440220652a04a2a301d9a031a034f3ae48174e204e17acf7bfc27f0dcab14243f73e2202207b29e964c434dfb2c515232d36566a40dccd4dd93ccb7fd15260ecbda10f0d9801210231994e564a0530068d17a9b0f85bec58d1352517a2861ea99e5b3070d2c5dbda02473044022072186473874919019da0e3d92b6e0aa4f88cba448ed5434615e5a3c8e2b7c42a02203ec05cef66960d5bc45d0f3d25675190cf8035b11a05ed4b719fd9c3a894899b012102f5fdca8c4e30ba0a1babf9cf9ebe62519b08aead351c349ed1ffc8316c24f542d7f61c0000220203b1b437d6d3366441e63e387594ffacb80676d7d518971d1d284b775cd7d8c38b109c9fff98000000800100000000000000000000',
                         tx_copy.serialize_as_bytes().hex())
        self.assertEqual('6a8ed07cd97a10ace851b67a65035f04ff477d67cde62bb8679007e87b214e79', tx_copy.txid())

    async def _bump_fee_when_not_all_inputs_are_ismine_subcase_all_outputs_are_ismine(self, *, simulate_moving_txs, config):
        class NetworkMock:
            relay_fee = 1000
            async def get_transaction(self, txid, timeout=None):
                if txid == "08557327673db61cc921e1a30826608599b86457836be3021105c13940d9a9a3":
                    return "02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c00"
                else:
                    raise Exception("unexpected txid")
            def has_internet_connection(self):
                return True
            run_from_another_thread = Network.run_from_another_thread
            def get_local_height(self):
                return 0
            def blockchain(self):
                class BlockchainMock:
                    def is_tip_stale(self):
                        return True
                return BlockchainMock()

        wallet = self.create_standard_wallet_from_seed(
            'faint orbit extend hope moon head mercy still debate sick cotton path',
            config=config,
            gap_limit=4,
        )
        wallet.network = NetworkMock()

        # bootstrap wallet
        funding_tx = Transaction('02000000000102c247447533b530cacc3e716aae84621857f04a483252374cbdccfdf8b4ef816b0000000000fdffffffc247447533b530cacc3e716aae84621857f04a483252374cbdccfdf8b4ef816b0100000000fdffffff01d63f0f00000000001600141ef4658adb12ec745a1a1fef6ab8897f04bade060247304402201dc5be86749d8ce33571a6f1a2f8bbfceba89b9dbf2b4683e66c8c17cf7df6090220729199516cb894569ebbe3e998d47fc74030231ed30f110c9babd8a9dc361115012102728251a5f5f55375eef3c14fe59ab0755ba4d5f388619895238033ac9b51aad20247304402202e5d416489c20810e96e931b98a84b0c0c4fc32d2d34d3470b7ee16810246a4c022040f86cf8030d2117d6487bbe6e23d68d6d70408b002d8055de1f33d038d3a0550121039c009e7e7dad07e74ec5a8ac9f9e3499420dd9fe9709995525c714170152512620f71c00')
        funding_txid = funding_tx.txid()
        self.assertEqual('59ff0dd3962db651444d9fa6a61311302e47158533714d006e7e024ce45777da', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('02000000000102a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdffffffda7757e44c027e6e004d71338515472e301113a6a69f4d4451b62d96d30dff590000000000fdffffff02b2a00700000000001600144710cfecc31828d31e68ad101dd022fe091a02b1683f0f00000000001600145fd89e3ff2f32c48d85ac65edb4fdf40112ffdfb02473044022032a64a01b0975b65b0adfee53baa6dfb2ca9917714ae3f3acbe609397cc4912d02207da348511a156f6b6eab9d4c762a421e629784108c61d128ad9409483c1e4819012102a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb024730440220620795910e9d96680a2d869024fc5048cb80d038e60a5b92850de65eb938a49c02201a550737b18eda5f93ce3ce0c5907d7b0a9856bbc3bb81cec14349c5b6c97c08012102999b1062a5acf7071a43fd6f2bd37a4e0f7162182490661949dbeeb7d1b03401eef61c00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('2dcc543035c90c25734c9381096cc2f211ac1c2467e072170bc9e51e4580029b', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        # bump tx
        orig_rbf_tx = tx_from_any(orig_rbf_tx.serialize())
        orig_rbf_tx.add_info_from_wallet(wallet=wallet)
        await orig_rbf_tx.add_info_from_network(network=wallet.network)
        tx = wallet.bump_fee(tx=orig_rbf_tx, new_fee_rate=50)
        tx.locktime = 1898273
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff01009a0200000002a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdffffffda7757e44c027e6e004d71338515472e301113a6a69f4d4451b62d96d30dff590000000000fdffffff02bc780700000000001600144710cfecc31828d31e68ad101dd022fe091a02b1683f0f00000000001600145fd89e3ff2f32c48d85ac65edb4fdf40112ffdfb21f71c00000100de02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c000001011fd63f0f00000000001600141ef4658adb12ec745a1a1fef6ab8897f04bade060100fd530102000000000102c247447533b530cacc3e716aae84621857f04a483252374cbdccfdf8b4ef816b0000000000fdffffffc247447533b530cacc3e716aae84621857f04a483252374cbdccfdf8b4ef816b0100000000fdffffff01d63f0f00000000001600141ef4658adb12ec745a1a1fef6ab8897f04bade060247304402201dc5be86749d8ce33571a6f1a2f8bbfceba89b9dbf2b4683e66c8c17cf7df6090220729199516cb894569ebbe3e998d47fc74030231ed30f110c9babd8a9dc361115012102728251a5f5f55375eef3c14fe59ab0755ba4d5f388619895238033ac9b51aad20247304402202e5d416489c20810e96e931b98a84b0c0c4fc32d2d34d3470b7ee16810246a4c022040f86cf8030d2117d6487bbe6e23d68d6d70408b002d8055de1f33d038d3a0550121039c009e7e7dad07e74ec5a8ac9f9e3499420dd9fe9709995525c714170152512620f71c00220602999b1062a5acf7071a43fd6f2bd37a4e0f7162182490661949dbeeb7d1b0340110277f031200000080000000000000000000220202519a4072fd8c29362693439f441bd7a45c0d8dea26ce88872a4bca7e5d07cb4510277f03120000008000000000020000000022020314c9b46fce4c6111e4bbe89bb06b3dd29c6cbac586a4914bb18fe8bb7e0a463c10277f031200000080000000000100000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('70736274ff01009a0200000002a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdffffffda7757e44c027e6e004d71338515472e301113a6a69f4d4451b62d96d30dff590000000000fdffffff02bc780700000000001600144710cfecc31828d31e68ad101dd022fe091a02b1683f0f00000000001600145fd89e3ff2f32c48d85ac65edb4fdf40112ffdfb21f71c00000100de02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c000001011fd63f0f00000000001600141ef4658adb12ec745a1a1fef6ab8897f04bade060100fd530102000000000102c247447533b530cacc3e716aae84621857f04a483252374cbdccfdf8b4ef816b0000000000fdffffffc247447533b530cacc3e716aae84621857f04a483252374cbdccfdf8b4ef816b0100000000fdffffff01d63f0f00000000001600141ef4658adb12ec745a1a1fef6ab8897f04bade060247304402201dc5be86749d8ce33571a6f1a2f8bbfceba89b9dbf2b4683e66c8c17cf7df6090220729199516cb894569ebbe3e998d47fc74030231ed30f110c9babd8a9dc361115012102728251a5f5f55375eef3c14fe59ab0755ba4d5f388619895238033ac9b51aad20247304402202e5d416489c20810e96e931b98a84b0c0c4fc32d2d34d3470b7ee16810246a4c022040f86cf8030d2117d6487bbe6e23d68d6d70408b002d8055de1f33d038d3a0550121039c009e7e7dad07e74ec5a8ac9f9e3499420dd9fe9709995525c714170152512620f71c0001070001086b0247304402206842258bbe37829facadef81fa17eb1c97e6f9a4c66717c0cea37b61c9be804902203d291a2c9e3df57e3422f9b90589c2350f0168867c3320e994258169b8da402b012102999b1062a5acf7071a43fd6f2bd37a4e0f7162182490661949dbeeb7d1b0340100220202519a4072fd8c29362693439f441bd7a45c0d8dea26ce88872a4bca7e5d07cb4510277f03120000008000000000020000000022020314c9b46fce4c6111e4bbe89bb06b3dd29c6cbac586a4914bb18fe8bb7e0a463c10277f031200000080000000000100000000',
                         tx_copy.serialize_as_bytes().hex())
        self.assertEqual('b46cdce7e7564dfd09618ab9008ec3a921c6372f3dcdab2f6094735b024485f0', tx_copy.txid())


    async def _bump_fee_p2wpkh_when_there_is_only_a_single_output_and_that_is_a_change_address(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('tb1q7rl9cxr85962ztnsze089zs8ycv52hk43f3m9n', '!')]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100520200000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f882980000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a9039800000080000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('02000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f882980000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402201050a398878098e695e2fcef181383d529d0bd0c959554bc01c35cc1791dd83b02202a193fbc77ab47879093d01c131fd4f2c80dd76750b7f0be027751ca970b84a50121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('839b4d7ec2480975126ffa0c2a4552a85dd43435b23b375536391943e1f27074', tx_copy.txid())
        self.assertEqual('b6fc78267494951771d935ef0338f50b13e62258e54265ad4989fe9ffe98b018', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 5000, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=tx_from_any(tx.serialize()), new_fee_rate=75)
        tx.locktime = 1325500
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100520200000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff014676980000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bc3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a9039800000080000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff014676980000000000160014f0fe5c1867a174a12e70165e728a072619455ed502473044022008bcb6fab261e9f4d5ccdd11c389b0620de1a1f493e97df6ec83f0c1a261e96c02205e352d3096cc68d4b1279f05dd4a2b1f9d1134dd01f761d01e21f4a88e608cca0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bc391400',
                         str(tx_copy))
        self.assertEqual('0787da6829907ede8a322273d19ba47943ac234ad7fd1cb1821f6a0e78fcc003', tx_copy.txid())
        self.assertEqual('65760ae60ed5feedfd10a9198b44e483ea64dcfa116d32cf247f45d474ee5ce0', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 9991750, 0), wallet.get_balance())

    async def _bump_fee_when_user_sends_max(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', '!')]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100530100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987024730440220520ab41536d5d0fac8ad44e6aa4a8258a266121bab1eb6599f1ee86bbc65719d02205944c2fb765fca4753a850beadac49f5305c6722410c347c08cec4d90e3eb4430121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('dc4b622f3225f00edb886011fa02b74630cdbc24cebdd3210d5ea3b68bef5cc9', tx_copy.txid())
        self.assertEqual('a00340ee8c90673e05f2cf368601b6bba6a7f0513bd974feb218a326e39b1874', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 0, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=tx_from_any(tx.serialize()), new_fee_rate=70.0, strategy=BumpFeeStrategy.DECREASE_PAYMENT)
        tx.locktime = 1325500
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100530100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01267898000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987bc3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01267898000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f98702473044022069412007c3a6509fdfcfbe90679395c202c973740b0530b8ff366bc86ebff99d02206a02e3c0beb0921fa7d30379db4999d685d4b97239a2b8c7dd839531c72863110121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bc391400',
                         str(tx_copy))
        self.assertEqual('53824cc67e8fe973b0dfa1b8cc10f4e2441b9b4b2b1eb92576fbba7000c2908a', tx_copy.txid())
        self.assertEqual('bb137a5a810bb44d3b1cc77fb4f840e7c8c0f84771f7ce4671c3b1a9f5f93724', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 0, 0), wallet.get_balance())

    async def _bump_fee_when_new_inputs_need_to_be_added(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)

        # bootstrap wallet (incoming funding_tx1)
        funding_tx1 = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid1 = funding_tx1.txid()
        #funding_output_value = 10_000_000
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid1)
        wallet.adb.receive_tx_callback(funding_tx1, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', '!')]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100530100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987024730440220520ab41536d5d0fac8ad44e6aa4a8258a266121bab1eb6599f1ee86bbc65719d02205944c2fb765fca4753a850beadac49f5305c6722410c347c08cec4d90e3eb4430121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('dc4b622f3225f00edb886011fa02b74630cdbc24cebdd3210d5ea3b68bef5cc9', tx_copy.txid())
        self.assertEqual('a00340ee8c90673e05f2cf368601b6bba6a7f0513bd974feb218a326e39b1874', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 0, 0), wallet.get_balance())

        # another incoming transaction (funding_tx2)
        funding_tx2 = Transaction('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400')
        funding_txid2 = funding_tx2.txid()
        #funding_output_value = 5_000_000
        self.assertEqual('c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a', funding_txid2)
        wallet.adb.receive_tx_callback(funding_tx2, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 5_000_000, 0), wallet.get_balance())

        # bump tx
        tx = wallet.bump_fee(tx=tx_from_any(tx.serialize()), new_fee_rate=70.0)
        tx.locktime = 1325500
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff01009b0100000002c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff4a5d2593658f7feb9fadcf70dced3bc18db8c90bf77495e608f14dd51c6e6ac30100000000fdffffff025c254c0000000000160014f0fe5c1867a174a12e70165e728a072619455ed5f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987bc3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000001011f404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab900100f601000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400220602a6ff1ffc189b4776b78e20edca969cc45da3e610cc0cc79925604be43fee469f10e8a9039800000080000000000100000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a903980000008001000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('01000000000102c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff4a5d2593658f7feb9fadcf70dced3bc18db8c90bf77495e608f14dd51c6e6ac30100000000fdffffff025c254c0000000000160014f0fe5c1867a174a12e70165e728a072619455ed5f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f9870247304402200d295ba3935c797c8eec441f1525f43697ddb07b2d5950a1474054d594bc2e4e0220549e9f07c01d35c19737d7e651c8a0a87c28b33b489ac2be2cc5f1cebbab3fc80121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c50247304402206ac987d1ac834bc29c8b763da115942da6b070988eed1c33a3a53571f9d7c18e02204cb082efb881b1852abafdc28693ca45864b0130e252d97f58e790618010a629012102a6ff1ffc189b4776b78e20edca969cc45da3e610cc0cc79925604be43fee469fbc391400',
                         str(tx_copy))
        self.assertEqual('cdcf070cb8ddd9fbdd6b5cd29f2da395aa1e00640c3123a1a60941f49baddb6c', tx_copy.txid())
        self.assertEqual('dceb4ffe55261c861f6f0841ba603fdd18f187df13d2b67c86bfbcb57e6a1870', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 4_990_300, 0), wallet.get_balance())

    async def _rbf_batching(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)
        wallet.config.WALLET_BATCH_RBF = True

        # bootstrap wallet (incoming funding_tx1)
        funding_tx1 = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid1 = funding_tx1.txid()
        #funding_output_value = 10_000_000
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid1)
        wallet.adb.receive_tx_callback(funding_tx1, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', 2_500_000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100720100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402205442705e988abe74bf391b293bb1b886674284a92ed0788c33024f9336d60aef022013a93049d3bed693254cd31a704d70bb988a36750f0b74d0a5b4d9e29c54ca9d0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('b019bbad45a46ed25365e46e4cae6428fb12ae425977eb93011ffb294cb4977e', tx_copy.txid())
        self.assertEqual('ba87313e2b3b42f1cc478843d4d53c72d6e06f6c66ac8cfbe2a59cdac2fd532d', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 7_495_000, 0), wallet.get_balance())

        # another incoming transaction (funding_tx2)
        funding_tx2 = Transaction('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400')
        funding_txid2 = funding_tx2.txid()
        #funding_output_value = 5_000_000
        self.assertEqual('c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a', funding_txid2)
        wallet.adb.receive_tx_callback(funding_tx2, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 12_495_000, 0), wallet.get_balance())

        # create new tx (output should be batched with existing!)
        # no new input will be needed. just a new output, and change decreased.
        outputs = [PartialTxOutput.from_address_and_value('tb1qy6xmdj96v5dzt3j08hgc05yk3kltqsnmw4r6ry', 2_500_000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=20000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100910100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff03a025260000000000160014268db6c8ba651a25c64f3dd187d0968dbeb0427ba02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f98720fd4b0000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a90398000000800000000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff03a025260000000000160014268db6c8ba651a25c64f3dd187d0968dbeb0427ba02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f98720fd4b0000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402206add1d6fc8b5fc6fd1bbf50d06fe432e65b16a9d715dbfe7f2d26473f48a128302207983d8db3508e3b953e6e26581d2bbba5a7ca0ff0dd07361de60977dc61ed1580121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('21112d35fa08b9577bfe46405ad17720d0fa85bcefab0b0a1cffe79b9d6167c4', tx_copy.txid())
        self.assertEqual('d49ffdaa832a35d88f3f43bcfb08306347c2342200098f450e41ccb289b26db3', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 9_980_000, 0), wallet.get_balance())

        # create new tx (output should be batched with existing!)
        # new input will be needed!
        outputs = [PartialTxOutput.from_address_and_value('2NCVwbmEpvaXKHpXUGJfJr9iB5vtRN3vcut', 6_000_000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=100_000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100da0100000002c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff4a5d2593658f7feb9fadcf70dced3bc18db8c90bf77495e608f14dd51c6e6ac30100000000fdffffff04a025260000000000160014268db6c8ba651a25c64f3dd187d0968dbeb0427ba02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f98760823b0000000000160014f0fe5c1867a174a12e70165e728a072619455ed5808d5b000000000017a914d332f2f63019da6f2d23ee77bbe30eed7739790587bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000001011f404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab900100f601000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400220602a6ff1ffc189b4776b78e20edca969cc45da3e610cc0cc79925604be43fee469f10e8a90398000000800000000001000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a903980000008001000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(2, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000102c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff4a5d2593658f7feb9fadcf70dced3bc18db8c90bf77495e608f14dd51c6e6ac30100000000fdffffff04a025260000000000160014268db6c8ba651a25c64f3dd187d0968dbeb0427ba02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f98760823b0000000000160014f0fe5c1867a174a12e70165e728a072619455ed5808d5b000000000017a914d332f2f63019da6f2d23ee77bbe30eed7739790587024730440220730ac17af4ac14f008ee5d0a7be524d8ca344afc19b548faa9ac8c21a216df81022010d9cc878402103c1dd6b06e97e7910a23b7ec88251627f47ed1d5a8d741beba0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c50247304402201005fc1e9091ac36d98b60c1c8b65aada0d4fe4da438d69b3262028644005cfc02207353c987be9e33d1e8702689960df76ac28adacc2f9093d731bc56c9578c5458012102a6ff1ffc189b4776b78e20edca969cc45da3e610cc0cc79925604be43fee469fbb391400',
                         str(tx_copy))
        self.assertEqual('88791bcd352b50592a5521c15595972b14b5d6be165be2df0e57ea19e588c025', tx_copy.txid())
        self.assertEqual('7c5e5bff601e5467036b574b41090681a86de403867dd2b14097920b95e392ed', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 3_900_000, 0), wallet.get_balance())

    async def test_rbf_batching__cannot_batch_as_would_need_to_use_ismine_outputs_of_basetx(self):
        """Wallet history contains unconf tx1 that spends all its coins to two ismine outputs,
        one 'recv' address (20k sats) and one 'change' (80k sats).
        The user tries to create tx2, that pays an invoice for 90k sats.
        Even if batch_rbf==True, no batching should be done. Instead, the outputs of tx1 should be used.
        """
        wallet = self.create_standard_wallet_from_seed('cause carbon luggage air humble mistake melt paper supreme sense gravity void',
                                                       config=self.config)

        # bootstrap wallet (incoming funding_tx0)
        funding_tx = Transaction('020000000001021798e10f8b7220c57ea0d605316a52453ca9b3eed99996b5b7bdf4699548bb520000000000fdffffff277d82678d238ca45dd3490ac9fbb49272f0980b093b9197ff70ec8eb082cfb00100000000fdffffff028c360100000000001600147a9bfd90821be827275023849dd91ee80d494957a08601000000000016001476efaaa243327bf3a2c0f5380cb3914099448cec024730440220354b2a74f5ac039cca3618f7ff98229d243b89ac40550c8b027894f2c5cb88ff022064cb5ab1539b4c5367c2e01a8362e0aa12c2732bc8d08c3fce6eab9e56b7fe19012103e0a1499cb3d8047492c60466722c435dfbcffae8da9b83e758fbd203d12728f502473044022073cef8b0cfb093aed5b8eaacbb58c2fa6a69405a8e266cd65e76b726c9151d7602204d5820b23ab96acc57c272aac96d94740a20a6b89c016aa5aed7c06d1e6b9100012102f09e50a265c6a0dcf7c87153ea73d7b12a0fbe9d7d0bbec5db626b2402c1e85c02fa2400')
        funding_txid = funding_tx.txid()
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # to_self_payment tx1
        toself_tx = Transaction('02000000000101ce05b8ae96fe8d2875fd1efcb591b6fb5c5d924bf05d75d880a0e44498fe14b80100000000fdffffff02204e0000000000001600142266c890fad71396f106319368107d5b2a1146feb837010000000000160014b113a47f3718da3fd161339a6681c150fef2cfe3024730440220197bfea1bc5c86c35d68029422342de97c1e5d9adc12e48d99ae359940211a660220770ddb228ae75698f827e2fddc574f0c8eb2a3e109678a2a2b6bc9cbb9593b1c012102b07ca318381fcef5998f34ee4197e96c17aa19867cbe99c544d321807db95ed2f1f92400')
        toself_txid = toself_tx.txid()
        wallet.adb.receive_tx_callback(toself_tx, TX_HEIGHT_UNCONFIRMED)

        # create outgoing tx2
        outputs = [PartialTxOutput.from_address_and_value("tb1qkfn0fude7z789uys2u7sf80kd4805zpvs3na0h", 90_000)]
        for batch_rbf in (False, True):
            with self.subTest(batch_rbf=batch_rbf):
                coins = wallet.get_spendable_coins(domain=None)
                self.assertEqual(2, len(coins))

                wallet.config.WALLET_BATCH_RBF = batch_rbf
                tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=1000)
                tx.set_rbf(True)
                tx.locktime = 2423302
                tx.version = 2
                wallet.sign_transaction(tx, password=None)
                self.assertEqual('02000000000102bbef0182c2c746bd28517b6fd27ba9eef9c7fb5982efd27bd612cc5a28615a3a0000000000fdffffffbbef0182c2c746bd28517b6fd27ba9eef9c7fb5982efd27bd612cc5a28615a3a0100000000fdffffff02602200000000000016001413fabce9be995554a722fc4e1c5ae53ebfd58164905f010000000000160014b266f4f1b9f0bc72f090573d049df66d4efa082c0247304402205c50b9ddb1b3ead6214d7d9707c74ba29ff547880d017aae2459db156bf85b9b022041134562fffa3dccf1ac05d9b07da62a8d57dd158d25d22d1965a011325e64aa012102c72b815ba00ccb0b469cc61a0ceb843d974e630cf34abcfac178838f1974f68f02473044022049774c32b0ad046b7acdb4acc38107b6b1be57c0d167643a48cbc045850c86c202205189ed61342fc52a377c2865a879c4c2606de98eebd6bf4d73874d62329668c70121033484c8ed83c359d1c3e569accb04b77988daab9408fc82869051c10d0749ac2006fa2400',
                                 str(tx))

    async def test_rbf_batching__merge_duplicate_outputs(self):
        """txos paying to the same address might be merged into a single output with a larger value"""
        wallet = self.create_standard_wallet_from_seed('response era cable net spike again observe dumb wage wonder sail tortoise',
                                                       config=self.config)
        wallet.config.WALLET_BATCH_RBF = True

        # bootstrap wallet (incoming funding_tx0): for 500k sat
        funding_tx = Transaction('02000000000101013548c9019890e27ce9e58766de05f18ea40ede70751fb6cd7a3a1715ece0a30100000000fdffffff0220a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa05485a080000000000160014bc69f7d82c403a9f35dfb6d1a4531d6b19cab0e3024730440220346b200f21c3024e1d51fb4ecddbdbd68bd24ae7b9dfd501519f6dcbeb7c052402200617e3ce7b0eb308e30caf23894fb0388b68fb1c15dd0681dd13ae5e735f148101210360d0c9ef15b8b6a16912d341ad218a4e4e4e07e9347f4a2dbc7ca8d974f8bc9ec1ad2600')
        funding_txid = funding_tx.txid()
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        dest_addr = "tb1qtzhwpufqr5dwztdaysfqnwlf9m29uwdkq8zm9w"
        # first payment to dest_addr
        outputs1 = [PartialTxOutput.from_address_and_value(dest_addr, 200_000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx1 = wallet.make_unsigned_transaction(coins=coins, outputs=outputs1, fee=2000)
        tx1.set_rbf(True)
        tx1.locktime = 2534850
        tx1.version = 2
        wallet.sign_transaction(tx1, password=None)
        self.assertEqual(2, len(tx1.outputs()))
        self.assertEqual('020000000001019264597cffcce8f0c17b16a02adca7a95ae90f2ea51bd4b4df60c76dfe86686e0000000000fdffffff02400d03000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b6108c0400000000001600144e1b662f616fe134430054e29295ea6e5c18f1730247304402205ea932303bb89bfe07c1e4c28117cb84f613e09dd51464aa2ed2b184c2f2b76902202968280003b0e7d4098bf9adc47246db7b84c83f718e70a609de05f3b2ae64e80121029b1a61d66896486ab893741b38dbafb9673b91a82237d6e4ca0da3cda7cbeb7cc2ad2600',
                         str(tx1))
        wallet.adb.receive_tx_callback(tx1, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 298_000, 0), wallet.get_balance())

        wallet.config.WALLET_MERGE_DUPLICATE_OUTPUTS = True
        # second payment to dest_addr  (merged)
        outputs2 = [PartialTxOutput.from_address_and_value(dest_addr, 100_000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx2 = wallet.make_unsigned_transaction(coins=coins, outputs=outputs2, fee=3000)
        tx2.set_rbf(True)
        tx2.locktime = 2534850
        tx2.version = 2
        wallet.sign_transaction(tx2, password=None)
        self.assertEqual(2, len(tx2.outputs()))
        self.assertEqual('020000000001019264597cffcce8f0c17b16a02adca7a95ae90f2ea51bd4b4df60c76dfe86686e0000000000fdffffff0288010300000000001600144e1b662f616fe134430054e29295ea6e5c18f173e09304000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b60247304402201b5856f572a70f667392f000780044a6c6677eadadd5b56d2b15d1f90a8bf4b7022046566836d7e1e1a099ff72b4ecb09d6b24e701e12c0fb4c5667172d47d9b54520121029b1a61d66896486ab893741b38dbafb9673b91a82237d6e4ca0da3cda7cbeb7cc2ad2600',
                         str(tx2))
        wallet.adb.receive_tx_callback(tx2, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 197_000, 0), wallet.get_balance())

        # remove tx2 from wallet, by replacing it with tx1
        wallet.adb.receive_tx_callback(tx1, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 298_000, 0), wallet.get_balance())

        wallet.config.WALLET_MERGE_DUPLICATE_OUTPUTS = False
        # second payment to dest_addr  (not merged, just duplicate outputs)
        outputs2 = [PartialTxOutput.from_address_and_value(dest_addr, 100_000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx3 = wallet.make_unsigned_transaction(coins=coins, outputs=outputs2, fee=3000)
        tx3.set_rbf(True)
        tx3.locktime = 2534850
        tx3.version = 2
        wallet.sign_transaction(tx3, password=None)
        self.assertEqual(3, len(tx3.outputs()))
        self.assertEqual('020000000001019264597cffcce8f0c17b16a02adca7a95ae90f2ea51bd4b4df60c76dfe86686e0000000000fdffffff03a08601000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b688010300000000001600144e1b662f616fe134430054e29295ea6e5c18f173400d03000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b602473044022061386129ebefda19e22ab9e2c06642a2a5eb7637e1b492d5c164591ff0fb27c9022006129d5d0c780d6830fb6cf924e3eeef03b8a349a9ebb36969cae410d9ff0fa50121029b1a61d66896486ab893741b38dbafb9673b91a82237d6e4ca0da3cda7cbeb7cc2ad2600',
                         str(tx3))
        wallet.adb.receive_tx_callback(tx3, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 197_000, 0), wallet.get_balance())

    async def test_join_psbts__merge_duplicate_outputs(self):
        """txos paying to the same address might be merged into a single output with a larger value"""
        rawtx1 = "70736274ff01007102000000019264597cffcce8f0c17b16a02adca7a95ae90f2ea51bd4b4df60c76dfe86686e0000000000fdffffff02400d03000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b6108c0400000000001600144e1b662f616fe134430054e29295ea6e5c18f173c2ad26000001011f20a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa050100de02000000000101013548c9019890e27ce9e58766de05f18ea40ede70751fb6cd7a3a1715ece0a30100000000fdffffff0220a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa05485a080000000000160014bc69f7d82c403a9f35dfb6d1a4531d6b19cab0e3024730440220346b200f21c3024e1d51fb4ecddbdbd68bd24ae7b9dfd501519f6dcbeb7c052402200617e3ce7b0eb308e30caf23894fb0388b68fb1c15dd0681dd13ae5e735f148101210360d0c9ef15b8b6a16912d341ad218a4e4e4e07e9347f4a2dbc7ca8d974f8bc9ec1ad26002206029b1a61d66896486ab893741b38dbafb9673b91a82237d6e4ca0da3cda7cbeb7c101f1b48320000008000000000000000000000220203db4846ec1841f48484590e67fcd7d1039f124a04410c5794f38ec8625329ea23101f1b483200000080010000000000000000"
        rawtx2 = "70736274ff0100710200000001a4c6da70097e1bfbbcba0edad4ba1143295300b60851aa6c4916a0b32381bf7f0000000000fdffffff02a08601000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b6108c040000000000160014fac4435311276a6cfda5681cfb02252acdd14c3fc2ad26000001011f801a06000000000016001452af44a1e32754fd8d2e7c1c3cc1b305379f0b660100de020000000001018eeaf0cd7de0e0e117af1a7f2bab59b4ddfbd416ef7460b3fd42a1f7bc039cfd0000000000fdffffff02801a06000000000016001452af44a1e32754fd8d2e7c1c3cc1b305379f0b66909f0700000000001600140847a3685a3ce9911cdce3fbf33cb42edc8f6dd902473044022044d3485c09784f03cd648117ef2d4d0dabeeb2929b30f2e52c3bbd5efd1c0f820220346655235eb9fcb54b23bbf194217092cc8aa6dd33ecf018907626b90289be6801210304e06afd290a4e7a9eb008cf408a4f9b0640fd2688258b523aa3dbb236bb3f7eccad2600220602c1ed648e71f15643950b444b864ab784b9d0e31e6ca6ec7d849d3dda4d98da05101f1b48320000008000000000010000000000220203aba60233db3aab45d0196cb70a22d667faa92124760700d20c953b0222ced96d101f1b483200000080010000000100000000"

        self.config.WALLET_MERGE_DUPLICATE_OUTPUTS = False
        joined_tx = tx_from_any(rawtx1)
        joined_tx.join_with_other_psbt(tx_from_any(rawtx2), config=self.config)
        self.assertEqual(4, len(joined_tx.outputs()))
        self.assertEqual("70736274ff0100d802000000029264597cffcce8f0c17b16a02adca7a95ae90f2ea51bd4b4df60c76dfe86686e0000000000fdffffffa4c6da70097e1bfbbcba0edad4ba1143295300b60851aa6c4916a0b32381bf7f0000000000fdffffff04a08601000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b6400d03000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b6108c0400000000001600144e1b662f616fe134430054e29295ea6e5c18f173108c040000000000160014fac4435311276a6cfda5681cfb02252acdd14c3fc2ad26000001011f20a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa050100de02000000000101013548c9019890e27ce9e58766de05f18ea40ede70751fb6cd7a3a1715ece0a30100000000fdffffff0220a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa05485a080000000000160014bc69f7d82c403a9f35dfb6d1a4531d6b19cab0e3024730440220346b200f21c3024e1d51fb4ecddbdbd68bd24ae7b9dfd501519f6dcbeb7c052402200617e3ce7b0eb308e30caf23894fb0388b68fb1c15dd0681dd13ae5e735f148101210360d0c9ef15b8b6a16912d341ad218a4e4e4e07e9347f4a2dbc7ca8d974f8bc9ec1ad26002206029b1a61d66896486ab893741b38dbafb9673b91a82237d6e4ca0da3cda7cbeb7c101f1b48320000008000000000000000000001011f801a06000000000016001452af44a1e32754fd8d2e7c1c3cc1b305379f0b660100de020000000001018eeaf0cd7de0e0e117af1a7f2bab59b4ddfbd416ef7460b3fd42a1f7bc039cfd0000000000fdffffff02801a06000000000016001452af44a1e32754fd8d2e7c1c3cc1b305379f0b66909f0700000000001600140847a3685a3ce9911cdce3fbf33cb42edc8f6dd902473044022044d3485c09784f03cd648117ef2d4d0dabeeb2929b30f2e52c3bbd5efd1c0f820220346655235eb9fcb54b23bbf194217092cc8aa6dd33ecf018907626b90289be6801210304e06afd290a4e7a9eb008cf408a4f9b0640fd2688258b523aa3dbb236bb3f7eccad2600220602c1ed648e71f15643950b444b864ab784b9d0e31e6ca6ec7d849d3dda4d98da05101f1b4832000000800000000001000000000000220203db4846ec1841f48484590e67fcd7d1039f124a04410c5794f38ec8625329ea23101f1b483200000080010000000000000000220203aba60233db3aab45d0196cb70a22d667faa92124760700d20c953b0222ced96d101f1b483200000080010000000100000000",
                         joined_tx.serialize_as_bytes().hex())

        self.config.WALLET_MERGE_DUPLICATE_OUTPUTS = True
        joined_tx = tx_from_any(rawtx1)
        joined_tx.join_with_other_psbt(tx_from_any(rawtx2), config=self.config)
        self.assertEqual(3, len(joined_tx.outputs()))
        self.assertEqual("70736274ff0100b902000000029264597cffcce8f0c17b16a02adca7a95ae90f2ea51bd4b4df60c76dfe86686e0000000000fdffffffa4c6da70097e1bfbbcba0edad4ba1143295300b60851aa6c4916a0b32381bf7f0000000000fdffffff03108c0400000000001600144e1b662f616fe134430054e29295ea6e5c18f173108c040000000000160014fac4435311276a6cfda5681cfb02252acdd14c3fe09304000000000016001458aee0f1201d1ae12dbd241209bbe92ed45e39b6c2ad26000001011f20a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa050100de02000000000101013548c9019890e27ce9e58766de05f18ea40ede70751fb6cd7a3a1715ece0a30100000000fdffffff0220a1070000000000160014542266519a44eb9b903761d40c6fe1055d33fa05485a080000000000160014bc69f7d82c403a9f35dfb6d1a4531d6b19cab0e3024730440220346b200f21c3024e1d51fb4ecddbdbd68bd24ae7b9dfd501519f6dcbeb7c052402200617e3ce7b0eb308e30caf23894fb0388b68fb1c15dd0681dd13ae5e735f148101210360d0c9ef15b8b6a16912d341ad218a4e4e4e07e9347f4a2dbc7ca8d974f8bc9ec1ad26002206029b1a61d66896486ab893741b38dbafb9673b91a82237d6e4ca0da3cda7cbeb7c101f1b48320000008000000000000000000001011f801a06000000000016001452af44a1e32754fd8d2e7c1c3cc1b305379f0b660100de020000000001018eeaf0cd7de0e0e117af1a7f2bab59b4ddfbd416ef7460b3fd42a1f7bc039cfd0000000000fdffffff02801a06000000000016001452af44a1e32754fd8d2e7c1c3cc1b305379f0b66909f0700000000001600140847a3685a3ce9911cdce3fbf33cb42edc8f6dd902473044022044d3485c09784f03cd648117ef2d4d0dabeeb2929b30f2e52c3bbd5efd1c0f820220346655235eb9fcb54b23bbf194217092cc8aa6dd33ecf018907626b90289be6801210304e06afd290a4e7a9eb008cf408a4f9b0640fd2688258b523aa3dbb236bb3f7eccad2600220602c1ed648e71f15643950b444b864ab784b9d0e31e6ca6ec7d849d3dda4d98da05101f1b483200000080000000000100000000220203db4846ec1841f48484590e67fcd7d1039f124a04410c5794f38ec8625329ea23101f1b483200000080010000000000000000220203aba60233db3aab45d0196cb70a22d667faa92124760700d20c953b0222ced96d101f1b48320000008001000000010000000000",
                         joined_tx.serialize_as_bytes().hex())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_cpfp_p2wpkh(self, mock_save_db):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage')

        # bootstrap wallet
        funding_tx = Transaction('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 5000000
        self.assertEqual('c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # cpfp tx
        tx = wallet.cpfp(funding_tx, fee=50000)
        tx.set_rbf(True)
        tx.locktime = 1325501
        tx.version = 1
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('010000000001014a5d2593658f7feb9fadcf70dced3bc18db8c90bf77495e608f14dd51c6e6ac30100000000fdffffff01f0874b0000000000160014f0fe5c1867a174a12e70165e728a072619455ed502473044022029314c8fb5e05dcd6e94d26f7d96bd9824290977bdc0602b2ef1faf8aa7da53c022003c0477a2b45f05ec4e06e4669a9c3a9e8d9ad0ab78ed85a37b93064c5358e9a012102a6ff1ffc189b4776b78e20edca969cc45da3e610cc0cc79925604be43fee469fbd391400',
                         str(tx_copy))
        self.assertEqual('6bb0490b29b65c7292f6bb1715982fe4474417b4fbdcf8a4675a0994ce12d156', tx_copy.txid())
        self.assertEqual('ce94905afcb396d7bc6de28e4d102dcefc85224abae7df16399b2789f5596db8', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 50000, 0), wallet.get_balance())

    async def test_sweep_uncompressed_p2pk(self):
        class NetworkMock:
            relay_fee = 1000
            async def listunspent_for_scripthash(self, scripthash):
                if scripthash == '460e4fb540b657d775d84ff4955c9b13bd954c2adc26a6b998331343f85b6a45':
                    return [{'tx_hash': 'ac24de8b58e826f60bd7b9ba31670bdfc3e8aedb2f28d0e91599d741569e3429', 'tx_pos': 1, 'height': 1325785, 'value': 1000000}]
                else:
                    return []
            async def get_transaction(self, txid):
                if txid == "ac24de8b58e826f60bd7b9ba31670bdfc3e8aedb2f28d0e91599d741569e3429":
                    return "010000000001021b41471d6af3aa80ebe536dbf4f505a6d46af456131a8e12e1950171959b690e0f00000000fdffffff2ef29833a69863b31e884fc5e6f7b99a23b5601e14f0eb65905faa42fec0776d0000000000fdffffff02f96a070000000000160014e61b989a740056254b5f8061281ac96ca15d35e140420f00000000004341049afa8fb50f52104b381a673c6e4fb7fb54987271d0e948dd9a568bb2af6f9310a7a809ce06e09d1510e5836f20414596232e2c0be63715459fa3cf8e7092af05ac0247304402201fe20012c1c732a6a8f942c4e0feed5ed0bddfb94db736ec3d0c0d38f0f7f46a022021d690e6d2688b90b76002f4c3134981502d666211e85e8a6ca91e78405dfa3801210346fb31136ab48e6c648865264d32004b43643d01f0ba485cffac4bb0b3f739470247304402204a2473ab4b3bfc8e6b1a6b8675dc2c3d115d8c04f5df37f29779dca6d300d9db02205e72ebbccd018c67b86ae4da6b0e6222902a8de85915ed6115330b9328764b370121027a93ffc9444a12d99307318e2e538949072cb35b2aca344b8163795a022414c7d73a1400"
                else:
                    raise Exception("unexpected txid")

        privkeys = ['93NQ7CFbwTPyKDJLXe97jczw33fiLijam2SCZL3Uinz1NSbHrTu',]
        network = NetworkMock()
        dest_addr = 'tb1q3ws2p0qjk5vrravv065xqlnkckvzcpclk79eu2'
        tx = await sweep(privkeys, network=network, config=self.config, to_address=dest_addr, fee=5000, locktime=1325785, tx_version=1)

        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('010000000129349e5641d79915e9d0282fdbaee8c3df0b6731bab9d70bf626e8588bde24ac010000004847304402206bf0d0a93abae0d5873a62ebf277a5dd2f33837821e8b93e74d04e19d71b578002201a6d729bc159941ef5c4c9e5fe13ece9fc544351ba531b00f68ba549c8b38a9a01fdffffff01b82e0f00000000001600148ba0a0bc12b51831f58c7ea8607e76c5982c071fd93a1400',
                         str(tx_copy))
        self.assertEqual('7f827fc5256c274fd1094eb7e020c8ded0baf820356f61aa4f14a9093b0ea0ee', tx_copy.txid())
        self.assertEqual('7f827fc5256c274fd1094eb7e020c8ded0baf820356f61aa4f14a9093b0ea0ee', tx_copy.wtxid())

    async def test_sweep_compressed_p2pk(self):
        class NetworkMock:
            relay_fee = 1000
            async def listunspent_for_scripthash(self, scripthash):
                if scripthash == 'cc911adb9fb939d0003a138ebdaa5195bf1d6f9172e438309ab4c00a5ebc255b':
                    return [{'tx_hash': '84a4a1943f7a620e0d8413f4c10877000768797a93bb106b3e7cd6fccc59b35e', 'tx_pos': 1, 'height': 2420005, 'value': 111111}]
                else:
                    return []
            async def get_transaction(self, txid):
                if txid == "84a4a1943f7a620e0d8413f4c10877000768797a93bb106b3e7cd6fccc59b35e":
                    return "02000000000102b7bfcd442c91134743c6e4100bb9f79456a6015de3c3920166bb0c3b7a8f7c070100000000fdffffff5ab39480d4b35ffa843691d944a8479dfe825d38b03fcb1804197482bfad80fb0100000000fdffffff02d4ec000000000000160014769114e56e0913de3719a3b00a446b78e61751f007b201000000000023210332e147520e4743299d95196afaf9db7c86fe02507d9ca89acd7a4e96a63653d5ac0247304402200387fe79ffe10cec73d9b131058d7128665f729d14597828b483842889c4f5ea02201197b2f1295e4011e2d174d53c240fd13c6351451ab961ccb3678fc21fa5323b0121023c221dfbf7c3f61b9e5f66343c1a302d6beca2a8883504b0f484faec9919636b024730440220687d387af37df458efc104ee0065262cb5ea195e526ed7a480fd16e6cf708c3a022019bd3fd9c3ca3f1a1fbeabe20547876eb4572a7339de37b706fbd55031e60428012102c9c459e58b01a864d7bb80f6d577326465a04219c48541b5f3ea556a06ca61a425ed2400"
                else:
                    raise Exception("unexpected txid")

        privkeys = ['cUygTZe4jZLVwE4G44NznCPTeGvgsgassqucUHkAJxGC71Rst2kH',]
        network = NetworkMock()
        dest_addr = 'tb1q5uy5xjcn55gwdkmghht8yp3vwz3088f6e3e0em'
        tx = await sweep(privkeys, network=network, config=self.config, to_address=dest_addr, fee=5000, locktime=2420006, tx_version=2)

        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000015eb359ccfcd67c3e6b10bb937a796807007708c1f413840d0e627a3f94a1a48401000000484730440220043fc85a43e918ac41e494e309fdf204ca245d260cb5ea09108b196ca65d8a09022056f852f0f521e79ab2124d7e9f779c7290329ce5628ef8e92601980b065d3eb501fdffffff017f9e010000000000160014a709434b13a510e6db68bdd672062c70a2f39d3a26ed2400',
                         str(tx_copy))
        self.assertEqual('968a501350b954ecb51948202b8d0613aa84123ca9b745c14e208cb14feeff59', tx_copy.txid())
        self.assertEqual('968a501350b954ecb51948202b8d0613aa84123ca9b745c14e208cb14feeff59', tx_copy.wtxid())

    async def test_sweep_uncompressed_p2pkh(self):
        class NetworkMock:
            relay_fee = 1000
            async def listunspent_for_scripthash(self, scripthash):
                if scripthash == '71e8c6a9fd8ab498290d5ccbfe1cfe2c5dc2a389b4c036dd84e305a59c4a4d53':
                    return [{'tx_hash': '15a78cc7664c42f1040474763bf794d555f6092bfba97d6c276f296c2d141506', 'tx_pos': 0, 'height': -1, 'value': 222222}]
                else:
                    return []
            async def get_transaction(self, txid):
                if txid == "15a78cc7664c42f1040474763bf794d555f6092bfba97d6c276f296c2d141506":
                    return "02000000000101c6a49fbd701f1526c8e43025a6dda8dd235b3593cfd38af040cba3e37b474fdb0e00000000fdffffff020e640300000000001976a914f1b02b7028fb81aefbb25809a2baf8d94d0c2ba288acb9e3080000000000160014c2eee75efe6621be177f7edd8198f671d1640c2602473044022072b8a6154590704063c377af451b4d69f76cc9064085d4a0c80f08625c57628802207844164839d93ce54ce7db092bbd809d5270142b5dedc823e95400e8bdae88c6012102b6ad13f48fd679a209b7d822376550e5e694a3a2862546ceb72c4012977eac4829ed2400"
                else:
                    raise Exception("unexpected txid")

        privkeys = ['p2pkh:91gxDahzHiJ63HXmLP7pvZrkF8i5gKBXk4VqWfhbhJjtf6Ni5NU',]
        network = NetworkMock()
        dest_addr = 'tb1q3ws2p0qjk5vrravv065xqlnkckvzcpclk79eu2'
        tx = await sweep(privkeys, network=network, config=self.config, to_address=dest_addr, fee=5000, locktime=2420010, tx_version=2)

        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000010615142d6c296f276c7da9fb2b09f655d594f73b76740404f1424c66c78ca715000000008a47304402206d2dae571ca2f51e0d4a8ce6a6335fa25ac09f4bbed26439124d93f035bdbb130220249dc2039f1da338a40679f0e79c25a2dc2983688e6c04753348f2aa8435e375014104b875ab889006d4a9be8467c9256cf54e1073f7f9a037604f571cc025bbf47b2987b4c862d5b687bb5328adccc69e67a17b109b6328228695a1c384573acd6199fdffffff0186500300000000001600148ba0a0bc12b51831f58c7ea8607e76c5982c071f2aed2400',
                         str(tx_copy))
        self.assertEqual('d62048493bf8459be5e1e3cab6caabc8f15661d02c364d8dc008297e573772bf', tx_copy.txid())
        self.assertEqual('d62048493bf8459be5e1e3cab6caabc8f15661d02c364d8dc008297e573772bf', tx_copy.wtxid())

    async def test_sweep_compressed_p2pkh(self):
        class NetworkMock:
            relay_fee = 1000
            async def listunspent_for_scripthash(self, scripthash):
                if scripthash == '941b2ca8bd850e391abc5e024c83b773842c40268a8fa8a5ef7aeca19fb395c5':
                    return [{'tx_hash': '8a764102b4a5c5d1b5235e6ce7e67ed3c146130f8a52e7692a151e2e5a831767', 'tx_pos': 0, 'height': -1, 'value': 123456}]
                else:
                    return []
            async def get_transaction(self, txid):
                if txid == "8a764102b4a5c5d1b5235e6ce7e67ed3c146130f8a52e7692a151e2e5a831767":
                    return "020000000001010615142d6c296f276c7da9fb2b09f655d594f73b76740404f1424c66c78ca7150100000000fdffffff0240e20100000000001976a914f1d49f51f9b58c4805431c303d12d3dcf51ae54188ace9000700000000001600145bdb04f2d096ee48b8b350c85481392ab47c01e70247304402200a72a4599cb27f16011cd67e2951733d6775cbd008506eacb2c20d69db3f531702204c944ec09224a347481c9eea78cac79b77b194b19dfef01b1e3b428010a82570012102fc38612ca7cc42d05a7089f1a6ec3900535604bd779f83c7817aae7bfd907dbd2aed2400"
                else:
                    raise Exception("unexpected txid")

        privkeys = ['p2pkh:cN3LiXmurmGRF5xngYd8XS2ZsP2KeXFUh4SH7wpC8uJJzw52JPq1',]
        network = NetworkMock()
        dest_addr = 'tb1q782f750ekkxysp2rrscr6yknmn634e2pv8lktu'
        tx = await sweep(privkeys, network=network, config=self.config, to_address=dest_addr, fee=1000, locktime=2420010, tx_version=2)

        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000016717835a2e1e152a69e7528a0f1346c1d37ee6e76c5e23b5d1c5a5b40241768a000000006a473044022038ad38003943bfd3ed39ba4340d545753fcad632a8fe882d01e4f0140ddb3cfb022019498260e29f5fbbcde9176bfb3553b7acec5fe284a9a3a33547a2d082b60355012103b875ab889006d4a9be8467c9256cf54e1073f7f9a037604f571cc025bbf47b29fdffffff0158de010000000000160014f1d49f51f9b58c4805431c303d12d3dcf51ae5412aed2400',
                         str(tx_copy))
        self.assertEqual('432c108626581fc6a7d3efc9dac5f3dec8286cec47dfaab86b4267d10381586c', tx_copy.txid())
        self.assertEqual('432c108626581fc6a7d3efc9dac5f3dec8286cec47dfaab86b4267d10381586c', tx_copy.wtxid())

    async def test_sweep_p2wpkh_p2sh(self):
        class NetworkMock:
            relay_fee = 1000
            async def listunspent_for_scripthash(self, scripthash):
                if scripthash == '9ee9bddbe9dc47f7f6c5a652a09012f49dfc54d5b997f58d7ccc49040871e61b':
                    return [{'tx_hash': '9a7bf98ed72b1002559d3d61805838a00e94afec78b8597a68606e2a0725171d', 'tx_pos': 0, 'height': -1, 'value': 150000}]
                else:
                    return []
            async def get_transaction(self, txid):
                if txid == "9a7bf98ed72b1002559d3d61805838a00e94afec78b8597a68606e2a0725171d":
                    return "020000000001038fc862be3bc8022866cc83b4f2feeaa914b015a3c6644251960baaccc4a5740b0000000000fdffffff7bfd61e391034e28848fae269183f1c5929e26befd5b2d798cf12c91d4d00dbf0100000000fdffffff014764d324e70e7e3e4fa27077bda2d880b3d1545588b75f79deb2855d9f31cb0000000000fdffffff01f04902000000000017a9147d0530db22c8124ff1558269f543dfeedd37131b87024730440220568ae75314f6414ccf2b0bbed522e1b4b1086ed6eb185ba4bc044ba2723c1f3402206c82253797d0f180db38986b46d8ad952829cf25bc31e3ca6ee54665f5a44b3c0121038a466bdcb979b96d70fde84b9ded4aba0c3cd9c0d2d59121fc3555428fd1a4890247304402203ba1b482b0b6ce5c3d29ef21ee8afad641af8381d3b131103c384757922f0c04022072320e260b60fc862669b2ea3dfb663f7f3a0b6babe8d265ac9ebf268e7225c2012103ff0877f34157a3444afbfdd7432032a93187bc1932e1c155d56dd66ef527906c02473044022058b1c1a2a8c1a256d4870b550ba93777a2cce36b89abe3515f024fd4eec48ce4022023e0002193a26064275433e8ade98642d74d58ee4f8e9717a8acca737856a6c401210364e8f5d9c30986931bca1197138d7250a17a0711a223f113b3ccc11ef09efccb2aed2400"
                else:
                    raise Exception("unexpected txid")

        privkeys = ['p2wpkh-p2sh:cQMRGsiEsFX5YoxVZaMEzBruAkCWnoFf1SG7SRm2tLHDEN165TrA',]
        network = NetworkMock()
        dest_addr = 'tb1qu7n2tzm90a3f29kvxlhzsc7t40ddk075ut5w44'
        tx = await sweep(privkeys, network=network, config=self.config, to_address=dest_addr, fee=500, locktime=2420010, tx_version=2)

        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('020000000001011d1725072a6e60687a59b878ecaf940ea0385880613d9d5502102bd78ef97b9a0000000017160014e7a6a58b657f629516cc37ee2863cbabdadb3fd4fdffffff01fc47020000000000160014e7a6a58b657f629516cc37ee2863cbabdadb3fd402473044022048ea4c558fd374f5d5066440a7f4933393cb377802cb949e3039fedf0378a29402204b4a58c591117cc1e37f07b03cc03cc6198dbf547e2bff813e2e2102bd2057e00121029f46ba81b3c6ad84e52841364dc54ca1097d0c30a68fb529766504c4b1c599352aed2400',
                         str(tx_copy))
        self.assertEqual('0680124954ccc158cbf24d289c93579f68fd75916509214066f69e09adda1861', tx_copy.txid())
        self.assertEqual('da8567d9b28e9e0ed8b3dcef6e619eba330cec6cb0c55d57f658f5ca06e02eb0', tx_copy.wtxid())

    async def test_sweep_p2wpkh(self):
        class NetworkMock:
            relay_fee = 1000
            async def listunspent_for_scripthash(self, scripthash):
                if scripthash == '7630f6b2121336279b55e5b71d4a59be5ffa782e86bae249ba0b5ad6a791933f':
                    return [{'tx_hash': '01d76acdb8992f4262fb847f5efbd95ea178049be59c70a2851bdcf9b4ae28e3', 'tx_pos': 0, 'height': 2420006, 'value': 98300}]
                else:
                    return []
            async def get_transaction(self, txid):
                if txid == "01d76acdb8992f4262fb847f5efbd95ea178049be59c70a2851bdcf9b4ae28e3":
                    return "02000000000101208840a3310ae4b88181374b5812f56f5dd56f12574f3bcd8041b48bfadc92cf0000000000fdffffff02fc7f010000000000160014d339efed7cd5d28d31995caf10b8973a9a13c656a08601000000000043410403886197eb13c59721b94a29f9a68a841caedb7782b35121cd81d50d0cc70db3f8955c7a07b08dd6470141b66eedd324406e29d6b6799033314512334461e3f9ac0247304402203328153753e934d7a13215bf58f093f84281d57f8c7d42f3b7704cd714c7b32c02205a502f3f3e4302561ccc93df413be3c78a439ff35b60cea03d19f8804a9a1239012103f41052be701441d1bc8f7cc6a6053d7e7f5e63be212fe5e3687344ddd52e3af525ed2400"
                else:
                    raise Exception("unexpected txid")

        privkeys = ['p2wpkh:cV2BvgtpLNX328m4QrhqycBGA6EkZUFfHM9kKjVXjfyD53uNfC4q',]
        network = NetworkMock()
        dest_addr = 'tb1qhuy2e45lrdcp9s4ezeptx5kwxcnahzgpar9scc'
        tx = await sweep(privkeys, network=network, config=self.config, to_address=dest_addr, fee=500, locktime=2420010, tx_version=2)

        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101e328aeb4f9dc1b85a2709ce59b0478a15ed9fb5e7f84fb62422f99b8cd6ad7010000000000fdffffff01087e010000000000160014bf08acd69f1b7012c2b91642b352ce3627db89010247304402204993099c4663d92ef4c9a28b3f45a40a6585754fe22ecfdc0a76c43fda7c9d04022006a75e0fd3ad1862d8e81015a71d2a1489ec7a9264e6e63b8fe6bb90c27e799b0121038ca94e7c715152fd89803c2a40a934c7c4035fb87b3cba981cd1e407369cfe312aed2400',
                         str(tx_copy))
        self.assertEqual('e02641928e5394332eec0a36c196f1e30e2b8645ebbeef89d6cc27bf237ae548', tx_copy.txid())
        self.assertEqual('b062d2e19880c66b36e80b823c2d00a2769658d1e574ff854dab15efd8fd7da8', tx_copy.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_coinjoin_between_two_p2wpkh_electrum_seeds(self, mock_save_db):
        wallet1 = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_seed('humor argue expand gain goat shiver remove morning security casual leopard degree', passphrase=''),
            gap_limit=2,
            config=self.config
        )
        wallet2 = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_seed('couple fade lift useless text thank badge act august roof drastic violin', passphrase=''),
            gap_limit=2,
            config=self.config
        )

        # bootstrap wallet1
        funding_tx = Transaction('0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca010851800')
        funding_txid = funding_tx.txid()
        self.assertEqual('d8f8186379085cffc9a3fd747e7a7527435db974d1e2941f52f063be8e4fbdd5', funding_txid)
        wallet1.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # bootstrap wallet2
        funding_tx = Transaction('02000000000101d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80100000000fdffffff025066350000000000160014e3aa82aa2e754507d5585c0b6db06cc0cb4927b7a037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c302483045022100f42e27519bd2379c22951c16b038fa6d49164fe6802854f2fdc7ee87fe31a8bc02204ea71e9324781b44bf7fea2f318caf3bedc5b497cbd1b4313fa71f833500bcb7012103a7853e1ee02a1629c8e870ec694a1420aeb98e6f5d071815257028f62d6f784169851800')
        funding_txid = funding_tx.txid()
        self.assertEqual('934f26a72c840293f06c37dc10a358df056dfe245cdf072ae836977c0abc46e5', funding_txid)
        wallet2.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 creates tx1, with output back to himself
        outputs = [PartialTxOutput.from_address_and_value("tb1qhye4wfp26kn0l7ynpn5a4hvt539xc3zf0n76t3", 10_000_000)]
        tx1 = wallet1.create_transaction(outputs=outputs, fee=5000, tx_version=2, rbf=True, sign=False)
        tx1.locktime = 1607022
        partial_tx1 = tx1.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100710200000001d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff02b82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44496e8518000001011fc0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15a0100df0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca01085180022060205e8db1b1906219782fadb18e763c0874a3118a17ce931e01707cbde194e041510775087560000008000000000000000000022020240ef5d2efee3b04b313a254df1b13a0b155451581e73943b21f3346bf6e1ba351077508756000000800100000000000000002202024a410b1212e88573561887b2bc38c90c074e4be425b9f3d971a9207825d9d3c8107750875600000080000000000100000000",
                         partial_tx1)
        tx1.prepare_for_export_for_coinjoin()
        partial_tx1 = tx1.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100710200000001d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff02b82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44496e8518000001011fc0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15a0100df0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca010851800000000",
                         partial_tx1)

        # wallet2 creates tx2, with output back to himself
        outputs = [PartialTxOutput.from_address_and_value("tb1qufnj5k2rrsnpjq7fg6d2pq3q9um6skdyyehw5m", 10_000_000)]
        tx2 = wallet2.create_transaction(outputs=outputs, fee=5000, tx_version=2, rbf=True, sign=False)
        tx2.locktime = 1607023
        partial_tx2 = tx2.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100710200000001e546bc0a7c9736e82a07df5c24fe6d05df58a310dc376cf09302842ca7264f930100000000fdffffff02988d07000000000016001453675a59be834aa6d139c3ebea56646a9b160c4c8096980000000000160014e2672a59431c261903c9469aa082202f37a859a46f8518000001011fa037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c30100df02000000000101d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80100000000fdffffff025066350000000000160014e3aa82aa2e754507d5585c0b6db06cc0cb4927b7a037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c302483045022100f42e27519bd2379c22951c16b038fa6d49164fe6802854f2fdc7ee87fe31a8bc02204ea71e9324781b44bf7fea2f318caf3bedc5b497cbd1b4313fa71f833500bcb7012103a7853e1ee02a1629c8e870ec694a1420aeb98e6f5d071815257028f62d6f784169851800220602275b4fba18bb34e5198a9cfb3e940306658839079b3bda50d504a9cf2bae36f41067f36697000000800000000001000000002202036e4d0a5fb845b2f1c3c868c2ce7212b155b73e91c05be1b7a77c48830831ba4f1067f366970000008001000000000000000022020200062fdea2b0a056b17fa6b91dd87f5b5d838fe1ee84d636a5022f9a340eebcc1067f3669700000080000000000000000000",
                         partial_tx2)

        # wallet2 gets raw partial tx1, merges it into his own tx2
        tx2.join_with_other_psbt(tx_from_any(partial_tx1), config=self.config)
        partial_tx2 = tx2.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100d80200000002e546bc0a7c9736e82a07df5c24fe6d05df58a310dc376cf09302842ca7264f930100000000fdffffffd5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff04988d07000000000016001453675a59be834aa6d139c3ebea56646a9b160c4cb82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44498096980000000000160014e2672a59431c261903c9469aa082202f37a859a46f8518000001011fa037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c30100df02000000000101d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80100000000fdffffff025066350000000000160014e3aa82aa2e754507d5585c0b6db06cc0cb4927b7a037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c302483045022100f42e27519bd2379c22951c16b038fa6d49164fe6802854f2fdc7ee87fe31a8bc02204ea71e9324781b44bf7fea2f318caf3bedc5b497cbd1b4313fa71f833500bcb7012103a7853e1ee02a1629c8e870ec694a1420aeb98e6f5d071815257028f62d6f784169851800220602275b4fba18bb34e5198a9cfb3e940306658839079b3bda50d504a9cf2bae36f41067f366970000008000000000010000000001011fc0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15a0100df0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca010851800002202036e4d0a5fb845b2f1c3c868c2ce7212b155b73e91c05be1b7a77c48830831ba4f1067f3669700000080010000000000000000000022020200062fdea2b0a056b17fa6b91dd87f5b5d838fe1ee84d636a5022f9a340eebcc1067f3669700000080000000000000000000",
                         partial_tx2)
        tx2.prepare_for_export_for_coinjoin()
        partial_tx2 = tx2.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100d80200000002e546bc0a7c9736e82a07df5c24fe6d05df58a310dc376cf09302842ca7264f930100000000fdffffffd5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff04988d07000000000016001453675a59be834aa6d139c3ebea56646a9b160c4cb82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44498096980000000000160014e2672a59431c261903c9469aa082202f37a859a46f8518000001011fa037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c30100df02000000000101d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80100000000fdffffff025066350000000000160014e3aa82aa2e754507d5585c0b6db06cc0cb4927b7a037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c302483045022100f42e27519bd2379c22951c16b038fa6d49164fe6802854f2fdc7ee87fe31a8bc02204ea71e9324781b44bf7fea2f318caf3bedc5b497cbd1b4313fa71f833500bcb7012103a7853e1ee02a1629c8e870ec694a1420aeb98e6f5d071815257028f62d6f7841698518000001011fc0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15a0100df0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca0108518000000000000",
                         partial_tx2)

        # wallet2 signs
        wallet2.sign_transaction(tx2, password=None)
        partial_tx2 = tx2.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100d80200000002e546bc0a7c9736e82a07df5c24fe6d05df58a310dc376cf09302842ca7264f930100000000fdffffffd5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff04988d07000000000016001453675a59be834aa6d139c3ebea56646a9b160c4cb82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44498096980000000000160014e2672a59431c261903c9469aa082202f37a859a46f8518000001011fa037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c30100df02000000000101d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80100000000fdffffff025066350000000000160014e3aa82aa2e754507d5585c0b6db06cc0cb4927b7a037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c302483045022100f42e27519bd2379c22951c16b038fa6d49164fe6802854f2fdc7ee87fe31a8bc02204ea71e9324781b44bf7fea2f318caf3bedc5b497cbd1b4313fa71f833500bcb7012103a7853e1ee02a1629c8e870ec694a1420aeb98e6f5d071815257028f62d6f78416985180001070001086b0247304402205106349e1644223b5128009376fc497477227172ac28a54942da58014869d4f502205aa60ba466f53b52c5933c39cfa1ab735c1722029039d7a5a7577789ae891389012102275b4fba18bb34e5198a9cfb3e940306658839079b3bda50d504a9cf2bae36f40001011fc0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15a0100df0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca010851800002202036e4d0a5fb845b2f1c3c868c2ce7212b155b73e91c05be1b7a77c48830831ba4f1067f3669700000080010000000000000000000022020200062fdea2b0a056b17fa6b91dd87f5b5d838fe1ee84d636a5022f9a340eebcc1067f3669700000080000000000000000000",
                         partial_tx2)
        tx2.prepare_for_export_for_coinjoin()
        partial_tx2 = tx2.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100d80200000002e546bc0a7c9736e82a07df5c24fe6d05df58a310dc376cf09302842ca7264f930100000000fdffffffd5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff04988d07000000000016001453675a59be834aa6d139c3ebea56646a9b160c4cb82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44498096980000000000160014e2672a59431c261903c9469aa082202f37a859a46f8518000001011fa037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c30100df02000000000101d5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80100000000fdffffff025066350000000000160014e3aa82aa2e754507d5585c0b6db06cc0cb4927b7a037a000000000001600140719d12228c61cab793ecd659c09cfe565a845c302483045022100f42e27519bd2379c22951c16b038fa6d49164fe6802854f2fdc7ee87fe31a8bc02204ea71e9324781b44bf7fea2f318caf3bedc5b497cbd1b4313fa71f833500bcb7012103a7853e1ee02a1629c8e870ec694a1420aeb98e6f5d071815257028f62d6f78416985180001070001086b0247304402205106349e1644223b5128009376fc497477227172ac28a54942da58014869d4f502205aa60ba466f53b52c5933c39cfa1ab735c1722029039d7a5a7577789ae891389012102275b4fba18bb34e5198a9cfb3e940306658839079b3bda50d504a9cf2bae36f40001011fc0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15a0100df0200000000010162ecbac2f0c8662f53505d9410fdc56c84c5642ddbd3358d9a27d564e26731130200000000fdffffff02c0d8a70000000000160014aba1c9faecc3f8882e641583e8734a3f9d01b15ab89ed5000000000016001470afbd97b2dc351bd167f714e294b2fd3b60aedf02483045022100c93449989510e279eb14a0193d5c262ae93034b81376a1f6be259c6080d3ba5d0220536ab394f7c20f301d7ec2ef11be6e7b6d492053dce56458931c1b54218ec0fd012103b8f5a11df8e68cf335848e83a41fdad3c7413dc42148248a3799b58c93919ca0108518000000000000",
                         partial_tx2)

        # wallet1 gets raw partial tx2, and signs
        tx2 = tx_from_any(partial_tx2)
        wallet1.sign_transaction(tx2, password=None)
        tx = tx_from_any(tx2.serialize_as_bytes().hex())  # simulates moving partial txn between cosigners

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual("02000000000102e546bc0a7c9736e82a07df5c24fe6d05df58a310dc376cf09302842ca7264f930100000000fdffffffd5bd4f8ebe63f0521f94e2d174b95d4327757a7e74fda3c9ff5c08796318f8d80000000000fdffffff04988d07000000000016001453675a59be834aa6d139c3ebea56646a9b160c4cb82e0f0000000000160014250dbabd5761d7e0773d6147699938dd08ec2eb88096980000000000160014b93357242ad5a6fff8930ce9dadd8ba44a6c44498096980000000000160014e2672a59431c261903c9469aa082202f37a859a40247304402205106349e1644223b5128009376fc497477227172ac28a54942da58014869d4f502205aa60ba466f53b52c5933c39cfa1ab735c1722029039d7a5a7577789ae891389012102275b4fba18bb34e5198a9cfb3e940306658839079b3bda50d504a9cf2bae36f402473044022003010ece3471f7a23f31b2a0fd157f88f7d436c0c73ec408043c7f5dd2b7ccbb02204bd21f5829555c3f94fbd0b5295d1071f739c6b8f2682f8a688e34d0ad26c90101210205e8db1b1906219782fadb18e763c0874a3118a17ce931e01707cbde194e04156f851800",
                         str(tx))
        self.assertEqual('4a33546eeaed0e25f9e6a58968be92a804a7e70a5332360dabc79f93cd059752', tx.txid())
        self.assertEqual('32584f78479a1b6f7aeff4f4d0e0323b67c36ce155d010f9b324b6189b91a540', tx.wtxid())

        wallet1.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        wallet2.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # wallet level checks
        self.assertEqual((0, 10995000, 0), wallet1.get_balance())
        self.assertEqual((0, 10495000, 0), wallet2.get_balance())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_standard_wallet_cannot_sign_multisig_input_even_if_cosigner(self, mock_save_db):
        """Just because our keystore recognizes the pubkeys in a txin, if the prevout does not belong to the wallet,
        then wallet.is_mine and wallet.can_sign should return False (e.g. multisig input for single-sig wallet).
        (see issue #5948)
        """
        wallet_2of2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                # seed: frost repair depend effort salon ring foam oak cancel receive save usage
                # convert_xkey(wallet.get_master_public_key(), "p2wsh")
                keystore.from_xpub('Vpub5gqF73Wpbp9ThwEgZKHLjBDthsatXjajYvrN8CVnkdBYeTR1M1sfZFQqQ5wpKHGhnwKhzgMhaWrtgKG2LthCzxjd653KqKVUAw7UrwYnbKQ'),
                # seed: bitter grass shiver impose acquire brush forget axis eager alone wine silver
                # convert_xkey(wallet.get_master_public_key(), "p2wsh")
                keystore.from_xpub('Vpub5gSKXzxK7FeKNi2WPNW9iuA48SbJRZvKFBwtgucpegMWPdohQPeK2DoR6XFtC7BBLsHhfWDAPKaiecqJ7jTzYSfeg5YATowmPcgCWxARabT')
            ],
            '2of2', gap_limit=2,
            config=self.config
        )
        wallet_frost = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage')

        # bootstrap wallet_2of2
        funding_tx = Transaction('020000000001018ed0132bb5f35d097572081524cd5e847c895e765b93d5af46b8a8bef621244a0100000000fdffffff0220a1070000000000220020302981db44eb5dad0dab3987134a985b360ae2227a7e7a10cfe8cffd23bacdc9b07912000000000016001442b423aab2aa803f957084832b10359beaa2469002473044022065c5e28900b4706487223357e8539e176552e3560e2081ac18de7c26e8e420ba02202755c7fc8177ff502634104c090e3fd4c4252bfa8566d4eb6605bb9e236e7839012103b63bbf85ec9e5e312e4d7a2b45e690f48b916a442e787a47a6092d6c052394c5966a1900')
        funding_txid = funding_tx.txid()
        self.assertEqual('0c2f5981981a6cb69d7b729feceb55be7962b16dc41e8aaf64e5203f7cb604d0', funding_txid)
        wallet_2of2.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('tb1qfrlx5pza9vmez6vpx7swt8yp0nmgz3qa7jjkuf', 100_000)]
        coins = wallet_2of2.get_spendable_coins(domain=None)
        tx = wallet_2of2.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1665628

        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007d0200000001d004b67c3f20e564af8a1ec46db16279be55ebec9f727b9db66c1a9881592f0c0000000000fdffffff02a08601000000000016001448fe6a045d2b3791698137a0e59c817cf681441df806060000000000220020eb428a0bdeca2c1b3731aedb81c0518456875a99755d177d204d6516d8f6b3075c6a19000001012b20a1070000000000220020302981db44eb5dad0dab3987134a985b360ae2227a7e7a10cfe8cffd23bacdc90100ea020000000001018ed0132bb5f35d097572081524cd5e847c895e765b93d5af46b8a8bef621244a0100000000fdffffff0220a1070000000000220020302981db44eb5dad0dab3987134a985b360ae2227a7e7a10cfe8cffd23bacdc9b07912000000000016001442b423aab2aa803f957084832b10359beaa2469002473044022065c5e28900b4706487223357e8539e176552e3560e2081ac18de7c26e8e420ba02202755c7fc8177ff502634104c090e3fd4c4252bfa8566d4eb6605bb9e236e7839012103b63bbf85ec9e5e312e4d7a2b45e690f48b916a442e787a47a6092d6c052394c5966a19000105475221028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c521030faee9b4a25b7db82023ca989192712cdd4cb53d3d9338591c7909e581ae1c0c52ae2206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000002206030faee9b4a25b7db82023ca989192712cdd4cb53d3d9338591c7909e581ae1c0c10b2e35a7d0000008000000000000000000000010147522102105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea21028584e789e39f41391b2f27852ca18abec06a5411c21be350fed61eec7120de5352ae220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a903980000008001000000000000002202028584e789e39f41391b2f27852ca18abec06a5411c21be350fed61eec7120de5310b2e35a7d00000080010000000000000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners

        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('652c1a903a659c9fabb9caf4a2281a9fbcc59cd598bf6edc88cd60f940c2352c', tx.txid())

        self.assertEqual('tb1qxq5crk6yadw66rdt8xr3xj5ctvmq4c3z0fl85yx0ar8l6ga6ehysk0rjrk', tx.inputs()[0].address)
        self.assertEqual('tb1qfrlx5pza9vmez6vpx7swt8yp0nmgz3qa7jjkuf',                     tx.outputs()[0].address)
        self.assertEqual('tb1qadpg5z77egkpkde34mdcrsz3s3tgwk5ew4w3wlfqf4j3dk8kkvrs3t3mn0', tx.outputs()[1].address)

        # check that wallet_frost does not mistakenly think tx is related to it in any way
        tx.add_info_from_wallet(wallet_frost)
        self.assertFalse(wallet_frost.can_sign(tx))
        self.assertFalse(any([wallet_frost.is_mine(txin.address) for txin in tx.inputs()]))
        self.assertFalse(any([wallet_frost.is_mine(txout.address) for txout in tx.outputs()]))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_dscancel(self, mock_save_db):
        self.maxDiff = None
        config = SimpleConfig({'electrum_path': self.electrum_path})
        config.WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = False

        for simulate_moving_txs in (False, True):
            with self.subTest(msg="_dscancel_when_all_outputs_are_ismine", simulate_moving_txs=simulate_moving_txs):
                await self._dscancel_when_all_outputs_are_ismine(
                    simulate_moving_txs=simulate_moving_txs,
                    config=config)
            with self.subTest(msg="_dscancel_p2wpkh_when_there_is_a_change_address", simulate_moving_txs=simulate_moving_txs):
                await self._dscancel_p2wpkh_when_there_is_a_change_address(
                    simulate_moving_txs=simulate_moving_txs,
                    config=config)
            with self.subTest(msg="_dscancel_when_user_sends_max", simulate_moving_txs=simulate_moving_txs):
                await self._dscancel_when_user_sends_max(
                    simulate_moving_txs=simulate_moving_txs,
                    config=config)
            with self.subTest(msg="_dscancel_when_not_all_inputs_are_ismine", simulate_moving_txs=simulate_moving_txs):
                await self._dscancel_when_not_all_inputs_are_ismine(
                    simulate_moving_txs=simulate_moving_txs,
                    config=config)

    async def _dscancel_when_all_outputs_are_ismine(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('fold object utility erase deputy output stadium feed stereo usage modify bean',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('010000000001011f4db0ecd81f4388db316bc16efb4e9daf874cf4950d54ecb4c0fb372433d68500000000171600143d57fd9e88ef0e70cddb0d8b75ef86698cab0d44fdffffff0280969800000000001976a91472e34cebab371967b038ce41d0e8fa1fb983795e88ac86a0ae020000000017a9149188bc82bdcae077060ebb4f02201b73c806edc887024830450221008e0725d531bd7dee4d8d38a0f921d7b1213e5b16c05312a80464ecc2b649598d0220596d309cf66d5f47cb3df558dbb43c5023a7796a80f5a88b023287e45a4db6b9012102c34d61ceafa8c216f01e05707672354f8119334610f7933a3f80dd7fb6290296bd391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('03052739fcfa2ead5f8e57e26021b0c2c546bcd3d74c6e708d5046dc58d90762', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('miFLSDZBXUo4on8PGhTRTAufUn4mP61uoH', '!')]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1859362
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff01005502000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc392705030000000000fdffffff01f8829800000000001976a9141df43441a3a3ee563e560d3ddc7e07cc9f9c3cdb88ac225f1c00000100fa010000000001011f4db0ecd81f4388db316bc16efb4e9daf874cf4950d54ecb4c0fb372433d68500000000171600143d57fd9e88ef0e70cddb0d8b75ef86698cab0d44fdffffff0280969800000000001976a91472e34cebab371967b038ce41d0e8fa1fb983795e88ac86a0ae020000000017a9149188bc82bdcae077060ebb4f02201b73c806edc887024830450221008e0725d531bd7dee4d8d38a0f921d7b1213e5b16c05312a80464ecc2b649598d0220596d309cf66d5f47cb3df558dbb43c5023a7796a80f5a88b023287e45a4db6b9012102c34d61ceafa8c216f01e05707672354f8119334610f7933a3f80dd7fb6290296bd391400220602a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587a0c8296e571000000000000000000220202a7536f0bfbc60c5a8e86e2b9df26431fc062f9f454016dbc26f2467e0bc98b3f0c8296e571000000000100000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('02000000016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc39270503000000006a47304402200c1ad6499cfd7a808c2463e211e0aaf503a571c85b679e69af215b76f05ad74d022066fccfec30164ad62686734ec3eca024e33e935b1bf30a98df85d87f01ba1b5f012102a807c07bd7975211078e916bdda061d97e98d59a3631a804aada2f9a3f5b587afdffffff01f8829800000000001976a9141df43441a3a3ee563e560d3ddc7e07cc9f9c3cdb88ac225f1c00',
                         str(tx_copy))
        self.assertEqual('200d5173d3113e9cec7a63e885b64836245572d93b6dda4035f3ed44341b6277', tx_copy.txid())
        self.assertEqual('200d5173d3113e9cec7a63e885b64836245572d93b6dda4035f3ed44341b6277', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 5000, 0), wallet.get_balance())

        # cancel tx
        tx_details = wallet.get_tx_info(tx_from_any(tx.serialize()))
        self.assertFalse(tx_details.can_dscancel)

    async def _dscancel_p2wpkh_when_there_is_a_change_address(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid = funding_tx.txid()
        funding_output_value = 10000000
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', 2500000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100720100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed5bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff02a02526000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987585d720000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402205442705e988abe74bf391b293bb1b886674284a92ed0788c33024f9336d60aef022013a93049d3bed693254cd31a704d70bb988a36750f0b74d0a5b4d9e29c54ca9d0121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('b019bbad45a46ed25365e46e4cae6428fb12ae425977eb93011ffb294cb4977e', tx_copy.txid())
        self.assertEqual('ba87313e2b3b42f1cc478843d4d53c72d6e06f6c66ac8cfbe2a59cdac2fd532d', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, funding_output_value - 2500000 - 5000, 0), wallet.get_balance())

        # cancel tx
        tx_details = wallet.get_tx_info(tx_from_any(tx.serialize()))
        self.assertTrue(tx_details.can_dscancel)
        tx = wallet.dscancel(tx=tx_from_any(tx.serialize()), new_fee_rate=70.0)
        tx.locktime = 1859397
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100520200000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff016c78980000000000160014f0fe5c1867a174a12e70165e728a072619455ed5455f1c000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a9039800000080000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff016c78980000000000160014f0fe5c1867a174a12e70165e728a072619455ed50247304402201e706f7ab50e4212a98782e483476102cd6579dad91196002b13dedec79a9a6302205ae30e6c3cf6dd8c566ddae090eeedaac09ba0adc4c0205dfa77bc627621a6b70121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5455f1c00',
                         str(tx_copy))
        self.assertEqual('165f82b1440cd3a31c005cec660cf834917a1e0a89011805a620c702840fc46a', tx_copy.txid())
        self.assertEqual('a164fff4f4231a09e8745eb27d0fe636c5c291400b8506d932b0bde6ff8cf9ee', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 9992300, 0), wallet.get_balance())

    async def _dscancel_when_user_sends_max(self, *, simulate_moving_txs, config):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=config)

        # bootstrap wallet
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx
        outputs = [PartialTxOutput.from_address_and_value('2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL', '!')]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1325499
        tx.version = 1
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100530100000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987bb3914000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a903980000008000000000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        wallet.sign_transaction(tx, password=None)

        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        tx_copy = tx_from_any(tx.serialize())
        self.assertTrue(wallet.is_mine(wallet.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())
        self.assertEqual(tx.wtxid(), tx_copy.wtxid())
        self.assertEqual('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff01f88298000000000017a9145a71fc1a7a98ddd67be935ade1600981c0d066f987024730440220520ab41536d5d0fac8ad44e6aa4a8258a266121bab1eb6599f1ee86bbc65719d02205944c2fb765fca4753a850beadac49f5305c6722410c347c08cec4d90e3eb4430121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c5bb391400',
                         str(tx_copy))
        self.assertEqual('dc4b622f3225f00edb886011fa02b74630cdbc24cebdd3210d5ea3b68bef5cc9', tx_copy.txid())
        self.assertEqual('a00340ee8c90673e05f2cf368601b6bba6a7f0513bd974feb218a326e39b1874', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 0, 0), wallet.get_balance())

        # cancel tx
        tx_details = wallet.get_tx_info(tx_from_any(tx.serialize()))
        self.assertTrue(tx_details.can_dscancel)
        tx = wallet.dscancel(tx=tx_from_any(tx.serialize()), new_fee_rate=70.0)
        tx.locktime = 1859455
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100520200000001c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff016c78980000000000160014f0fe5c1867a174a12e70165e728a072619455ed57f5f1c000001011f8096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b70100fda20101000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb3914002206028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c510e8a9039800000080000000000000000000220202105dd9133f33cbd4e50443ef9af428c0be61f097f8942aaa916f50b530125aea10e8a9039800000080010000000000000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520100000000fdffffff016c78980000000000160014f0fe5c1867a174a12e70165e728a072619455ed502473044022013892ba1580bd8b35fe74cb7a0dceb6914b01ed5cfef6435b94ac0256866971c02200290d08d5f199fcdbba1a2dc4884f5cdea0177cb88e423d8588480d6a5fd62740121028d4c44ca36d2c4bff3813df8d5d3c0278357521ecb892cd694c473c03970e4c57f5f1c00',
                         str(tx_copy))
        self.assertEqual('42e222b8faff6cb7fcb82697e04f7bc88a5ed57293773a57a5e400ce0450203e', tx_copy.txid())
        self.assertEqual('0c6511d0c008604948ea68b0f8cb3da00966c5a97a08a220716ff47eecd4922d', tx_copy.wtxid())

        wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual((0, 9992300, 0), wallet.get_balance())

    async def _dscancel_when_not_all_inputs_are_ismine(self, *, simulate_moving_txs, config):
        class NetworkMock:
            relay_fee = 1000
            async def get_transaction(self, txid, timeout=None):
                if txid == "597098f9077cd2a7bf5bb2a03c9ae5fcd9d1f07c0891cb42cbb129cf9eaf57fd":
                    return "02000000000102a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540000000000fdffffffbdeb0175b1c51c96843d1952f7e1c49c1703717d7d020048d4de0a8eed94dad50000000000fdffffff03b2a00700000000001600140cd6c9f8ce0aa73d77fcf7f156c74f5cbec6906bb2a00700000000001600146435504ddc95e6019a90bb7dfc7ca81a88a8633106d790000000000016001444bd3017ee214370abf683abaa7f6204c9f40210024730440220652a04a2a301d9a031a034f3ae48174e204e17acf7bfc27f0dcab14243f73e2202207b29e964c434dfb2c515232d36566a40dccd4dd93ccb7fd15260ecbda10f0d9801210231994e564a0530068d17a9b0f85bec58d1352517a2861ea99e5b3070d2c5dbda02473044022072186473874919019da0e3d92b6e0aa4f88cba448ed5434615e5a3c8e2b7c42a02203ec05cef66960d5bc45d0f3d25675190cf8035b11a05ed4b719fd9c3a894899b012102f5fdca8c4e30ba0a1babf9cf9ebe62519b08aead351c349ed1ffc8316c24f542d7f61c00"
                else:
                    raise Exception("unexpected txid")
            def has_internet_connection(self):
                return True
            run_from_another_thread = Network.run_from_another_thread
            def get_local_height(self):
                return 0
            def blockchain(self):
                class BlockchainMock:
                    def is_tip_stale(self):
                        return True
                return BlockchainMock()

        wallet = self.create_standard_wallet_from_seed('mix total present junior leader live state athlete mistake crack wall valve',
                                                       config=config)
        wallet.network = NetworkMock()

        # bootstrap wallet
        funding_tx = Transaction('02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c00')
        funding_txid = funding_tx.txid()
        self.assertEqual('08557327673db61cc921e1a30826608599b86457836be3021105c13940d9a9a3', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        orig_rbf_tx = Transaction('02000000000102a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdfffffffd57af9ecf29b1cb42cb91087cf0d1d9fce59a3ca0b25bbfa7d27c07f99870590200000000fdffffff03b2a00700000000001600145dc80fd43eb70fd21a6c4446e3ce043df94f100cb2a00700000000001600147db4ab480b7d2218fba561ff304178f4afcbc972be358900000000001600149d91f0053172fab394d277ae27e9fa5c5a49210902473044022003999f03be8b9e299b2cd3bc7bce05e273d5d9ce24fc47af8754f26a7a13e13f022004e668499a67061789f6ebd2932c969ece74417ae3f2307bf696428bbed4fe36012102a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb0247304402207121358a66c0e716e2ba2be928076736261c691b4fbf89ea8d255449a4f5837b022042cadf9fe1b4f3c03ede3cef6783b42f0ba319f2e0273b624009cd023488c4c1012103a5ba95fb1e0043428ed70680fc17db254b3f701dfccf91e48090aa17c1b7ea40fef61c00')
        orig_rbf_txid = orig_rbf_tx.txid()
        self.assertEqual('6057690010ddac93a371629e1f41866400623e13a9cd336d280fc3239086a983', orig_rbf_txid)
        wallet.adb.receive_tx_callback(orig_rbf_tx, TX_HEIGHT_UNCONFIRMED)

        # bump tx
        orig_rbf_tx = tx_from_any(orig_rbf_tx.serialize())
        orig_rbf_tx.add_info_from_wallet(wallet=wallet)
        await orig_rbf_tx.add_info_from_network(network=wallet.network)
        tx = wallet.dscancel(tx=orig_rbf_tx, new_fee_rate=70)
        tx.locktime = 1898278
        tx.version = 2
        if simulate_moving_txs:
            partial_tx = tx.serialize_as_bytes().hex()
            self.assertEqual("70736274ff0100520200000001a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdffffff010c830700000000001600145dc80fd43eb70fd21a6c4446e3ce043df94f100c26f71c000001011f20a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec7270100de02000000000101a5883f3de780d260e6f26cf85144403c7744a65a44cd38f9ff45aecadf010c540100000000fdffffff0220a1070000000000160014db44724ac632ae47ee5765954d64796dd5fec72708de3c000000000016001424b32aadb42a89016c4de8f11741c3b29b15f21c02473044022045cc6c1cc875cbb0c0d8fe323dc1de9716e49ed5659741b0fb3dd9a196894066022077c242640071d12ec5763c5870f482a4823d8713e4bd14353dd621ed29a7f96d012102aea8d439a0f79d8b58e8d7bda83009f587e1f3da350adaa484329bf47cd03465fef61c00220602a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb109c9fff980000008000000000000000000022020353becea8bbfe746452e5d2fa2e0688013e43ca6409c8e30b6cc99e7625ff2265109c9fff9800000080000000000100000000",
                             partial_tx)
            tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertFalse(tx.is_complete())

        wallet.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101a3a9d94039c1051102e36b835764b89985602608a3e121c91cb63d67277355080000000000fdffffff010c830700000000001600145dc80fd43eb70fd21a6c4446e3ce043df94f100c0247304402202e75e1edceb8ce27d75814bc7895bc48a0d5c423b492b980b655908612485cc8022072a947c4516ab220d0825634efd8b1ad3a5503e63ed8fbb97700b5d73786c63f012102a1c9b25b37aa31ccbb2d72caaffce81ec8253020a74017d92bbfc14a832fc9cb26f71c00',
                         str(tx_copy))
        self.assertEqual('3021a4fe24e33af9d0ccdf25c478387c97df671fe1fd8b4db0de4255b3a348c5', tx_copy.txid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_wallet_history_chain_of_unsigned_transactions(self, mock_save_db):
        wallet = self.create_standard_wallet_from_seed('cross end slow expose giraffe fuel track awake turtle capital ranch pulp',
                                                       config=self.config, gap_limit=3)

        # bootstrap wallet
        funding_tx = Transaction('0200000000010132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a02473044022041ed68ef7ef122813ac6a5e996b8284f645c53fbe6823b8e430604a8915a867802203233f5f4d347a687eb19b2aa570829ab12aeeb29a24cc6d6d20b8b3d79e971ae012102bee0ee043817e50ac1bb31132770f7c41e35946ccdcb771750fb9696bdd1b307ad951d00')
        funding_txid = funding_tx.txid()
        self.assertEqual('db949963c3787c90a40fb689ffdc3146c27a9874a970d1fd20921afbe79a7aa9', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create tx1
        outputs = [PartialTxOutput.from_address_and_value('tb1qsfcddwf7yytl62e3catwv8hpl2hs9e36g2cqxl', 100000)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=190)
        tx.set_rbf(True)
        tx.locktime = 1938861
        tx.version = 2
        self.assertEqual("70736274ff0100710200000001a97a9ae7fb1a9220fdd170a974987ac24631dcff89b60fa4907c78c3639994db0000000000fdffffff02a0860100000000001600148270d6b93e2117fd2b31c756e61ee1faaf02e63ab4fc1c0000000000160014b8e4fdc91593b67de2bf214694ef47e38dc2ee8ead951d000001011f12841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a0100bf0200000000010132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a02473044022041ed68ef7ef122813ac6a5e996b8284f645c53fbe6823b8e430604a8915a867802203233f5f4d347a687eb19b2aa570829ab12aeeb29a24cc6d6d20b8b3d79e971ae012102bee0ee043817e50ac1bb31132770f7c41e35946ccdcb771750fb9696bdd1b307ad951d002206026cc6a74c2b0e38661d341ffae48fe7dde5196ca4afe95d28b496673fa4cf6467105f83afb40000008000000000000000000022020312ea49b9b1eea28e3330316a5b7e6673b43e01da38f802c99a777d30b903fa5e105f83afb40000008000000000010000000022020349321bee98c012887997f26c6400018b0711dd254b702c038b96a30ebe2af1d2105f83afb400000080010000000000000000",
                         tx.serialize_as_bytes().hex())
        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        wallet.adb.add_transaction(tx)

        # create tx2, which spends from unsigned tx1
        outputs = [PartialTxOutput.from_address_and_value('tb1qq0lm9esmq6pfjc3jls7v6twy93lnqcs85wlth3', '!')]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 1938863
        tx.version = 2
        self.assertEqual("70736274ff01007b020000000288234495e0ff1d8ac06038f6cc5d5a92738d719f4c15afd581366da94754478f0000000000fdffffff88234495e0ff1d8ac06038f6cc5d5a92738d719f4c15afd581366da94754478f0100000000fdffffff01cc6f1e000000000016001403ffb2e61b0682996232fc3ccd2dc42c7f306207af951d000001011fa0860100000000001600148270d6b93e2117fd2b31c756e61ee1faaf02e63a22060312ea49b9b1eea28e3330316a5b7e6673b43e01da38f802c99a777d30b903fa5e105f83afb40000008000000000010000000001011fb4fc1c0000000000160014b8e4fdc91593b67de2bf214694ef47e38dc2ee8e22060349321bee98c012887997f26c6400018b0711dd254b702c038b96a30ebe2af1d2105f83afb4000000800100000000000000002202036f9a5913f1c22742dbc9e7f3ac3064be8b125a23563fcc8a519f387e16c7244c105f83afb400000080000000000200000000",
                         tx.serialize_as_bytes().hex())
        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        wallet.adb.add_transaction(tx)

        coins = wallet.get_spendable_coins(domain=None)
        self.assertEqual(1, len(coins))
        self.assertEqual("bf08206effded4126a95fbed375cedc0452b5e16a5d2025ac645dfae81addbe4:0",
                         coins[0].prevout.to_str())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_wallet_does_not_create_zero_input_tx(self, mock_save_db):
        wallet = self.create_standard_wallet_from_seed('cross end slow expose giraffe fuel track awake turtle capital ranch pulp',
                                                       config=self.config, gap_limit=3)

        with self.subTest(msg="no coins to use as inputs, max output value, zero fee"):
            outputs = [PartialTxOutput.from_address_and_value('tb1qsfcddwf7yytl62e3catwv8hpl2hs9e36g2cqxl', '!')]
            coins = wallet.get_spendable_coins(domain=None)
            with self.assertRaises(NotEnoughFunds):
                tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=0)

        # bootstrap wallet
        funding_tx = Transaction('0200000000010132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a02473044022041ed68ef7ef122813ac6a5e996b8284f645c53fbe6823b8e430604a8915a867802203233f5f4d347a687eb19b2aa570829ab12aeeb29a24cc6d6d20b8b3d79e971ae012102bee0ee043817e50ac1bb31132770f7c41e35946ccdcb771750fb9696bdd1b307ad951d00')
        funding_txid = funding_tx.txid()
        self.assertEqual('db949963c3787c90a40fb689ffdc3146c27a9874a970d1fd20921afbe79a7aa9', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        with self.subTest(msg="funded wallet, zero output value, zero fee"):
            outputs = [PartialTxOutput.from_address_and_value('tb1qsfcddwf7yytl62e3catwv8hpl2hs9e36g2cqxl', 0)]
            coins = wallet.get_spendable_coins(domain=None)
            tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=0)
            self.assertEqual(1, len(tx.inputs()))
            self.assertEqual(2, len(tx.outputs()))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_imported_wallet_usechange_off(self, mock_save_db):
        wallet = restore_wallet_from_text(
            "p2wpkh:cVcwSp488C8Riguq55Tuktgi6TpzuyLdDwUxkBDBz3yzV7FW4af2 p2wpkh:cPWyoPvnv2hiyyxbhMkhX3gPEENzB6DqoP9bbR8SDTg5njK5SL9n",
            path='if_this_exists_mocking_failed_648151893',
            config=self.config)['wallet']  # type: Abstract_Wallet

        # bootstrap wallet
        funding_tx = Transaction('02000000000101c6edaaf0157020a38de8b07810b22ffe331d5b79c83b680dad24da15c572ae7d0000000000fdffffff026080010000000000160014eabbd791df76eeeaa3ed273cac4e1dde3be295cca0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210247304402203cb8b2f84ed4fb8de5f51a07b2159bc0d8d474e5dba0f77cc66ab641cf48621b022076fb3c6b4bc76aa06dd29ebe1dd081c063cdbd2949ffcf4ab4bd8bddae6c948b0121029f16b602a6b3c738b66a03dd5133abe810169a377bbc2fdf5c5363f59b8d9bdec3951e00')
        funding_txid = funding_tx.txid()
        self.assertEqual('9bed2a210b4154183295bc7b78c8841a3a6116197713f744e5cd95ab0c0c01ce', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # imported wallets do not send change to change addresses by default
        # (they send it back to the "from address")
        self.assertFalse(wallet.use_change)

        outputs = [PartialTxOutput.from_address_and_value('tb1qq4pypzwxf5uanfyckmsu3ejxxf6rrvjqchza3v', 49646)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=1000)
        tx.set_rbf(True)
        tx.locktime = 2004420
        tx.version = 2

        # check that change is sent back to the "from address"
        self.assertEqual(2, len(tx.outputs()))
        self.assertTrue(tx.output_value_for_address("tb1q0fj7pxa3m2q2hlr964zn3z3wvx4t03ep5fgnhy") > 0)
        self.assertEqual(49646, tx.output_value_for_address("tb1qq4pypzwxf5uanfyckmsu3ejxxf6rrvjqchza3v"))

        self.assertEqual("70736274ff0100710200000001ce010c0cab95cde544f713771916613a1a84c8787bbc95321854410b212aed9b0100000000fdffffff02cac00000000000001600147a65e09bb1da80abfc65d545388a2e61aab7c721eec100000000000016001405424089c64d39d9a498b6e1c8e646327431b240c4951e000001011fa0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210100de02000000000101c6edaaf0157020a38de8b07810b22ffe331d5b79c83b680dad24da15c572ae7d0000000000fdffffff026080010000000000160014eabbd791df76eeeaa3ed273cac4e1dde3be295cca0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210247304402203cb8b2f84ed4fb8de5f51a07b2159bc0d8d474e5dba0f77cc66ab641cf48621b022076fb3c6b4bc76aa06dd29ebe1dd081c063cdbd2949ffcf4ab4bd8bddae6c948b0121029f16b602a6b3c738b66a03dd5133abe810169a377bbc2fdf5c5363f59b8d9bdec3951e00000000",
                         tx.serialize_as_bytes().hex())
        wallet.sign_transaction(tx, password=None)
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101ce010c0cab95cde544f713771916613a1a84c8787bbc95321854410b212aed9b0100000000fdffffff02cac00000000000001600147a65e09bb1da80abfc65d545388a2e61aab7c721eec100000000000016001405424089c64d39d9a498b6e1c8e646327431b240024730440220526eac6c56cba19842b67f6c9e45af113b1a2d44fb229335bdeaf08cb2cc164e0220087fba65619016fd3f62f6c8717070e48f94b45743b86d8e0517698d2b9c3afc012102d67eaa10463f5c786271feb9ae3456c27d35c3cf6c7d881617e915d1f32cb875c4951e00',
                         str(tx_copy))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_imported_wallet_usechange_on(self, mock_save_db):
        wallet = restore_wallet_from_text(
            "p2wpkh:cVcwSp488C8Riguq55Tuktgi6TpzuyLdDwUxkBDBz3yzV7FW4af2 p2wpkh:cPWyoPvnv2hiyyxbhMkhX3gPEENzB6DqoP9bbR8SDTg5njK5SL9n",
            path='if_this_exists_mocking_failed_648151893',
            config=self.config)['wallet']  # type: Abstract_Wallet

        # bootstrap wallet
        funding_tx = Transaction('02000000000101c6edaaf0157020a38de8b07810b22ffe331d5b79c83b680dad24da15c572ae7d0000000000fdffffff026080010000000000160014eabbd791df76eeeaa3ed273cac4e1dde3be295cca0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210247304402203cb8b2f84ed4fb8de5f51a07b2159bc0d8d474e5dba0f77cc66ab641cf48621b022076fb3c6b4bc76aa06dd29ebe1dd081c063cdbd2949ffcf4ab4bd8bddae6c948b0121029f16b602a6b3c738b66a03dd5133abe810169a377bbc2fdf5c5363f59b8d9bdec3951e00')
        funding_txid = funding_tx.txid()
        self.assertEqual('9bed2a210b4154183295bc7b78c8841a3a6116197713f744e5cd95ab0c0c01ce', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # instead of sending the change back to the "from address", we want it sent to another unused address
        wallet.use_change = True

        outputs = [PartialTxOutput.from_address_and_value('tb1qq4pypzwxf5uanfyckmsu3ejxxf6rrvjqchza3v', 49646)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=1000)
        tx.set_rbf(True)
        tx.locktime = 2004420
        tx.version = 2

        # check that change is sent to another unused imported address
        self.assertEqual(2, len(tx.outputs()))
        self.assertTrue(tx.output_value_for_address("tb1qetcgdwuzlpdnt5fmzxxdpczjhadz06cynpttpv") > 0)
        self.assertEqual(49646, tx.output_value_for_address("tb1qq4pypzwxf5uanfyckmsu3ejxxf6rrvjqchza3v"))

        self.assertEqual("70736274ff0100710200000001ce010c0cab95cde544f713771916613a1a84c8787bbc95321854410b212aed9b0100000000fdffffff02cac0000000000000160014caf086bb82f85b35d13b118cd0e052bf5a27eb04eec100000000000016001405424089c64d39d9a498b6e1c8e646327431b240c4951e000001011fa0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210100de02000000000101c6edaaf0157020a38de8b07810b22ffe331d5b79c83b680dad24da15c572ae7d0000000000fdffffff026080010000000000160014eabbd791df76eeeaa3ed273cac4e1dde3be295cca0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210247304402203cb8b2f84ed4fb8de5f51a07b2159bc0d8d474e5dba0f77cc66ab641cf48621b022076fb3c6b4bc76aa06dd29ebe1dd081c063cdbd2949ffcf4ab4bd8bddae6c948b0121029f16b602a6b3c738b66a03dd5133abe810169a377bbc2fdf5c5363f59b8d9bdec3951e00000000",
                         tx.serialize_as_bytes().hex())
        wallet.sign_transaction(tx, password=None)
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101ce010c0cab95cde544f713771916613a1a84c8787bbc95321854410b212aed9b0100000000fdffffff02cac0000000000000160014caf086bb82f85b35d13b118cd0e052bf5a27eb04eec100000000000016001405424089c64d39d9a498b6e1c8e646327431b24002473044022006dfe30f851b0174e5c920fd5b2e294a25fe5d449b17b422f3fda485d514c39b022047a6760f9d6ddfac5273094bed1f640fc1622a42938ebfb0b5f61cce7b161a00012102d67eaa10463f5c786271feb9ae3456c27d35c3cf6c7d881617e915d1f32cb875c4951e00',
                         str(tx_copy))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_imported_wallet_usechange_on__no_more_unused_addresses(self, mock_save_db):
        wallet = restore_wallet_from_text(
            "p2wpkh:cVcwSp488C8Riguq55Tuktgi6TpzuyLdDwUxkBDBz3yzV7FW4af2 p2wpkh:cPWyoPvnv2hiyyxbhMkhX3gPEENzB6DqoP9bbR8SDTg5njK5SL9n",
            path='if_this_exists_mocking_failed_648151893',
            config=self.config)['wallet']  # type: Abstract_Wallet

        # bootstrap wallet
        funding_tx = Transaction('02000000000101c6edaaf0157020a38de8b07810b22ffe331d5b79c83b680dad24da15c572ae7d0000000000fdffffff026080010000000000160014eabbd791df76eeeaa3ed273cac4e1dde3be295cca0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210247304402203cb8b2f84ed4fb8de5f51a07b2159bc0d8d474e5dba0f77cc66ab641cf48621b022076fb3c6b4bc76aa06dd29ebe1dd081c063cdbd2949ffcf4ab4bd8bddae6c948b0121029f16b602a6b3c738b66a03dd5133abe810169a377bbc2fdf5c5363f59b8d9bdec3951e00')
        funding_txid = funding_tx.txid()
        self.assertEqual('9bed2a210b4154183295bc7b78c8841a3a6116197713f744e5cd95ab0c0c01ce', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)
        # add more txs so that all addresses become used
        _txs = [
            ("077c8f7a3b0cbb660192c3e35d01a65694f7b90b10e4c6434713912c44cdbfb7", "02000000000101bc125beec2014e3b89679207116e28bcf5bf85cab63ac2903119c8c21ab84cac0100000000fdffffff02daff000000000000160014caf086bb82f85b35d13b118cd0e052bf5a27eb04814201000000000016001491145275b4c4a4814b733fbd28f2a519a5874bad02473044022008ae14e4f7802639a34e92348db7eef95c9fb5d480d7a110d4b11e7d0c45a0cc02205d29414eebcdc76a07f5e2422ed3e560cd663de4b733a0f9c7b3ad7102a733510121030438b8bdbe8121b6a6508e54247b9d1b0547d9ac94c4d3154afd7d7376fe7ae6b6951e00"),
            ("5f8e17612ad4e04819f1b1cf9039509518e230db07140b2eec81582a8647f8d6", "02000000000101b7bfcd442c91134743c6e4100bb9f79456a6015de3c3920166bb0c3b7a8f7c070000000000fdffffff016cff0000000000001600146a84f3681e545d13fa41de090b6e404401198e7d0247304402204e16704d836cb6e1fffa34244c42578267853e8c3933a3d367bd6a236c24596a0220025a7be9483eeba06a433b96b5cb35a6a4b117ffa884569b09cedc4a5f3d6381012103c19caa2ced1b74bf31ba7885d83eeda35c0011e740273ebdf6750e0298588cc5c7951e00"),
        ]
        for txid, rawtx in _txs:
            tx = Transaction(rawtx)
            self.assertEqual(txid, tx.txid())
            wallet.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        # instead of sending the change back to the "from address", we want it sent to another unused address.
        # (except all our addresses are used! so we expect change sent back to "from address")
        wallet.use_change = True

        outputs = [PartialTxOutput.from_address_and_value('tb1qq4pypzwxf5uanfyckmsu3ejxxf6rrvjqchza3v', 49646)]
        coins = wallet.get_spendable_coins(domain=None)
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=1000)
        tx.set_rbf(True)
        tx.locktime = 2004420
        tx.version = 2

        # check that change is sent back to the "from address"
        self.assertEqual(2, len(tx.outputs()))
        self.assertTrue(tx.output_value_for_address("tb1q0fj7pxa3m2q2hlr964zn3z3wvx4t03ep5fgnhy") > 0)
        self.assertEqual(49646, tx.output_value_for_address("tb1qq4pypzwxf5uanfyckmsu3ejxxf6rrvjqchza3v"))

        self.assertEqual("70736274ff0100710200000001ce010c0cab95cde544f713771916613a1a84c8787bbc95321854410b212aed9b0100000000fdffffff02cac00000000000001600147a65e09bb1da80abfc65d545388a2e61aab7c721eec100000000000016001405424089c64d39d9a498b6e1c8e646327431b240c4951e000001011fa0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210100de02000000000101c6edaaf0157020a38de8b07810b22ffe331d5b79c83b680dad24da15c572ae7d0000000000fdffffff026080010000000000160014eabbd791df76eeeaa3ed273cac4e1dde3be295cca0860100000000001600147a65e09bb1da80abfc65d545388a2e61aab7c7210247304402203cb8b2f84ed4fb8de5f51a07b2159bc0d8d474e5dba0f77cc66ab641cf48621b022076fb3c6b4bc76aa06dd29ebe1dd081c063cdbd2949ffcf4ab4bd8bddae6c948b0121029f16b602a6b3c738b66a03dd5133abe810169a377bbc2fdf5c5363f59b8d9bdec3951e00000000",
                         tx.serialize_as_bytes().hex())
        wallet.sign_transaction(tx, password=None)
        tx_copy = tx_from_any(tx.serialize())
        self.assertEqual('02000000000101ce010c0cab95cde544f713771916613a1a84c8787bbc95321854410b212aed9b0100000000fdffffff02cac00000000000001600147a65e09bb1da80abfc65d545388a2e61aab7c721eec100000000000016001405424089c64d39d9a498b6e1c8e646327431b240024730440220526eac6c56cba19842b67f6c9e45af113b1a2d44fb229335bdeaf08cb2cc164e0220087fba65619016fd3f62f6c8717070e48f94b45743b86d8e0517698d2b9c3afc012102d67eaa10463f5c786271feb9ae3456c27d35c3cf6c7d881617e915d1f32cb875c4951e00',
                         str(tx_copy))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_get_spendable_coins(self, mock_save_db):
        wallet = self.create_standard_wallet_from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                                       config=self.config)

        # bootstrap wallet (incoming funding_tx1)
        funding_tx1 = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        funding_txid1 = funding_tx1.txid()
        self.assertEqual('52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0', funding_txid1)
        wallet.adb.receive_tx_callback(funding_tx1, TX_HEIGHT_UNCONFIRMED)

        # another incoming transaction (funding_tx2)
        funding_tx2 = Transaction('01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400')
        funding_txid2 = funding_tx2.txid()
        self.assertEqual('c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a', funding_txid2)
        wallet.adb.receive_tx_callback(funding_tx2, TX_HEIGHT_UNCONFIRMED)

        self.assertEqual((0, 15_000_000, 0), wallet.get_balance())
        self.assertEqual(
            {'c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a:1',
             '52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0:1'},
            {txi.prevout.to_str() for txi in wallet.get_spendable_coins()})
        self.assertEqual(
            {'52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0:1'},
            {txi.prevout.to_str() for txi in wallet.get_spendable_coins(["tb1q6n99dl96mx8mfh90m3tn5awk5mllkzdh25dw7z"])})
        # test freezing an address
        wallet.set_frozen_state_of_addresses(["tb1q6n99dl96mx8mfh90m3tn5awk5mllkzdh25dw7z"], freeze=True)
        self.assertEqual(
            {'c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a:1'},
            {txi.prevout.to_str() for txi in wallet.get_spendable_coins()})
        wallet.set_frozen_state_of_addresses(["tb1q6n99dl96mx8mfh90m3tn5awk5mllkzdh25dw7z"], freeze=False)
        self.assertEqual(
            {'c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a:1',
             '52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0:1'},
            {txi.prevout.to_str() for txi in wallet.get_spendable_coins()})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_export_psbt_with_xpubs__multisig(self, mock_save_db):
        """When exporting a PSBT to be signed by a hw device, test that we populate
        the PSBT_GLOBAL_XPUB field with wallet xpubs.
        """
        wallet = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39 seed: "pulse mixture jazz invite dune enrich minor weapon mosquito flight fly vapor"
                # der path: m/48'/1'/0'/2'
                keystore.from_xpub('Vpub5n73Y3mMpc5vXFt3EUzvWjLdTrsDw3X4ksZ7GxZHi8yrGc4zBEyd77VzKaC21A4FmGqDMKwcVKFpmLUSzFM6LG84HjMfcLcbvyM1oGj5LGd'),
                # bip39 seed: "treat dwarf wealth gasp brass outside high rent blood crowd make initial"
                # der path: m/9999'
                keystore.from_xpub('Vpub5gDjDJrhnjJRXQwyhugFGx8u9B88wQ2ZkDNPoTVtYzPvu2ykP75yVhVzqnJYukhiqZ8X5FpULWYEXTs3Ve3A1Zo2hgson1Q9qPzz8uxL63m')
            ],
            '2of2', gap_limit=2,
            config=self.config
        )

        # bootstrap wallet
        funding_tx = Transaction('02000000000102deab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0000000000fdffffffdeab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0100000000fdffffff02f49f070000000000160014473b34b7da0aa9f7add803019f649e0729fd39d220a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0247304402202a4ec3df7bf2b82505bcd4833eeb32875784b4e93d09ac3cf4a8981dc89a049b02205239bad290877fb810a12538a275d5467f3f6afc88d1e0be3d8f6dc4876e6793012103e48cae7f140e15440f4ad6b3d96cb0deb471bbb45daf527e6eb4d5f6c5e26ec802473044022031028192a8307e52829ad1428941000629de73726306ca71d18c5bcfcb98a4a602205ad0240f7dd6c83686ea257f3146ba595b787d7f68b514569962fd5d3692b07c0121033c8af340bd9abf4a56c7cf7554f52e84a1128e5206ffe5da166ca18a57a260077b4a2400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98c039c9b528a8edf2c64e295bb50cf773ddbf418c98119ef54c31b60e73c322', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        outputs = [PartialTxOutput.from_address_and_value("tb1q0ezagv55krljkz9973fryeyczhj3dnlsgr02g7", 123456)]
        coins = wallet.get_spendable_coins(domain=None)

        # create spending tx
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000, rbf=True)
        tx.version = 2
        tx.locktime = 2378363
        self.assertEqual("04cf670cc809560ab6b1a362c119dbd59ea6a7621d00a4a05c0ef1839e65c035", tx.txid())
        self.assertEqual(
            "wsh(sortedmulti(2,[9559fbd1/9999h]tpubD9MoDeHnEQnU5EMgt9mc4yKU6SURbfq2ooMToY5GH95B8Li1CEsuo9dBKXM2sdjuDGq4KCXLuigss3y22fZULzVrfVuZDxEN55Sp6CcU9DK/0/0,[015148ee]tpubDFF7YPCSGHZy55HkQj6HJkXCR8DWbKKXpTYBH38fSHf6VuoEzNmZQZdAoKEVy36S8zXkbGeV4XQU6vaRXGsQfgptFYPR4HSpAenqkY7J7Lg/0/0))",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        self.assertEqual({}, tx.to_json()['xpubs'])
        self.assertEqual(
            {'022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc48275049': ('9559fbd1', "m/9999h/0/0"),
             '03cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca': ('015148ee', "m/0/0")},
            tx.inputs()[0].to_json()['bip32_paths'])
        self.assertEqual("70736274ff01007d020000000122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0240e20100000000001600147e45d43294b0ff2b08a5f45232649815e516cff058ab05000000000022002014d2823afee4d75f0f83b91a9d625972df41be222c1373d28e068c3eaae9e00a7b4a24000001012b20a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0100fd7e0102000000000102deab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0000000000fdffffffdeab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0100000000fdffffff02f49f070000000000160014473b34b7da0aa9f7add803019f649e0729fd39d220a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0247304402202a4ec3df7bf2b82505bcd4833eeb32875784b4e93d09ac3cf4a8981dc89a049b02205239bad290877fb810a12538a275d5467f3f6afc88d1e0be3d8f6dc4876e6793012103e48cae7f140e15440f4ad6b3d96cb0deb471bbb45daf527e6eb4d5f6c5e26ec802473044022031028192a8307e52829ad1428941000629de73726306ca71d18c5bcfcb98a4a602205ad0240f7dd6c83686ea257f3146ba595b787d7f68b514569962fd5d3692b07c0121033c8af340bd9abf4a56c7cf7554f52e84a1128e5206ffe5da166ca18a57a260077b4a24000105475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae2206022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc48275049109559fbd10f2700800000000000000000220603cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca0c015148ee000000000000000000000101475221027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e221028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd52ae2202027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e2109559fbd10f27008001000000000000002202028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd0c015148ee010000000000000000",
                         tx.serialize_as_bytes().hex())
        await tx.prepare_for_export_for_hardware_device(wallet)
        # As the keystores were created from just xpubs, they are missing key origin information
        # (derivation prefix and root fingerprint).
        # Note that info for ks1 contains the expected bip32 path (m/9999') and fingerprint, but not ks0.
        # It just so happens that as the der prefix is shallow (<=1 deep) for ks1, we can read it from the xpub itself.
        # For ks0, as the der prefix is missing, we treat the given xpub as the root.
        # Note that xpub0 itself has to be changed as its serialisation includes depth/fp/child_num.
        self.assertEqual(
            {'tpubD6NzVbkrYhZ4WW1saJM1hDjGz1rm5swdKwbhcsx9hW5VVXDdbnt6GbXEQVXQq97dYsvGVeMEw5Ge2Zx4QGBy6W5KXahih4aTRs5hLqgy9c9': ('015148ee', 'm'),
             'tpubD9MoDeHnEQnU5EMgt9mc4yKU6SURbfq2ooMToY5GH95B8Li1CEsuo9dBKXM2sdjuDGq4KCXLuigss3y22fZULzVrfVuZDxEN55Sp6CcU9DK': ('9559fbd1', "m/9999h")},
            tx.to_json()['xpubs'])
        self.assertEqual("70736274ff01007d020000000122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0240e20100000000001600147e45d43294b0ff2b08a5f45232649815e516cff058ab05000000000022002014d2823afee4d75f0f83b91a9d625972df41be222c1373d28e068c3eaae9e00a7b4a24004f01043587cf0000000000000000001044dcc4a72f0084f25ca3b7927abd5596715a515e2a59004ce10a51a17cf4b403a5b8b89c28c5a51832be51bb184749ac2ea6c561259bfc5bf58b852ad60f6fe404015148ee4f01043587cf019559fbd18000270f1b7a7db8a20f23be687941c8bcc8b330fd8823f19eea6ad5cb4af09b00cf6fd802db662ac8cf00e16cebe67e4d9f88b266eddbe0dfbb24b884bf3002b68ade721b089559fbd10f2700800001012b20a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0100fd7e0102000000000102deab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0000000000fdffffffdeab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0100000000fdffffff02f49f070000000000160014473b34b7da0aa9f7add803019f649e0729fd39d220a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0247304402202a4ec3df7bf2b82505bcd4833eeb32875784b4e93d09ac3cf4a8981dc89a049b02205239bad290877fb810a12538a275d5467f3f6afc88d1e0be3d8f6dc4876e6793012103e48cae7f140e15440f4ad6b3d96cb0deb471bbb45daf527e6eb4d5f6c5e26ec802473044022031028192a8307e52829ad1428941000629de73726306ca71d18c5bcfcb98a4a602205ad0240f7dd6c83686ea257f3146ba595b787d7f68b514569962fd5d3692b07c0121033c8af340bd9abf4a56c7cf7554f52e84a1128e5206ffe5da166ca18a57a260077b4a24000105475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae2206022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc48275049109559fbd10f2700800000000000000000220603cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca0c015148ee000000000000000000000101475221027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e221028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd52ae2202027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e2109559fbd10f27008001000000000000002202028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd0c015148ee010000000000000000",
                         tx.serialize_as_bytes().hex())

        # create spending tx again, but now we have full key origin info
        wallet.get_keystores()[0].add_key_origin(derivation_prefix="m/48'/1'/0'/2'", root_fingerprint="30cf1be5")
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000, rbf=True)
        tx.version = 2
        tx.locktime = 2378363
        self.assertEqual("04cf670cc809560ab6b1a362c119dbd59ea6a7621d00a4a05c0ef1839e65c035", tx.txid())
        self.assertEqual(
            "wsh(sortedmulti(2,[9559fbd1/9999h]tpubD9MoDeHnEQnU5EMgt9mc4yKU6SURbfq2ooMToY5GH95B8Li1CEsuo9dBKXM2sdjuDGq4KCXLuigss3y22fZULzVrfVuZDxEN55Sp6CcU9DK/0/0,[30cf1be5/48h/1h/0h/2h]tpubDFF7YPCSGHZy55HkQj6HJkXCR8DWbKKXpTYBH38fSHf6VuoEzNmZQZdAoKEVy36S8zXkbGeV4XQU6vaRXGsQfgptFYPR4HSpAenqkY7J7Lg/0/0))",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        self.assertEqual({}, tx.to_json()['xpubs'])
        self.assertEqual(
            {'022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc48275049': ('9559fbd1', "m/9999h/0/0"),
             '03cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca': ('30cf1be5', "m/48h/1h/0h/2h/0/0")},
            tx.inputs()[0].to_json()['bip32_paths'])
        self.assertEqual("70736274ff01007d020000000122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0240e20100000000001600147e45d43294b0ff2b08a5f45232649815e516cff058ab05000000000022002014d2823afee4d75f0f83b91a9d625972df41be222c1373d28e068c3eaae9e00a7b4a24000001012b20a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0100fd7e0102000000000102deab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0000000000fdffffffdeab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0100000000fdffffff02f49f070000000000160014473b34b7da0aa9f7add803019f649e0729fd39d220a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0247304402202a4ec3df7bf2b82505bcd4833eeb32875784b4e93d09ac3cf4a8981dc89a049b02205239bad290877fb810a12538a275d5467f3f6afc88d1e0be3d8f6dc4876e6793012103e48cae7f140e15440f4ad6b3d96cb0deb471bbb45daf527e6eb4d5f6c5e26ec802473044022031028192a8307e52829ad1428941000629de73726306ca71d18c5bcfcb98a4a602205ad0240f7dd6c83686ea257f3146ba595b787d7f68b514569962fd5d3692b07c0121033c8af340bd9abf4a56c7cf7554f52e84a1128e5206ffe5da166ca18a57a260077b4a24000105475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae2206022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc48275049109559fbd10f2700800000000000000000220603cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca1c30cf1be530000080010000800000008002000080000000000000000000000101475221027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e221028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd52ae2202027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e2109559fbd10f27008001000000000000002202028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd1c30cf1be530000080010000800000008002000080010000000000000000",
                         tx.serialize_as_bytes().hex())
        await tx.prepare_for_export_for_hardware_device(wallet)
        self.assertEqual(
            {'tpubDFF7YPCSGHZy55HkQj6HJkXCR8DWbKKXpTYBH38fSHf6VuoEzNmZQZdAoKEVy36S8zXkbGeV4XQU6vaRXGsQfgptFYPR4HSpAenqkY7J7Lg': ('30cf1be5', "m/48h/1h/0h/2h"),
             'tpubD9MoDeHnEQnU5EMgt9mc4yKU6SURbfq2ooMToY5GH95B8Li1CEsuo9dBKXM2sdjuDGq4KCXLuigss3y22fZULzVrfVuZDxEN55Sp6CcU9DK': ('9559fbd1', "m/9999h")},
            tx.to_json()['xpubs'])
        self.assertEqual("70736274ff01007d020000000122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0240e20100000000001600147e45d43294b0ff2b08a5f45232649815e516cff058ab05000000000022002014d2823afee4d75f0f83b91a9d625972df41be222c1373d28e068c3eaae9e00a7b4a24004f01043587cf04b5faa014800000021044dcc4a72f0084f25ca3b7927abd5596715a515e2a59004ce10a51a17cf4b403a5b8b89c28c5a51832be51bb184749ac2ea6c561259bfc5bf58b852ad60f6fe41430cf1be5300000800100008000000080020000804f01043587cf019559fbd18000270f1b7a7db8a20f23be687941c8bcc8b330fd8823f19eea6ad5cb4af09b00cf6fd802db662ac8cf00e16cebe67e4d9f88b266eddbe0dfbb24b884bf3002b68ade721b089559fbd10f2700800001012b20a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0100fd7e0102000000000102deab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0000000000fdffffffdeab5844de4aadc177d992696fda2aa6e4692403633d31a4b4073710594d2fca0100000000fdffffff02f49f070000000000160014473b34b7da0aa9f7add803019f649e0729fd39d220a10700000000002200207f50b9d6eb4d899c710d8c48903de33d966ff52445d5a57b5210d02a5dd7e3bf0247304402202a4ec3df7bf2b82505bcd4833eeb32875784b4e93d09ac3cf4a8981dc89a049b02205239bad290877fb810a12538a275d5467f3f6afc88d1e0be3d8f6dc4876e6793012103e48cae7f140e15440f4ad6b3d96cb0deb471bbb45daf527e6eb4d5f6c5e26ec802473044022031028192a8307e52829ad1428941000629de73726306ca71d18c5bcfcb98a4a602205ad0240f7dd6c83686ea257f3146ba595b787d7f68b514569962fd5d3692b07c0121033c8af340bd9abf4a56c7cf7554f52e84a1128e5206ffe5da166ca18a57a260077b4a24000105475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae2206022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc48275049109559fbd10f2700800000000000000000220603cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca1c30cf1be530000080010000800000008002000080000000000000000000000101475221027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e221028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd52ae2202027f7f2eaf9a44316c2cd98b67584d1e71ccaced29a347673f3364efe16f5919e2109559fbd10f27008001000000000000002202028d9b8ff374e0f60fbc698c5a494c12d9a31a3ce364b1f81ae4a46f48ae45acdd1c30cf1be530000080010000800000008002000080010000000000000000",
                         tx.serialize_as_bytes().hex())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_export_psbt_with_xpubs__singlesig(self, mock_save_db):
        """When exporting a PSBT to be signed by a hw device, test that we populate
        the PSBT_GLOBAL_XPUB field with wallet xpubs.
        """
        root_seed = keystore.bip39_to_seed("pulse mixture jazz invite dune enrich minor weapon mosquito flight fly vapor", passphrase='')
        ks = keystore.from_bip43_rootseed(root_seed, derivation="m/84'/1'/0'")
        wallet = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=2, config=self.config)

        # bootstrap wallet
        funding_tx = Transaction('0200000000010122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0196a007000000000016001413ce91db66299806c4f35b2b4f8426b0bd4f2cd704004730440220112840ce5486c6b2d15bc3b12e45c2a4518828e1b34f9bb0b3a78220c0cec52f02205b146a1f683289909ecbd3f53932d5acc321444101d8002e435b38a54adbf47201473044022058dfb4c75de119595119f35dcd7b1b2c28c40d7e2e746baeae83f09396c6bb9e02201c3c40fb684253638f12392af3934a90a6c6a512441aac861022f927473c952001475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae4a4a2400')
        funding_txid = funding_tx.txid()
        self.assertEqual('c70d83827d09b334bb373738be25c93dbe7dd37186d09bb10cae80704da06f91', funding_txid)
        wallet.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        outputs = [PartialTxOutput.from_address_and_value("tb1q0ezagv55krljkz9973fryeyczhj3dnlsgr02g7", 123456)]
        coins = wallet.get_spendable_coins(domain=None)

        # create spending tx
        tx = wallet.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000, rbf=True)
        tx.version = 2
        tx.locktime = 2378367
        self.assertEqual("5c0d5eea8c2c12a383406bb37e6158167e44bfe6cd1ad590b7d97002cdfc9fff", tx.txid())
        self.assertEqual({}, tx.to_json()['xpubs'])
        self.assertEqual(
            {'029e65093d22877cbfcc27cb754c58d144ec96635af1fcc63e5a7b90b23bb6acb8': ('30cf1be5', "m/84h/1h/0h/0/0")},
            tx.inputs()[0].to_json()['bip32_paths'])
        self.assertEqual("70736274ff0100710200000001916fa04d7080ae0cb19bd08671d37dbe3dc925be383737bb34b3097d82830dc70000000000fdffffff0240e20100000000001600147e45d43294b0ff2b08a5f45232649815e516cff0ceaa05000000000016001456ec9cad206160ab578fa1dfbe13311b3be4a3107f4a24000001011f96a007000000000016001413ce91db66299806c4f35b2b4f8426b0bd4f2cd70100fd2e010200000000010122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0196a007000000000016001413ce91db66299806c4f35b2b4f8426b0bd4f2cd704004730440220112840ce5486c6b2d15bc3b12e45c2a4518828e1b34f9bb0b3a78220c0cec52f02205b146a1f683289909ecbd3f53932d5acc321444101d8002e435b38a54adbf47201473044022058dfb4c75de119595119f35dcd7b1b2c28c40d7e2e746baeae83f09396c6bb9e02201c3c40fb684253638f12392af3934a90a6c6a512441aac861022f927473c952001475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae4a4a24002206029e65093d22877cbfcc27cb754c58d144ec96635af1fcc63e5a7b90b23bb6acb81830cf1be5540000800100008000000080000000000000000000002202031503b2e74b21d4583b7f0d9e65b2c0ef19fd6e8aae7d0524fc770a1d2b2127501830cf1be5540000800100008000000080010000000000000000",
                         tx.serialize_as_bytes().hex())
        # if there are no multisig inputs, we never include xpubs in the psbt:
        await tx.prepare_for_export_for_hardware_device(wallet)
        self.assertEqual({}, tx.to_json()['xpubs'])
        self.assertEqual("70736274ff0100710200000001916fa04d7080ae0cb19bd08671d37dbe3dc925be383737bb34b3097d82830dc70000000000fdffffff0240e20100000000001600147e45d43294b0ff2b08a5f45232649815e516cff0ceaa05000000000016001456ec9cad206160ab578fa1dfbe13311b3be4a3107f4a24000001011f96a007000000000016001413ce91db66299806c4f35b2b4f8426b0bd4f2cd70100fd2e010200000000010122c3730eb6314cf59e11988c41bfdd73f70cb55b294ec6f2eda828b5c939c0980100000000fdffffff0196a007000000000016001413ce91db66299806c4f35b2b4f8426b0bd4f2cd704004730440220112840ce5486c6b2d15bc3b12e45c2a4518828e1b34f9bb0b3a78220c0cec52f02205b146a1f683289909ecbd3f53932d5acc321444101d8002e435b38a54adbf47201473044022058dfb4c75de119595119f35dcd7b1b2c28c40d7e2e746baeae83f09396c6bb9e02201c3c40fb684253638f12392af3934a90a6c6a512441aac861022f927473c952001475221022c4338968f87a09b0fefd0aaac36f1b983bab237565d521944c60fdc482750492103cf9a6ac058d36a6dc325b19715a2223c6416e1cef13bc047a99bded8c99463ca52ae4a4a24002206029e65093d22877cbfcc27cb754c58d144ec96635af1fcc63e5a7b90b23bb6acb81830cf1be5540000800100008000000080000000000000000000002202031503b2e74b21d4583b7f0d9e65b2c0ef19fd6e8aae7d0524fc770a1d2b2127501830cf1be5540000800100008000000080010000000000000000",
                         tx.serialize_as_bytes().hex())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_export_psbt__rm_witness_utxo_from_non_segwit_input(self, mock_save_db):
        """We sometimes convert full utxo to witness_utxo in psbt inputs when using QR codes, to save space,
        even for non-segwit inputs (which goes against the spec).
        This tests that upon scanning the QR code, if we can add the full utxo to the input (e.g. via network),
        we remove the witness_utxo before e.g. re-exporting it. (see #8305)
        """
        wallet1a = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_bip43_rootseed(
                    keystore.bip39_to_seed("income sample useless art skate lucky fold field bargain course hope chest", passphrase=''),
                    derivation="m/45h/0", xtype="standard"),
                keystore.from_xpub('tpubDC1y33c2iTcxCBFva3zxbQxUnbzBT1TPVrwLgwVHtqSnVRx2pbJsrHzNYmXnKEnrNqyKk9BERrpSatqVu4JHV4K4hepFQdqnMojA5NVKxcF'),
            ],
            '2of2', gap_limit=2,
            config=self.config,
        )
        wallet1a.get_keystores()[1].add_key_origin(derivation_prefix="m/45h/0", root_fingerprint="25750cf7")
        wallet1b = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_xpub('tpubDAKtPDG6fezcwhB7rNJ9NVEWwGokNzowW3AaMVYFTS4WKoBTNESS1NpntWYDq2uABVYM1xa5cVmu8LD2xKYipMRVLy1VjBQeVe6pixJeBgr'),
                keystore.from_xpub('tpubDC1y33c2iTcxCBFva3zxbQxUnbzBT1TPVrwLgwVHtqSnVRx2pbJsrHzNYmXnKEnrNqyKk9BERrpSatqVu4JHV4K4hepFQdqnMojA5NVKxcF'),
            ],
            '2of2', gap_limit=2,
            config=self.config,
        )
        wallet1b.get_keystores()[0].add_key_origin(derivation_prefix="m/45h/0", root_fingerprint="18c2928f")
        wallet1b.get_keystores()[1].add_key_origin(derivation_prefix="m/45h/0", root_fingerprint="25750cf7")
        wallet1b_offline = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_bip43_rootseed(
                    keystore.bip39_to_seed("wear wasp subject october amount essay maximum monkey excuse plastic ginger donor", passphrase=''),
                    derivation="m/45h/0", xtype="standard"),
                keystore.from_xpub('tpubDAKtPDG6fezcwhB7rNJ9NVEWwGokNzowW3AaMVYFTS4WKoBTNESS1NpntWYDq2uABVYM1xa5cVmu8LD2xKYipMRVLy1VjBQeVe6pixJeBgr'),
            ],
            '2of2', gap_limit=2,
            config=self.config,
        )
        wallet1b_offline.get_keystores()[1].add_key_origin(derivation_prefix="m/45h/0", root_fingerprint="18c2928f")

        # bootstrap wallet
        funding_tx = Transaction('0200000000010199b6eb9629c9763e9e95c49f2e81d7a9bda0c8e96165897ce42df0c7a4757aa60100000000fdffffff0220a107000000000017a91482e2921d413a7cad08f76d1d35565dbcc85088db8750560e000000000016001481e6fc4a427d0176373bdd7482b8c1d08f3563300247304402202cf7be624cc30640e2b928adeb25b21ed581f32149f78bc1b0fa9c01da785486022066fadccb1aef8d46841388e83386f85ca5776f50890b9921f165f093fabfd2800121022e43546769a51181fad61474a773b0813106895971b6e3f1d43278beb7154d0a1a112500')
        funding_txid = funding_tx.txid()
        self.assertEqual('e1a5465e813b51047e1ee95a2c635416f0105b52361084c7e005325f685f374e', funding_txid)
        wallet1a.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)
        wallet1b.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # cosignerA creates and signs the tx
        outputs = [PartialTxOutput.from_address_and_value("tb1qgacvp0zvgtk3etggjayuezrc2mkql8veshv4xw", 200_000)]
        coins = wallet1a.get_spendable_coins(domain=None)
        tx = wallet1a.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        tx.set_rbf(True)
        tx.locktime = 2429212
        tx.version = 2
        wallet1a.sign_transaction(tx, password=None)

        # cosignerA shares psbt with cosignerB
        orig_tx1 = tx
        for uses_qr_code1 in (False, True, ):
            with self.subTest(uses_qr_code1=uses_qr_code1):
                tx = copy.deepcopy(orig_tx1)
                if uses_qr_code1:
                    partial_tx, is_complete = tx.to_qr_data()
                    self.assertEqual("3PMZFRKS5WP6JMMK.-I6Z5JFJ+3ABTDQ.SEM2ATLOB0EF-5I3VH0+Z:P$3SWOO75P/P41QSRJ+4-P*V6MJLC0H.XH1CJ+066VC6IV/5+H1S0R*1NNW.EBSHKZ7IA3T$-$OTUQMP22B+ZVM4QSL/K/BIT8WOM1712MQWDH1DQA/0DEUH$YKYDYDC+/MO-$ZXBM:L+/8F83FD5*:N8HU45:9YULHULQ/P.HLIHVHFQR+WRVT7P.DTUE0BE91DK56:S$Y8+ZBJ0ZSSRRUPNE$I18Y.TXFRM.CTZSGVTSQWNX8Z+YLWR5F8.RVZ1039*U.H7BN6ZMHSBWS*PLY3SK+9LV/FBGJK4+YU3IGI3S4Z9RXS8$JVP+VZUZ:PDJI$KI-6DG2A//O5PRDLP3RUSX.KBFP.IY2JZV+B:DF3.C+R9LU0JUXF26W3SME9A*/WWNNH0-59RCI-YKG:SOO:U0F*SV5R5VERVP2J57EJMO*9.GH++/7P55YE/QTLU$MB8.KT*HD4S2ISP35+*R14HXP:SDUGWGGH$Y8O/NZSH0*CXQZ+H3G7E5:5HFFB8C-BA/O*04I/GF6.X0DKYETTJ:NO27RKHTL:/44U.PK/F/9+9V4D:N3*YS5OTA7+/:P70+L/JMB0OD7ZMO/HFJXRFCK7GS1-K464$96KODYGML8IJLR31-2W1EI0HXOWG:3N9M7QRTU83-NK*G:6SI.JU*71UW85MZ./Y:03L6KZTG7SJ.VKO3WFZU.XV+745QZ.OWET:VNV/.QNR-ETA2S/LTV-U-M2OC2LV7.*1AIN4XW3LR$*75/BVIV.KG1ZGMBJ7L0IE9F-7O4+1QSZ8JR$GECW6RZFKPZ516O+2GV9FTA:3L1C1QL/6YVSF*L8-38/7L1$**Y7K5FLOP-4T20.*1*8JK-M$C+:5U+S*KLZW3E3U0N$ODSMT",
                                     partial_tx)
                    self.assertFalse(is_complete)
                else:
                    partial_tx = tx.serialize_as_bytes().hex()
                    self.assertEqual("70736274ff01007202000000014e375f685f3205e0c7841036525b10f01654632c5ae91e7e04513b815e46a5e10000000000fdffffff02400d0300000000001600144770c0bc4c42ed1cad089749cc887856ec0f9d99588004000000000017a914493900cdec652a41c633436b53d574647e329b18871c112500000100df0200000000010199b6eb9629c9763e9e95c49f2e81d7a9bda0c8e96165897ce42df0c7a4757aa60100000000fdffffff0220a107000000000017a91482e2921d413a7cad08f76d1d35565dbcc85088db8750560e000000000016001481e6fc4a427d0176373bdd7482b8c1d08f3563300247304402202cf7be624cc30640e2b928adeb25b21ed581f32149f78bc1b0fa9c01da785486022066fadccb1aef8d46841388e83386f85ca5776f50890b9921f165f093fabfd2800121022e43546769a51181fad61474a773b0813106895971b6e3f1d43278beb7154d0a1a1125002202026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd4730440220414287f36a02b004d2e9a3892e1862edaf49c35d50b65ae10b601879b8c793ef0220073234c56d5a8ae9f4fcfeaecaa757e2724bf830d45aabfab8ffe37329ebf459010104475221026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd2103a8b896e5216fe7239516a494407c0cc90c6dc33918c7df04d1cda8d57a3bb98152ae2206026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd1418c2928f2d000080000000000000000000000000220603a8b896e5216fe7239516a494407c0cc90c6dc33918c7df04d1cda8d57a3bb9811425750cf72d000080000000000000000000000000000001004752210212de0581d6570d3cc432cdad2b07514807007dc80b792fafeb47bed69fe6276821028748a66f10b13944ccb14640ba36f65dc7a1f3462e9aca65ba8b05013842270b52ae22020212de0581d6570d3cc432cdad2b07514807007dc80b792fafeb47bed69fe627681425750cf72d0000800000000001000000000000002202028748a66f10b13944ccb14640ba36f65dc7a1f3462e9aca65ba8b05013842270b1418c2928f2d00008000000000010000000000000000",
                                     partial_tx)
                # load tx into cosignerB's online wallet
                tx = tx_from_any(partial_tx)
                self.assertFalse(tx.is_segwit())
                self.assertFalse(tx.is_complete())
                tx.add_info_from_wallet(wallet1b)

                # cosignerB moves psbt from his online wallet to offline wallet
                orig_tx2 = tx
                for uses_qr_code2 in (False, True, ):
                    with self.subTest(uses_qr_code2=uses_qr_code2):
                        tx = copy.deepcopy(orig_tx2)
                        if uses_qr_code2:
                            partial_tx, is_complete = tx.to_qr_data()
                            self.assertEqual("3PMZFRKS5WP6JMMK.-I6Z5JFJ+3ABTDQ.SEM2ATLOB0EF-5I3VH0+Z:P$3SWOO75P/P41QSRJ+4-P*V6MJLC0H.XH1CJ+066VC6IV/5+H1S0R*1NNW.EBSHKZ7IA3T$-$OTUQMP22B+ZVM4QSL/K/BIT8WOM1712MQWDH1DQA/0DEUH$YKYDYDC+/MO-$ZXBM:L+/8F83FD5*:N8HU45:9YULHULQ/P.HLIHVHFQR+WRVT7P.DTUE0BE91DK56:S$Y8+ZBJ0ZSSRRUPNE$I18Y.TXFRM.CTZSGVTSQWNX8Z+YLWR5F8.RVZ1039*U.H7BN6ZMHSBWS*PLY3SK+9LV/FBGJK4+YU3IGI3S4Z9RXS8$JVP+VZUZ:PDJI$KI-6DG2A//O5PRDLP3RUSX.KBFP.IY2JZV+B:DF3.C+R9LU0JUXF26W3SME9A*/WWNNH0-59RCI-YKG:SOO:U0F*SV5R5VERVP2J57EJMO*9.GH++/7P55YE/QTLU$MB8.KT*HD4S2ISP35+*R14HXP:SDUGWGGH$Y8O/NZSH0*CXQZ+H3G7E5:5HFFB8C-BA/O*04I/GF6.X0DKYETTJ:NO27RKHTL:/44U.PK/F/9+9V4D:N3*YS5OTA7+/:P70+L/JMB0OD7ZMO/HFJXRFCK7GS1-K464$96KODYGML8IJLR31-2W1EI0HXOWG:3N9M7QRTU83-NK*G:6SI.JU*71UW85MZ./Y:03L6KZTG7SJ.VKO3WFZU.XV+745QZ.OWET:VNV/.QNR-ETA2S/LTV-U-M2OC2LV7.*1AIN4XW3LR$*75/BVIV.KG1ZGMBJ7L0IE9F-7O4+1QSZ8JR$GECW6RZFKPZ516O+2GV9FTA:3L1C1QL/6YVSF*L8-38/7L1$**Y7K5FLOP-4T20.*1*8JK-M$C+:5U+S*KLZW3E3U0N$ODSMT",
                                             partial_tx)
                            self.assertFalse(is_complete)
                        else:
                            partial_tx = tx.serialize_as_bytes().hex()
                            self.assertEqual("70736274ff01007202000000014e375f685f3205e0c7841036525b10f01654632c5ae91e7e04513b815e46a5e10000000000fdffffff02400d0300000000001600144770c0bc4c42ed1cad089749cc887856ec0f9d99588004000000000017a914493900cdec652a41c633436b53d574647e329b18871c112500000100df0200000000010199b6eb9629c9763e9e95c49f2e81d7a9bda0c8e96165897ce42df0c7a4757aa60100000000fdffffff0220a107000000000017a91482e2921d413a7cad08f76d1d35565dbcc85088db8750560e000000000016001481e6fc4a427d0176373bdd7482b8c1d08f3563300247304402202cf7be624cc30640e2b928adeb25b21ed581f32149f78bc1b0fa9c01da785486022066fadccb1aef8d46841388e83386f85ca5776f50890b9921f165f093fabfd2800121022e43546769a51181fad61474a773b0813106895971b6e3f1d43278beb7154d0a1a1125002202026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd4730440220414287f36a02b004d2e9a3892e1862edaf49c35d50b65ae10b601879b8c793ef0220073234c56d5a8ae9f4fcfeaecaa757e2724bf830d45aabfab8ffe37329ebf459010104475221026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd2103a8b896e5216fe7239516a494407c0cc90c6dc33918c7df04d1cda8d57a3bb98152ae2206026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd1418c2928f2d000080000000000000000000000000220603a8b896e5216fe7239516a494407c0cc90c6dc33918c7df04d1cda8d57a3bb9811425750cf72d000080000000000000000000000000000001004752210212de0581d6570d3cc432cdad2b07514807007dc80b792fafeb47bed69fe6276821028748a66f10b13944ccb14640ba36f65dc7a1f3462e9aca65ba8b05013842270b52ae22020212de0581d6570d3cc432cdad2b07514807007dc80b792fafeb47bed69fe627681425750cf72d0000800000000001000000000000002202028748a66f10b13944ccb14640ba36f65dc7a1f3462e9aca65ba8b05013842270b1418c2928f2d00008000000000010000000000000000",
                                             partial_tx)
                        # load tx into cosignerB's offline wallet
                        tx = tx_from_any(partial_tx)
                        wallet1b_offline.sign_transaction(tx, password=None, ignore_warnings=True)

                        self.assertEqual('02000000014e375f685f3205e0c7841036525b10f01654632c5ae91e7e04513b815e46a5e100000000d9004730440220414287f36a02b004d2e9a3892e1862edaf49c35d50b65ae10b601879b8c793ef0220073234c56d5a8ae9f4fcfeaecaa757e2724bf830d45aabfab8ffe37329ebf4590147304402203ba7cc21e407ce31c1eecd11c367df716a5d47f06e0bf7109f08063ede25a364022039f6bef0dd401aa2c3103b8cbab57cc4fed3905ccb0a726dc6594bf5930ae0b401475221026addf5fd752c92e8a53955e430ca5964feb1b900ce569f968290f65ae7fecbfd2103a8b896e5216fe7239516a494407c0cc90c6dc33918c7df04d1cda8d57a3bb98152aefdffffff02400d0300000000001600144770c0bc4c42ed1cad089749cc887856ec0f9d99588004000000000017a914493900cdec652a41c633436b53d574647e329b18871c112500',
                                         str(tx))
                        self.assertEqual('d6823918ff82ed240995e9e6f02e0d2f3f15e0b942616ab34481ce8a3399dc72', tx.txid())
                        self.assertEqual('d6823918ff82ed240995e9e6f02e0d2f3f15e0b942616ab34481ce8a3399dc72', tx.wtxid())

                        # again, but raise on warnings (here: signing non-segwit inputs is risky)
                        tx = tx_from_any(partial_tx)
                        try:
                            wallet1b_offline.sign_transaction(tx, password=None)
                            self.assertFalse(uses_qr_code2)
                        except TransactionDangerousException:
                            raise
                        except TransactionPotentiallyDangerousException:
                            self.assertTrue(uses_qr_code2)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_we_dont_sign_tx_including_dummy_address(self, mock_save_db):
        wallet1 = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver')

        # bootstrap wallet1
        funding_tx = Transaction('01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000')
        funding_txid = funding_tx.txid()
        self.assertEqual('add2535aedcbb5ba79cc2260868bb9e57f328738ca192937f2c92e0e94c19203', funding_txid)
        wallet1.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # wallet1 -> dummy address
        outputs = [PartialTxOutput.from_address_and_value(bitcoin.DummyAddress.CHANNEL, 250000)]

        with self.assertRaises(bitcoin.DummyAddressUsedInTxException):
            tx = wallet1.create_transaction(outputs=outputs, password=None, fee=5000, tx_version=1, rbf=False)

        coins = wallet1.get_spendable_coins(domain=None)
        tx = wallet1.make_unsigned_transaction(coins=coins, outputs=outputs, fee=5000)
        with self.assertRaises(bitcoin.DummyAddressUsedInTxException):
            wallet1.sign_transaction(tx, password=None)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sighash_warnings(self, mock_save_db):
        wallet1 = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver')

        # bootstrap wallet1
        funding_tx = Transaction('01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000')
        self.assertEqual('add2535aedcbb5ba79cc2260868bb9e57f328738ca192937f2c92e0e94c19203', funding_tx.txid())
        wallet1.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)
        funding_tx = Transaction('0200000000010141f2de02db45f99c3618e4bfb51cd3e5ec64db096886cfd8253bdbaf0bba58c72c01000000fdffffff0220e00900000000001600144d46b4729c7bf894fa5c510d6e72bec1d02b1aa640420f0000000000160014284520c815980d426264766d8d930013dd20aa6002473044022078a86cd15acb981a5aa4948176cb66583a4a4f4b728962f1497fbdd5f323ae3e02205301e5e3b34232bc139ca311a795377a3416b109b7bb8c70f3f6bb3fcc40e589012103cf9ad82ebea31e5c1bf08219c38302cc0ce5eba2ff5eecd90b9d3a951eebfb1cca2c1800')
        self.assertEqual('9d221a69ca3997cbeaf5624d723e7dc5f829b1023078c177d37bdae95f37c539', funding_tx.txid())
        wallet1.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        outputs = [PartialTxOutput.from_address_and_value('tb1qgacvp0zvgtk3etggjayuezrc2mkql8veshv4xw', '!')]
        coins = wallet1.get_spendable_coins(domain=None)
        tx = wallet1.make_unsigned_transaction(coins=coins, outputs=outputs, fee=1000)
        self.assertEqual(2, len(tx.inputs()))

        tx.inputs()[0].sighash = Sighash.NONE
        tx.inputs()[1].sighash = Sighash.ALL
        self.assertEqual(TxSighashRiskLevel.INSANE_SIGHASH, wallet1.check_sighash(tx).risk_level)
        with self.assertRaises(TransactionDangerousException):
            wallet1.sign_transaction(tx, password=None)
        with self.assertRaises(TransactionDangerousException):
            wallet1.sign_transaction(tx, password=None, ignore_warnings=True)

        tx.inputs()[0].sighash = Sighash.ALL
        tx.inputs()[1].sighash = Sighash.SINGLE
        self.assertEqual(TxSighashRiskLevel.WEIRD_SIGHASH, wallet1.check_sighash(tx).risk_level)
        with self.assertRaises(TransactionPotentiallyDangerousException):
            wallet1.sign_transaction(tx, password=None)

        tx.inputs()[0].sighash = Sighash.ALL | Sighash.ANYONECANPAY
        tx.inputs()[1].sighash = Sighash.ALL
        self.assertEqual(TxSighashRiskLevel.WEIRD_SIGHASH, wallet1.check_sighash(tx).risk_level)
        with self.assertRaises(TransactionPotentiallyDangerousException):
            wallet1.sign_transaction(tx, password=None)

        tx.inputs()[0].sighash = Sighash.ALL
        tx.inputs()[1].sighash = Sighash.ALL
        self.assertEqual(TxSighashRiskLevel.SAFE, wallet1.check_sighash(tx).risk_level)
        self.assertFalse(tx.is_complete())
        wallet1.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())


class TestWalletOfflineSigning(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_old_electrum_seed_online_mpk(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_seed('alone body father children lead goodbye phone twist exist grass kick join', passphrase='', for_multisig=False),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_master_key('cd805ed20aec61c7a8b409c121c6ba60a9221f46d20edbc2be83ebd91460e97937cd7d782e77c1cb08364c6bc1c98bc040fdad53f22f29f7d3a85c8e51f9c875'),
            gap_limit=4,
            config=self.config
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101161115f8d8110001aa0883989487f9c7a2faf4451038e4305c7594c5236cbb490100000000fdffffff0338117a0000000000160014c1d7b2ded7017cbde837aab36c1e7b2a3952a57800127a00000000001600143e2ab71fc9738ce16fbe6b3b1c210a68c12db84180969800000000001976a91424b64d981d621c227716b51479faf33019371f4688ac0247304402207a5efc6d970f6a5fdcd1933f68b353b4bf2904743f9f1dc3e9177d8754074baf02202eed707e661493bc450357f12cd7a8b8c610c7cb32ded10516c2933a2ba4346a01210287dce03f594fd889726b13a12970237992a0094a5c9f4eebcca6d50d454b39e9ff121600')
        funding_txid = funding_tx.txid()
        self.assertEqual('3b9e0581602f4656cb04633dac13662bc62d9f5191caa15cc901dcc76e430856', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1qyw3c0rvn6kk2c688y3dygvckn57525y8qnxt3a', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1446655
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual((0, 1), tx.signature_count())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007401000000015608436ec7dc01c95ca1ca91519f2dc62b6613ac3d6304cb56462f6081059e3b0200000000fdffffff02a02526000000000016001423a3878d93d5acac68e7245a4433169d3d455087585d7200000000001976a914b6a6bbbc4cf9da58786a8acc58291e218d52130688acff121600000100fd000101000000000101161115f8d8110001aa0883989487f9c7a2faf4451038e4305c7594c5236cbb490100000000fdffffff0338117a0000000000160014c1d7b2ded7017cbde837aab36c1e7b2a3952a57800127a00000000001600143e2ab71fc9738ce16fbe6b3b1c210a68c12db84180969800000000001976a91424b64d981d621c227716b51479faf33019371f4688ac0247304402207a5efc6d970f6a5fdcd1933f68b353b4bf2904743f9f1dc3e9177d8754074baf02202eed707e661493bc450357f12cd7a8b8c610c7cb32ded10516c2933a2ba4346a01210287dce03f594fd889726b13a12970237992a0094a5c9f4eebcca6d50d454b39e9ff121600420604e79eb77f2f3f989f5e9d090bc0af50afeb0d5bd6ec916f2022c5629ed022e84a87584ef647d69f073ea314a0f0c110ebe24ad64bc1922a10819ea264fc3f35f50c343ddcab000000000100000000004202048e2004ca581afcc54a5d9b3b47affdf48b3f89e16d5bd96774fc0f167f2d7873bac6264e3d1f1bb96f64d1530a54e026e0bd7d674151d146fba582e79f4ef5e80c343ddcab010000000000000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertEqual((1, 1), tx.signature_count())
        self.assertFalse(tx.is_segwit())
        self.assertEqual('01000000015608436ec7dc01c95ca1ca91519f2dc62b6613ac3d6304cb56462f6081059e3b020000008a47304402206bed3e02af8a38f6ba2fa3bf5908cb8c643aa62e78e8de6d9af2e19dec55fafc0220039cc1d81d4e5e0292bbc54ea92b8ec4ec016d4828eedc8975a66952cedf13a1014104e79eb77f2f3f989f5e9d090bc0af50afeb0d5bd6ec916f2022c5629ed022e84a87584ef647d69f073ea314a0f0c110ebe24ad64bc1922a10819ea264fc3f35f5fdffffff02a02526000000000016001423a3878d93d5acac68e7245a4433169d3d455087585d7200000000001976a914b6a6bbbc4cf9da58786a8acc58291e218d52130688acff121600',
                         str(tx))
        self.assertEqual('06032230d0bf6a277bc4f8c39e3311a712e0e614626d0dea7cc9f592abfae5d8', tx.txid())
        self.assertEqual('06032230d0bf6a277bc4f8c39e3311a712e0e614626d0dea7cc9f592abfae5d8', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_xprv_online_xpub_p2pkh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/44'/1'/0'
            keystore.from_xprv('tprv8gfKwjuAaqtHgqxMh1tosAQ28XvBMkcY5NeFRA3pZMpz6MR4H4YZ3MJM4fvNPnRKeXR1Td2vQGgjorNXfo94WvT5CYDsPAqjHxSn436G1Eu'),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('tpubDDMN69wQjDZxaJz9afZQGa48hZS7X5oSegF2hg67yddNvqfpuTN9DqvDEp7YyVf7AzXnqBqHdLhzTAStHvsoMDDb8WoJQzNrcHgDJHVYgQF'),
            gap_limit=4,
            config=self.config
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1qp0mv2sxsyxxfj5gl0332f9uyez93su9cf26757', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))

        orig_tx = tx
        for uses_qr_code in (False, True):
            with self.subTest(msg="uses_qr_code", uses_qr_code=uses_qr_code):
                tx = copy.deepcopy(orig_tx)
                if uses_qr_code:
                    partial_tx, is_complete = tx.to_qr_data()
                    self.assertEqual("8VXO.MYW+UE2.+5LGGVQP.$087REZNQ8:6*U1CLU+NW7:.T7K04HTV.JW78BXOF$IM*4YYL6LWVSZ4QA0Q-1*8W38XJH833$K3EUK:87-TGQ86XAQ3/RD*PZKM1RLVRAVCFG/8.UHCF8IX*ED1HXNGI*WQ37K*HWJ:XXNKMU.M2A$IYUM-AR:*P34/.EGOQF-YUJ.F0UF$LMW-YXWQU$$CMXD4-L21B7X5/OL7MKXCAD5-9IL/TDP5J2$13KFIH2K5B0/2F*/-XCY:/G-+8K*+1U$56WUE3:J/8KOGSRAN66CNZLG7Y4IB$Y*.S64CC2A9Q/-P5TQFZCF7F+CYG+V363/ME.W0WTPXJM3BC.YPH+Y3K7VIF2+0D.O.JS4LYMZ",
                                     partial_tx)
                    self.assertFalse(is_complete)
                else:
                    partial_tx = tx.serialize_as_bytes().hex()
                    self.assertEqual("70736274ff010074010000000162878508bdcd372fc4c33ce6145cd1fb1dcc5314d4930ceb6957e7f6c54b57980200000000fdffffff02a0252600000000001600140bf6c540d0218c99511f7c62a49784c88b1870b8585d7200000000001976a9149b308d0b3efd4e3469441bc83c3521afde4072b988ac1c391400000100fd4c0d01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400220602ab053d10eda769fab03ab52ee4f1692730288751369643290a8506e31d1e80f00c233d2ae40000000002000000000022020327295144ffff9943356c2d6625f5e2d6411bab77fd56dce571fda6234324e3d90c233d2ae4010000000000000000",
                                     partial_tx)
                tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
                self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

                self.assertEqual(tx.txid(), tx_copy.txid())

                # sign tx
                tx = wallet_offline.sign_transaction(tx_copy, password=None, ignore_warnings=True)
                self.assertTrue(tx.is_complete())
                self.assertFalse(tx.is_segwit())
                self.assertEqual('d9c21696eca80321933e7444ca928aaf25eeda81aaa2f4e5c085d4d0a9cf7aa7', tx.txid())
                self.assertEqual('d9c21696eca80321933e7444ca928aaf25eeda81aaa2f4e5c085d4d0a9cf7aa7', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_xprv_online_xpub_p2wpkh_p2sh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/49'/1'/0'
            keystore.from_xprv('uprv8zHHrMQMQ26utWwNJ5MK2SXpB9hbmy7pbPaneii69xT8cZTyFpxQFxkknGWKP8dxBTZhzy7yP6cCnLrRCQjzJDk3G61SjZpxhFQuB2NR8a5'),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('upub5DGeFrwFEPfD711qQ6tKPaUYjBY6BRqfxcWPT77hiHz7VMo7oNGeom5EdXoKXEazePyoN3ueJMqHBfp3MwmsaD8k9dFHoa8KGeVXev7Pbg2'),
            gap_limit=4,
            config=self.config
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1qp0mv2sxsyxxfj5gl0332f9uyez93su9cf26757', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325341
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff010072010000000162878508bdcd372fc4c33ce6145cd1fb1dcc5314d4930ceb6957e7f6c54b57980300000000fdffffff02a0252600000000001600140bf6c540d0218c99511f7c62a49784c88b1870b8585d72000000000017a914191e7373ae7b4829532220e8f281f4581ed52638871d39140000010120809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f870100fd4c0d01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a193914000104160014105db4dae7e5b8dd4dda7b7d3b1e588c9bf26f192206030dddd5d3c31738ca2d8b25391f648af6a8b08e6961e8f56d4173d03e9db82d3e0c105d19280000000002000000000001001600144f485261505d5cbd33dce02a723776c99240c28722020211ab9359cc49c95b3b9a87ee95fd4edf0cecce862f9e9f86ff63e10880baaba80c105d1928010000000000000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('3f0d188519237478258ad2bf881643618635d11c2bb95512e830fcf2eda3c522', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('3f0d188519237478258ad2bf881643618635d11c2bb95512e830fcf2eda3c522', tx.txid())
        self.assertEqual('27b78ec072a403b0545258e7a1a8d494e4b6fd48bf77f4251a12160c92207cbc', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_xprv_online_xpub_p2wpkh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/84'/1'/0'
            keystore.from_xprv('vprv9K9hbuA23Bidgj1KRSHUZMa59jJLeZBpXPVn4RP7sBLArNhZxJjw4AX7aQmVTErDt4YFC11ptMLjbwxgrsH8GLQ1cx77KggWeVPeDBjr9xM'),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('vpub5Y941QgusZGvuD5nXTpUvVWohm8q41uftcRNronjRWs9jB2iVr4BbxqbRfAoQjWHgJtDCQEXChgfsPbEuBnidtkFztZSD3zDKTrtwXa2LCa'),
            gap_limit=4,
            config=self.config
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1qp0mv2sxsyxxfj5gl0332f9uyez93su9cf26757', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325341
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual((0, 1), tx.signature_count())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))

        orig_tx = tx
        for uses_qr_code in (False, True):
            with self.subTest(msg="uses_qr_code", uses_qr_code=uses_qr_code):
                tx = copy.deepcopy(orig_tx)
                if uses_qr_code:
                    partial_tx, is_complete = tx.to_qr_data()
                    self.assertEqual("FP:A9SADM6+OGU/3KZ/RCI$7/Y2R7OZYNZXB1.$0Y9K69-BXZZ1EAWLM0/*SYX7G:1/0N9+E5YWF0KRPK/Y-GJSJ7TM/A0N0RO.H*S**8E*$W1P7-3RA-+I.1BA77$P8CSX55OHNIIG735$UEH5XTW5DDVD/HK*EQNTI:E3PO:K3$MSN4C3+LIR/-U91-Z9NS/AF*9BZ53VN.XPKD0$.GN*9HOFL3L7MA7ECA86IPZ1J-HJY:$EPZC*3D:+T-L195ULV7:DJ$$Q$H9:+UR:8:5X*S:YC9/HV-$+XQY8/*S1UN9UCE8R786.RW8V$TGQPUCP$KHFM-18I0Q7*RIHI-U0ULUSCG6L3YAS*O4:AEBQLHB37RHRI1E91",
                                     partial_tx)
                    self.assertFalse(is_complete)
                else:
                    partial_tx = tx.serialize_as_bytes().hex()
                    self.assertEqual("70736274ff010071010000000162878508bdcd372fc4c33ce6145cd1fb1dcc5314d4930ceb6957e7f6c54b57980100000000fdffffff02a0252600000000001600140bf6c540d0218c99511f7c62a49784c88b1870b8585d7200000000001600145543fe1a1364b806b27a5c9dc92ac9bbf0d42aa31d3914000001011f80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef0100fd4c0d01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400220603fd88f32a81e812af0187677fc0e7ac9b7fb63ca68c2d98c2afbcf99aa311ac060cdf758ae500000000020000000000220202ac05f54ef082ac98302d57d532e728653565bd55f46fcf03cacbddb168fd6c760cdf758ae5010000000000000000",
                                     partial_tx)
                tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
                self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

                self.assertEqual('ee76c0c6da87f0eb5ab4d1ae05d3942512dcd3c4c42518f9d3619e74400cfc1f', tx_copy.txid())
                self.assertEqual(tx.txid(), tx_copy.txid())

                # sign tx
                tx = wallet_offline.sign_transaction(tx_copy, password=None)
                self.assertTrue(tx.is_complete())
                self.assertEqual((1, 1), tx.signature_count())
                self.assertTrue(tx.is_segwit())
                self.assertEqual('ee76c0c6da87f0eb5ab4d1ae05d3942512dcd3c4c42518f9d3619e74400cfc1f', tx.txid())
                self.assertEqual('484e350beaa722a744bb3e2aa38de005baa8526d86536d6143e5814355acf775', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_offline_signing_beyond_gap_limit(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/84'/1'/0'
            keystore.from_xprv('vprv9K9hbuA23Bidgj1KRSHUZMa59jJLeZBpXPVn4RP7sBLArNhZxJjw4AX7aQmVTErDt4YFC11ptMLjbwxgrsH8GLQ1cx77KggWeVPeDBjr9xM'),
            gap_limit=1,  # gap limit of offline wallet intentionally set too low
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub('vpub5Y941QgusZGvuD5nXTpUvVWohm8q41uftcRNronjRWs9jB2iVr4BbxqbRfAoQjWHgJtDCQEXChgfsPbEuBnidtkFztZSD3zDKTrtwXa2LCa'),
            gap_limit=4,
            config=self.config
        )

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('98574bc5f6e75769eb0c93d41453cc1dfbd15c14e63cc3c42f37cdbd08858762', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1qp0mv2sxsyxxfj5gl0332f9uyez93su9cf26757', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325341
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff010071010000000162878508bdcd372fc4c33ce6145cd1fb1dcc5314d4930ceb6957e7f6c54b57980100000000fdffffff02a0252600000000001600140bf6c540d0218c99511f7c62a49784c88b1870b8585d7200000000001600145543fe1a1364b806b27a5c9dc92ac9bbf0d42aa31d3914000001011f80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef0100fd4c0d01000000000116e9c9dac2651672316aab3b9553257b6942c5f762c5d795776d9cfa504f183c000000000000fdffffff8085019852fada9da84b58dcf753d292dde314a19f5a5527f6588fa2566142130000000000fdffffffa4154a48db20ce538b28722a89c6b578bd5b5d60d6d7b52323976339e39405230000000000fdffffff0b5ef43f843a96364aebd708e25ea1bdcf2c7df7d0d995560b8b1be5f357b64f0100000000fdffffffd41dfe1199c76fdb3f20e9947ea31136d032d9da48c5e45d85c8f440e2351a510100000000fdffffff5bd015d17e4a1837b01c24ebb4a6b394e3da96a85442bd7dc6abddfbf16f20510000000000fdffffff13a3e7f80b1bd46e38f2abc9e2f335c18a4b0af1778133c7f1c3caae9504345c0200000000fdffffffdf4fc1ab21bca69d18544ddb10a913cd952dbc730ab3d236dd9471445ff405680100000000fdffffffe0424d78a30d5e60ac6b26e2274d7d6e7c6b78fe0b49bdc3ac4dd2147c9535750100000000fdffffff7ab6dd6b3c0d44b0fef0fdc9ab0ad6eee23eef799eee29c005d52bc4461998760000000000fdffffff48a77e5053a21acdf4f235ce00c82c9bc1704700f54d217f6a30704711b9737d0000000000fdffffff86918b39c1d9bb6f34d9b082182f73cedd15504331164dc2b186e95c568ccb870000000000fdffffff15a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff9a2875297f81dfd3b77426d63f621db350c270cc28c634ad86b9969ee33ac6960000000000fdffffffd6eeb1d1833e00967083d1ab86fa5a2e44355bd613d9277135240fe6f60148a20100000000fdffffffd8a6e5a9b68a65ff88220ca33e36faf6f826ae8c5c8a13fe818a5e63828b68a40100000000fdffffff73aab8471f82092e45ed1b1afeffdb49ea1ec74ce4853f971812f6a72a7e85aa0000000000fdffffffacd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba0000000000fdffffff1eddd5e13bef1aba1ff151762b5860837daa9b39db1eae8ea8227c81a5a1c8ba0000000000fdffffff67a096ff7c343d39e96929798097f6d7a61156bbdb905fbe534ba36f273271d40100000000fdffffff109a671eb7daf6dcd07c0ceff99f2de65864ab36d64fb3a890bab951569adeee0100000000fdffffff4f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0200000000fdffffff042f280000000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600146c540c1c9f546004539f45318b8d9f4d7b4857ef80969800000000001976a91422a6daa4a7b695c8a2dd104d47c5dc73d655c96f88ac809698000000000017a914a6885437e0762013facbda93894202a0fe86e35f8702473044022075ef5f04d7a63347064938e15a0c74277a79e5c9d32a26e39e8a517a44d565cc022015246790fb5b29c9bf3eded1b95699b1635bcfc6d521886fddf1135ba1b988ec012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe02473044022061aa9b0d9649ffd7259bc54b35f678565dbbe11507d348dd8885522eaf1fa70c02202cc79de09e8e63e8d57fde6ef66c079ddac4d9828e1936a9db833d4c142615c3012103a8f58fc1f5625f18293403104874f2d38c9279f777e512570e4199c7d292b81b0247304402207744dc1ab0bf77c081b58540c4321d090c0a24a32742a361aa55ad86f0c7c24e02201a9b0dd78b63b495ab5a0b5b161c54cb085d70683c90e188bb4dc2e41e142f6601210361fb354f8259abfcbfbdda36b7cb4c3b05a3ca3d68dd391fd8376e920d93870d0247304402204803e423c321acc6c12cb0ebf196d2906842fdfed6de977cc78277052ee5f15002200634670c1dc25e6b1787a65d3e09c8e6bb0340238d90b9d98887e8fd53944e080121031104c60d027123bf8676bcaefaa66c001a0d3d379dc4a9492a567a9e1004452d02473044022050e4b5348d30011a22b6ae8b43921d29249d88ea71b1fbaa2d9c22dfdef58b7002201c5d5e143aa8835454f61b0742226ebf8cd466bcc2cdcb1f77b92e473d3b13190121030496b9d49aa8efece4f619876c60a77d2c0dc846390ecdc5d9acbfa1bb3128760247304402204d6a9b986e1a0e3473e8aef84b3eb7052442a76dfd7631e35377f141496a55490220131ab342853c01e31f111436f8461e28bc95883b871ca0e01b5f57146e79d7bb012103262ffbc88e25296056a3c65c880e3686297e07f360e6b80f1219d65b0900e84e02483045022100c8ffacf92efa1dddef7e858a241af7a80adcc2489bcc325195970733b1f35fac022076f40c26023a228041a9665c5290b9918d06f03b716e4d8f6d47e79121c7eb37012102d9ba7e02d7cd7dd24302f823b3114c99da21549c663f72440dc87e8ba412120902483045022100b55545d84e43d001bbc10a981f184e7d3b98a7ed6689863716cab053b3655a2f0220537eb76a695fbe86bf020b4b6f7ae93b506d778bbd0885f0a61067616a2c8bce0121034a57f2fa2c32c9246691f6a922fb1ebdf1468792bae7eff253a99fc9f2a5023902483045022100f1d4408463dbfe257f9f778d5e9c8cdb97c8b1d395dbd2e180bc08cad306492c022002a024e19e1a406eaa24467f033659de09ab58822987281e28bb6359288337bd012103e91daa18d924eea62011ce596e15b6d683975cf724ea5bf69a8e2022c26fc12f0247304402204f1e12b923872f396e5e1a3aa94b0b2e86b4ce448f4349a017631db26d7dff8a022069899a05de2ad2bbd8e0202c56ab1025a7db9a4998eea70744e3c367d2a7eb71012103b0eee86792dbef1d4a49bc4ea32d197c8c15d27e6e0c5c33e58e409e26d4a39a0247304402201787dacdb92e0df6ad90226649f0e8321287d0bd8fddc536a297dd19b5fc103e022001fe89300a76e5b46d0e3f7e39e0ee26cc83b71d59a2a5da1dd7b13350cd0c07012103afb1e43d7ec6b7999ef0f1093069e68fe1dfe5d73fc6cfb4f7a5022f7098758c02483045022100acc1212bba0fe4fcc6c3ae5cf8e25f221f140c8444d3c08dfc53a93630ac25da02203f12982847244bd9421ef340293f3a38d2ab5d028af60769e46fcc7d81312e7e012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024830450221009c04934102402949484b21899271c3991c007b783b8efc85a3c3d24641ac7c24022006fb1895ce969d08a2cb29413e1a85427c7e85426f7a185108ca44b5a0328cb301210360248db4c7d7f76fe231998d2967104fee04df8d8da34f10101cc5523e82648c02483045022100b11fe61b393fa5dbe18ab98f65c249345b429b13f69ee2d1b1335725b24a0e73022010960cdc5565cbc81885c8ed95142435d3c202dfa5a3dc5f50f3914c106335ce0121029c878610c34c21381cda12f6f36ab88bf60f5f496c1b82c357b8ac448713e7b50247304402200ca080db069c15bbf98e1d4dff68d0aea51227ff5d17a8cf67ceae464c22bbb0022051e7331c0918cbb71bb2cef29ca62411454508a16180b0fb5df94248890840df0121028f0be0cde43ff047edbda42c91c37152449d69789eb812bb2e148e4f22472c0f0247304402201fefe258938a2c481d5a745ef3aa8d9f8124bbe7f1f8c693e2ddce4ddc9a927c02204049e0060889ede8fda975edf896c03782d71ba53feb51b04f5ae5897d7431dc012103946730b480f52a43218a9edce240e8b234790e21df5e96482703d81c3c19d3f1024730440220126a6a56dbe69af78d156626fc9cf41d6aac0c07b8b5f0f8491f68db5e89cb5002207ee6ed6f2f41da256f3c1e79679a3de6cf34cc08b940b82be14aefe7da031a6b012102801bc7170efb82c490e243204d86970f15966aa3bce6a06bef5c09a83a5bfffe024730440220363204a1586d7f13c148295122cbf9ec7939685e3cadab81d6d9e921436d21b7022044626b8c2bd4aa7c167d74bc4e9eb9d0744e29ce0ad906d78e10d6d854f23d170121037fb9c51716739bb4c146857fab5a783372f72a65987d61f3b58c74360f4328dd0247304402207925a4c2a3a6b76e10558717ee28fcb8c6fde161b9dc6382239af9f372ace99902204a58e31ce0b4a4804a42d2224331289311ded2748062c92c8aca769e81417a4c012102e18a8c235b48e41ef98265a8e07fa005d2602b96d585a61ad67168d74e7391cb02483045022100bbfe060479174a8d846b5a897526003eb2220ba307a5fee6e1e8de3e4e8b38fd02206723857301d447f67ac98a5a5c2b80ef6820e98fae213db1720f93d91161803b01210386728e2ac3ecee15f58d0505ee26f86a68f08c702941ffaf2fb7213e5026aea10247304402203a2613ae68f697eb02b5b7d18e3c4236966dac2b3a760e3021197d76e9ad4239022046f9067d3df650fcabbdfd250308c64f90757dec86f0b08813c979a42d06a6ec012102a1d7ee1cb4dc502f899aaafae0a2eb6cbf80d9a1073ae60ddcaabc3b1d1f15df02483045022100ab1bea2cc5388428fd126c7801550208701e21564bd4bd00cfd4407cfafc1acd0220508ee587f080f3c80a5c0b2175b58edd84b755e659e2135b3152044d75ebc4b501210236dd1b7f27a296447d0eb3750e1bdb2d53af50b31a72a45511dc1ec3fe7a684a19391400220603fd88f32a81e812af0187677fc0e7ac9b7fb63ca68c2d98c2afbcf99aa311ac060cdf758ae500000000020000000000220202ac05f54ef082ac98302d57d532e728653565bd55f46fcf03cacbddb168fd6c760cdf758ae5010000000000000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('ee76c0c6da87f0eb5ab4d1ae05d3942512dcd3c4c42518f9d3619e74400cfc1f', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('ee76c0c6da87f0eb5ab4d1ae05d3942512dcd3c4c42518f9d3619e74400cfc1f', tx.txid())
        self.assertEqual('484e350beaa722a744bb3e2aa38de005baa8526d86536d6143e5814355acf775', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_signing_where_offline_ks_does_not_have_keyorigin_but_psbt_contains_it(self, mock_save_db):
        # keystore has intermediate xprv without root fp; tx contains root fp and full path.
        # tx has input with key beyond gap limit
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39 seed: "brave scare company drastic consider confirm grow differ alter wide olympic utility"
            # der: m/84'/1'/0'
            keystore.from_xprv('vprv9KXDgRXYp3WCozCS3bMehASe2cJhY28DihCZ3KuyiTTjngopkfRC9QkH1SUREyCvnV7TSD6EgEHTTYa5yod7ZveBhVReEU1uDgfVASFqLNw'),
            gap_limit=4,
            config=self.config
        )

        tx = tx_from_any('70736274ff01005202000000017b748828553b1127b86674e71ad0cd4a2e5e8baeab8792a3c3263f7ea0ba86500000000000fdffffff01ad16010000000000160014d74b54300bc0d4b6e8f506fe540b47ce0da38b4a08f21c00000100bf0200000000010163a419b779be17167c54ff3acb1205e5347fbd72963f89fb1d66b5cf09f329c90000000000fdffffff011b17010000000000160014ed420532f0c33477b9b3fbb57431b4a1adce99c90247304402204e4ad4992fa8798e3b595d17c59961b905ca71c32dc3ba910ae14f139259ffbe02206ee2281f21499e46aa77f4bec2edce3674fea529d9dd340439365c2232bad35701210334080358ffdac08f83d6800a8e477e3512ad5c39ede553089db8c4bbe16f59aad7f11c00220602d137f257a96cbc58c7e60f2085cd65a311e242459e23d1efbed77dd8f372513818cc2bdaaa540000800100008000000080000000001e000000002202030671d324eeba0f85499a8749f783a4883103d23f5dedbe048391ff18c3da067818cc2bdaaa540000800100008000000080000000000100000000')
        self.assertEqual('065b6e0a5731107641828337f5e000c9ddd94a12d074708643b0bca517374c6a', tx.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertEqual('020000000001017b748828553b1127b86674e71ad0cd4a2e5e8baeab8792a3c3263f7ea0ba86500000000000fdffffff01ad16010000000000160014d74b54300bc0d4b6e8f506fe540b47ce0da38b4a0247304402203098741bf4d4f956e96f2706a517a1c0a63f67a242a50d155fbc56ad0bbac8b102207e535391c03bdab641f3205762311c1e6648b3459681e53d68fa44e63604a7f6012102d137f257a96cbc58c7e60f2085cd65a311e242459e23d1efbed77dd8f372513808f21c00',
                         str(tx))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_wif_online_addr_p2pkh(self, mock_save_db):  # compressed pubkey
        wallet_offline = WalletIntegrityHelper.create_imported_wallet(privkeys=True, config=self.config)
        wallet_offline.import_private_key('p2pkh:cQDxbmQfwRV3vP1mdnVHq37nJekHLsuD3wdSQseBRA2ct4MFk5Pq', password=None)
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('mg2jk6S5WGDhUPA8mLSxDLWpUoQnX1zzoG')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtta9ghm', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100740100000001626bbbb7a4ad82dbf7f6bd64ac3f40d0e2695b606d7953f2802b9ea426ea080a0100000000fdffffff02a025260000000000160014e5bddbfee3883729b48fe3385216e64e6035f6eb585d7200000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac1c391400000100fd200101000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(None, tx_copy.txid())  # not segwit
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.txid())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_wif_online_addr_p2wpkh_p2sh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_imported_wallet(privkeys=True, config=self.config)
        wallet_offline.import_private_key('p2wpkh-p2sh:cU9hVzhpvfn91u2zTVn8uqF2ymS7ucYH8V5TmsTDmuyMHgRk9WsJ', password=None)
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('2NA2JbUVK7HGWUCK5RXSVNHrkgUYF8d9zV8')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtta9ghm', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100720100000001626bbbb7a4ad82dbf7f6bd64ac3f40d0e2695b606d7953f2802b9ea426ea080a0200000000fdffffff02a025260000000000160014e5bddbfee3883729b48fe3385216e64e6035f6eb585d72000000000017a914b808938a8007bc54509cd946944c479c0fa6554f871c391400000100fd200101000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(None, tx_copy.txid())  # redeem script not available
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertEqual(
            "sh(wpkh(03845818239fe468a9e7c7ae1a3d3653a8333f89ff316a771a3acf6854b4d8c6db))",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('7642816d051aa3b333b6564bb6e44fe3a5885bfe7db9860dfbc9973a5c9a6562', tx.txid())
        self.assertEqual('9bb9949974954613945756c48ca5525cd5cba1b667ccb10c7a53e1ed076a1117', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_wif_online_addr_p2wpkh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_imported_wallet(privkeys=True, config=self.config)
        wallet_offline.import_private_key('p2wpkh:cPuQzcNEgbeYZ5at9VdGkCwkPA9r34gvEVJjuoz384rTfYpahfe7', password=None)
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('tb1qm2eh4787lwanrzr6pf0ekf5c7jnmghm2y9k529')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtta9ghm', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100710100000001626bbbb7a4ad82dbf7f6bd64ac3f40d0e2695b606d7953f2802b9ea426ea080a0000000000fdffffff02a025260000000000160014e5bddbfee3883729b48fe3385216e64e6035f6eb585d720000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a1c3914000001011f8096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a0100fd200101000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('f8039bd85279f2b5698f15d47f2e338d067d09af391bd8a19467aa94d03f280c', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('f8039bd85279f2b5698f15d47f2e338d067d09af391bd8a19467aa94d03f280c', tx.txid())
        self.assertEqual('3b7cc3c3352bbb43ddc086487ac696e09f2863c3d9e8636721851b8008a83ffa', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_xprv_online_addr_p2pkh(self, mock_save_db):  # compressed pubkey
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/44'/1'/0'
            keystore.from_xprv('tprv8gfKwjuAaqtHgqxMh1tosAQ28XvBMkcY5NeFRA3pZMpz6MR4H4YZ3MJM4fvNPnRKeXR1Td2vQGgjorNXfo94WvT5CYDsPAqjHxSn436G1Eu'),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('mg2jk6S5WGDhUPA8mLSxDLWpUoQnX1zzoG')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtta9ghm', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100740100000001626bbbb7a4ad82dbf7f6bd64ac3f40d0e2695b606d7953f2802b9ea426ea080a0100000000fdffffff02a025260000000000160014e5bddbfee3883729b48fe3385216e64e6035f6eb585d7200000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac1c391400000100fd200101000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(None, tx_copy.txid())  # not segwit
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertEqual(
            "pkh([233d2ae4]tpubDDMN69wQjDZxaJz9afZQGa48hZS7X5oSegF2hg67yddNvqfpuTN9DqvDEp7YyVf7AzXnqBqHdLhzTAStHvsoMDDb8WoJQzNrcHgDJHVYgQF/0/1)",
            tx.inputs()[0].script_descriptor.to_string_no_checksum())
        self.assertTrue(tx.is_complete())
        self.assertFalse(tx.is_segwit())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.txid())
        self.assertEqual('e56da664631b8c666c6df38ec80c954c4ac3c4f56f040faf0070e4681e937fc4', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_xprv_online_addr_p2wpkh_p2sh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/49'/1'/0'
            keystore.from_xprv('uprv8zHHrMQMQ26utWwNJ5MK2SXpB9hbmy7pbPaneii69xT8cZTyFpxQFxkknGWKP8dxBTZhzy7yP6cCnLrRCQjzJDk3G61SjZpxhFQuB2NR8a5'),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('2NA2JbUVK7HGWUCK5RXSVNHrkgUYF8d9zV8')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtta9ghm', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100720100000001626bbbb7a4ad82dbf7f6bd64ac3f40d0e2695b606d7953f2802b9ea426ea080a0200000000fdffffff02a025260000000000160014e5bddbfee3883729b48fe3385216e64e6035f6eb585d72000000000017a914b808938a8007bc54509cd946944c479c0fa6554f871c391400000100fd200101000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(None, tx_copy.txid())  # redeem script not available
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('7642816d051aa3b333b6564bb6e44fe3a5885bfe7db9860dfbc9973a5c9a6562', tx.txid())
        self.assertEqual('9bb9949974954613945756c48ca5525cd5cba1b667ccb10c7a53e1ed076a1117', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_xprv_online_addr_p2wpkh(self, mock_save_db):
        wallet_offline = WalletIntegrityHelper.create_standard_wallet(
            # bip39: "qwe", der: m/84'/1'/0'
            keystore.from_xprv('vprv9K9hbuA23Bidgj1KRSHUZMa59jJLeZBpXPVn4RP7sBLArNhZxJjw4AX7aQmVTErDt4YFC11ptMLjbwxgrsH8GLQ1cx77KggWeVPeDBjr9xM'),
            gap_limit=4,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('tb1qm2eh4787lwanrzr6pf0ekf5c7jnmghm2y9k529')

        # bootstrap wallet_online
        funding_tx = Transaction('01000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('0a08ea26a49e2b80f253796d605b69e2d0403fac64bdf6f7db82ada4b7bb6b62', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('tb1quk7ahlhr3qmjndy0uvu9y9hxfesrtahtta9ghm', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325340
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff0100710100000001626bbbb7a4ad82dbf7f6bd64ac3f40d0e2695b606d7953f2802b9ea426ea080a0000000000fdffffff02a025260000000000160014e5bddbfee3883729b48fe3385216e64e6035f6eb585d720000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a1c3914000001011f8096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a0100fd200101000000000101197a89cff51096b9dd4214cdee0eb90cb27a25477e739521d728a679724042730100000000fdffffff048096980000000000160014dab37af8fefbbb31887a0a5f9b2698f4a7b45f6a80969800000000001976a91405a20074ef7eb42c7c6fcd4f499faa699742783288ac809698000000000017a914b808938a8007bc54509cd946944c479c0fa6554f87131b2c0400000000160014a04dfdb9a9aeac3b3fada6f43c2a66886186e2440247304402204f5dbb9dda65eab26179f1ca7c37c8baf028153815085dd1bbb2b826296e3b870220379fcd825742d6e2bdff772f347b629047824f289a5499a501033f6c3495594901210363c9c98740fe0455c646215cea9b13807b758791c8af7b74e62968bef57ff8ae1e391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('f8039bd85279f2b5698f15d47f2e338d067d09af391bd8a19467aa94d03f280c', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx
        tx = wallet_offline.sign_transaction(tx_copy, password=None)
        self.assertTrue(tx.is_complete())
        self.assertTrue(tx.is_segwit())
        self.assertEqual('f8039bd85279f2b5698f15d47f2e338d067d09af391bd8a19467aa94d03f280c', tx.txid())
        self.assertEqual('3b7cc3c3352bbb43ddc086487ac696e09f2863c3d9e8636721851b8008a83ffa', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_hd_multisig_online_addr_p2sh(self, mock_save_db):
        # 2-of-3 legacy p2sh multisig
        wallet_offline1 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure', passphrase='', for_multisig=True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4XJzYkhsCbDCcZRmDAKSD7bXi9mdCni7acVt45fxbTVZyU6jRGh29ULKTjoapkfFsSJvQHitcVKbQgzgkkYsAmaovcro7Mhf')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        wallet_offline2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song', passphrase='', for_multisig=True),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YTPEgwk4zzr8wyo7pXGmbbVUnfYNtx6SgAMF5q3LN3Kch58P9hxGNsTmP7Dn49nnrmpE6upoRb1Xojg12FGLuLHkVpVtS44'),
                keystore.from_xpub('tpubD6NzVbkrYhZ4YARFMEZPckrqJkw59GZD1PXtQnw14ukvWDofR7Z1HMeSCxfYEZVvg4VdZ8zGok5VxHwdrLqew5cMdQntWc5mT7mh1CSgrnX')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('2N4z38eTKcWTZnfugCCfRyXtXWMLnn8HDfw')

        # bootstrap wallet_online
        funding_tx = Transaction('010000000001016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc3927050301000000171600147a4fc8cdc1c2cf7abbcd88ef6d880e59269797acfdffffff02809698000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e48870d0916020000000017a914703f83ef20f3a52d908475dcad00c5144164d5a2870247304402203b1a5cb48cadeee14fa6c7bbf2bc581ca63104762ec5c37c703df778884cc5b702203233fa53a2a0bfbd85617c636e415da72214e359282cce409019319d031766c50121021112c01a48cc7ea13cba70493c6bffebb3e805df10ff4611d2bf559d26e25c04bf391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('c59913a1fa9b1ef1f6928f0db490be67eeb9d7cb05aa565ee647e859642f3532', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('2MuCQQHJNnrXzQzuqfUCfAwAjPqpyEHbgue', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325503
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff010073010000000132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c50000000000fdffffff02a02526000000000017a9141567b2578f300fa618ef0033611fd67087aff6d187585d72000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887bf391400000100f7010000000001016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc3927050301000000171600147a4fc8cdc1c2cf7abbcd88ef6d880e59269797acfdffffff02809698000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e48870d0916020000000017a914703f83ef20f3a52d908475dcad00c5144164d5a2870247304402203b1a5cb48cadeee14fa6c7bbf2bc581ca63104762ec5c37c703df778884cc5b702203233fa53a2a0bfbd85617c636e415da72214e359282cce409019319d031766c50121021112c01a48cc7ea13cba70493c6bffebb3e805df10ff4611d2bf559d26e25c04bf391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(None, tx_copy.txid())  # not segwit
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx - first
        tx = wallet_offline1.sign_transaction(tx_copy, password=None)
        self.assertFalse(tx.is_complete())
        self.assertEqual((1, 2), tx.signature_count())
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff010073010000000132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c50000000000fdffffff02a02526000000000017a9141567b2578f300fa618ef0033611fd67087aff6d187585d72000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887bf391400000100f7010000000001016207d958dc46508d706e4cd7d3bc46c5c2b02160e2578e5fad2efafc3927050301000000171600147a4fc8cdc1c2cf7abbcd88ef6d880e59269797acfdffffff02809698000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e48870d0916020000000017a914703f83ef20f3a52d908475dcad00c5144164d5a2870247304402203b1a5cb48cadeee14fa6c7bbf2bc581ca63104762ec5c37c703df778884cc5b702203233fa53a2a0bfbd85617c636e415da72214e359282cce409019319d031766c50121021112c01a48cc7ea13cba70493c6bffebb3e805df10ff4611d2bf559d26e25c04bf391400220202afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f284730440220451f77cb18224adcb4981492d9be2c3fa7537f94f4b29eb405992dbdd5df04aa022071e6759d40dde810caa01ca7f16bad3cb742d64428c419c8fb4bad6f1c3f718101010469522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53ae220602afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f280c0036e9ac00000000000000002206030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf0c48adc7a00000000000000000220603e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce0cdb69242700000000000000000000010069522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53ae220202afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f280c0036e9ac00000000000000002202030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf0c48adc7a00000000000000000220203e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce0cdb692427000000000000000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners

        # sign tx - second
        tx = wallet_offline2.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        self.assertEqual((2, 2), tx.signature_count())
        tx = tx_from_any(tx.serialize())

        self.assertEqual('010000000132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c500000000fc004730440220451f77cb18224adcb4981492d9be2c3fa7537f94f4b29eb405992dbdd5df04aa022071e6759d40dde810caa01ca7f16bad3cb742d64428c419c8fb4bad6f1c3f718101473044022052980154bdf2e43d6bd8775316cc220ef5ae13b4b9574a7a904a691ee3c5efd3022069b3eddf904cc645bd8fc8b2aaa7aaf7eb5bbfb7bbbd3b6e6cd89b37dfb2856c014c69522102afb4af9a91264e1c6dce3ebe5312801723270ac0ba8134b7b49129328fcb0f2821030b482838721a38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cf2103e5db7969ae2f2576e6a061bf3bb2db16571e77ffb41e0b27170734359235cbce53aefdffffff02a02526000000000017a9141567b2578f300fa618ef0033611fd67087aff6d187585d72000000000017a91480c2353f6a7bc3c71e99e062655b19adb3dd2e4887bf391400',
                         str(tx))
        self.assertEqual('0e8fdc8257a85ebe7eeab14a53c2c258c61a511f64176b7f8fc016bc2263d307', tx.txid())
        self.assertEqual('0e8fdc8257a85ebe7eeab14a53c2c258c61a511f64176b7f8fc016bc2263d307', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_hd_multisig_online_addr_p2wsh_p2sh(self, mock_save_db):
        # 2-of-2 p2sh-embedded segwit multisig
        wallet_offline1 = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: finish seminar arrange erosion sunny coil insane together pretty lunch lunch rose, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9CvELvByqm8k2dpecJVjgLMX1z5DufEjY4fBC5YvdGF5WjGCa7GVJJ2fYni1tyuF7Hw83E6W2ZBjAhaFLZv2ri3rEsubkCd5avg4EHKoDBN'),
                keystore.from_xpub('Upub5Qb8ik4Cnu8g97KLXKgVXHqY6tH8emQvqtBncjSKsyfTZuorPtTZgX7ovKKZHuuVGBVd1MTTBkWez1XXt2weN1sWBz6SfgRPQYEkNgz81QF')
            ],
            '2of2', gap_limit=2,
            config=self.config
        )
        wallet_offline2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                # bip39: square page wood spy oil story rebel give milk screen slide shuffle, der: m/1234'/1'/0', p2wsh-p2sh multisig
                keystore.from_xprv('Uprv9BbnKEXJxXaNvdEsRJ9VA9toYrSeFJh5UfGBpM2iKe8Uh7UhrM9K8ioL53s8gvCoGfirHHaqpABDAE7VUNw8LNU1DMJKVoWyeNKu9XcDC19'),
                keystore.from_xpub('Upub5RuakRisg8h3F7u7iL2k3UJFa1uiK7xauHamzTxYBbn4PXbM7eajr6M9Q2VCr6cVGhfhqWQqxnABvtSATuVM1xzxk4nA189jJwzaMn1QX7V')
            ],
            '2of2', gap_limit=2,
            config=self.config
        )
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('2MsHQRm1pNi6VsmXYRxYMcCTdPu7Xa1RyFe')

        # bootstrap wallet_online
        funding_tx = Transaction('0100000000010118d494d28e5c3bf61566ca0313e22c3b561b888a317d689cc8b47b947adebd440000000017160014aec84704ea8508ddb94a3c6e53f0992d33a2a529fdffffff020f0925000000000017a91409f7aae0265787a02de22839d41e9c927768230287809698000000000017a91400698bd11c38f887f17c99846d9be96321fbf989870247304402206b906369f4075ebcfc149f7429dcfc34e11e1b7bbfc85d1185d5e9c324be0d3702203ce7fc12fd3131920fbcbb733250f05dbf7d03e18a4656232ee69d5c54dd46bd0121028a4b697a37f3f57f6e53f90db077fa9696095b277454fda839c211d640d48649c0391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('54356de9e156b85c8516fd4d51bdb68b5513f58b4a6147483978ae254627ee3e', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('2N8CtJRwxb2GCaiWWdSHLZHHLoZy53CCyxf', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325504
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007301000000013eee274625ae78394847614a8bf513558bb6bd514dfd16855cb856e1e96d35540100000000fdffffff02a02526000000000017a914a4189ef02c95cfe36f8e880c6cb54dff0837b22687585d72000000000017a91400698bd11c38f887f17c99846d9be96321fbf98987c0391400000100f70100000000010118d494d28e5c3bf61566ca0313e22c3b561b888a317d689cc8b47b947adebd440000000017160014aec84704ea8508ddb94a3c6e53f0992d33a2a529fdffffff020f0925000000000017a91409f7aae0265787a02de22839d41e9c927768230287809698000000000017a91400698bd11c38f887f17c99846d9be96321fbf989870247304402206b906369f4075ebcfc149f7429dcfc34e11e1b7bbfc85d1185d5e9c324be0d3702203ce7fc12fd3131920fbcbb733250f05dbf7d03e18a4656232ee69d5c54dd46bd0121028a4b697a37f3f57f6e53f90db077fa9696095b277454fda839c211d640d48649c0391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual(None, tx_copy.txid())  # redeem script not available
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx - first
        tx = wallet_offline1.sign_transaction(tx_copy, password=None)
        self.assertFalse(tx.is_complete())
        self.assertEqual('6a58a51591142429203b62b6ddf6b799a6926882efac229998c51bee6c3573eb', tx.txid())
        partial_tx = tx.serialize_as_bytes().hex()
        # note re PSBT: online wallet had put a NON-WITNESS UTXO for input0, as they did not know if it was segwit.
        #               offline wallet now replaced this with a WITNESS-UTXO.
        #               this switch is needed to interop with bitcoin core... https://github.com/bitcoin/bitcoin/blob/fba574c908bb61eff1a0e83c935f3526ba9035f2/src/psbt.cpp#L163
        self.assertEqual("70736274ff01007301000000013eee274625ae78394847614a8bf513558bb6bd514dfd16855cb856e1e96d35540100000000fdffffff02a02526000000000017a914a4189ef02c95cfe36f8e880c6cb54dff0837b22687585d72000000000017a91400698bd11c38f887f17c99846d9be96321fbf98987c0391400000100f70100000000010118d494d28e5c3bf61566ca0313e22c3b561b888a317d689cc8b47b947adebd440000000017160014aec84704ea8508ddb94a3c6e53f0992d33a2a529fdffffff020f0925000000000017a91409f7aae0265787a02de22839d41e9c927768230287809698000000000017a91400698bd11c38f887f17c99846d9be96321fbf989870247304402206b906369f4075ebcfc149f7429dcfc34e11e1b7bbfc85d1185d5e9c324be0d3702203ce7fc12fd3131920fbcbb733250f05dbf7d03e18a4656232ee69d5c54dd46bd0121028a4b697a37f3f57f6e53f90db077fa9696095b277454fda839c211d640d48649c0391400220202d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c4730440220234f6648c5741eb195f0f4cd645298a10ce02f6ef557d05df93331e21c4f58cb022058ce2af0de1c238c4a8dd3b3c7a9a0da6e381ddad7593cddfc0480f9fe5baadf0101042200206ee8d4bb1277b7dbe1d4e49b880993aa993f417a9101cb23865c7c7258732704010547522102975c00f6af579f9a1d283f1e5a43032deadbab2308aef30fb307c0cfe54777462102d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c52ae220602975c00f6af579f9a1d283f1e5a43032deadbab2308aef30fb307c0cfe54777460c17cea9140000000001000000220602d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c0cd1dbcc210000000001000000000001002200206ee8d4bb1277b7dbe1d4e49b880993aa993f417a9101cb23865c7c7258732704010147522102975c00f6af579f9a1d283f1e5a43032deadbab2308aef30fb307c0cfe54777462102d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c52ae220202975c00f6af579f9a1d283f1e5a43032deadbab2308aef30fb307c0cfe54777460c17cea9140000000001000000220202d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c0cd1dbcc21000000000100000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners

        # sign tx - second
        tx = wallet_offline2.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        tx = tx_from_any(tx.serialize())

        self.assertEqual('010000000001013eee274625ae78394847614a8bf513558bb6bd514dfd16855cb856e1e96d355401000000232200206ee8d4bb1277b7dbe1d4e49b880993aa993f417a9101cb23865c7c7258732704fdffffff02a02526000000000017a914a4189ef02c95cfe36f8e880c6cb54dff0837b22687585d72000000000017a91400698bd11c38f887f17c99846d9be96321fbf98987040047304402205a9dd9eb5676196893fb08f60079a2e9f567ee39614075d8c5d9fab0f11cbbc7022039640855188ebb7bccd9e3f00b397a888766d42d00d006f1ca7457c15449285f014730440220234f6648c5741eb195f0f4cd645298a10ce02f6ef557d05df93331e21c4f58cb022058ce2af0de1c238c4a8dd3b3c7a9a0da6e381ddad7593cddfc0480f9fe5baadf0147522102975c00f6af579f9a1d283f1e5a43032deadbab2308aef30fb307c0cfe54777462102d3f47041b424a84898e315cc8ef58190f6aec79c178c12de0790890ba7166e9c52aec0391400',
                         str(tx))
        self.assertEqual('6a58a51591142429203b62b6ddf6b799a6926882efac229998c51bee6c3573eb', tx.txid())
        self.assertEqual('96d0bca1001778c54e4c3a07929fab5562c5b5a23fd1ca3aa3870cc5df2bf97d', tx.wtxid())

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sending_offline_hd_multisig_online_addr_p2wsh(self, mock_save_db):
        # 2-of-3 p2wsh multisig
        wallet_offline1 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        wallet_offline2 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('snow nest raise royal more walk demise rotate smooth spirit canyon gun', passphrase='', for_multisig=True),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra'),
                keystore.from_xpub('Vpub5gSKXzxK7FeKQedu2q1z9oJWxqvX72AArW3HSWpEhc8othDH8xMDu28gr7gf17sp492BuJod8Tn7anjvJrKpETwqnQqX7CS8fcYyUtedEMk')
            ],
            '2of3', gap_limit=2,
            config=self.config
        )
        # ^ third seed: hedgehog sunset update estate number jungle amount piano friend donate upper wool
        wallet_online = WalletIntegrityHelper.create_imported_wallet(privkeys=False, config=self.config)
        wallet_online.import_address('tb1q83p6eqxkuvq4eumcha46crpzg4nj84s9p0hnynkxg8nhvfzqcc7q4erju6')

        # bootstrap wallet_online
        funding_tx = Transaction('0100000000010132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c501000000171600142e5d579693b2a7679622935df94d9f3c84909b24fdffffff0280969800000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c83717d010000000017a91441b772909ad301b41b76f4a3c5058888a7fe6f9a8702483045022100de54689f74b8efcce7fdc91e40761084686003bcd56c886ee97e75a7e803526102204dea51ae5e7d01bd56a8c336c64841f7fe02a8b101fa892e13f2d079bb14e6bf012102024e2f73d632c49f4b821ccd3b6da66b155427b1e5b1c4688cefd5a4b4bfa404c1391400')
        funding_txid = funding_tx.txid()
        self.assertEqual('643a7ab9083d0227dd9df314ce56b18d279e6018ff975079dfaab82cd7a66fa3', funding_txid)
        wallet_online.adb.receive_tx_callback(funding_tx, TX_HEIGHT_UNCONFIRMED)

        # create unsigned tx
        outputs = [PartialTxOutput.from_address_and_value('2MyoZVy8T1t94yLmyKu8DP1SmbWvnxbkwRA', 2500000)]
        tx = wallet_online.create_transaction(outputs=outputs, password=None, fee=5000, rbf=True)
        tx.locktime = 1325505
        tx.version = 1

        self.assertFalse(tx.is_complete())
        self.assertEqual(1, len(tx.inputs()))
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007e0100000001a36fa6d72cb8aadf795097ff18609e278db156ce14f39ddd27023d08b97a3a640000000000fdffffff02a02526000000000017a91447ee5a659f6ffb53f7e3afc1681b6415f3c00fa187585d7200000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63cc13914000001012b80969800000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c0100fd03010100000000010132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c501000000171600142e5d579693b2a7679622935df94d9f3c84909b24fdffffff0280969800000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c83717d010000000017a91441b772909ad301b41b76f4a3c5058888a7fe6f9a8702483045022100de54689f74b8efcce7fdc91e40761084686003bcd56c886ee97e75a7e803526102204dea51ae5e7d01bd56a8c336c64841f7fe02a8b101fa892e13f2d079bb14e6bf012102024e2f73d632c49f4b821ccd3b6da66b155427b1e5b1c4688cefd5a4b4bfa404c1391400000000",
                         partial_tx)
        tx_copy = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners
        self.assertTrue(wallet_online.is_mine(wallet_online.adb.get_txin_address(tx_copy.inputs()[0])))

        self.assertEqual('32e946761b4e718c1fa8d044db9e72d5831f6395eb284faf2fb5c4af0743e501', tx_copy.txid())
        self.assertEqual(tx.txid(), tx_copy.txid())

        # sign tx - first
        tx = wallet_offline1.sign_transaction(tx_copy, password=None)
        self.assertFalse(tx.is_complete())
        self.assertEqual('32e946761b4e718c1fa8d044db9e72d5831f6395eb284faf2fb5c4af0743e501', tx.txid())
        partial_tx = tx.serialize_as_bytes().hex()
        self.assertEqual("70736274ff01007e0100000001a36fa6d72cb8aadf795097ff18609e278db156ce14f39ddd27023d08b97a3a640000000000fdffffff02a02526000000000017a91447ee5a659f6ffb53f7e3afc1681b6415f3c00fa187585d7200000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63cc13914000001012b80969800000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c0100fd03010100000000010132352f6459e847e65e56aa05cbd7b9ee67be90b40d8f92f6f11e9bfaa11399c501000000171600142e5d579693b2a7679622935df94d9f3c84909b24fdffffff0280969800000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c83717d010000000017a91441b772909ad301b41b76f4a3c5058888a7fe6f9a8702483045022100de54689f74b8efcce7fdc91e40761084686003bcd56c886ee97e75a7e803526102204dea51ae5e7d01bd56a8c336c64841f7fe02a8b101fa892e13f2d079bb14e6bf012102024e2f73d632c49f4b821ccd3b6da66b155427b1e5b1c4688cefd5a4b4bfa404c139140022020223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa4730440220629d89626585f563202e6b38ceddc26ccd00737e0b7ee4239b9266ef9174ea2f02200b74828399a2e35ed46c9b484af4817438d5fea890606ebb201b821944db1fdc0101056952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae22060223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa10b2e35a7d01000080000000000000000022060273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e1053b77ddb010000800000000000000000220602aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae9411043067d63010000800000000000000000000001016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153ae22020223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa10b2e35a7d01000080000000000000000022020273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e1053b77ddb010000800000000000000000220202aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae9411043067d6301000080000000000000000000",
                         partial_tx)
        tx = tx_from_any(partial_tx)  # simulates moving partial txn between cosigners

        # sign tx - second
        tx = wallet_offline2.sign_transaction(tx, password=None)
        self.assertTrue(tx.is_complete())
        tx = tx_from_any(tx.serialize())

        self.assertEqual('01000000000101a36fa6d72cb8aadf795097ff18609e278db156ce14f39ddd27023d08b97a3a640000000000fdffffff02a02526000000000017a91447ee5a659f6ffb53f7e3afc1681b6415f3c00fa187585d7200000000002200203c43ac80d6e3015cf378bf6bac0c22456723d6050bef324ec641e7762440c63c04004730440220629d89626585f563202e6b38ceddc26ccd00737e0b7ee4239b9266ef9174ea2f02200b74828399a2e35ed46c9b484af4817438d5fea890606ebb201b821944db1fdc0147304402205d1a59c84c419992069e9764a7992abca6a812cc5dfd4f0d6515d4283e660ce802202597a38899f31545aaf305629bd488f36bf54e4a05fe983932cafbb3906efb8f016952210223f815ab09f6bfc8519165c5232947ae89d9d43d678fb3486f3b28382a2371fa210273c529c2c9a99592f2066cebc2172a48991af2b471cb726b9df78c6497ce984e2102aa8fc578b445a1e4257be6b978fcece92980def98dce0e1eb89e7364635ae94153aec1391400',
                         str(tx))
        self.assertEqual('32e946761b4e718c1fa8d044db9e72d5831f6395eb284faf2fb5c4af0743e501', tx.txid())
        self.assertEqual('4376fa5f1f6cb37b1f3956175d3bd4ef6882169294802b250a3c672f3ff431c1', tx.wtxid())


class TestWalletCreationChecks(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_duplicate_masterkeys_in_multisig(self, mock_save_db):
        # ks1 (seed) and ks2 have same xpub
        with self.assertRaises(Exception) as ctx1:
            w1 = WalletIntegrityHelper.create_multisig_wallet(
                [
                    keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                    keystore.from_xpub('Vpub5gSKXzxK7FeKQedu2q1z9oJWxqvX72AArW3HSWpEhc8othDH8xMDu28gr7gf17sp492BuJod8Tn7anjvJrKpETwqnQqX7CS8fcYyUtedEMk'),  # collides with seed
                    keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra'),
                ],
                '2of3', gap_limit=2,
                config=self.config
            )
        self.assertIn('duplicate xpubs in multisig', ctx1.exception.args[0])
        # ks2 and ks3 have same xpub
        with self.assertRaises(Exception) as ctx2:
            w2 = WalletIntegrityHelper.create_multisig_wallet(
                [
                    keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                    keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                    keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                ],
                '2of3', gap_limit=2,
                config=self.config
            )
        self.assertIn('duplicate xpubs in multisig', ctx2.exception.args[0])
        # all xpubs different. should not raise.
        w3 = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                keystore.from_xpub('Vpub5fcdcgEwTJmbmqAktuK8Kyq92fMf7sWkcP6oqAii2tG47dNbfkGEGUbfS9NuZaRywLkHE6EmUksrqo32ZL3ouLN1HTar6oRiHpDzKMAF1tf'),
                keystore.from_xpub('Vpub5fjkKyYnvSS4wBuakWTkNvZDaBM2vQ1MeXWq368VJHNr2eT8efqhpmZ6UUkb7s2dwCXv2Vuggjdhk4vZVyiAQTwUftvff73XcUGq2NQmWra'),
            ],
            '2of3', gap_limit=2,
            config=self.config
        )

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_heterogeneous_xpub_types_in_multisig(self, mock_save_db):
        # tpub + vpub
        with self.assertRaises(Exception) as ctx1:
            w1 = WalletIntegrityHelper.create_multisig_wallet(
                [
                    keystore.from_xpub('tpubD6NzVbkrYhZ4XYdbWCGSusTDQRAX4UnuqcikJAkqMYxBkvnGfUBvXBE84eyQS6e4To3Pz1xwLrEuxGgQayn4dqVXwNM7dWh4U4DgHai2scz'),
                    keystore.from_xpub('vpub5VmsevU91fpRaJkfa8b6c9MK53gKY8rSzZjrZdp6dkHZjnFhM1HN74ezHY96JCgFnbQJhRbeUyr5S1vzdcTB6qUKrrG7GBuwPYDTzBjLQmv'),
                ],
                '2of2', gap_limit=2,
                config=self.config
            )
        self.assertIn('multisig wallet needs to have homogeneous xpub types', ctx1.exception.args[0])
        # tpub + "segwit" seed
        with self.assertRaises(Exception) as ctx2:
            w1 = WalletIntegrityHelper.create_multisig_wallet(
                [
                    keystore.from_xpub('tpubD6NzVbkrYhZ4XYdbWCGSusTDQRAX4UnuqcikJAkqMYxBkvnGfUBvXBE84eyQS6e4To3Pz1xwLrEuxGgQayn4dqVXwNM7dWh4U4DgHai2scz'),
                    keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                ],
                '2of2', gap_limit=2,
                config=self.config
            )
        self.assertIn('multisig wallet needs to have homogeneous xpub types', ctx2.exception.args[0])
        # "standard" seed + "segwit" seed
        with self.assertRaises(Exception) as ctx3:
            w1 = WalletIntegrityHelper.create_multisig_wallet(
                [
                    keystore.from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song', passphrase='', for_multisig=True),
                    keystore.from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver', passphrase='', for_multisig=True),
                ],
                '2of2', gap_limit=2,
                config=self.config
            )
        self.assertIn('multisig wallet needs to have homogeneous xpub types', ctx3.exception.args[0])
        # "old" seed + "standard" seed
        with self.assertRaises(Exception) as ctx4:
            w1 = WalletIntegrityHelper.create_multisig_wallet(
                [
                    keystore.from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song', passphrase='', for_multisig=True),
                    keystore.from_seed('powerful random nobody notice nothing important anyway look away hidden message over', passphrase='', for_multisig=True),
                ],
                '2of2', gap_limit=2,
                config=self.config
            )
        self.assertIn('unexpected keystore type', ctx4.exception.args[0])


class TestWalletHistory_SimpleRandomOrder(ElectrumTestCase):
    TESTNET = True
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

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def create_old_wallet(self):
        ks = keystore.from_old_mpk('e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')
        # seed words: powerful random nobody notice nothing important anyway look away hidden message over
        w = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=20, config=self.config)
        # some txns are beyond gap limit:
        w.create_new_address(for_change=True)
        return w

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_restoring_old_wallet_txorder1(self, mock_save_db):
        w = self.create_old_wallet()
        for i in [2, 12, 7, 9, 11, 10, 16, 6, 17, 1, 13, 15, 5, 8, 4, 0, 14, 18, 3]:
            tx = Transaction(self.transactions[self.txid_list[i]])
            w.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(27633300, sum(w.get_balance()))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_restoring_old_wallet_txorder2(self, mock_save_db):
        w = self.create_old_wallet()
        for i in [9, 18, 2, 0, 13, 3, 1, 11, 4, 17, 7, 14, 12, 15, 10, 8, 5, 6, 16]:
            tx = Transaction(self.transactions[self.txid_list[i]])
            w.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(27633300, sum(w.get_balance()))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_restoring_old_wallet_txorder3(self, mock_save_db):
        w = self.create_old_wallet()
        for i in [5, 8, 17, 0, 9, 10, 12, 3, 15, 18, 2, 11, 14, 7, 16, 1, 4, 6, 13]:
            tx = Transaction(self.transactions[self.txid_list[i]])
            w.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(27633300, sum(w.get_balance()))


class TestWalletHistory_EvilGapLimit(ElectrumTestCase):
    TESTNET = True
    transactions = {
        # txn A:
        "511a35e240f4c8855de4c548dad932d03611a37e94e9203fdb6fc79911fe1dd4": "010000000001018aacc3c8f98964232ebb74e379d8ff4e800991eecfcf64bd1793954f5e50a8790100000000fdffffff0340420f0000000000160014dbf321e905d544b54b86a2f3ed95b0ac66a3ddb0ff0514000000000016001474f1c130d3db22894efb3b7612b2c924628d0d7e80841e000000000016001488492707677190c073b6555fb08d37e91bbb75d802483045022100cf2904e09ea9d2670367eccc184d92fcb8a9b9c79a12e4efe81df161077945db02203530276a3401d944cf7a292e0660f36ee1df4a1c92c131d2c0d31d267d52524901210215f523a412a5262612e1a5ef9842dc864b0d73dc61fb4c6bfd480a867bebb1632e181400",
        # txn B:
        "fde0b68938709c4979827caa576e9455ded148537fdb798fd05680da64dc1b4f": "01000000000101a317998ac6cc717de17213804e1459900fe257b9f4a3b9b9edd29806728277530100000000fdffffff03c0c62d00000000001600149543301687b1ca2c67718d55fbe10413c73ddec200093d00000000001600141bc12094a4475dcfbf24f9920dafddf9104ca95b3e4a4c0000000000160014b226a59f2609aa7da4026fe2c231b5ae7be12ac302483045022100f1082386d2ce81612a3957e2801803938f6c0066d76cfbd853918d4119f396df022077d05a2b482b89707a8a600013cb08448cf211218a462f2a23c2c0d80a8a0ca7012103f4aac7e189de53d95e0cb2e45d3c0b2be18e93420734934c61a6a5ad88dd541033181400",
        # txn C:
        "268fce617aaaa4847835c2212b984d7b7741fdab65de22813288341819bc5656": "010000000001014f1bdc64da8056d08f79db7f5348d1de55946e57aa7c8279499c703889b6e0fd0100000000fdffffff0260e316000000000016001445e9879cf7cd5b4a15df7ddcaf5c6dca0e1508bacc242600000000001600141bc12094a4475dcfbf24f9920dafddf9104ca95b02483045022100ae3618912f341fefee11b67e0047c47c88c4fa031561c3fafe993259dd14d846022056fa0a5b5d8a65942fa68bcc2f848fd71fa455ba42bc2d421b67eb49ba62aa4e01210394d8f4f06c2ea9c569eb050c897737a7315e7f2104d9b536b49968cc89a1f11033181400",
    }

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({
            'electrum_path': self.electrum_path,
        })
        self.config.NETWORK_SKIPMERKLECHECK = True  # needed for Synchronizer to generate new addresses without SPV

    def create_wallet(self):
        ks = keystore.from_xpub('vpub5Vhmk4dEJKanDTTw6immKXa3thw45u3gbd1rPYjREB6viP13sVTWcH6kvbR2YeLtGjradr6SFLVt9PxWDBSrvw1Dc1nmd3oko3m24CQbfaJ')
        # seed words: nephew work weather maze pyramid employ check permit garment scene kiwi smooth
        w = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=20, config=self.config)
        return w

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_restoring_wallet_txorder1(self, mock_save_db):
        w = self.create_wallet()
        w.db.put('stored_height', 1316917 + 100)
        for txid in self.transactions:
            tx = Transaction(self.transactions[txid])
            w.adb.add_transaction(tx)
        # txn A is an external incoming txn paying to addr (3) and (15)
        # txn B is an external incoming txn paying to addr (4) and (25)
        # txn C is an internal transfer txn from addr (25) -- to -- (1) and (25)
        w.adb.receive_history_callback('tb1qgh5c088he4d559wl0hw27hrdeg8p2z96pefn4q',  # HD index 1
                                   [('268fce617aaaa4847835c2212b984d7b7741fdab65de22813288341819bc5656', 1316917)],
                                   {})
        w.synchronize()
        w.adb.receive_history_callback('tb1qm0ejr6g964zt2jux5te7m9ds43n28hdsdz9ull',  # HD index 3
                                   [('511a35e240f4c8855de4c548dad932d03611a37e94e9203fdb6fc79911fe1dd4', 1316912)],
                                   {})
        w.synchronize()
        w.adb.receive_history_callback('tb1qj4pnq958k89zcem3342lhcgyz0rnmhkzl6x0cl',  # HD index 4
                                   [('fde0b68938709c4979827caa576e9455ded148537fdb798fd05680da64dc1b4f', 1316917)],
                                   {})
        w.synchronize()
        w.adb.receive_history_callback('tb1q3pyjwpm8wxgvquak240mprfhaydmkawcsl25je',  # HD index 15
                                   [('511a35e240f4c8855de4c548dad932d03611a37e94e9203fdb6fc79911fe1dd4', 1316912)],
                                   {})
        w.synchronize()
        w.adb.receive_history_callback('tb1qr0qjp99ygawul0eylxfqmt7alygye22mj33vej',  # HD index 25
                                   [('fde0b68938709c4979827caa576e9455ded148537fdb798fd05680da64dc1b4f', 1316917),
                                    ('268fce617aaaa4847835c2212b984d7b7741fdab65de22813288341819bc5656', 1316917)],
                                   {})
        w.synchronize()
        self.assertEqual(9999788, sum(w.get_balance()))


class TestWalletHistory_DoubleSpend(ElectrumTestCase):
    TESTNET = True
    transactions = {
        # txn A:
        "a3849040f82705151ba12a4389310b58a17b78025d81116a3338595bdefa1625": "020000000001011b7eb29921187b40209c234344f57a3365669c8883a3d511fbde5155f11f64d10000000000fdffffff024c400f0000000000160014b50d21483fb5e088db90bf766ea79219fb377fef40420f0000000000160014aaf5fc4a6297375c32403a9c2768e7029c8dbd750247304402206efd510954b289829f8f778163b98a2a4039deb93c3b0beb834b00cd0add14fd02201c848315ddc52ced0350a981fe1a7f3cbba145c7a43805db2f126ed549eaa500012103083a50d63264743456a3e812bfc91c11bd2a673ba4628c09f02d78f62157e56d788d1700",
        # txn B:
        "0e2182ead6660790290371516cb0b80afa8baebd30dad42b5e58a24ceea17f1c": "020000000001012516fade5b5938336a11815d02787ba1580b3189432aa11b150527f8409084a30100000000fdffffff02a086010000000000160014cb893c9fbb565363556fb18a3bcdda6f20af0bf8d8ba0d0000000000160014478902f02c2b6cd405bb6bd1f90e9860bec173e20247304402206940671b5bdb230a9721aa57396af73d399fb210d795e7dbb8ec1977e101a5470220625505de035d4006b72bd6dfcf09468d1e8da53071080b37b16b0dbbf776db78012102254b5b20ed21c3bba75ec2a9ff230257d13a2493f6b7da066d8195dcdd484310788d1700",
        # txn C:
        "2c9aa33d9c8ec649f9bfb84af027a5414b760be5231fe9eca4a95b9eb3f8a017": "020000000001012516fade5b5938336a11815d02787ba1580b3189432aa11b150527f8409084a30100000000fdffffff01d2410f00000000001600147880a7c79744b908a5f6d6235f2eb46c174c84f002483045022100974d27c872f09115e57c6acb674cd4da6d0b26656ad967ddb2678ff409714b9502206d91b49cf778ced6ca9e40b4094fb57b86c86fac09ce46ce53aea4afa68ff311012102254b5b20ed21c3bba75ec2a9ff230257d13a2493f6b7da066d8195dcdd484310788d1700",
    }

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_restoring_wallet_without_manual_delete(self, mock_save_db):
        w = restore_wallet_from_text("small rapid pattern language comic denial donate extend tide fever burden barrel",
                                     path='if_this_exists_mocking_failed_648151893',
                                     gap_limit=5,
                                     config=self.config)['wallet']  # type: Abstract_Wallet
        for txid in self.transactions:
            tx = Transaction(self.transactions[txid])
            w.adb.add_transaction(tx)
        # txn A is an external incoming txn funding the wallet
        # txn B is an outgoing payment to an external address
        # txn C is double-spending txn B, to a wallet address
        self.assertEqual(999890, sum(w.get_balance()))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_restoring_wallet_with_manual_delete(self, mock_save_db):
        w = restore_wallet_from_text("small rapid pattern language comic denial donate extend tide fever burden barrel",
                                     path='if_this_exists_mocking_failed_648151893',
                                     gap_limit=5,
                                     config=self.config)['wallet']  # type: Abstract_Wallet
        # txn A is an external incoming txn funding the wallet
        txA = Transaction(self.transactions["a3849040f82705151ba12a4389310b58a17b78025d81116a3338595bdefa1625"])
        w.adb.add_transaction(txA)
        # txn B is an outgoing payment to an external address
        txB = Transaction(self.transactions["0e2182ead6660790290371516cb0b80afa8baebd30dad42b5e58a24ceea17f1c"])
        w.adb.add_transaction(txB)
        # now the user manually deletes txn B to attempt the double spend
        # txn C is double-spending txn B, to a wallet address
        # rationale1: user might do this with opt-in RBF transactions
        # rationale2: this might be a local transaction, in which case the GUI even allows it
        w.adb.remove_transaction(txB.txid())
        txC = Transaction(self.transactions["2c9aa33d9c8ec649f9bfb84af027a5414b760be5231fe9eca4a95b9eb3f8a017"])
        w.adb.add_transaction(txC)
        self.assertEqual(999890, sum(w.get_balance()))


class TestImportedWallet(ElectrumTestCase):
    TESTNET = True
    transactions = {
        # txn A funds addr1:
        "0e350564ee7ed4ffce24a998b538f7f3ebbab6fcb4bb331f8bb6b9d86d86fcd8": "02000000000101470cfc737af6bf917ce35bf7224b1021ef87349cd7f150464e6a0e3ee0cf6f1a0400000000fdffffff0261de0c0000000000160014f6aa7ea83b54335553ece4de88b3e9af6fb4ff0b92b78b00000000001600141dfacc496a9c98227631e3df4796baf3ba8254120247304402201a1b70f27ffcaeecaebad147117e9f4f541e3c630112c395e8237b5f1404f9170220600c96b92a55f8ee99da3fcaf9ca5595468742107651c5cea5798b0e672c7a5b012103ccaf45a46ead9648fc60ba0476f3f820d73fbf75f7d9af626d0512a042c1fc9a41091e00",
        # txn B funds addr2:
        "314385a9f24457098de9fe5cb3893cc408b9f66085268457b82050c988c97908": "0200000000010165806607dd458280cb57bf64a16cf4be85d053145227b98c28932e953076b8e20000000000fdffffff01fa3e0f0000000000160014810480bbaf62145abf945ebe5f657c665a3a37320247304402206df590e0ebae186cd7078e2e9841ec8e2c4c1efff4ee3ac2029fe0a5f1a752c002204cd33bafe4145b66a28dff453d7cb440a7ec6ae53df786e0438bcd6aae50fc8e0121026269e54d06f7070c1f967eb2874ba60de550dfc327a945c98eb773672d9411fd7b181e00",
        # txn C spends both UTXOs:
        "54de13f7ee4853dc1a281c0e7132efb95330f7ceebc1dbce76fdf34c28028f14": "02000000000102d8fc866dd8b9b68b1f33bbb4fcb6baebf3f738b598a924ceffd47eee6405350e0000000000feffffff0879c988c95020b85784268560f6b908c43c89b35cfee98d095744f2a98543310000000000feffffff023cda0c000000000016001451c27c0521388d430ee91137a76d67a368e998c140420f0000000000220020210be57842d95c8cae3c9a2e0250407f9599c75c77eb435d5942fc5cf41505a40247304402201ec23b32a21c1efe186c6ffb0d0f0ed40f1819b4200a844f1a71463873a9e4240220613fca783787449d779cb3e2052682349cbf5f99316641e3eddc36cb510a4ac70121038e1724d08580eec8f7f7a52829a2f09473961df96010f55d913556dee69cc9a10247304402203441cd69d916fdd9fe1864713abad383972e51588fb161174d88471c907c803d022078ca2056407dca3b07f0b109d0f6f55aa5a15e2d385f58a928cac8a589afc026012103bf013054c5b2b4845a5f4b227bd6264dbbfe70936e2675b9ffe004226771e6c1e7692100",
    }

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_importing_and_deleting_addresses(self, mock_save_db):
        w = restore_wallet_from_text("tb1q7648a2pm2se425lvun0g3vlf4ahmflcthegz63",
                                     path='if_this_exists_mocking_failed_648151893',
                                     config=self.config)['wallet']  # type: Abstract_Wallet
        self.assertEqual(1, len(w.get_addresses()))
        w.adb.add_transaction(Transaction(self.transactions["0e350564ee7ed4ffce24a998b538f7f3ebbab6fcb4bb331f8bb6b9d86d86fcd8"]))
        w.adb.add_transaction(Transaction(self.transactions["54de13f7ee4853dc1a281c0e7132efb95330f7ceebc1dbce76fdf34c28028f14"]))
        self.assertEqual(0, sum(w.get_balance()))

        with self.assertRaises(UnrelatedTransactionException):
            w.adb.add_transaction(Transaction(self.transactions["314385a9f24457098de9fe5cb3893cc408b9f66085268457b82050c988c97908"]))
        w.import_address("tb1qsyzgpwa0vg2940u5t6l97etuvedr5dejpf9tdy")
        self.assertEqual(2, len(w.get_addresses()))
        self.assertEqual(2, len(w.db.transactions))
        self.assertEqual(0, sum(w.get_balance()))

        w.adb.add_transaction(Transaction(self.transactions["314385a9f24457098de9fe5cb3893cc408b9f66085268457b82050c988c97908"]))
        self.assertEqual(3, len(w.db.transactions))
        self.assertEqual(0, sum(w.get_balance()))

        w.delete_address("tb1q7648a2pm2se425lvun0g3vlf4ahmflcthegz63")
        self.assertEqual(2, len(w.db.transactions))
        self.assertEqual(
            {"54de13f7ee4853dc1a281c0e7132efb95330f7ceebc1dbce76fdf34c28028f14", "314385a9f24457098de9fe5cb3893cc408b9f66085268457b82050c988c97908"},
            set(w.db.transactions))
        self.assertEqual(0, sum(w.get_balance()))

        with self.assertRaises(UserFacingException) as ctx:
            w.delete_address("tb1qsyzgpwa0vg2940u5t6l97etuvedr5dejpf9tdy")
        self.assertTrue("Cannot delete last remaining address" in ctx.exception.args[0])
