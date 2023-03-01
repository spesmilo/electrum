import os
import time

from . import ElectrumTestCase

from electrum.simple_config import SimpleConfig
from electrum.wallet import restore_wallet_from_text, Standard_Wallet, Abstract_Wallet
from electrum.invoices import PR_UNPAID, PR_PAID, PR_UNCONFIRMED, BaseInvoice
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.transaction import Transaction, PartialTxOutput
from electrum.util import TxMinedInfo


class TestWalletPaymentRequests(ElectrumTestCase):
    """test 'incoming' invoices"""
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.wallet1_path = os.path.join(self.electrum_path, "somewallet1")
        self.wallet2_path = os.path.join(self.electrum_path, "somewallet2")
        self._orig_get_cur_time = BaseInvoice._get_cur_time

    def tearDown(self):
        super().tearDown()
        BaseInvoice._get_cur_time = staticmethod(self._orig_get_cur_time)

    def create_wallet2(self) -> Standard_Wallet:
        text = 'cross end slow expose giraffe fuel track awake turtle capital ranch pulp'
        d = restore_wallet_from_text(text, path=self.wallet2_path, gap_limit=2, config=self.config)
        wallet2 = d['wallet']  # type: Standard_Wallet
        # bootstrap wallet
        funding_tx = Transaction('0200000000010132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a02473044022041ed68ef7ef122813ac6a5e996b8284f645c53fbe6823b8e430604a8915a867802203233f5f4d347a687eb19b2aa570829ab12aeeb29a24cc6d6d20b8b3d79e971ae012102bee0ee043817e50ac1bb31132770f7c41e35946ccdcb771750fb9696bdd1b307ad951d00')
        funding_txid = funding_tx.txid()
        assert 'db949963c3787c90a40fb689ffdc3146c27a9874a970d1fd20921afbe79a7aa9' == funding_txid
        wallet2.adb.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)
        return wallet2

    async def test_wallet_with_ln_creates_payreq_and_gets_paid_on_ln(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        # get paid on LN
        wallet1.lnworker.set_request_status(bytes.fromhex(pr.rhash), PR_PAID)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_with_ln_creates_payreq_and_gets_paid_onchain(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx gets mined
        wallet1.db.put('stored_height', 1010)
        tx_info = TxMinedInfo(height=1001,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01"*32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_without_ln_creates_payreq_and_gets_paid_onchain(self):
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNone(wallet1.lnworker)
        self.assertFalse(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertFalse(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx gets mined
        wallet1.db.put('stored_height', 1010)
        tx_info = TxMinedInfo(height=1001,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01"*32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_gets_paid_onchain_in_the_past(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx mined in the past (before invoice creation)
        tx_info = TxMinedInfo(height=990,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01" * 32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))

    async def test_wallet_reuse_unused_fallback_onchain_addr_when_getting_paid_with_lightning(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=5, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertTrue(pr1.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr1))
        self.assertEqual(addr1, pr1.get_address())
        self.assertFalse(pr1.has_expired())

        # create payreq2
        addr2 = wallet1.get_unused_address()
        self.assertNotEqual(addr1, addr2)
        pr2_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr2, exp_delay=86400)
        pr2 = wallet1.get_request(pr2_key)
        self.assertTrue(pr2.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertEqual(addr2, pr2.get_address())

        # pr1 gets paid on LN
        wallet1.lnworker.set_request_status(bytes.fromhex(pr1.rhash), PR_PAID)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr1))

        # create payreq3, which should auto-reuse addr1
        addr3 = wallet1.get_unused_address()
        self.assertEqual(addr1, addr3)
        pr3_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr3, exp_delay=86400)
        pr3 = wallet1.get_request(pr3_key)
        self.assertTrue(pr3.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr3))
        self.assertEqual(addr3, pr3.get_address())

        # pr2 gets paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr2.get_address(), pr2.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))

        # create payreq4, which should not reuse addr2
        addr4 = wallet1.get_unused_address()
        self.assertEqual(3, len({addr1, addr2, addr3, addr4}))
        pr4_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr4, exp_delay=86400)
        pr4 = wallet1.get_request(pr4_key)
        self.assertTrue(pr4.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr4))
        self.assertEqual(addr4, pr4.get_address())

    async def test_wallet_reuse_addr_of_expired_request(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=3, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertTrue(pr1.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr1))
        self.assertEqual(addr1, pr1.get_address())
        self.assertFalse(pr1.has_expired())

        BaseInvoice._get_cur_time = lambda *args: time.time() + 100_000
        self.assertTrue(pr1.has_expired())

        # create payreq2
        addr2 = wallet1.get_unused_address()
        self.assertEqual(addr1, addr2)
        pr2_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr2, exp_delay=86400)
        pr2 = wallet1.get_request(pr2_key)
        self.assertTrue(pr2.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertEqual(addr2, pr2.get_address())
        self.assertFalse(pr2.has_expired())

    async def test_wallet_get_request_by_addr(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=3, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr1))
        self.assertFalse(pr1.has_expired())
        self.assertEqual(pr1, wallet1.get_request_by_addr(addr1))

        BaseInvoice._get_cur_time = lambda *args: time.time() + 100_000
        self.assertTrue(pr1.has_expired())
        self.assertEqual(None, wallet1.get_request_by_addr(addr1))

        # create payreq2
        addr2 = wallet1.get_unused_address()
        self.assertEqual(addr1, addr2)
        pr2_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr2, exp_delay=86400)
        pr2 = wallet1.get_request(pr2_key)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertFalse(pr2.has_expired())
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))

        # pr2 gets paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr2.get_address(), pr2.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))

        # FIXME the expired pr should stay "expired" - this might require storing state for it (see #8061):
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr1))

        # now make both invoices be past their expiration date. pr2 should be unaffected.
        BaseInvoice._get_cur_time = lambda *args: time.time() + 200_000
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))
