import os
import time
from decimal import Decimal

from electrum import util
from electrum.simple_config import SimpleConfig
from electrum.wallet import Standard_Wallet, Abstract_Wallet
from electrum.invoices import PR_UNPAID, PR_PAID, PR_UNCONFIRMED, PR_BROADCASTING, BaseInvoice, Invoice, LN_EXPIRY_NEVER
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.transaction import Transaction, PartialTxOutput
from electrum.util import TxMinedInfo, InvoiceError
from electrum.fee_policy import FixedFeePolicy

from . import ElectrumTestCase
from . import restore_wallet_from_text__for_unittest


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
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet2_path, config=self.config)
        wallet2 = d['wallet']  # type: Standard_Wallet
        # bootstrap wallet
        funding_tx = Transaction('0200000000010132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a02473044022041ed68ef7ef122813ac6a5e996b8284f645c53fbe6823b8e430604a8915a867802203233f5f4d347a687eb19b2aa570829ab12aeeb29a24cc6d6d20b8b3d79e971ae012102bee0ee043817e50ac1bb31132770f7c41e35946ccdcb771750fb9696bdd1b307ad951d00')
        funding_txid = funding_tx.txid()
        assert 'db949963c3787c90a40fb689ffdc3146c27a9874a970d1fd20921afbe79a7aa9' == funding_txid
        wallet2.adb.receive_tx_callback(funding_tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        return wallet2

    async def test_wallet_with_ln_creates_payreq_and_gets_paid_on_ln(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet1_path, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=None, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        # get paid on LN
        wallet1.lnworker.set_request_status(bytes.fromhex(pr.rhash), PR_PAID)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_with_ln_creates_payreq_and_gets_paid_onchain(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet1_path, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(not pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(5000))
        wallet2.sign_transaction(tx, password=None)
        wallet1.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx gets mined
        wallet1.db.put('stored_height', 1010)
        tx_info = TxMinedInfo(_height=1001,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01"*32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_without_ln_creates_payreq_and_gets_paid_onchain(self):
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet1_path, config=self.config)
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
        tx = wallet2.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(5000))
        wallet2.sign_transaction(tx, password=None)
        wallet1.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx gets mined
        wallet1.db.put('stored_height', 1010)
        tx_info = TxMinedInfo(_height=1001,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01"*32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_gets_paid_onchain_in_the_past(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet1_path, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(not pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(5000))
        wallet2.sign_transaction(tx, password=None)
        wallet1.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx mined in the past (before invoice creation)
        tx_info = TxMinedInfo(_height=990,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01" * 32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))

    async def test_wallet_reuse_addr_of_expired_request(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet1_path, gap_limit=3, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertTrue(not pr1.is_lightning())
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
        self.assertTrue(not pr2.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertEqual(addr2, pr2.get_address())
        self.assertFalse(pr2.has_expired())

    async def test_wallet_get_request_by_addr(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet1_path, gap_limit=3, config=self.config)
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
        tx = wallet2.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(5000))
        wallet2.sign_transaction(tx, password=None)
        wallet1.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))

        # FIXME the expired pr should stay "expired" - this might require storing state for it (see #8061):
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr1))

        # now make both invoices be past their expiration date. pr2 should be unaffected.
        BaseInvoice._get_cur_time = lambda *args: time.time() + 200_000
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))


class TestBaseInvoice(ElectrumTestCase):
    TESTNET = True

    async def test_arg_validation(self):
        amount_sat = 10_000
        outputs = [PartialTxOutput.from_address_and_value("tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385", amount_sat)]
        invoice = Invoice(
            amount_msat=amount_sat * 1000,
            message="mymsg",
            time=1692716965,
            exp=LN_EXPIRY_NEVER,
            outputs=outputs,
            height=0,
            lightning_invoice=None,
        )
        with self.assertRaises(InvoiceError):
            invoice.amount_msat = 10**20
        with self.assertRaises(InvoiceError):
            invoice.set_amount_msat(10**20)
        with self.assertRaises(InvoiceError):
            invoice.amount_msat = Decimal(amount_sat * 1000)
        with self.assertRaises(AssertionError):
            invoice.set_amount_msat(Decimal(amount_sat * 1000))
        with self.assertRaises(InvoiceError):
            invoice2 = Invoice(
                amount_msat=10**20,
                message="mymsg",
                time=1692716965,
                exp=LN_EXPIRY_NEVER,
                outputs=outputs,
                height=0,
                lightning_invoice=None,
            )
        with self.assertRaises(TypeError):
            invoice.time = "asd"
        with self.assertRaises(TypeError):
            invoice.exp = "asd"

    async def test_get_amount_sat_msat_precision(self):
        amount_sat = 10_000
        outputs = [PartialTxOutput.from_address_and_value("tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385", amount_sat)]
        invoice = Invoice(
            amount_msat=amount_sat * 1000,
            message="mymsg",
            time=1692716965,
            exp=LN_EXPIRY_NEVER,
            outputs=outputs,
            height=0,
            lightning_invoice=None,
        )
        self.assertTrue(isinstance(invoice.get_amount_sat_msat_precision(), int))
        invoice.set_amount_msat(500)
        self.assertTrue(isinstance(invoice.get_amount_sat_msat_precision(), Decimal))
        self.assertEqual(invoice.get_amount_sat_msat_precision(), Decimal('0.500'))
        invoice.set_amount_msat(1000)
        self.assertTrue(isinstance(invoice.get_amount_sat_msat_precision(), int))
        self.assertEqual(invoice.get_amount_sat_msat_precision(), 1)
        invoice.set_amount_msat('!')
        self.assertTrue(isinstance(invoice.get_amount_sat_msat_precision(), str))
        self.assertEqual(invoice.get_amount_sat_msat_precision(), '!')
        with self.assertRaises(AssertionError):
            invoice.set_amount_msat(None)  # different semantics than just setting the property w validator.
        invoice.amount_msat = None
        self.assertIsNone(invoice.get_amount_sat_msat_precision())


class TestOutgoingInvoicesPaidCache(ElectrumTestCase):
    """test caching of paid-status for outgoing invoices"""
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.wallet_path = os.path.join(self.electrum_path, "outgoing_inv_wallet")

    def _make_wallet(self):
        # Seed matches the funding tx output below (see TestWalletPaymentRequests.create_wallet2).
        text = 'cross end slow expose giraffe fuel track awake turtle capital ranch pulp'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        funding_tx = Transaction('0200000000010132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e000000000016001477fe6d2a27e8860c278d4d2cd90bad716bb9521a02473044022041ed68ef7ef122813ac6a5e996b8284f645c53fbe6823b8e430604a8915a867802203233f5f4d347a687eb19b2aa570829ab12aeeb29a24cc6d6d20b8b3d79e971ae012102bee0ee043817e50ac1bb31132770f7c41e35946ccdcb771750fb9696bdd1b307ad951d00')
        wallet.adb.receive_tx_callback(funding_tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        return wallet

    def _make_outgoing_invoice(self, dest_addr: str, amount_sat: int, *, t: int = 1700000000):
        outputs = [PartialTxOutput.from_address_and_value(dest_addr, amount_sat)]
        return Invoice(
            amount_msat=amount_sat * 1000,
            message="",
            time=t,
            exp=LN_EXPIRY_NEVER,
            outputs=outputs,
            height=0,
            lightning_invoice=None,
        )

    async def test_paid_keys_empty_for_fresh_unpaid_invoice(self):
        wallet = self._make_wallet()
        inv = self._make_outgoing_invoice("tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385", 5_000)
        wallet.save_invoice(inv, write_to_disk=False)
        self.assertNotIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        self.assertEqual(PR_UNPAID, wallet.get_invoice_status(inv))
        self.assertEqual([inv], wallet.get_unpaid_invoices())

    async def test_paid_keys_populated_when_invoice_gets_paid(self):
        wallet = self._make_wallet()
        dest = "tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385"
        amount_sat = 5_000
        inv = self._make_outgoing_invoice(dest, amount_sat)
        wallet.save_invoice(inv, write_to_disk=False)
        # Pay the invoice with a confirmed outgoing tx so it becomes PR_PAID.
        outputs = [PartialTxOutput.from_address_and_value(dest, amount_sat)]
        tx = wallet.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(1000))
        wallet.sign_transaction(tx, password=None)
        wallet.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        wallet.db.put('stored_height', 1010)
        wallet.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=1001, timestamp=1700000001, txpos=1, header_hash="01"*32))
        self.assertEqual(PR_PAID, wallet.get_invoice_status(inv))
        self.assertIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        self.assertEqual([], wallet.get_unpaid_invoices())

    async def test_paid_keys_removed_on_delete_and_clear(self):
        wallet = self._make_wallet()
        inv = self._make_outgoing_invoice("tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385", 5_000)
        wallet.save_invoice(inv, write_to_disk=False)
        # Force into the cache via the internal hook so we don't depend on the slow path here.
        wallet._paid_invoice_keys_cache.add(inv.get_id())
        wallet.delete_invoice(inv.get_id(), write_to_disk=False)
        self.assertNotIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        # Re-add and clear all
        wallet.save_invoice(inv, write_to_disk=False)
        wallet._paid_invoice_keys_cache.add(inv.get_id())
        wallet.clear_invoices()
        self.assertEqual(set(), wallet._paid_invoice_keys_cache)

    async def test_get_invoice_status_short_circuits_on_cache_hit(self):
        wallet = self._make_wallet()
        inv = self._make_outgoing_invoice("tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385", 5_000)
        wallet.save_invoice(inv, write_to_disk=False)
        # Seed the cache and assert the slow path is not taken.
        wallet._paid_invoice_keys_cache.add(inv.get_id())
        called = []
        orig = wallet._is_onchain_invoice_paid
        def spy(invoice):
            called.append(invoice.get_id())
            return orig(invoice)
        wallet._is_onchain_invoice_paid = spy
        self.assertEqual(PR_PAID, wallet.get_invoice_status(inv))
        self.assertEqual([], called, "cache hit must avoid _is_onchain_invoice_paid")

    async def test_set_broadcasting_skips_already_paid_invoices(self):
        wallet = self._make_wallet()
        dest = "tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385"
        # Two invoices share the same output scriptpubkey but only one is unpaid.
        inv_paid = self._make_outgoing_invoice(dest, 5_000, t=1700000000)
        inv_unpaid = self._make_outgoing_invoice(dest, 5_000, t=1700000005)
        wallet.save_invoice(inv_paid, write_to_disk=False)
        wallet.save_invoice(inv_unpaid, write_to_disk=False)
        wallet._paid_invoice_keys_cache.add(inv_paid.get_id())

        events = []
        def on_status(w, key, status):
            events.append((key, status))
        util.register_callback(on_status, ['invoice_status'])
        try:
            # Build a tx whose output matches the shared scriptpubkey.
            tx = wallet.make_unsigned_transaction(
                outputs=[PartialTxOutput.from_address_and_value(dest, 5_000)],
                fee_policy=FixedFeePolicy(1000),
            )
            wallet.set_broadcasting(tx, broadcasting_status=PR_BROADCASTING)
        finally:
            util.unregister_callback(on_status)

        notified_keys = {key for key, _ in events}
        self.assertIn(inv_unpaid.get_id(), notified_keys)
        self.assertNotIn(inv_paid.get_id(), notified_keys,
                         "invoice_status callback should not fire for already-paid invoices")

    async def test_set_broadcasting_does_not_rescan_paid_invoices_with_shared_outputs(self):
        """Regression for the freeze scenario: many already-paid invoices share an
        output scriptpubkey, so a new tx paying that scriptpubkey touches all of them.
        set_broadcasting must not call _is_onchain_invoice_paid for the paid ones."""
        wallet = self._make_wallet()
        dest = "tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385"
        # Many paid invoices, all sharing the same destination scriptpubkey.
        paid_ids = set()
        for i in range(50):
            inv = self._make_outgoing_invoice(dest, 1_000 + i, t=1700000000 + i)
            wallet.save_invoice(inv, write_to_disk=False)
            paid_ids.add(inv.get_id())
            wallet._paid_invoice_keys_cache.add(inv.get_id())
        # One fresh unpaid invoice with the same destination.
        unpaid = self._make_outgoing_invoice(dest, 9_999, t=1700001000)
        wallet.save_invoice(unpaid, write_to_disk=False)

        # Spy on the slow path.
        called = []
        orig = wallet._is_onchain_invoice_paid
        def spy(invoice):
            called.append(invoice.get_id())
            return orig(invoice)
        wallet._is_onchain_invoice_paid = spy

        tx = wallet.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(dest, 1_000)],
            fee_policy=FixedFeePolicy(1000),
        )
        wallet.set_broadcasting(tx, broadcasting_status=PR_BROADCASTING)

        # The slow path may run for the unpaid invoice (via get_invoice_status),
        # but must NOT run for any of the cached-paid ones.
        called_set = set(called)
        self.assertFalse(called_set & paid_ids,
                         f"slow path ran for paid invoices: {called_set & paid_ids}")

    async def test_paid_keys_populated_on_wallet_load(self):
        """After the initial _prepare_onchain_invoice_paid_detection pass, the cache
        should reflect what _is_onchain_invoice_paid found, so that subsequent
        get_invoice_status calls take the fast path."""
        wallet = self._make_wallet()
        dest = "tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385"
        amount_sat = 5_000
        inv = self._make_outgoing_invoice(dest, amount_sat)
        wallet.save_invoice(inv, write_to_disk=False)
        # Pay it (confirmed)
        outputs = [PartialTxOutput.from_address_and_value(dest, amount_sat)]
        tx = wallet.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(1000))
        wallet.sign_transaction(tx, password=None)
        wallet.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        wallet.db.put('stored_height', 1010)
        wallet.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=1001, timestamp=1700000001, txpos=1, header_hash="01"*32))
        # Force a rebuild of the cache as would happen at wallet load.
        wallet._paid_invoice_keys_cache.clear()
        wallet._prepare_onchain_invoice_paid_detection()
        self.assertIn(inv.get_id(), wallet._paid_invoice_keys_cache)

    async def test_paid_keys_demoted_on_reorg(self):
        """A reorg unverifying the paying tx must remove the invoice from the cache,
        otherwise get_invoice_status would keep returning a stale PR_PAID."""
        wallet = self._make_wallet()
        dest = "tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385"
        amount_sat = 5_000
        inv = self._make_outgoing_invoice(dest, amount_sat)
        wallet.save_invoice(inv, write_to_disk=False)
        # Pay and confirm.
        outputs = [PartialTxOutput.from_address_and_value(dest, amount_sat)]
        tx = wallet.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(1000))
        wallet.sign_transaction(tx, password=None)
        wallet.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        wallet.db.put('stored_height', 1010)
        wallet.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=1001, timestamp=1700000001, txpos=1, header_hash="01"*32))
        self.assertEqual(PR_PAID, wallet.get_invoice_status(inv))
        self.assertIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        # Simulate reorg: unverify the tx and fire the same event the verifier would.
        wallet.adb.db.remove_verified_tx(tx.txid())
        util.trigger_callback('adb_removed_verified_tx', wallet.adb, tx.txid())
        self.assertNotIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        self.assertNotEqual(PR_PAID, wallet.get_invoice_status(inv))

    async def test_clear_history_resets_paid_keys(self):
        """clear_history() wipes _prevouts_by_scripthash; the cache must follow,
        otherwise get_invoice_status would keep returning a stale PR_PAID."""
        wallet = self._make_wallet()
        dest = "tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385"
        amount_sat = 5_000
        inv = self._make_outgoing_invoice(dest, amount_sat)
        wallet.save_invoice(inv, write_to_disk=False)
        # Pay and confirm.
        outputs = [PartialTxOutput.from_address_and_value(dest, amount_sat)]
        tx = wallet.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(1000))
        wallet.sign_transaction(tx, password=None)
        wallet.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        wallet.db.put('stored_height', 1010)
        wallet.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=1001, timestamp=1700000001, txpos=1, header_hash="01"*32))
        self.assertIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        # Wipe history.
        wallet.clear_history()
        self.assertNotIn(inv.get_id(), wallet._paid_invoice_keys_cache)
        self.assertNotEqual(PR_PAID, wallet.get_invoice_status(inv))
