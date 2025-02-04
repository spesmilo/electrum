import gc
import shutil
import tempfile
import weakref

from PyQt6.QtCore import QEvent

from electrum import SimpleConfig, keystore, Network
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.fee_policy import FixedFeePolicy
from electrum.gui.qml.qedaemon import QEDaemon
from electrum.gui.qml.qeconfig import QEConfig
from tests.qml.qt_util import QETestCase, QEventReceiver, qt_test
from electrum.transaction import PartialTxOutput, Transaction
from tests.test_wallet_vertical import WalletIntegrityHelper


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

    def is_connected(self):
        return False


class TestQEWallet(QETestCase):

    def setUp(self):
        super().setUp()
        self.electrum_path = tempfile.mkdtemp()
        self.config = SimpleConfig({
            'electrum_path': self.electrum_path,
            'decimal_point': 5
        })
        # QEConfig singleton is assumed always present
        QEConfig(self.config)

    def tearDown(self):
        super().tearDown()
        # drop any QEWallet that survived qt_teardown (e.g. if a test
        # failed before it ran)
        QEDaemon._QEDaemon__qewallet_instances.clear()
        QEConfig.instance = None
        shutil.rmtree(self.electrum_path)

    def qt_teardown(self):
        # runs on QtTestThread
        instances = QEDaemon._QEDaemon__qewallet_instances
        for qw in list(instances):
            instances.remove(qw)
            qw.on_destroy()
            qw.deleteLater()
        self.app.processEvents()

    def create_standard_wallet_from_seed(self, seed_words, *, with_password=None):
        # seed_words = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)
        if with_password:
            if not ks.may_have_password():
                raise Exception('cannot have password')
            ks.update_password(None, with_password)
        wallet = WalletIntegrityHelper.create_standard_wallet(ks, config=self.config)
        wallet.network = NetworkMock()

        if with_password:
            wallet.db.put('use_encryption', True)
        return wallet

    @qt_test
    def test_single_qobject_per_wallet_instance(self):
        wallet = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver')

        qw = QEDaemon.getQEWalletInstanceFor(wallet)
        self.assertIsNotNone(qw)

        qw2 = QEDaemon.getQEWalletInstanceFor(wallet)
        self.assertTrue(qw == qw2)

    @qt_test
    def test_standard_wallet_properties(self):
        wallet1 = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver',
                                                        with_password='password')
        qw1 = QEDaemon.getQEWalletInstanceFor(wallet1)

        self.assertTrue(qw1.isDeterministic)
        self.assertTrue(qw1.hasSeed)
        self.assertFalse(qw1.isWatchOnly)
        self.assertFalse(qw1.isMultisig)
        # self.assertTrue(qw1.isEncrypted)  # only checks storage encryption a.t.m
        self.assertTrue(qw1.canHaveLightning)
        self.assertTrue(qw1.canSignMessage)
        self.assertTrue(qw1.canSignWithoutServer)
        self.assertTrue(qw1.canSignWithoutCosigner)
        self.assertEqual(qw1.derivationPrefix, 'm/0h')

    @qt_test
    def test_auth_protected_methods(self):
        wallet1 = self.create_standard_wallet_from_seed('bitter grass shiver impose acquire brush forget axis eager alone wine silver',
                                                        with_password='password')
        wallet2 = self.create_standard_wallet_from_seed('cycle rocket west magnet parrot shuffle foot correct salt library feed song')

        # fund
        funding_tx = Transaction(
            '01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000')
        funding_txid = funding_tx.txid()
        funding_output_value = 1000000
        self.assertEqual('add2535aedcbb5ba79cc2260868bb9e57f328738ca192937f2c92e0e94c19203', funding_txid)
        wallet1.adb.receive_tx_callback(funding_tx, tx_height=TX_HEIGHT_UNCONFIRMED)

        qw1 = QEDaemon.getQEWalletInstanceFor(wallet1)
        wallet1.unlock('password')
        qw2 = QEDaemon.getQEWalletInstanceFor(wallet2)

        # wallet1 -> wallet2
        outputs = [PartialTxOutput.from_address_and_value(wallet2.get_receiving_address(), 250000)]
        coins = wallet1.get_spendable_coins()
        tx = wallet1.make_unsigned_transaction(
            coins=coins,
            outputs=outputs,
            fee_policy=FixedFeePolicy(100),
        )

        def sign_success(*args):
            self._signed = True

        def sign_failed(*args):
            self._signed = False

        er1 = QEventReceiver(qw1.authRequired, qw1.paymentFailed)
        qw1.sign(tx, on_success=sign_success, on_failure=sign_failed)

        self.assertTrue(er1.receivedForSignal(qw1.authRequired))

        qw1.authProceed()

        self.assertTrue(self._signed)

        er1.clear()

        qw1.requestShowSeed()
        self.assertTrue(er1.receivedForSignal(qw1.authRequired))
        qw1.authProceed()
        self.assertEqual(qw1.seed, 'bitter grass shiver impose acquire brush forget axis eager alone wine silver')

        er1.clear()

        class InvoiceMock:
            def get_id(self):
                return '1'

            def get_amount_msat(self):
                return '1'

            def is_lightning(self):
                return True

            # stub for serialize to db
            def to_json(self):
                return {}

        qw1.pay_lightning_invoice(InvoiceMock())
        self.assertTrue(er1.receivedForSignal(qw1.authRequired))
        qw1.authProceed()
        self.assertTrue(self.waitForSignal(er1, qw1.paymentFailed))

    @qt_test
    def test_bound_on_destroy_does_not_leak_wrapper(self):
        # QEWallet connects destroyed to the *bound* on_destroy method, not a
        # self-capturing lambda, so PyQt holds the receiver weakly and the wrapper
        # is collectible once the C++ object is gone. The daemon's registry is the
        # only remaining strong ref; unloadWallet() drops it in production, so we
        # do the same here. Guards against regressing to a leaking lambda slot or a
        # strong registry hold.
        wallet = self.create_standard_wallet_from_seed(
            'bitter grass shiver impose acquire brush forget axis eager alone wine silver')
        qw = QEDaemon.getQEWalletInstanceFor(wallet)
        qw_ref = weakref.ref(qw)

        QEDaemon._QEDaemon__qewallet_instances.remove(qw)
        qw.deleteLater()
        # deliver DeferredDelete -> destroy C++ object -> emit destroyed -> on_destroy()
        self.app.sendPostedEvents(None, QEvent.Type.DeferredDelete)

        del qw, wallet
        gc.collect()
        gc.collect()
        self.assertIsNone(qw_ref(), "QEWallet wrapper leaked after destruction (self-capturing slot or strong registry?)")
