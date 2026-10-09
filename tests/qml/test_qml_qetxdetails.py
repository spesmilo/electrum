import gc

from electrum import SimpleConfig
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.bitcoin import address_to_script
from electrum.fee_policy import FixedFeePolicy
from electrum.gui.qml.qetxdetails import QETxDetails
from electrum.gui.qml.qewallet import QEWallet
from electrum.transaction import PartialTxOutput, Transaction

from .. import ElectrumTestCase, restore_wallet_from_text__for_unittest


class TestTxDetails(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # free the QObjects (and the wallets they hold) before other tests check for lingering wallets
        cls.addClassCleanup(gc.collect)

    def _create_wallet_and_unsigned_tx_with_legacy_input(self, config):
        wallet = restore_wallet_from_text__for_unittest(
            'p2pkh:cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw', path=None, config=config)['wallet']
        addr = wallet.get_addresses()[0]
        # fund the wallet: one dummy input, one output of 100000 sat to addr
        spk = address_to_script(addr)
        funding_tx = Transaction(
            '02000000' + '01' + '11' * 32 + '00000000' + '00' + 'fdffffff'
            + '01' + (100_000).to_bytes(8, 'little').hex() + bytes([len(spk)]).hex() + spk.hex()
            + '00000000')
        wallet.adb.receive_tx_callback(funding_tx, tx_height=TX_HEIGHT_UNCONFIRMED)

        tx = wallet.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(addr, 50_000)], fee_policy=FixedFeePolicy(1000))
        self.assertIsNone(tx.txid())  # legacy input: the txid is only known once signed
        return wallet, tx

    async def test_remove_saved_tx_with_legacy_inputs(self):
        # see #9004, #8775
        config = SimpleConfig({'electrum_path': self.electrum_path})
        wallet, tx = self._create_wallet_and_unsigned_tx_with_legacy_input(config)

        qewallet = QEWallet(wallet)
        self.addCleanup(qewallet.unregister_callbacks)
        txdetails = QETxDetails()
        self.addCleanup(txdetails.unregister_callbacks)
        txdetails.wallet = qewallet
        txdetails.rawtx = tx.serialize()
        self.assertFalse(txdetails.txid)
        self.assertFalse(txdetails.canSaveAsLocal)
        txdetails.setLabel('rent')

        txdetails.sign()
        qewallet.authProceed()
        self.assertTrue(txdetails.isComplete)
        txid = txdetails._tx.txid()
        self.assertTrue(txid)
        self.assertTrue(txdetails.canSaveAsLocal)
        self.assertEqual(txid, txdetails.txid)
        self.assertEqual('rent', txdetails.label)
        self.assertEqual('rent', wallet.get_label_for_txid(txid))

        txdetails.save()
        self.assertIsNotNone(wallet.db.get_transaction(txid))
        self.assertFalse(txdetails.canSaveAsLocal)
        self.assertTrue(txdetails.canRemove)

        txdetails.removeLocalTx(confirm=True)
        self.assertIsNone(wallet.db.get_transaction(txid))

    async def test_open_unsigned_tx_with_legacy_inputs_in_lightning_wallet(self):
        # see #8395
        config = SimpleConfig({'electrum_path': self.electrum_path})
        _, tx = self._create_wallet_and_unsigned_tx_with_legacy_input(config)
        wallet = restore_wallet_from_text__for_unittest(
            'bitter grass shiver impose acquire brush forget axis eager alone wine silver', path=None, config=config)['wallet']
        self.assertIsNotNone(wallet.lnworker)

        qewallet = QEWallet(wallet)
        self.addCleanup(qewallet.unregister_callbacks)
        txdetails = QETxDetails()
        self.addCleanup(txdetails.unregister_callbacks)
        txdetails.wallet = qewallet
        txdetails.rawtx = tx.serialize()
        self.assertIsNotNone(txdetails._tx)
