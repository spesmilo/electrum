from io import StringIO
import json
import os, sys
from electrum.bitcoin import address_to_script
from electrum.fee_policy import FixedFeePolicy
from electrum.plugins.timelock_recovery.timelock_recovery import TimelockRecoveryContext
from electrum.simple_config import SimpleConfig
from electrum.storage import WalletStorage
from electrum.transaction import PartialTxOutput
from electrum.wallet import Wallet
from electrum.json_db import JsonDB
from electrum.wallet_db import WalletDB

from . import ElectrumTestCase


class TestTimelockRecovery(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super(TestTimelockRecovery, self).setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

        self.wallet_path = os.path.join(self.electrum_path, "timelock_recovery_wallet")

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(TestTimelockRecovery, self).tearDown()
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout

    def _create_default_wallet(self):
        with open(os.path.join(os.path.dirname(__file__), "test_timelock_recovery", "default_wallet"), "r") as f:
            wallet_str = f.read()
        storage = WalletStorage(self.wallet_path)
        db = WalletDB(JsonDB(wallet_str, storage=storage).get_stored_dict(), upgrade=True)
        wallet = Wallet(db, config=self.config)
        return wallet

    async def test_get_alert_address(self):
        wallet = self._create_default_wallet()

        context = TimelockRecoveryContext(wallet)
        alert_address = context.get_alert_address()
        self.assertEqual(alert_address, 'tb1qchyc02y9mv4xths4je9puc4yzuxt8rfm26ef07')

    async def test_get_cancellation_address(self):
        wallet = self._create_default_wallet()

        context = TimelockRecoveryContext(wallet)
        context.get_alert_address()
        cancellation_address = context.get_cancellation_address()
        self.assertEqual(cancellation_address, 'tb1q6k5h4cz6ra8nzhg90xm9wldvadgh0fpttfthcg')

    async def test_make_unsigned_alert_tx(self):
        wallet = self._create_default_wallet()

        context = TimelockRecoveryContext(wallet)
        context.outputs = [
            PartialTxOutput(scriptpubkey=address_to_script('tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd'), value='!'),
        ]

        alert_tx = context.make_unsigned_alert_tx(fee_policy=FixedFeePolicy(5000))
        self.assertEqual(alert_tx.version, 2)
        alert_tx_inputs = [tx_input.prevout.to_str() for tx_input in alert_tx.inputs()]
        self.assertEqual(alert_tx_inputs, [
            '59a9ff5fa62586f102b92504584f52e47f4ca0d5af061e99a0a3023fa70a70e2:1',
            '778b01899d5ed48df03e406bc5babd1fdc8f1be4b7e5b9d20dd8caf24dd66ff4:1',
        ])
        alert_tx_outputs = [(tx_output.address, tx_output.value) for tx_output in alert_tx.outputs()]
        self.assertEqual(alert_tx_outputs, [
            ('tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd', 600),
            ('tb1qchyc02y9mv4xths4je9puc4yzuxt8rfm26ef07', 743065),
        ])
        self.assertEqual(alert_tx.txid(), '01c227f136c4490ec7cb0fe2ba5e44c436f58906b7fc29a83cb865d7e3bfaa60')

    async def test_make_unsigned_recovery_tx(self):
        wallet = self._create_default_wallet()

        context = TimelockRecoveryContext(wallet)
        context.outputs = [
            PartialTxOutput(scriptpubkey=address_to_script('tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd'), value='!'),
        ]
        context.alert_tx = context.make_unsigned_alert_tx(fee_policy=FixedFeePolicy(5000))
        context.timelock_days = 90

        recovery_tx = context.make_unsigned_recovery_tx(fee_policy=FixedFeePolicy(5000))
        self.assertEqual(recovery_tx.version, 2)
        recovery_tx_inputs = [tx_input.prevout.to_str() for tx_input in recovery_tx.inputs()]
        self.assertEqual(recovery_tx_inputs, [
            '01c227f136c4490ec7cb0fe2ba5e44c436f58906b7fc29a83cb865d7e3bfaa60:1',
        ])
        self.assertEqual(recovery_tx.inputs()[0].nsequence, 0x00403b54)

        recovery_tx_outputs = [(tx_output.address, tx_output.value) for tx_output in recovery_tx.outputs()]
        self.assertEqual(recovery_tx_outputs, [
            ('tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd', 738065),
        ])

    async def test_make_unsigned_cancellation_tx(self):
        wallet = self._create_default_wallet()

        context = TimelockRecoveryContext(wallet)
        context.outputs = [
            PartialTxOutput(scriptpubkey=address_to_script('tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd'), value='!'),
        ]
        context.alert_tx = context.make_unsigned_alert_tx(fee_policy=FixedFeePolicy(5000))

        cancellation_tx = context.make_unsigned_cancellation_tx(fee_policy=FixedFeePolicy(6000))
        self.assertEqual(cancellation_tx.version, 2)
        cancellation_tx_inputs = [tx_input.prevout.to_str() for tx_input in cancellation_tx.inputs()]
        self.assertEqual(cancellation_tx_inputs, [
            '01c227f136c4490ec7cb0fe2ba5e44c436f58906b7fc29a83cb865d7e3bfaa60:1',
        ])
        self.assertEqual(cancellation_tx.inputs()[0].nsequence, 0xfffffffd)
        cancellation_tx_outputs = [(tx_output.address, tx_output.value) for tx_output in cancellation_tx.outputs()]
        self.assertEqual(cancellation_tx_outputs, [
            ('tb1q6k5h4cz6ra8nzhg90xm9wldvadgh0fpttfthcg', 737065),
        ])
