from io import StringIO
import os
import sys

from electrum.bitcoin import address_to_script
from electrum.fee_policy import FixedFeePolicy
from electrum.simple_config import SimpleConfig
from electrum.storage import WalletStorage
from electrum.transaction import PartialTxOutput
from electrum.wallet import Wallet
from electrum.wallet_db import WalletDB

from electrum.plugins.timelock_recovery.timelock_recovery import TimelockRecoveryContext, TimelockRecoveryPlugin

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
        db = WalletDB(wallet_str, storage=storage, upgrade=True)
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

    def test_checksum_non_ascii(self):
        # Non-ASCII characters must be serialized as-is (ensure_ascii=False),
        # not escaped as \uXXXX sequences, before hashing.
        json_data = {"wallet_name": "Ωmega Wörld Ñoño 日本語 中文 עברית العربية", "id": "abc-123"}
        result = TimelockRecoveryPlugin.json_checksum(json_data)
        self.assertEqual(result, "74674eca")

    def test_checksum_bip_example(self):
        # test vector from https://github.com/bitcoin/bips/blob/b3827283792882ed0176a12033944fd63c5d398b/bip-0128.mediawiki#reference-implementation
        json_data = {
          "kind": "timelock-recovery-plan",
          "id": "exported-692452189b301b561ed57cbe",
          "name": "Recovery Plan ac300e72-7612-497e-96b0-df2fdeda59ea",
          "description": "RITREK APP 1.1.0: Trezor Account #1",
          "created_at": "2025-11-24T12:39:53.532Z",
          "plugin_version": "1.0.1",
          "wallet_version": "1.0.1",
          "wallet_name": "RITREK Service",
          "wallet_kind": "RITREK BACKEND",
          "timelock_days": 2,
          "anchor_amount_sats": 600,
          "anchor_addresses": [
            "bc1qnda6x2gxdh3yujd2zjpsd7qzx3awxmlaf9wwlk"
          ],
          "alert_address": "bc1qj0f9sjenwyjs0u7mlgvptjp05z3syzq7mru3ep",
          "alert_inputs": [
            "a265a485df4c6417019b91379257eb387bceeda96f7bb6311794b8ed358cf104:0",
            "2f621c2151f33173983133cbc1000e3b603b8a18423b0379feffe8513171d5d3:0"
          ],
          "alert_tx": "0200000000010204F18C35EDB8941731B67B6FA9EDCE7B38EB579237919B0117644CDF85A465A20000000000FDFFFFFFD3D5713151E8FFFE79033B42188A3B603B0E00C1CB3331987331F351211C622F0000000000FDFFFFFF0258020000000000001600149B7BA329066DE24E49AA148306F802347AE36FFD205600000000000016001493D2584B33712507F3DBFA1815C82FA0A302081E02483045022100DCDBAE77C35EB4A0B3ED0DE5484206AB6B07041BE99B2BBAF0243C125916523C0220396959C3C52B2B1F9E472AEEE7C5D9540531B131C3221DE942754C6D0941397D012103C08FF3ADBA14B742646572BCA6F07AEB910666FB28E4DDDC40E33755E7C869D30248304502210089084472FDA3CF82D6ABC11BF1A5E77C9B423617C8B840F58C02746035B3BA6302203942AA1FA13F952F49FB114D48130A9AAF70151E7D09036D15734DB1F41A8B6001210397064EDED7DAD7D662290DC2847E87C5C27DA8865B89DDB58FDE9A006BA7DB3900000000",
          "alert_txid": "f1413fedadaf30697820bcd8f6a393fcc73ea00a15bea3253f89d5658690d2f7",
          "alert_fee": 231,
          "alert_weight": 834,
          "recovery_tx": "02000000000101F7D2908665D5893F25A3BE150AA03EC7FC93A3F6D8BC20786930AFADED3F41F101000000005201400001A6550000000000001600149B7BA329066DE24E49AA148306F802347AE36FFD0247304402204AFF87C2127F5697F300C6522067A8D5E5290CA8D140D2E5BCEF4A36606C5FE5022056673BEC5BB459DFFBD4D266EE95AEF0D701383ED80BD433A02C3C486A826D76012102774DBCD59F2D08EFF718BC09972ADC609FBC31C26B551B3E4EA30A1D43EEDB9700000000",
          "recovery_txid": "bc304610e8f282036345e87163d4cba5b16488a3bf2e4d738379d7bda3a0bca3",
          "recovery_fee": 122,
          "recovery_weight": 437,
          "recovery_outputs": [
            [
              "bc1qnda6x2gxdh3yujd2zjpsd7qzx3awxmlaf9wwlk",
              21926,
              "My Backup Wallet"
            ]
          ],
          "metadata": "sig:825d6b3858c175c7fc16da3134030e095c4f9089c3c89722247eeedc08a7ef4f",
        }
        result = TimelockRecoveryPlugin.json_checksum(json_data)
        self.assertEqual(result, "92f8b3da")
