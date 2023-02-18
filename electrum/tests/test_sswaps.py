from electrum import SimpleConfig
from electrum.util import bfh
from electrum.transaction import PartialTxInput, TxOutpoint
from electrum.submarine_swaps import SwapManager, SwapData

from . import ElectrumTestCase


class TestSwapTxs(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.set_key('dynamic_fees', False)
        self.config.set_key('fee_per_kb', 1000)

    def test_claim_tx_for_successful_reverse_swap(self):
        swap_data = SwapData(
            is_reverse=True,
            locktime=2420532,
            onchain_amount=198694,
            lightning_amount=200000,
            redeem_script=bytes.fromhex('8201208763a914d7a62ef0270960fe23f0f351b28caadab62c21838821030bfd61153816df786036ea293edce851d3a4b9f4a1c66bdc1a17f00ffef3d6b167750334ef24b1752102fc8128f17f9e666ea281c702171ab16c1dd2a4337b71f08970f5aa10c608a93268ac'),
            preimage=bytes.fromhex('f1939b5723155713855d7ebea6e174f77d41d669269e7f138856c3de190e7a36'),
            prepay_hash=None,
            privkey=bytes.fromhex('58fd0018a9a2737d1d6b81d380df96bf0c858473a9592015508a270a7c9b1d8d'),
            lockup_address='tb1q2pvugjl4w56rqw4c7zg0q6mmmev0t5jjy3qzg7sl766phh9fxjxsrtl77t',
            receive_address='tb1ql0adrj58g88xgz375yct63rclhv29hv03u0mel',
            funding_txid='897eea7f53e917323e7472d7a2e3099173f7836c57f1b6850f5cbdfe8085dbf9',
            spending_txid=None,
            is_redeemed=False,
        )
        txin = PartialTxInput(
            prevout=TxOutpoint(txid=bfh(swap_data.funding_txid), out_idx=0),
        )
        txin._trusted_value_sats = swap_data.onchain_amount
        tx = SwapManager._create_and_sign_claim_tx(
            txin=txin,
            swap=swap_data,
            config=self.config,
        )
        self.assertEqual(
            "02000000000101f9db8580febd5c0f85b6f1576c83f7739109e3a2d772743e3217e9537fea7e890000000000fdffffff019e07030000000000160014fbfad1ca8741ce640a3ea130bd4478fdd8a2dd8f034730440220156d62534a4e8247eef6bb185c89c4013353c017e45d41ce634976b9d7122c6202202ddb593983fd789cf2166038411425c119d087bc37ec7f8b51bebf603e428fbb0120f1939b5723155713855d7ebea6e174f77d41d669269e7f138856c3de190e7a366a8201208763a914d7a62ef0270960fe23f0f351b28caadab62c21838821030bfd61153816df786036ea293edce851d3a4b9f4a1c66bdc1a17f00ffef3d6b167750334ef24b1752102fc8128f17f9e666ea281c702171ab16c1dd2a4337b71f08970f5aa10c608a93268ac00000000",
            str(tx)
        )

    def test_claim_tx_for_timing_out_forward_swap(self):
        swap_data = SwapData(
            is_reverse=False,
            locktime=2420537,
            onchain_amount=130000,
            lightning_amount=129014,
            redeem_script=bytes.fromhex('a914b12bd886ef4fd9ef1c03e899123f2c4b96cec0878763210267ca676c2ed05bb6c380880f1e50b6ef91025dfa963dc49d6c5cb9848f2acf7d670339ef24b1752103d8190cdfcc7dd929a583b7ea8fa8eb1d8463195d336be2f2df94f950ce8b659968ac'),
            preimage=bytes.fromhex('116f62c3283e4eb0b947a9cb672f1de7321d2c2373d12cd010500adffc32b1f2'),
            prepay_hash=None,
            privkey=bytes.fromhex('8d30dead21f5a7a6eeab7456a9a9d449511e942abef9302153cfff84e436614c'),
            lockup_address='tb1qte2qwev6qvmrhsddac82tnskmjg02ntn73xqg2rjt0qx2xpz693sw2ljzg',
            receive_address='tb1qj76twx886pkfcs7d808n0yzsgxm33wqlwe0dt0',
            funding_txid='08ecdcb19ab38fc1288c97da546b8c90549be2348ef306f476dcf6e505158706',
            spending_txid=None,
            is_redeemed=False,
        )
        txin = PartialTxInput(
            prevout=TxOutpoint(txid=bfh(swap_data.funding_txid), out_idx=0),
        )
        txin._trusted_value_sats = swap_data.onchain_amount
        tx = SwapManager._create_and_sign_claim_tx(
            txin=txin,
            swap=swap_data,
            config=self.config,
        )
        self.assertEqual(
            "0200000000010106871505e5f6dc76f406f38e34e29b54908c6b54da978c28c18fb39ab1dcec080000000000fdffffff0148fb01000000000016001497b4b718e7d06c9c43cd3bcf37905041b718b81f034730440220254e054fc195801aca3d62641a0f27d888f44d1dd66760ae5c3418502e82c141022014305da98daa27d665310115845d2fa6d4dc612d910a186db2624aa558bff9fe010065a914b12bd886ef4fd9ef1c03e899123f2c4b96cec0878763210267ca676c2ed05bb6c380880f1e50b6ef91025dfa963dc49d6c5cb9848f2acf7d670339ef24b1752103d8190cdfcc7dd929a583b7ea8fa8eb1d8463195d336be2f2df94f950ce8b659968ac39ef2400",
            str(tx)
        )

