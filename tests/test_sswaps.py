from electrum import SimpleConfig
from electrum.util import bfh
from electrum.transaction import PartialTxInput, TxOutpoint
from electrum.submarine_swaps import SwapData, create_claim_tx

from . import ElectrumTestCase


class TestSwapTxs(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.maxDiff = None
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.FEE_EST_DYNAMIC = False
        self.config.FEE_EST_STATIC_FEERATE = 1000

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
        tx = create_claim_tx(
            txin=txin,
            swap=swap_data,
            config=self.config,
        )
        self.assertEqual(
            "02000000000101f9db8580febd5c0f85b6f1576c83f7739109e3a2d772743e3217e9537fea7e890000000000fdffffff019007030000000000160014fbfad1ca8741ce640a3ea130bd4478fdd8a2dd8f03473044022025506044aba4939f4f2faa94710673ca65530a621f1fa538a3d046dc98bb685e02205f8d463dc6f81e1083f26fa963e581dabc80ea42f8cd59c9e31f3bf531168a9c0120f1939b5723155713855d7ebea6e174f77d41d669269e7f138856c3de190e7a366a8201208763a914d7a62ef0270960fe23f0f351b28caadab62c21838821030bfd61153816df786036ea293edce851d3a4b9f4a1c66bdc1a17f00ffef3d6b167750334ef24b1752102fc8128f17f9e666ea281c702171ab16c1dd2a4337b71f08970f5aa10c608a93268ac00000000",
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
        tx = create_claim_tx(
            txin=txin,
            swap=swap_data,
            config=self.config,
        )
        self.assertEqual(
            "0200000000010106871505e5f6dc76f406f38e34e29b54908c6b54da978c28c18fb39ab1dcec080000000000fdffffff013afb01000000000016001497b4b718e7d06c9c43cd3bcf37905041b718b81f0347304402200ae708af1393f785c541bbc4d7351791b76a53077a292b71cb2a25ad13a15f9902206b7b91c414ec0d6e5098a1acc26de4b47f3aac414b7a49741e8f27cc6a967a19010065a914b12bd886ef4fd9ef1c03e899123f2c4b96cec0878763210267ca676c2ed05bb6c380880f1e50b6ef91025dfa963dc49d6c5cb9848f2acf7d670339ef24b1752103d8190cdfcc7dd929a583b7ea8fa8eb1d8463195d336be2f2df94f950ce8b659968ac39ef2400",
            str(tx)
        )

