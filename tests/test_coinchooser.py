from electrum.coinchooser import CoinChooserPrivacy
from electrum.util import NotEnoughFunds
from electrum.transaction import PartialTxInput, TxOutpoint, Transaction, PartialTxOutput
from electrum.fee_policy import FeePolicy, FixedFeePolicy
from functools import partial
from typing import Optional

from . import ElectrumTestCase


class TestCoinChooser(ElectrumTestCase):

    @staticmethod
    def get_dummy_txin_1_284_474_sat() -> PartialTxInput:
        # value of 1_284_474 sat
        prevout_txid = bytes.fromhex(
            "b3d9174cb5d3234764a089bb91fdbd1117b7958be4870d1a544136ab017a67dd"
        )
        coin = PartialTxInput(
            prevout=TxOutpoint(txid=prevout_txid, out_idx=0),
        )
        coin.utxo = Transaction(
            "02000000000105a5a00ad10e754a17154446bbe1c557b44b86a7cd53308ad9ab813388a9d6d1520000000000fdffffff2c48659d10a752b0c0a3efa4092ebee5210943a2f41ff0607ba0e03a4cdf7bbd0000000000fdffffff93f4feb485581654caffa523c500dc417a98097fb731045040bb162acb3e14e90000000000fdffffffbf4b69292acaabf8a415db412eedd8a202d4dd2ca12e532628a756276fec00f50000000000fdffffffa96e18c45ecc56608d0be3c1b2cd93e52d569a9c3a68ed51aead570beeef29ff0000000000fdffffff017a991300000000001600142a55fbef3e419e1c862632a826ae89ade0b07e3a0247304402204de416135d26711df2cbd5209e3f79f95a1de5ddea5980215606ebfe639747bd0220286f9de38a96a078c818e97fe6fbbbe3637287461cd7407adf9e85ba6d899005012102c329033555adccaadb6c83fb486f540ba00aad3edba7a4ec3347b5cc0935c4050247304402200132c1c4c41b840f05efeacf96cccedab38d68c9021c79f940738572b049c1a302200d59ba4719d4d4e55ced651cde35cbf79838bf7122cbafd6584dd934a67db0ed01210380194ab3704b5524a0c97f78b4458b80efd365faaedaebe90fa7807eeab041700247304402202c966fbea5db4bb3794e843b59240d678a3c8e97be1d10c18475a467c101b97c02203edb0ca11e7605af2437ddffbbe416317bca8788c23c4816c13698042222d30f0121035edcdcad9affcff41302ad49a19ccbd47ae50b153ba7c2abaaf3bb2d22c859120247304402206890a622513bb9c8b8ca83e5e82532f9753ecd3188c27d8da9452e264f5500cc022012dad8fb872478b7f9d0d9d310859fca6534b8e9f44511eeef5450beaf13c690012103f683aa56e036b1307c1ae75e81553b6730aea312560e36afad487ba2bc6cf98f02473044022006807df115d6bce73e384651fbb9e932ee313133218be7769e52809b758529b6022078b2859f98a62211f130e69982f96d2968e1820c58bb817f9ab31645b6b4ceae0121026402c3c0a2b4dd5703686f8c5b5b3dcecbbf4d772ef83e440bfad22b742753e730a60300"
        )
        coin.block_height = 100
        return coin

    @staticmethod
    def get_dummy_txout_1(amount: Optional[int] = 1000000) -> PartialTxOutput:
        output = PartialTxOutput.from_address_and_value(
            address="bc1q2089yvkkyw7yq7m6a7lxt45n35c587hk4sgj7c",
            value=amount,
        )
        return output

    def test_bucket_candidates_with_empty_buckets(self):
        def sufficient_funds(buckets, *, bucket_value_sum):
            return True
        coin_chooser = CoinChooserPrivacy(enable_output_value_rounding=False)
        self.assertEqual([[]], coin_chooser.bucket_candidates_any([], sufficient_funds))
        self.assertEqual([[]], coin_chooser.bucket_candidates_prefer_confirmed([], sufficient_funds))
        def sufficient_funds(buckets, *, bucket_value_sum):
            return False
        with self.assertRaises(NotEnoughFunds):
            coin_chooser.bucket_candidates_any([], sufficient_funds)
        with self.assertRaises(NotEnoughFunds):
            coin_chooser.bucket_candidates_prefer_confirmed([], sufficient_funds)

    def test_make_tx_no_outputs_adds_change(self):
        coin_chooser = CoinChooserPrivacy(enable_output_value_rounding=False)
        fee_estimator = partial(FeePolicy('eta:2').estimate_fee, allow_fallback_to_static_rates=True)

        # dummy input with value of 330 sat
        prevout_txid = bytes.fromhex("81d0b29f08c6256dcfbaf02ff1f1e756461cb1df550672e049af7429331c643f")
        single_txin = PartialTxInput(
            prevout=TxOutpoint(txid=prevout_txid, out_idx=0),
        )
        single_txin.utxo = Transaction("02000000000101956449bdc8059b680a20483e64e139ce63fe64333b92cd7811a1b116d6b967ad0000000000fdffffff024a01000000000000160014a21d1fbcf571153f57b40855e059c134405a89ecd682010000000000160014fd7debf75d6c410bf6ba1c8ba05f90f23ce4646a0247304402207f07ec0c2415b31743527dea2f7bff3868f494dc0a5d45adec5e05031725a0af02202aa0ac7d06dbcad8ac0b9808a829b6bdaa98bc831aef31a5ab4e5d1890f7552101210278a5d9b2796f2743ccf1b36b2bf47695d766d0841c17b00ce83943c8b37dde0ceea60300")

        # dummy input to be used as potential additional input of higher value
        coin = self.get_dummy_txin_1_284_474_sat()

        tx = coin_chooser.make_tx(
            coins=[coin],
            inputs=[single_txin],
            outputs=[],
            change_addrs=["bc1q2089yvkkyw7yq7m6a7lxt45n35c587hk4sgj7c"],
            fee_estimator_vb=fee_estimator,
            dust_threshold=500,
        )
        # make_tx should add one additional input and a change output
        assert len(tx.outputs()) == 1, f"expected 1 output got {len(tx.outputs())}"
        assert len(tx.inputs()) == 2, f"expected 2 input got {len(tx.inputs())}"

        # dummy input with value of 99030 sat
        prevout_txid = bytes.fromhex("81d0b29f08c6256dcfbaf02ff1f1e756461cb1df550672e049af7429331c643f")
        single_txin = PartialTxInput(
            prevout=TxOutpoint(txid=prevout_txid, out_idx=1),
        )
        single_txin.utxo = Transaction("02000000000101956449bdc8059b680a20483e64e139ce63fe64333b92cd7811a1b116d6b967ad0000000000fdffffff024a01000000000000160014a21d1fbcf571153f57b40855e059c134405a89ecd682010000000000160014fd7debf75d6c410bf6ba1c8ba05f90f23ce4646a0247304402207f07ec0c2415b31743527dea2f7bff3868f494dc0a5d45adec5e05031725a0af02202aa0ac7d06dbcad8ac0b9808a829b6bdaa98bc831aef31a5ab4e5d1890f7552101210278a5d9b2796f2743ccf1b36b2bf47695d766d0841c17b00ce83943c8b37dde0ceea60300")

        tx = coin_chooser.make_tx(
            coins=[coin],
            inputs=[single_txin],
            outputs=[],
            change_addrs=["bc1q2089yvkkyw7yq7m6a7lxt45n35c587hk4sgj7c"],
            fee_estimator_vb=fee_estimator,
            dust_threshold=500,
        )
        # make_tx should not add an additional input, as single_txin is large enough
        assert len(tx.outputs()) == 1, f"expected 1 output got {len(tx.outputs())}"
        assert len(tx.inputs()) == 1, f"expected 1 input got {len(tx.inputs())}"

    def test_doesnt_round_output_value_with_zerofee_estimator(self):
        # output value rounding is enabled (as by default)
        coin_chooser = CoinChooserPrivacy(enable_output_value_rounding=True)

        # fixed fee estimator always returns 0
        fee_estimator = FixedFeePolicy(0).estimate_fee

        tx = coin_chooser.make_tx(
            coins=[],
            inputs=[self.get_dummy_txin_1_284_474_sat()] ,
            outputs=[self.get_dummy_txout_1(1_000_000)],
            change_addrs=[],
            fee_estimator_vb=fee_estimator,
            dust_threshold=500,
        )
        assert tx.get_fee() == 0, f"fee should be 0, is {tx.get_fee()}"
        assert len(tx.outputs()) == 2, f"expected 2 output got {len(tx.outputs())}"
        assert len(tx.inputs()) == 1, f"expected 1 input got {len(tx.inputs())}"
