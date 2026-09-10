from electrum.fee_policy import FeeHistogram, FeePolicy

from . import ElectrumTestCase


class Test_FeeHistogram(ElectrumTestCase):

    def setUp(self):
        super(Test_FeeHistogram, self).setUp()

    def tearDown(self):
        super(Test_FeeHistogram, self).tearDown()

    def test_depth_target_to_fee(self):
        mempool_fees = FeeHistogram()
        mempool_fees.set_data([[49, 100110], [10, 121301], [6, 153731], [5, 125872], [1, 36488810]])
        self.assertEqual( 2 * 1000, mempool_fees.depth_target_to_fee(1000000))
        self.assertEqual( 6 * 1000, mempool_fees.depth_target_to_fee( 500000))
        self.assertEqual( 7 * 1000, mempool_fees.depth_target_to_fee( 250000))
        self.assertEqual(11 * 1000, mempool_fees.depth_target_to_fee( 200000))
        self.assertEqual(50 * 1000, mempool_fees.depth_target_to_fee( 100000))
        mempool_fees.set_data([])
        self.assertEqual( 1 * 1000, mempool_fees.depth_target_to_fee(10 ** 5))
        self.assertEqual( 1 * 1000, mempool_fees.depth_target_to_fee(10 ** 6))
        self.assertEqual( 1 * 1000, mempool_fees.depth_target_to_fee(10 ** 7))
        mempool_fees.set_data([[1, 36488810]])
        self.assertEqual( 2 * 1000, mempool_fees.depth_target_to_fee(10 ** 5))
        self.assertEqual( 2 * 1000, mempool_fees.depth_target_to_fee(10 ** 6))
        self.assertEqual( 2 * 1000, mempool_fees.depth_target_to_fee(10 ** 7))
        self.assertEqual( 1 * 1000, mempool_fees.depth_target_to_fee(10 ** 8))
        mempool_fees.set_data([[5, 125872], [1, 36488810]])
        self.assertEqual( 6 * 1000, mempool_fees.depth_target_to_fee(10 ** 5))
        self.assertEqual( 2 * 1000, mempool_fees.depth_target_to_fee(10 ** 6))
        self.assertEqual( 2 * 1000, mempool_fees.depth_target_to_fee(10 ** 7))
        self.assertEqual( 1 * 1000, mempool_fees.depth_target_to_fee(10 ** 8))
        mempool_fees.set_data([])
        self.assertEqual(1 * 1000, mempool_fees.depth_target_to_fee(10 ** 5))
        mempool_fees.set_data(None)
        self.assertEqual(None, mempool_fees.depth_target_to_fee(10 ** 5))

    def test_fee_to_depth(self):
        mempool_fees = FeeHistogram()
        mempool_fees.set_data([[49, 100000], [10, 120000], [6, 150000], [5, 125000], [1, 36000000]])
        self.assertEqual(100000, mempool_fees.fee_to_depth(500))
        self.assertEqual(100000, mempool_fees.fee_to_depth(50))
        self.assertEqual(100000, mempool_fees.fee_to_depth(49))
        self.assertEqual(220000, mempool_fees.fee_to_depth(48))
        self.assertEqual(220000, mempool_fees.fee_to_depth(10))
        self.assertEqual(370000, mempool_fees.fee_to_depth(9))
        self.assertEqual(370000, mempool_fees.fee_to_depth(6.5))
        self.assertEqual(370000, mempool_fees.fee_to_depth(6))
        self.assertEqual(495000, mempool_fees.fee_to_depth(5.5))
        self.assertEqual(36495000, mempool_fees.fee_to_depth(0.5))


class Test_FeePolicy(ElectrumTestCase):

    def test_estimate_fee_honors_explicit_feerate(self):
        # an explicitly set feerate should be used at its full (sat/kvB) precision,
        # instead of being rounded to FEERATE_PRECISION decimal places
        self.assertEqual(45, FeePolicy('feerate:450').estimate_fee(100))    # 0.45 sat/vB
        self.assertEqual(64, FeePolicy('feerate:450').estimate_fee(141))    # ceil(63.45)
        self.assertEqual(125, FeePolicy('feerate:1250').estimate_fee(100))  # 1.25 sat/vB
        self.assertEqual(40, FeePolicy('feerate:400').estimate_fee(100))    # 0.4 sat/vB

    def test_estimate_fee_for_feerate_quantizes_by_default(self):
        # estimates not explicitly set by the user keep being quantized,
        # to stay consistent with what is displayed in the GUI
        self.assertEqual(40, FeePolicy.estimate_fee_for_feerate(fee_per_kb=450, size=100))
        self.assertEqual(120, FeePolicy.estimate_fee_for_feerate(fee_per_kb=1250, size=100))
