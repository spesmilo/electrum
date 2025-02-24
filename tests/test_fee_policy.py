from electrum.fee_policy import FeeHistogram

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


