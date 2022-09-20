import random

import electrum.mpp_split as mpp_split  # side effect for PART_PENALTY
from electrum.lnutil import NoPathFound

from . import ElectrumTestCase

PART_PENALTY = mpp_split.PART_PENALTY


class TestMppSplit(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        # to make tests reproducible:
        random.seed(0)
        # key tuple denotes (channel_id, node_id)
        self.channels_with_funds = {
            (0, 0): 1_000_000_000,
            (1, 1): 500_000_000,
            (2, 0): 302_000_000,
            (3, 2): 101_000_000,
        }

    def tearDown(self):
        super().tearDown()
        # undo side effect
        mpp_split.PART_PENALTY = PART_PENALTY

    def test_suggest_splits(self):
        with self.subTest(msg="do a payment with the maximal amount spendable over a single channel"):
            splits = mpp_split.suggest_splits(1_000_000_000, self.channels_with_funds, exclude_single_part_payments=True)
            self.assertEqual({
                (0, 0): [671_020_676],
                (1, 1): [328_979_324],
                (2, 0): [],
                (3, 2): []},
                splits[0].config
            )

        with self.subTest(msg="payment amount that does not require to be split"):
            splits = mpp_split.suggest_splits(50_000_000, self.channels_with_funds, exclude_single_part_payments=False)
            self.assertEqual({(0, 0): [50_000_000]}, splits[0].config)
            self.assertEqual({(1, 1): [50_000_000]}, splits[1].config)
            self.assertEqual({(2, 0): [50_000_000]}, splits[2].config)
            self.assertEqual({(3, 2): [50_000_000]}, splits[3].config)
            self.assertEqual(2, mpp_split.number_parts(splits[4].config))

        with self.subTest(msg="do a payment with a larger amount than what is supported by a single channel"):
            splits = mpp_split.suggest_splits(1_100_000_000, self.channels_with_funds, exclude_single_part_payments=False)
            self.assertEqual(2, mpp_split.number_parts(splits[0].config))

        with self.subTest(msg="do a payment with the maximal amount spendable over all channels"):
            splits = mpp_split.suggest_splits(
                sum(self.channels_with_funds.values()), self.channels_with_funds, exclude_single_part_payments=True)
            self.assertEqual({
                (0, 0): [1_000_000_000],
                (1, 1): [500_000_000],
                (2, 0): [302_000_000],
                (3, 2): [101_000_000]},
                splits[0].config
            )

        with self.subTest(msg="do a payment with the amount supported by all channels"):
            splits = mpp_split.suggest_splits(101_000_000, self.channels_with_funds, exclude_single_part_payments=False)
            for split in splits[:3]:
                self.assertEqual(1, mpp_split.number_nonzero_channels(split.config))
            # due to exhaustion of the smallest channel, the algorithm favors
            # a splitting of the parts into two
            self.assertEqual(2, mpp_split.number_parts(splits[4].config))

    def test_send_to_single_node(self):
        splits = mpp_split.suggest_splits(1_000_000_000, self.channels_with_funds, exclude_single_part_payments=False, exclude_multinode_payments=True)
        for split in splits:
            assert mpp_split.number_nonzero_nodes(split.config) == 1

    def test_saturation(self):
        """Split configurations which spend the full amount in a channel should be avoided."""
        channels_with_funds = {(0, 0): 159_799_733_076, (1, 1): 499_986_152_000}
        splits = mpp_split.suggest_splits(600_000_000_000, channels_with_funds, exclude_single_part_payments=True)

        uses_full_amount = False
        for c, a in splits[0].config.items():
            if a == channels_with_funds[c]:
                uses_full_amount |= True

        self.assertFalse(uses_full_amount)

    def test_payment_below_min_part_size(self):
        amount = mpp_split.MIN_PART_SIZE_MSAT // 2
        splits = mpp_split.suggest_splits(amount, self.channels_with_funds, exclude_single_part_payments=False)
        # we only get four configurations that end up spending the full amount
        # in a single channel
        self.assertEqual(4, len(splits))

    def test_suggest_part_penalty(self):
        """Test is mainly for documentation purposes.
        Decreasing the part penalty from 1.0 towards 0.0 leads to an increase
        in the number of parts a payment is split. A configuration which has
        about equally distributed amounts will result."""
        with self.subTest(msg="split payments with intermediate part penalty"):
            mpp_split.PART_PENALTY = 1.0
            splits = mpp_split.suggest_splits(1_100_000_000, self.channels_with_funds)
            self.assertEqual(2, mpp_split.number_parts(splits[0].config))

        with self.subTest(msg="split payments with intermediate part penalty"):
            mpp_split.PART_PENALTY = 0.3
            splits = mpp_split.suggest_splits(1_100_000_000, self.channels_with_funds)
            self.assertEqual(4, mpp_split.number_parts(splits[0].config))

        with self.subTest(msg="split payments with no part penalty"):
            mpp_split.PART_PENALTY = 0.0
            splits = mpp_split.suggest_splits(1_100_000_000, self.channels_with_funds)
            self.assertEqual(5, mpp_split.number_parts(splits[0].config))

    def test_suggest_splits_single_channel(self):
        channels_with_funds = {
            (0, 0): 1_000_000_000,
        }

        with self.subTest(msg="do a payment with the maximal amount spendable on a single channel"):
            splits = mpp_split.suggest_splits(1_000_000_000, channels_with_funds, exclude_single_part_payments=False)
            self.assertEqual({(0, 0): [1_000_000_000]}, splits[0].config)
        with self.subTest(msg="test sending an amount greater than what we have available"):
            self.assertRaises(NoPathFound, mpp_split.suggest_splits, *(1_100_000_000, channels_with_funds))
        with self.subTest(msg="test sending a large amount over a single channel in chunks"):
            mpp_split.PART_PENALTY = 0.5
            splits = mpp_split.suggest_splits(1_000_000_000, channels_with_funds, exclude_single_part_payments=False)
            self.assertEqual(2, len(splits[0].config[(0, 0)]))
        with self.subTest(msg="test sending a large amount over a single channel in chunks"):
            mpp_split.PART_PENALTY = 0.3
            splits = mpp_split.suggest_splits(1_000_000_000, channels_with_funds, exclude_single_part_payments=False)
            self.assertEqual(3, len(splits[0].config[(0, 0)]))
        with self.subTest(msg="exclude all single channel splits"):
            mpp_split.PART_PENALTY = 0.3
            splits = mpp_split.suggest_splits(1_000_000_000, channels_with_funds, exclude_single_channel_splits=True)
            self.assertEqual(1, len(splits[0].config[(0, 0)]))
