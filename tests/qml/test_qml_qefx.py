from decimal import Decimal

from electrum import SimpleConfig
from electrum.bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from electrum.gui.qml.qefx import QEFX

from .. import ElectrumTestCase


class FxThreadMock:
    def __init__(self, rate):
        self.rate = Decimal(rate)

    def exchange_rate(self) -> Decimal:
        return self.rate


class TestQEFX(ElectrumTestCase):

    def test_satoshivalue_clamp(self):
        config = SimpleConfig({'electrum_path': self.electrum_path})
        fx = QEFX(FxThreadMock(50_000), config)
        self.addCleanup(fx.unregister_callbacks)
        max_sats = COIN * TOTAL_COIN_SUPPLY_LIMIT_IN_BTC

        # below the supply limit, converted as is
        self.assertEqual(COIN, fx.satoshiValue('50000').satsInt)
        # exactly the supply limit
        self.assertEqual(max_sats, fx.satoshiValue('1050000000000').satsInt)
        # 1 sat above the supply limit is clamped
        self.assertEqual(max_sats, fx.satoshiValue('1050000000000.0005').satsInt)
        # absurd amounts are clamped, msats fit in qint64
        amount = fx.satoshiValue('9' * 100)
        self.assertEqual(max_sats, amount.satsInt)
        self.assertLessEqual(amount.msatsInt, 2**63 - 1)
