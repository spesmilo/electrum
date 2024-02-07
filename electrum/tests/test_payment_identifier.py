from electrum import payment_identifier
from electrum.payment_identifier import maybe_extract_lightning_payment_identifier

from . import ElectrumTestCase


class TestPaymentIdentifier(ElectrumTestCase):

    def test_maybe_extract_lightning_payment_identifier(self):
        bolt11 = "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy"
        lnurl = "lnurl1dp68gurn8ghj7um9wfmxjcm99e5k7telwy7nxenrxvmrgdtzxsenjcm98pjnwxq96s9"
        self.assertEqual(bolt11, maybe_extract_lightning_payment_identifier(f"{bolt11}".upper()))
        self.assertEqual(bolt11, maybe_extract_lightning_payment_identifier(f"lightning:{bolt11}"))
        self.assertEqual(bolt11, maybe_extract_lightning_payment_identifier(f"  lightning:{bolt11}   ".upper()))
        self.assertEqual(lnurl, maybe_extract_lightning_payment_identifier(lnurl))
        self.assertEqual(lnurl, maybe_extract_lightning_payment_identifier(f"  lightning:{lnurl}   ".upper()))

        self.assertEqual(None, maybe_extract_lightning_payment_identifier(f"bitcoin:{bolt11}"))
        self.assertEqual(None, maybe_extract_lightning_payment_identifier(f":{bolt11}"))
        self.assertEqual(None, maybe_extract_lightning_payment_identifier(f"garbage text"))
