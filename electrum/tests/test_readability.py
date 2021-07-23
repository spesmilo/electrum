from decimal import Decimal

from electrum.util import (format_satoshis, format_fee_satoshis, parse_URI,
                           is_hash256_str, chunks, is_ip_address, list_enabled_bits,
                           format_satoshis_plain, is_private_netaddress, is_hex_str,
                           is_integer, is_non_negative_integer, is_int_or_float,
                           is_non_negative_int_or_float)

from . import ElectrumTestCase


class Test_Satoshi_Readability(ElectrumTestCase):

    def test_format_satoshis_readability(self):
        self.assertEqual("178 890 000.", format_satoshis(Decimal(178890000), decimal_point=0, add_thousands_sep=True))
        self.assertEqual("458 312.757 48", format_satoshis(Decimal("45831275.748"), decimal_point=2, add_thousands_sep=True, precision=5))
        self.assertEqual("+4 583 127.574 8", format_satoshis(Decimal("45831275.748"), decimal_point=1, is_diff=True, add_thousands_sep=True, precision=4))
        self.assertEqual("+456 789 112.004 56", format_satoshis(Decimal("456789112.00456"), decimal_point=0, is_diff=True, add_thousands_sep=True, precision=5))
        self.assertEqual("-0.00001234", format_satoshis(-1234, is_diff=True)) 
        self.assertEqual("-456789.00001234", format_satoshis(-45678900001234, is_diff=True)) 
        self.assertEqual("-0.000 012 34", format_satoshis(-1234, is_diff=True, add_thousands_sep=True)) 
        self.assertEqual("-456 789.000 012 34", format_satoshis(-45678900001234, is_diff=True, add_thousands_sep=True))