from decimal import Decimal

from electrum_ltc import util
from electrum_ltc.util import (format_satoshis, format_fee_satoshis, parse_URI,
                               is_hash256_str, chunks, is_ip_address, list_enabled_bits,
                               format_satoshis_plain, is_private_netaddress, is_hex_str,
                               is_integer, is_non_negative_integer, is_int_or_float,
                               is_non_negative_int_or_float, is_subpath, InvalidBitcoinURI)

from . import ElectrumTestCase, as_testnet


class TestUtil(ElectrumTestCase):

    def test_format_satoshis(self):
        self.assertEqual("0.00001234", format_satoshis(1234))

    def test_format_satoshis_negative(self):
        self.assertEqual("-0.00001234", format_satoshis(-1234))

    def test_format_satoshis_to_mbtc(self):
        self.assertEqual("0.01234", format_satoshis(1234, decimal_point=5))

    def test_format_satoshis_decimal(self):
        self.assertEqual("0.00001234", format_satoshis(Decimal(1234)))

    def test_format_satoshis_msat_resolution(self):
        self.assertEqual("45831276.",    format_satoshis(Decimal("45831276"), decimal_point=0))
        self.assertEqual("45831276.",    format_satoshis(Decimal("45831275.748"), decimal_point=0))
        self.assertEqual("45831275.75", format_satoshis(Decimal("45831275.748"), decimal_point=0, precision=2))
        self.assertEqual("45831275.748", format_satoshis(Decimal("45831275.748"), decimal_point=0, precision=3))

        self.assertEqual("458312.76",    format_satoshis(Decimal("45831276"), decimal_point=2))
        self.assertEqual("458312.76",    format_satoshis(Decimal("45831275.748"), decimal_point=2))
        self.assertEqual("458312.7575", format_satoshis(Decimal("45831275.748"), decimal_point=2, precision=2))
        self.assertEqual("458312.75748", format_satoshis(Decimal("45831275.748"), decimal_point=2, precision=3))

        self.assertEqual("458.31276", format_satoshis(Decimal("45831276"), decimal_point=5))
        self.assertEqual("458.31276", format_satoshis(Decimal("45831275.748"), decimal_point=5))
        self.assertEqual("458.3127575", format_satoshis(Decimal("45831275.748"), decimal_point=5, precision=2))
        self.assertEqual("458.31275748", format_satoshis(Decimal("45831275.748"), decimal_point=5, precision=3))

    def test_format_fee_float(self):
        self.assertEqual("1.7", format_fee_satoshis(1700/1000))

    def test_format_fee_decimal(self):
        self.assertEqual("1.7", format_fee_satoshis(Decimal("1.7")))

    def test_format_fee_precision(self):
        self.assertEqual("1.666",
                         format_fee_satoshis(1666/1000, precision=6))
        self.assertEqual("1.7",
                         format_fee_satoshis(1666/1000, precision=1))

    def test_format_satoshis_whitespaces(self):
        self.assertEqual("     0.0001234 ", format_satoshis(12340, whitespaces=True))
        self.assertEqual("     0.00001234", format_satoshis(1234, whitespaces=True))
        self.assertEqual("     0.45831275", format_satoshis(Decimal("45831275."), whitespaces=True))
        self.assertEqual("     0.45831275   ", format_satoshis(Decimal("45831275."), whitespaces=True, precision=3))
        self.assertEqual("     0.458312757  ", format_satoshis(Decimal("45831275.7"), whitespaces=True, precision=3))
        self.assertEqual("     0.45831275748", format_satoshis(Decimal("45831275.748"), whitespaces=True, precision=3))

    def test_format_satoshis_whitespaces_negative(self):
        self.assertEqual("    -0.0001234 ", format_satoshis(-12340, whitespaces=True))
        self.assertEqual("    -0.00001234", format_satoshis(-1234, whitespaces=True))

    def test_format_satoshis_diff_positive(self):
        self.assertEqual("+0.00001234", format_satoshis(1234, is_diff=True))
        self.assertEqual("+456789.00001234", format_satoshis(45678900001234, is_diff=True))

    def test_format_satoshis_diff_negative(self):
        self.assertEqual("-0.00001234", format_satoshis(-1234, is_diff=True))
        self.assertEqual("-456789.00001234", format_satoshis(-45678900001234, is_diff=True))

    def test_format_satoshis_add_thousands_sep(self):
        self.assertEqual("178 890 000.", format_satoshis(Decimal(178890000), decimal_point=0, add_thousands_sep=True))
        self.assertEqual("458 312.757 48", format_satoshis(Decimal("45831275.748"), decimal_point=2, add_thousands_sep=True, precision=5))
        # is_diff
        self.assertEqual("+4 583 127.574 8", format_satoshis(Decimal("45831275.748"), decimal_point=1, is_diff=True, add_thousands_sep=True, precision=4))
        self.assertEqual("+456 789 112.004 56", format_satoshis(Decimal("456789112.00456"), decimal_point=0, is_diff=True, add_thousands_sep=True, precision=5))
        self.assertEqual("-0.000 012 34", format_satoshis(-1234, is_diff=True, add_thousands_sep=True))
        self.assertEqual("-456 789.000 012 34", format_satoshis(-45678900001234, is_diff=True, add_thousands_sep=True))
        # num_zeros
        self.assertEqual("-456 789.123 400", format_satoshis(-45678912340000, num_zeros=6, add_thousands_sep=True))
        self.assertEqual("-456 789.123 4", format_satoshis(-45678912340000, num_zeros=2, add_thousands_sep=True))
        # whitespaces
        self.assertEqual("      1 432.731 11", format_satoshis(143273111, decimal_point=5, add_thousands_sep=True, whitespaces=True))
        self.assertEqual("      1 432.731   ", format_satoshis(143273100, decimal_point=5, add_thousands_sep=True, whitespaces=True))
        self.assertEqual(" 67 891 432.731   ", format_satoshis(6789143273100, decimal_point=5, add_thousands_sep=True, whitespaces=True))
        self.assertEqual("       143 273 100.", format_satoshis(143273100, decimal_point=0, add_thousands_sep=True, whitespaces=True))
        self.assertEqual(" 6 789 143 273 100.", format_satoshis(6789143273100, decimal_point=0, add_thousands_sep=True, whitespaces=True))
        self.assertEqual("56 789 143 273 100.", format_satoshis(56789143273100, decimal_point=0, add_thousands_sep=True, whitespaces=True))

    def test_format_satoshis_plain(self):
        self.assertEqual("0.00001234", format_satoshis_plain(1234))

    def test_format_satoshis_plain_decimal(self):
        self.assertEqual("0.00001234", format_satoshis_plain(Decimal(1234)))

    def test_format_satoshis_plain_to_mbtc(self):
        self.assertEqual("0.01234", format_satoshis_plain(1234, decimal_point=5))

    def _do_test_parse_URI(self, uri, expected):
        result = parse_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv'})

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('LectrumELqJWMECz7W2iarBpT4VvAPqwAv',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv'})


    def test_parse_URI_address_label(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?label=electrum%20test',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'label': 'electrum test'})

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?message=electrum%20test',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'message': 'electrum test', 'memo': 'electrum test'})

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?amount=0.0003',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?test=test',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
                                {'address': 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'amount': 4000, 'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test', 'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('litecoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(InvalidBitcoinURI, parse_URI, 'litecoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(InvalidBitcoinURI, parse_URI, 'notlitecoin:LPzGaoLUtXFkmNo3u1chDxGxDnSaBQTTxm')

    def test_parse_URI_parameter_pollution(self):
        self.assertRaises(InvalidBitcoinURI, parse_URI, 'litecoin:LPzGaoLUtXFkmNo3u1chDxGxDnSaBQTTxm?amount=0.0003&label=test&amount=30.0')

    @as_testnet
    def test_parse_URI_lightning_consistency(self):
        # bip21 uri that *only* includes a "lightning" key. LN part does not have fallback address
        self._do_test_parse_URI('litecoin:?lightning=lntltc700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqt5n3hanrkydrkl9h3tdp5wsqa6eypgtldr8dqgdtfgnxrjax6jr935yrjvfyh457dhyu267vezkkrc02xseh6euf4d64alpucyskqusqq4dwfg',
                                {'lightning': 'lntltc700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqt5n3hanrkydrkl9h3tdp5wsqa6eypgtldr8dqgdtfgnxrjax6jr935yrjvfyh457dhyu267vezkkrc02xseh6euf4d64alpucyskqusqq4dwfg'})
        # bip21 uri that *only* includes a "lightning" key. LN part has fallback address
        self._do_test_parse_URI('litecoin:?lightning=lntltc700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy905wk42pyx829xxywq93zuzfezr3vzwudcngdp3ruj3xxuamnf5v9v8hjlnzw4ys9ya0gypddvj9ztqf9jcmeq9dfte4ez2slrkjqysgppyppx9',
                                {'lightning': 'lntltc700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy905wk42pyx829xxywq93zuzfezr3vzwudcngdp3ruj3xxuamnf5v9v8hjlnzw4ys9ya0gypddvj9ztqf9jcmeq9dfte4ez2slrkjqysgppyppx9'})
        # bip21 uri that includes "lightning" key. LN part does not have fallback address
        self._do_test_parse_URI('litecoin:tltc1qu5ua3szskclyd48wlfdwfd32j65phxy9apu6mk?amount=0.0007&message=test266&lightning=lntltc700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqt5n3hanrkydrkl9h3tdp5wsqa6eypgtldr8dqgdtfgnxrjax6jr935yrjvfyh457dhyu267vezkkrc02xseh6euf4d64alpucyskqusqq4dwfg',
                                {'address': 'tltc1qu5ua3szskclyd48wlfdwfd32j65phxy9apu6mk',
                                 'amount': 70000,
                                 'lightning': 'lntltc700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqt5n3hanrkydrkl9h3tdp5wsqa6eypgtldr8dqgdtfgnxrjax6jr935yrjvfyh457dhyu267vezkkrc02xseh6euf4d64alpucyskqusqq4dwfg',
                                 'memo': 'test266',
                                 'message': 'test266'})
        # bip21 uri that includes "lightning" key. LN part has fallback address
        self._do_test_parse_URI('litecoin:tltc1qu5ua3szskclyd48wlfdwfd32j65phxy9apu6mk?amount=0.0007&message=test266&lightning=lntltc700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy905wk42pyx829xxywq93zuzfezr3vzwudcngdp3ruj3xxuamnf5v9v8hjlnzw4ys9ya0gypddvj9ztqf9jcmeq9dfte4ez2slrkjqysgppyppx9',
                                {'address': 'tltc1qu5ua3szskclyd48wlfdwfd32j65phxy9apu6mk',
                                 'amount': 70000,
                                 'lightning': 'lntltc700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy905wk42pyx829xxywq93zuzfezr3vzwudcngdp3ruj3xxuamnf5v9v8hjlnzw4ys9ya0gypddvj9ztqf9jcmeq9dfte4ez2slrkjqysgppyppx9',
                                 'memo': 'test266',
                                 'message': 'test266'})
        # bip21 uri that includes "lightning" key. LN part has fallback address BUT it mismatches the top-level address
        self.assertRaises(InvalidBitcoinURI, parse_URI, 'litecoin:tltc1qvu0c9xme0ul3gzx4nzqdgxsu25acuk9w4cs5zr?amount=0.0007&message=test266&lightning=lntltc700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy905wk42pyx829xxywq93zuzfezr3vzwudcngdp3ruj3xxuamnf5v9v8hjlnzw4ys9ya0gypddvj9ztqf9jcmeq9dfte4ez2slrkjqysgppyppx9')
        # bip21 uri that includes "lightning" key. top-level amount mismatches LN amount
        self.assertRaises(InvalidBitcoinURI, parse_URI, 'litecoin:tltc1qu5ua3szskclyd48wlfdwfd32j65phxy9apu6mk?amount=0.0008&message=test266&lightning=lntltc700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy905wk42pyx829xxywq93zuzfezr3vzwudcngdp3ruj3xxuamnf5v9v8hjlnzw4ys9ya0gypddvj9ztqf9jcmeq9dfte4ez2slrkjqysgppyppx9')
        # bip21 uri that includes "lightning" key with garbage unparseable value
        self.assertRaises(InvalidBitcoinURI, parse_URI, 'litecoin:tltc1qu5ua3szskclyd48wlfdwfd32j65phxy9apu6mk?amount=0.0008&message=test266&lightning=lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdasdasdasdasd')

    def test_is_hash256_str(self):
        self.assertTrue(is_hash256_str('09a4c03e3bdf83bbe3955f907ee52da4fc12f4813d459bc75228b64ad08617c7'))
        self.assertTrue(is_hash256_str('2A5C3F4062E4F2FCCE7A1C7B4310CB647B327409F580F4ED72CB8FC0B1804DFA'))
        self.assertTrue(is_hash256_str('00' * 32))

        self.assertFalse(is_hash256_str('00' * 33))
        self.assertFalse(is_hash256_str('qweqwe'))
        self.assertFalse(is_hash256_str(None))
        self.assertFalse(is_hash256_str(7))

    def test_is_hex_str(self):
        self.assertTrue(is_hex_str('09a4'))
        self.assertTrue(is_hex_str('abCD'))
        self.assertTrue(is_hex_str('2A5C3F4062E4F2FCCE7A1C7B4310CB647B327409F580F4ED72CB8FC0B1804DFA'))
        self.assertTrue(is_hex_str('00' * 33))

        self.assertFalse(is_hex_str('0x09a4'))
        self.assertFalse(is_hex_str('2A 5C3F'))
        self.assertFalse(is_hex_str(' 2A5C3F'))
        self.assertFalse(is_hex_str('2A5C3F '))
        self.assertFalse(is_hex_str('000'))
        self.assertFalse(is_hex_str('123'))
        self.assertFalse(is_hex_str('0x123'))
        self.assertFalse(is_hex_str('qweqwe'))
        self.assertFalse(is_hex_str(b'09a4'))
        self.assertFalse(is_hex_str(b'\x09\xa4'))
        self.assertFalse(is_hex_str(None))
        self.assertFalse(is_hex_str(7))
        self.assertFalse(is_hex_str(7.2))

    def test_is_integer(self):
        self.assertTrue(is_integer(7))
        self.assertTrue(is_integer(0))
        self.assertTrue(is_integer(-1))
        self.assertTrue(is_integer(-7))

        self.assertFalse(is_integer(Decimal("2.0")))
        self.assertFalse(is_integer(Decimal(2.0)))
        self.assertFalse(is_integer(Decimal(2)))
        self.assertFalse(is_integer(0.72))
        self.assertFalse(is_integer(2.0))
        self.assertFalse(is_integer(-2.0))
        self.assertFalse(is_integer('09a4'))
        self.assertFalse(is_integer('2A5C3F4062E4F2FCCE7A1C7B4310CB647B327409F580F4ED72CB8FC0B1804DFA'))
        self.assertFalse(is_integer('000'))
        self.assertFalse(is_integer('qweqwe'))
        self.assertFalse(is_integer(None))

    def test_is_non_negative_integer(self):
        self.assertTrue(is_non_negative_integer(7))
        self.assertTrue(is_non_negative_integer(0))

        self.assertFalse(is_non_negative_integer(Decimal("2.0")))
        self.assertFalse(is_non_negative_integer(Decimal(2.0)))
        self.assertFalse(is_non_negative_integer(Decimal(2)))
        self.assertFalse(is_non_negative_integer(0.72))
        self.assertFalse(is_non_negative_integer(2.0))
        self.assertFalse(is_non_negative_integer(-2.0))
        self.assertFalse(is_non_negative_integer(-1))
        self.assertFalse(is_non_negative_integer(-7))
        self.assertFalse(is_non_negative_integer('09a4'))
        self.assertFalse(is_non_negative_integer('2A5C3F4062E4F2FCCE7A1C7B4310CB647B327409F580F4ED72CB8FC0B1804DFA'))
        self.assertFalse(is_non_negative_integer('000'))
        self.assertFalse(is_non_negative_integer('qweqwe'))
        self.assertFalse(is_non_negative_integer(None))

    def test_is_int_or_float(self):
        self.assertTrue(is_int_or_float(7))
        self.assertTrue(is_int_or_float(0))
        self.assertTrue(is_int_or_float(-1))
        self.assertTrue(is_int_or_float(-7))
        self.assertTrue(is_int_or_float(0.72))
        self.assertTrue(is_int_or_float(2.0))
        self.assertTrue(is_int_or_float(-2.0))

        self.assertFalse(is_int_or_float(Decimal("2.0")))
        self.assertFalse(is_int_or_float(Decimal(2.0)))
        self.assertFalse(is_int_or_float(Decimal(2)))
        self.assertFalse(is_int_or_float('09a4'))
        self.assertFalse(is_int_or_float('2A5C3F4062E4F2FCCE7A1C7B4310CB647B327409F580F4ED72CB8FC0B1804DFA'))
        self.assertFalse(is_int_or_float('000'))
        self.assertFalse(is_int_or_float('qweqwe'))
        self.assertFalse(is_int_or_float(None))

    def test_is_non_negative_int_or_float(self):
        self.assertTrue(is_non_negative_int_or_float(7))
        self.assertTrue(is_non_negative_int_or_float(0))
        self.assertTrue(is_non_negative_int_or_float(0.0))
        self.assertTrue(is_non_negative_int_or_float(0.72))
        self.assertTrue(is_non_negative_int_or_float(2.0))

        self.assertFalse(is_non_negative_int_or_float(-1))
        self.assertFalse(is_non_negative_int_or_float(-7))
        self.assertFalse(is_non_negative_int_or_float(-2.0))
        self.assertFalse(is_non_negative_int_or_float(Decimal("2.0")))
        self.assertFalse(is_non_negative_int_or_float(Decimal(2.0)))
        self.assertFalse(is_non_negative_int_or_float(Decimal(2)))
        self.assertFalse(is_non_negative_int_or_float('09a4'))
        self.assertFalse(is_non_negative_int_or_float('2A5C3F4062E4F2FCCE7A1C7B4310CB647B327409F580F4ED72CB8FC0B1804DFA'))
        self.assertFalse(is_non_negative_int_or_float('000'))
        self.assertFalse(is_non_negative_int_or_float('qweqwe'))
        self.assertFalse(is_non_negative_int_or_float(None))

    def test_chunks(self):
        self.assertEqual([[1, 2], [3, 4], [5]],
                         list(chunks([1, 2, 3, 4, 5], 2)))
        self.assertEqual([], list(chunks(b'', 64)))
        self.assertEqual([b'12', b'34', b'56'],
                         list(chunks(b'123456', 2)))
        with self.assertRaises(ValueError):
            list(chunks([1, 2, 3], 0))

    def test_list_enabled_bits(self):
        self.assertEqual((0, 2, 3, 6), list_enabled_bits(77))
        self.assertEqual((), list_enabled_bits(0))

    def test_is_ip_address(self):
        self.assertTrue(is_ip_address("127.0.0.1"))
        #self.assertTrue(is_ip_address("127.000.000.1"))  # disabled as result differs based on python version
        self.assertTrue(is_ip_address("255.255.255.255"))
        self.assertFalse(is_ip_address("255.255.256.255"))
        self.assertFalse(is_ip_address("123.456.789.000"))
        self.assertTrue(is_ip_address("2001:0db8:0000:0000:0000:ff00:0042:8329"))
        self.assertTrue(is_ip_address("2001:db8:0:0:0:ff00:42:8329"))
        self.assertTrue(is_ip_address("2001:db8::ff00:42:8329"))
        self.assertFalse(is_ip_address("2001:::db8::ff00:42:8329"))
        self.assertTrue(is_ip_address("::1"))
        self.assertFalse(is_ip_address("2001:db8:0:0:g:ff00:42:8329"))
        self.assertFalse(is_ip_address("lol"))
        self.assertFalse(is_ip_address(":@ASD:@AS\x77\x22\xff¬!"))

    def test_is_private_netaddress(self):
        self.assertTrue(is_private_netaddress("127.0.0.1"))
        self.assertTrue(is_private_netaddress("127.5.6.7"))
        self.assertTrue(is_private_netaddress("::1"))
        self.assertTrue(is_private_netaddress("[::1]"))
        self.assertTrue(is_private_netaddress("localhost"))
        self.assertTrue(is_private_netaddress("localhost."))
        self.assertFalse(is_private_netaddress("[::2]"))
        self.assertFalse(is_private_netaddress("2a00:1450:400e:80d::200e"))
        self.assertFalse(is_private_netaddress("[2a00:1450:400e:80d::200e]"))
        self.assertFalse(is_private_netaddress("8.8.8.8"))
        self.assertFalse(is_private_netaddress("example.com"))

    def test_is_subpath(self):
        self.assertTrue(util.is_subpath("/a/b/c/d/e", "/"))
        self.assertTrue(util.is_subpath("/a/b/c/d/e", "/a"))
        self.assertTrue(util.is_subpath("/a/b/c/d/e", "/a/"))
        self.assertTrue(util.is_subpath("/a/b/c/d/e", "/a/b/c/"))
        self.assertTrue(util.is_subpath("/a/b/c/d/e/", "/a/b/c/"))
        self.assertTrue(util.is_subpath("/a/b/c/d/e/", "/a/b/c"))
        self.assertTrue(util.is_subpath("/a/b/c/d/e/", "/a/b/c/d/e/"))
        self.assertTrue(util.is_subpath("/", "/"))
        self.assertTrue(util.is_subpath("a/b/c", "a"))
        self.assertTrue(util.is_subpath("a/b/c", "a/"))
        self.assertTrue(util.is_subpath("a/b/c", "a/b"))
        self.assertTrue(util.is_subpath("a/b/c", "a/b/c"))

        self.assertFalse(util.is_subpath("/a/b/c/d/e/", "/b"))
        self.assertFalse(util.is_subpath("/a/b/c/d/e/", "/b/c/"))
        self.assertFalse(util.is_subpath("/a/b/c", "/a/b/c/d/e/"))
        self.assertFalse(util.is_subpath("/a/b/c", "a"))
        self.assertFalse(util.is_subpath("/a/b/c", "c"))
        self.assertFalse(util.is_subpath("a", "/a/b/c"))
        self.assertFalse(util.is_subpath("c", "/a/b/c"))
