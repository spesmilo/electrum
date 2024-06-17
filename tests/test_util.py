from datetime import datetime
from decimal import Decimal

from electrum import util
from electrum.util import (format_satoshis, format_fee_satoshis, is_hash256_str, chunks, is_ip_address,
                           list_enabled_bits, format_satoshis_plain, is_private_netaddress, is_hex_str,
                           is_integer, is_non_negative_integer, is_int_or_float, is_non_negative_int_or_float)
from electrum.bip21 import parse_bip21_URI, InvalidBitcoinURI
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
        result = parse_bip21_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'})

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'})


    def test_parse_URI_address_label(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'label': 'electrum test'})

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?message=electrum%20test',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'message': 'electrum test', 'memo': 'electrum test'})

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?test=test',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'amount': 4000, 'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test', 'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('bitcoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'bitcoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'notbitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')

    def test_parse_URI_parameter_pollution(self):
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003&label=test&amount=30.0')

    @as_testnet
    def test_parse_URI_unsupported_req_key(self):
        self._do_test_parse_URI('bitcoin:TB1QXJ6KVTE6URY2MX695METFTFT7LR5HYK4M3VT5F?amount=0.00100000&label=test&somethingyoudontunderstand=50',
                                {'address': 'TB1QXJ6KVTE6URY2MX695METFTFT7LR5HYK4M3VT5F', 'amount': 100000, 'label': 'test', 'somethingyoudontunderstand': '50'})
        # now test same URI but with "req-test=1" added
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'bitcoin:TB1QXJ6KVTE6URY2MX695METFTFT7LR5HYK4M3VT5F?amount=0.00100000&label=test&req-test=1&somethingyoudontunderstand=50')

    @as_testnet
    def test_parse_URI_lightning_consistency(self):
        # bip21 uri that *only* includes a "lightning" key. LN part does not have fallback address
        self._do_test_parse_URI('bitcoin:?lightning=lntb700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqyznyzw55q63yytup920n9qcsnh6qqht48maapzgadll2qy5vheeq26crapt0rcv9aqmpm93ljkapgtc05keud9jhlasns795fylfdjsphud9uh',
                                {'lightning': 'lntb700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqyznyzw55q63yytup920n9qcsnh6qqht48maapzgadll2qy5vheeq26crapt0rcv9aqmpm93ljkapgtc05keud9jhlasns795fylfdjsphud9uh'})
        # bip21 uri that *only* includes a "lightning" key. LN part has fallback address
        self._do_test_parse_URI('bitcoin:?lightning=lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy9vu8dmmk3u20u0e0yqw484xzn4hc3cux6kk2wenhw7zy0mseu9ntpk9l4fws2d46svzszrc6mqy535740ks9j22w67fw0x4dt8w2hhzspcqakql',
                                {'lightning': 'lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy9vu8dmmk3u20u0e0yqw484xzn4hc3cux6kk2wenhw7zy0mseu9ntpk9l4fws2d46svzszrc6mqy535740ks9j22w67fw0x4dt8w2hhzspcqakql'})
        # bip21 uri that includes "lightning" key. LN part does not have fallback address
        self._do_test_parse_URI('bitcoin:tb1qu5ua3szskclyd48wlfdwfd32j65phxy9yf7ytl?amount=0.0007&message=test266&lightning=lntb700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqyznyzw55q63yytup920n9qcsnh6qqht48maapzgadll2qy5vheeq26crapt0rcv9aqmpm93ljkapgtc05keud9jhlasns795fylfdjsphud9uh',
                                {'address': 'tb1qu5ua3szskclyd48wlfdwfd32j65phxy9yf7ytl',
                                 'amount': 70000,
                                 'lightning': 'lntb700u1p3kqy0cpp5azvqy3wez7hcz3ka7tpqqvw5mpsa7fknxl4ca7a7669kswhf0hgqsp5qxhxul9k88w2nsk643elzuu4nepwkq052ek79esmz47yj6lfrhuqdqvw3jhxapjxcmscqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqyznyzw55q63yytup920n9qcsnh6qqht48maapzgadll2qy5vheeq26crapt0rcv9aqmpm93ljkapgtc05keud9jhlasns795fylfdjsphud9uh',
                                 'memo': 'test266',
                                 'message': 'test266'})
        # bip21 uri that includes "lightning" key. LN part has fallback address
        self._do_test_parse_URI('bitcoin:tb1qu5ua3szskclyd48wlfdwfd32j65phxy9yf7ytl?amount=0.0007&message=test266&lightning=lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy9vu8dmmk3u20u0e0yqw484xzn4hc3cux6kk2wenhw7zy0mseu9ntpk9l4fws2d46svzszrc6mqy535740ks9j22w67fw0x4dt8w2hhzspcqakql',
                                {'address': 'tb1qu5ua3szskclyd48wlfdwfd32j65phxy9yf7ytl',
                                 'amount': 70000,
                                 'lightning': 'lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy9vu8dmmk3u20u0e0yqw484xzn4hc3cux6kk2wenhw7zy0mseu9ntpk9l4fws2d46svzszrc6mqy535740ks9j22w67fw0x4dt8w2hhzspcqakql',
                                 'memo': 'test266',
                                 'message': 'test266'})
        # bip21 uri that includes "lightning" key. LN part has fallback address BUT it mismatches the top-level address
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'bitcoin:tb1qvu0c9xme0ul3gzx4nzqdgxsu25acuk9wvsj2j2?amount=0.0007&message=test266&lightning=lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy9vu8dmmk3u20u0e0yqw484xzn4hc3cux6kk2wenhw7zy0mseu9ntpk9l4fws2d46svzszrc6mqy535740ks9j22w67fw0x4dt8w2hhzspcqakql')
        # bip21 uri that includes "lightning" key. top-level amount mismatches LN amount
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'bitcoin:tb1qu5ua3szskclyd48wlfdwfd32j65phxy9yf7ytl?amount=0.0008&message=test266&lightning=lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdhkk8a597sn865rhap4h4jenjefdk7ssp5d9zjr96ezp89gsyenfse5f4jn9ls29p0awvp0zxlt6tpzn2m3j5qdqvw3jhxapjxcmqcqzynxq8zals8sq9q7sqqqqqqqqqqqqqqqqqqqqqqqqq9qsqfppqu5ua3szskclyd48wlfdwfd32j65phxy9vu8dmmk3u20u0e0yqw484xzn4hc3cux6kk2wenhw7zy0mseu9ntpk9l4fws2d46svzszrc6mqy535740ks9j22w67fw0x4dt8w2hhzspcqakql')
        # bip21 uri that includes "lightning" key with garbage unparseable value
        self.assertRaises(InvalidBitcoinURI, parse_bip21_URI, 'bitcoin:tb1qu5ua3szskclyd48wlfdwfd32j65phxy9yf7ytl?amount=0.0008&message=test266&lightning=lntb700u1p3kqy26pp5l7rj7w0u5sdsj24umzdlhdasdasdasdasd')

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

    def test_error_text_bytes_to_safe_str(self):
        # ascii
        self.assertEqual("'test'", util.error_text_bytes_to_safe_str(b"test"))
        self.assertEqual('"test123 \'QWE"', util.error_text_bytes_to_safe_str(b"test123 'QWE"))
        self.assertEqual("'prefix: \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08malicious_stuff'",
                         util.error_text_bytes_to_safe_str(b"prefix: " + 8 * b"\x08" + b"malicious_stuff"))
        # unicode
        self.assertEqual("'here is some unicode: \\\\xe2\\\\x82\\\\xbf \\\\xf0\\\\x9f\\\\x98\\\\x80 \\\\xf0\\\\x9f\\\\x98\\\\x88'",
                         util.error_text_bytes_to_safe_str(b'here is some unicode: \xe2\x82\xbf \xf0\x9f\x98\x80 \xf0\x9f\x98\x88'))
        # not even unicode
        self.assertEqual("""\'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !"#$%&\\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\\x7f\\\\x80\\\\x81\\\\x82\\\\x83\\\\x84\\\\x85\\\\x86\\\\x87\\\\x88\\\\x89\\\\x8a\\\\x8b\\\\x8c\\\\x8d\\\\x8e\\\\x8f\\\\x90\\\\x91\\\\x92\\\\x93\\\\x94\\\\x95\\\\x96\\\\x97\\\\x98\\\\x99\\\\x9a\\\\x9b\\\\x9c\\\\x9d\\\\x9e\\\\x9f\\\\xa0\\\\xa1\\\\xa2\\\\xa3\\\\xa4\\\\xa5\\\\xa6\\\\xa7\\\\xa8\\\\xa9\\\\xaa\\\\xab\\\\xac\\\\xad\\\\xae\\\\xaf\\\\xb0\\\\xb1\\\\xb2\\\\xb3\\\\xb4\\\\xb5\\\\xb6\\\\xb7\\\\xb8\\\\xb9\\\\xba\\\\xbb\\\\xbc\\\\xbd\\\\xbe\\\\xbf\\\\xc0\\\\xc1\\\\xc2\\\\xc3\\\\xc4\\\\xc5\\\\xc6\\\\xc7\\\\xc8\\\\xc9\\\\xca\\\\xcb\\\\xcc\\\\xcd\\\\xce\\\\xcf\\\\xd0\\\\xd1\\\\xd2\\\\xd3\\\\xd4\\\\xd5\\\\xd6\\\\xd7\\\\xd8\\\\xd9\\\\xda\\\\xdb\\\\xdc\\\\xdd\\\\xde\\\\xdf\\\\xe0\\\\xe1\\\\xe2\\\\xe3\\\\xe4\\\\xe5\\\\xe6\\\\xe7\\\\xe8\\\\xe9\\\\xea\\\\xeb\\\\xec\\\\xed\\\\xee\\\\xef\\\\xf0\\\\xf1\\\\xf2\\\\xf3\\\\xf4\\\\xf5\\\\xf6\\\\xf7\\\\xf8\\\\xf9\\\\xfa\\\\xfb\\\\xfc\\\\xfd\\\\xfe\\\\xff\'""",
                         util.error_text_bytes_to_safe_str(bytes(range(256)), max_len=1000))
        # long text
        t1 = util.error_text_bytes_to_safe_str(b"test" * 10000)
        self.assertTrue(t1.endswith("... (truncated. orig_len=40002)"))
        self.assertTrue(len(t1) < 550)

    def test_error_text_str_to_safe_str(self):
        # ascii
        self.assertEqual("'test'", util.error_text_str_to_safe_str("test"))
        self.assertEqual('"test123 \'QWE"', util.error_text_str_to_safe_str("test123 'QWE"))
        self.assertEqual("'prefix: \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08malicious_stuff'",
                         util.error_text_str_to_safe_str("prefix: " + 8 * "\x08" + "malicious_stuff"))
        # unicode
        self.assertEqual("'here is some unicode: \\\\u20bf \\\\U0001f600 \\\\U0001f608'",
                         util.error_text_str_to_safe_str("here is some unicode: ₿ 😀 😈"))
        # long text
        t1 = util.error_text_str_to_safe_str("test"*10000)
        self.assertTrue(t1.endswith("... (truncated. orig_len=40002)"))
        self.assertTrue(len(t1) < 550)

    def test_age(self):
        now = datetime(2023, 4, 16, 22, 30, 00)
        self.assertEqual("Unknown",
                         util.age(from_date=None, since_date=now))
        # past
        self.assertEqual("less than a minute ago",
                         util.age(from_date=now.timestamp()-1, since_date=now))
        self.assertEqual("1 seconds ago",
                         util.age(from_date=now.timestamp()-1, since_date=now, include_seconds=True))
        self.assertEqual("25 seconds ago",
                         util.age(from_date=now.timestamp()-25, since_date=now, include_seconds=True))
        self.assertEqual("about 30 minutes ago",
                         util.age(from_date=now.timestamp()-1800, since_date=now))
        self.assertEqual("about 30 minutes ago",
                         util.age(from_date=now.timestamp()-1800, since_date=now, include_seconds=True))
        self.assertEqual("about 1 hour ago",
                         util.age(from_date=now.timestamp()-3300, since_date=now))
        self.assertEqual("about 2 hours ago",
                         util.age(from_date=now.timestamp()-8700, since_date=now))
        self.assertEqual("about 7 hours ago",
                         util.age(from_date=now.timestamp()-26700, since_date=now))
        self.assertEqual("about 1 day ago",
                         util.age(from_date=now.timestamp()-109800, since_date=now))
        self.assertEqual("about 3 days ago",
                         util.age(from_date=now.timestamp()-282600, since_date=now))
        self.assertEqual("about 15 days ago",
                         util.age(from_date=now.timestamp()-1319400, since_date=now))
        self.assertEqual("about 1 month ago",
                         util.age(from_date=now.timestamp()-3220200, since_date=now))
        self.assertEqual("about 3 months ago",
                         util.age(from_date=now.timestamp()-8317800, since_date=now))
        self.assertEqual("about 1 year ago",
                         util.age(from_date=now.timestamp()-39853800, since_date=now))
        self.assertEqual("over 3 years ago",
                         util.age(from_date=now.timestamp()-103012200, since_date=now))
        # future
        self.assertEqual("in less than a minute",
                         util.age(from_date=now.timestamp()+1, since_date=now))
        self.assertEqual("in 1 seconds",
                         util.age(from_date=now.timestamp()+1, since_date=now, include_seconds=True))
        self.assertEqual("in 25 seconds",
                         util.age(from_date=now.timestamp()+25, since_date=now, include_seconds=True))
        self.assertEqual("in about 30 minutes",
                         util.age(from_date=now.timestamp()+1800, since_date=now))
        self.assertEqual("in about 30 minutes",
                         util.age(from_date=now.timestamp()+1800, since_date=now, include_seconds=True))
        self.assertEqual("in about 1 hour",
                         util.age(from_date=now.timestamp()+3300, since_date=now))
        self.assertEqual("in about 2 hours",
                         util.age(from_date=now.timestamp()+8700, since_date=now))
        self.assertEqual("in about 7 hours",
                         util.age(from_date=now.timestamp()+26700, since_date=now))
        self.assertEqual("in about 1 day",
                         util.age(from_date=now.timestamp()+109800, since_date=now))
        self.assertEqual("in about 3 days",
                         util.age(from_date=now.timestamp()+282600, since_date=now))
        self.assertEqual("in about 15 days",
                         util.age(from_date=now.timestamp()+1319400, since_date=now))
        self.assertEqual("in about 1 month",
                         util.age(from_date=now.timestamp()+3220200, since_date=now))
        self.assertEqual("in about 3 months",
                         util.age(from_date=now.timestamp()+8317800, since_date=now))
        self.assertEqual("in about 1 year",
                         util.age(from_date=now.timestamp()+39853800, since_date=now))
        self.assertEqual("in over 3 years",
                         util.age(from_date=now.timestamp()+103012200, since_date=now))


