import unittest
from lib.util import format_satoshis, parse_URI


class TestUtil(unittest.TestCase):

    def test_format_satoshis(self):
        result = format_satoshis(1234)
        expected = "0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_positive(self):
        result = format_satoshis(1234, is_diff=True)
        expected = "+0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_negative(self):
        result = format_satoshis(-1234, is_diff=True)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def _do_test_parse_URI(self, uri, expected_address, expected_amount,
                           expected_label, expected_message,
                           expected_request_url):
        address, amount, label, message, request_url = parse_URI(uri)
        self.assertEqual(expected_address, address)
        self.assertEqual(expected_amount, amount)
        self.assertEqual(expected_label, label)
        self.assertEqual(expected_message, message)
        self.assertEqual(expected_request_url, request_url)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                '', '', '', '')

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                None, None, None, None)

    def test_parse_URI_address_label(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', '', 'electrum test', '', '')

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?'
            'message=electrum%20test',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', '', '', 'electrum test', '')

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 30000, '', '', '')

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?'
            'r=http://domain.tld/page?h%3D2a8628fc2fbe',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
            '', '', '', 'http://domain.tld/page?h=2a8628fc2fbe')

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?test=test',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', '', '', '', '')

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?'
            'amount=0.00004&label=electrum-test&'
            'message=electrum%20test&test=none&r=http://domain.tld/page',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
            4000, 'electrum-test', 'electrum test', 'http://domain.tld/page')

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI(
            'bitcoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
            '', '', '', '', 'http://domain.tld/page?h=2a8628fc2fbe')

    def test_parse_URI_invalid_address(self):
        self.assertRaises(AssertionError, parse_URI, 'bitcoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(AssertionError, parse_URI,
                          'notbitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')

    def test_parse_URI_parameter_polution(self):
        self.assertRaises(Exception, parse_URI,
                          'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?'
                          'amount=0.0003&label=test&amount=30.0')
