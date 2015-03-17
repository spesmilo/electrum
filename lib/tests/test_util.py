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

    def _do_test_parse_URI(self, uri, expected_address, expected_amount, expected_label, expected_message, expected_request_url):
        address, amount, label, message, request_url = parse_URI(uri)
        self.assertEqual(expected_address, address)
        self.assertEqual(expected_amount, amount)
        self.assertEqual(expected_label, label)
        self.assertEqual(expected_message, message)
        self.assertEqual(expected_request_url, request_url)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', '', '', '', '')

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', None, None, None, None)


    def test_parse_URI_address_label(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?label=electrum%20test', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', '', 'electrum test', '', '')

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?message=electrum%20test', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', '', '', 'electrum test', '')

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?amount=0.0003', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 30000, '', '', '')

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?r=http://domain.tld/page?h%3D2a8628fc2fbe', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', '', '', '', 'http://domain.tld/page?h=2a8628fc2fbe')

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?test=test', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', '', '', '', '')

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI('litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page', 'LectrumELqJWMECz7W2iarBpT4VvAPqwAv', 4000, 'electrum-test', 'electrum test', 'http://domain.tld/page')

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('litecoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe', '', '', '', '', 'http://domain.tld/page?h=2a8628fc2fbe')

    def test_parse_URI_invalid_address(self):
        self.assertRaises(AssertionError, parse_URI, 'litecoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(AssertionError, parse_URI, 'notlitecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv')

    def test_parse_URI_parameter_polution(self):
        self.assertRaises(Exception, parse_URI, 'litecoin:LectrumELqJWMECz7W2iarBpT4VvAPqwAv?amount=0.0003&label=test&amount=30.0')

