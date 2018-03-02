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

    def _do_test_parse_URI(self, uri, expected):
        result = parse_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS'})

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS'})


    def test_parse_URI_address_label(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?label=electrum%20test',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS', 'label': 'electrum test'})

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?message=electrum%20test',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS', 'message': 'electrum test', 'memo': 'electrum test'})

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?amount=0.0003',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS', 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?test=test',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI('feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
                                {'address': '6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS', 'amount': 4000, 'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test', 'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('feathercoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(BaseException, parse_URI, 'feathercoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(BaseException, parse_URI, 'notfeathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS')

    def test_parse_URI_parameter_polution(self):
        self.assertRaises(Exception, parse_URI, 'feathercoin:6hR4DL6rgjHYCGKQ4o4eigvfgrirgGNrsS?amount=0.0003&label=test&amount=30.0')
