from unittest import TestCase

from electrum import lnurl


class TestLnurl(TestCase):
    def test_decode(self):
        LNURL = (
            "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E5K7TELWY7NXENRXVMRGDTZXSENJCM98PJNWXQ96S9"
        )
        url = lnurl.decode_lnurl(LNURL)
        self.assertEqual("https://service.io/?q=3fc3645b439ce8e7", url)

    def test_encode(self):
        lnurl_ = lnurl.encode_lnurl("https://jhoenicke.de/.well-known/lnurlp/mempool")
        self.assertEqual(
            "LNURL1DP68GURN8GHJ76NGDAJKU6TRDDJJUER99UH8WETVDSKKKMN0WAHZ7MRWW4EXCUP0D4JK6UR0DAKQHMHNX2",
            lnurl_)

    def test_lightning_address_to_url(self):
        url = lnurl.lightning_address_to_url("mempool@jhoenicke.de")
        self.assertEqual("https://jhoenicke.de/.well-known/lnurlp/mempool", url)

    def test_parse_lnurl3_response(self):
        # Test successful parsing with all fields
        sample_response = {
            'callback': 'https://service.io/withdraw?sessionid=123',
            'k1': 'abcdef1234567890',
            'defaultDescription': 'Withdraw from service',
            'minWithdrawable': 10_000_000,
            'maxWithdrawable': 100_000_000,
        }

        result = lnurl._parse_lnurl3_response(sample_response)

        self.assertEqual('https://service.io/withdraw?sessionid=123', result.callback_url)
        self.assertEqual('abcdef1234567890', result.k1)
        self.assertEqual('Withdraw from service', result.default_description)
        self.assertEqual(10_000, result.min_withdrawable_sat)
        self.assertEqual(100_000, result.max_withdrawable_sat)

        # Test with .onion URL
        onion_response = {
            'callback': 'http://robosatsy56bwqn56qyadmcxkx767hnabg4mihxlmgyt6if5gnuxvzad.onion/withdraw?sessionid=123',
            'k1': 'abcdef1234567890',
            'minWithdrawable': 10_000_000,
            'maxWithdrawable': 100_000_000
        }

        result = lnurl._parse_lnurl3_response(onion_response)
        self.assertEqual('http://robosatsy56bwqn56qyadmcxkx767hnabg4mihxlmgyt6if5gnuxvzad.onion/withdraw?sessionid=123',
                         result.callback_url)
        self.assertEqual('', result.default_description)  # Missing defaultDescription uses empty string

        # Test missing callback (should raise error)
        no_callback_response = {
            'k1': 'abcdef1234567890',
            'minWithdrawable': 10_000_000,
            'maxWithdrawable': 100_000_000
        }

        with self.assertRaises(lnurl.LNURLError):
            lnurl._parse_lnurl3_response(no_callback_response)

        # Test unsafe callback URL
        unsafe_response = {
            'callback': 'http://service.io/withdraw?sessionid=123',  # HTTP URL
            'k1': 'abcdef1234567890',
            'minWithdrawable': 10_000_000,
            'maxWithdrawable': 100_000_000
        }

        with self.assertRaises(lnurl.LNURLError):
            lnurl._parse_lnurl3_response(unsafe_response)

        # Test missing k1 (should raise error)
        no_k1_response = {
            'callback': 'https://service.io/withdraw?sessionid=123',
            'minWithdrawable': 10_000_000,
            'maxWithdrawable': 100_000_000
        }

        with self.assertRaises(lnurl.LNURLError):
            lnurl._parse_lnurl3_response(no_k1_response)

        # Test missing withdrawable amounts (should raise error)
        no_amounts_response = {
            'callback': 'https://service.io/withdraw?sessionid=123',
            'k1': 'abcdef1234567890',
        }

        with self.assertRaises(lnurl.LNURLError):
            lnurl._parse_lnurl3_response(no_amounts_response)

        # Test malformed withdrawable amounts (should raise error)
        bad_amounts_response = {
            'callback': 'https://service.io/withdraw?sessionid=123',
            'k1': 'abcdef1234567890',
            'minWithdrawable': 'this is not a number',
            'maxWithdrawable': 100_000_000
        }

        with self.assertRaises(lnurl.LNURLError):
            lnurl._parse_lnurl3_response(bad_amounts_response)
