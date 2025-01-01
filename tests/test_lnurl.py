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
