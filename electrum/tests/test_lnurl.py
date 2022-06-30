from unittest import TestCase

from electrum import lnurl


class TestLnurl(TestCase):
    def test_decode(self):
        LNURL = (
            "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E5K7TELWY7NXENRXVMRGDTZXSENJCM98PJNWXQ96S9"
        )
        url = lnurl.decode_lnurl(LNURL)
        self.assertTrue("https://service.io/?q=3fc3645b439ce8e7", url)
