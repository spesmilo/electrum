import unittest

from lib import ripemd


class Test_ripemd(unittest.TestCase):

    def test_digests(self):
        self.assertEqual('37f332f68db77bd9d7edd4969571ad671cf9dd3b', ripemd.new('The quick brown fox jumps over the lazy dog').hexdigest())
        self.assertEqual('132072df690933835eb8b6ad0b77e7b6f14acad7', ripemd.new('The quick brown fox jumps over the lazy cog').hexdigest())
        self.assertEqual('37f332f68db77bd9d7edd4969571ad671cf9dd3b', ripemd.new(b'The quick brown fox jumps over the lazy dog').hexdigest())
