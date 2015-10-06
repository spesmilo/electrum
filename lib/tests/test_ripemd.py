import unittest
import random
import hashlib

from lib import ripemd

class Test_RIPEMD160(unittest.TestCase):
    """ Test pure Python implementation against standard library. """

    def test_ripemd(self):
        r = random.Random(0)
        for i in range(128):
            blob = bytearray([r.randrange(0, 256) for j in range(1024)])
            h = hashlib.new('ripemd160')
            h.update(blob)
            self.assertEqual(h.hexdigest(), ripemd.new(blob).hexdigest())
