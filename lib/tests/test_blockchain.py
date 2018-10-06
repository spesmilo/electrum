import unittest
from .. import blockchain as bc


class MyBlockchain(bc.Blockchain):

    def __init__(self):
        self.filename = '/something'
        self.catch_up = None
        self.is_saved = True
        self.base_height = 0
        self.headers = []

    def set_local_height(self):
        self.local_height = 0


def get_block(prior, time_interval, bits):
    return {
        'version': prior['version'],
        'prev_block_hash': bc.hash_header(prior),
        'merkle_root': prior['merkle_root'],
        'timestamp': prior['timestamp'] + time_interval,
        'bits': bits,
        'nonce': prior['nonce'],
        'block_height': prior['block_height'] + 1
    }

class TestBlockchain(unittest.TestCase):

    def test_bits_to_target_conversion(self):
        self.assertEqual(bc.bits_to_target(0), 0)
        self.assertEqual(bc.target_to_bits(0), 0)
        bits = bc.MAX_BITS
        for step in (1, 17, 149, 1019, 14851, 104729, 1000001):
            for n in range(100):
                if (bits & 0x00ffffff) >= 0x8000:
                    test_bits = bits
                    if test_bits & 0x800000:
                        test_bits -= 0x800000
                    target = bc.bits_to_target(test_bits)
                    self.assertEqual(bc.target_to_bits(target), test_bits)
                bits -= step

    def test_retargetting(self):
        z = '0000000000000000000000000000000000000000000000000000000000000000'
        first = {
            'version': 4,
            'prev_block_hash': z,
            'merkle_root': z,
            'timestamp': 1269211443,
            'bits': 0x18015ddc,
            'nonce': 0,
            'block_height': 0
        }
        blocks = [first]
        chunk_bytes = bytes.fromhex(bc.serialize_header(first))
        for n in range(1, 1000):
            block = get_block(blocks[-1], 600, first['bits'])
            blocks.append(block)
            chunk_bytes += bytes.fromhex(bc.serialize_header(block))

        chain = MyBlockchain()

        # Get blocks every 2hrs now.  Heights 1000 ... 1010 inclusive
        for n in range(11):
            block = get_block(blocks[-1], 2 * 3600, first['bits'])
            blocks.append(block)
            chunk_bytes += bytes.fromhex(bc.serialize_header(block))
            chunk = bc.HeaderChunk(0, chunk_bytes)
            self.assertEqual(chain.get_bits(block, chunk), first['bits'])

        # Now we expect difficulty to decrease
        # MTP(1010) is TimeStamp(1005), MTP(1004) is TimeStamp(999)
        hdr = {'block_height': block['block_height'] + 1}
        self.assertEqual(chain.get_bits(hdr, chunk), 0x1801b553)
