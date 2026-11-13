import io
import random

from electrum import cbor
from electrum.cbor import CBORTag, CBORDecodeError, CBORDecodeEOF, CBOREncodeError

from . import ElectrumTestCase


# RFC 8949, Appendix A, without floats, simple values and indefinite-length items.
# Tags are not interpreted, e.g. bignums (tags 2 and 3) are not converted to int.
RFC8949_EXAMPLES = [
    ('00', 0),
    ('01', 1),
    ('0a', 10),
    ('17', 23),
    ('1818', 24),
    ('1819', 25),
    ('1864', 100),
    ('1903e8', 1000),
    ('1a000f4240', 1000000),
    ('1b000000e8d4a51000', 1000000000000),
    ('1bffffffffffffffff', 18446744073709551615),
    ('c249010000000000000000', CBORTag(2, bytes.fromhex('010000000000000000'))),
    ('3bffffffffffffffff', -18446744073709551616),
    ('c349010000000000000000', CBORTag(3, bytes.fromhex('010000000000000000'))),
    ('20', -1),
    ('29', -10),
    ('3863', -100),
    ('3903e7', -1000),
    ('f4', False),
    ('f5', True),
    ('f6', None),
    ('c074323031332d30332d32315432303a30343a30305a', CBORTag(0, '2013-03-21T20:04:00Z')),
    ('c11a514b67b0', CBORTag(1, 1363896240)),
    ('d74401020304', CBORTag(23, bytes.fromhex('01020304'))),
    ('d818456449455446', CBORTag(24, bytes.fromhex('6449455446'))),
    ('d82076687474703a2f2f7777772e6578616d706c652e636f6d', CBORTag(32, 'http://www.example.com')),
    ('40', b''),
    ('4401020304', bytes.fromhex('01020304')),
    ('60', ''),
    ('6161', 'a'),
    ('6449455446', 'IETF'),
    ('62225c', '"\\'),
    ('62c3bc', 'ü'),
    ('63e6b0b4', '水'),
    ('64f0908591', '\U00010151'),
    ('80', []),
    ('83010203', [1, 2, 3]),
    ('8301820203820405', [1, [2, 3], [4, 5]]),
    ('98190102030405060708090a0b0c0d0e0f101112131415161718181819', list(range(1, 26))),
    ('a0', {}),
    ('a201020304', {1: 2, 3: 4}),
    ('a26161016162820203', {'a': 1, 'b': [2, 3]}),
    ('826161a161626163', ['a', {'b': 'c'}]),
    ('a56161614161626142616361436164614461656145', {'a': 'A', 'b': 'B', 'c': 'C', 'd': 'D', 'e': 'E'}),
]

# RFC 8949, Appendix A: floats, simple values and indefinite-length items are not supported
RFC8949_UNSUPPORTED = [
    'f90000', 'f98000', 'f93c00', 'fb3ff199999999999a', 'f93e00', 'f97bff', 'fa47c35000', 'fa7f7fffff',
    'fb7e37e43c8800759c', 'f90001', 'f90400', 'f9c400', 'fbc010666666666666', 'f97c00', 'f97e00', 'f9fc00',
    'fa7f800000', 'fa7fc00000', 'faff800000', 'fb7ff0000000000000', 'fb7ff8000000000000', 'fbfff0000000000000',
    'f7', 'f0', 'f8ff', 'c1fb41d452d9ec200000',
    '5f42010243030405ff', '7f657374726561646d696e67ff', '9fff', '9f018202039f0405ffff', '9f01820203820405ff',
    '83018202039f0405ff', '83019f0203ff820405', '9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff',
    'bf61610161629f0203ffff', '826161bf61626163ff', 'bf6346756ef563416d7421ff',
]

# RFC 8949, Appendix F.1: not well-formed
RFC8949_NOT_WELL_FORMED = [
    # end of input in a head
    '18', '19', '1a', '1b', '1901', '1a0102', '1b01020304050607', '38', '58', '78', '98', '9a01ff00', 'b8', 'd8',
    'f8', 'f900', 'fa0000', 'fb000000',
    # definite-length strings with short data
    '41', '61', '5affffffff00', '5bffffffffffffffff010203', '7affffffff00', '7b7fffffffffffffff010203',
    # definite-length maps and arrays not closed with enough items
    '81', '818181818181818181', '8200', 'a1', 'a20102', 'a100', 'a2000000',
    # tag number not followed by tag content
    'c0',
    # indefinite-length strings, maps and arrays not closed by a break
    '5f4100', '7f6100', '9f', '9f0102', 'bf', 'bf01020102', '819f', '9f8000', '9f9f9f9f9fffffffff', '9f819f819f9fffffff',
    # reserved additional information values
    '1c', '1d', '1e', '3c', '3d', '3e', '5c', '5d', '5e', '7c', '7d', '7e',
    '9c', '9d', '9e', 'bc', 'bd', 'be', 'dc', 'dd', 'de', 'fc', 'fd', 'fe',
    # reserved two-byte encodings of simple values
    'f800', 'f801', 'f818', 'f81f',
    # indefinite-length string chunks of the wrong type, or not of definite length
    '5f00ff', '5f21ff', '5f6100ff', '5f80ff', '5fa0ff', '5fc000ff', '5fe0ff', '7f4100ff', '5f5f4100ffff', '7f7f6100ffff',
    # break outside of an indefinite-length item, or in a value position
    'ff', '81ff', '8200ff', 'a1ff', 'a1ff00', 'a100ff', 'a20000ff', '9f81ff', '9f829f819f9fffffffff', 'bf00ff', 'bf000000ff',
    # major types 0, 1 and 6 with additional information 31
    '1f', '3f', 'df',
]


def random_object(rng: random.Random, depth: int = 0, kind: int = None):
    if kind is None:
        kind = rng.randrange(8 if depth < 4 else 5)
    if kind == 0:
        return rng.choice((None, True, False))
    if kind == 1:
        n = rng.randrange(1 << rng.choice((5, 8, 16, 32, 64)))
        return n if rng.randrange(2) else -1 - n
    if kind == 2:
        return rng.randbytes(rng.randrange(30))
    if kind == 3:
        return ''.join(rng.choice(('a', '\x00', 'ü', '水', '\U00010151')) for _ in range(rng.randrange(10)))
    if kind == 4:
        return CBORTag(rng.choice((0, 24, 310, 40310, 55799, 2**64 - 1)), random_object(rng, depth + 1))
    if kind == 5:
        return {random_object(rng, kind=rng.randrange(1, 4)): random_object(rng, depth + 1) for _ in range(rng.randrange(5))}
    return [random_object(rng, depth + 1) for _ in range(rng.randrange(5))]


class TestCBOR(ElectrumTestCase):

    def test_rfc8949_examples(self):
        for hex_, value in RFC8949_EXAMPLES:
            with self.subTest(hex_):
                data = bytes.fromhex(hex_)
                self.assertEqual(data, cbor.dumps(value))
                self.assertEqual(value, cbor.loads(data))
                self.assertEqual(data, cbor.dumps(cbor.loads(data)))  # e.g. True == 1
                for i in range(len(data)):
                    with self.assertRaises(CBORDecodeEOF):
                        cbor.loads(data[:i])
                with self.assertRaises(CBORDecodeError):
                    cbor.loads(data + b'\x00')

    def test_rfc8949_unsupported_and_not_well_formed(self):
        for hex_ in RFC8949_UNSUPPORTED + RFC8949_NOT_WELL_FORMED:
            with self.subTest(hex_), self.assertRaises(CBORDecodeError) as ctx:
                cbor.loads(bytes.fromhex(hex_))
            if hex_ in RFC8949_UNSUPPORTED:  # complete items, not truncated ones
                self.assertNotIsInstance(ctx.exception, EOFError)

    def test_decode_non_minimal(self):
        # accepted, like the cbor2 package does
        for hex_, value in (('1800', 0), ('1b0000000000000017', 23), ('3900ff', -256), ('5900020102', b'\x01\x02'),
                            ('7a0000000161', 'a'), ('9b000000000000000100', [0]), ('b800', {}), ('d8000a', CBORTag(0, 10))):
            with self.subTest(hex_):
                self.assertEqual(value, cbor.loads(bytes.fromhex(hex_)))

    def test_decode_rejects(self):
        for hex_ in (
                'a1f500', 'a1f600', 'a18000', 'a1c00000',  # map keys: true, null, [], tag
                'a2616101616102', 'a20102180103',  # duplicate map keys
                '62c328', '63eda080',  # invalid UTF-8, incl. surrogate
                '1c' + '00' * 16,  # reserved additional information
        ):
            with self.subTest(hex_), self.assertRaises(CBORDecodeError) as ctx:
                cbor.loads(bytes.fromhex(hex_))
            self.assertNotIsInstance(ctx.exception, EOFError)
        self.assertTrue(issubclass(CBORDecodeEOF, EOFError))  # jadepy expects EOFError on timeouts

        # huge declared lengths do not allocate memory: never read more than 64 KiB at once
        class Stream(io.BytesIO):
            def read(self, n):
                assert n <= 65536
                return super().read(n)
        for hex_ in ('5affffffff', '7bffffffffffffffff', '9bffffffffffffffff', 'bbffffffffffffffff'):
            with self.subTest(hex_), self.assertRaises(CBORDecodeEOF):
                cbor.load(Stream(bytes.fromhex(hex_)))
        long = b'\x01' * (2 * 65536 + 1)  # read in chunks
        self.assertEqual(long, cbor.loads(cbor.dumps(long)))
        with self.assertRaises(CBORDecodeEOF):
            cbor.loads(cbor.dumps(long)[:-1])

    def test_max_depth(self):
        for prefix in (b'\x81', b'\xa1\x00', b'\xc1'):  # array, map, tag
            with self.subTest(prefix):
                data = prefix * 64 + b'\x00'
                self.assertEqual(data, cbor.dumps(cbor.loads(data)))
                with self.assertRaises(CBORDecodeError):
                    cbor.loads(prefix + data)
                with self.assertRaises(CBOREncodeError):
                    cbor.dumps([cbor.loads(data)])
        with self.assertRaises(CBORDecodeError):  # map keys nest, too
            cbor.loads(b'\xa1' * 10_000)

    def test_encode(self):
        self.assertEqual(cbor.dumps([1, b'a']), cbor.dumps((1, bytearray(b'a'))))
        for value in (2**64, -2**64 - 1, 1.0, {1}, object(), memoryview(b''), '\ud800',
                      {True: 1}, {None: 1}, {(1,): 1},
                      CBORTag(-1, 0), CBORTag(2**64, 0), CBORTag(True, 0), CBORTag('1', 0)):
            with self.subTest(value), self.assertRaises(CBOREncodeError):
                cbor.dumps(value)
        with self.assertRaises(CBOREncodeError):  # too large to be converted to str
            cbor.dumps(10**5000)

    def test_jade_messages(self):
        request = {'method': 'get_xpub', 'id': '42', 'params': {'network': 'mainnet', 'path': [2**31 + 84, 2**31, 2**31]}}
        self.assertEqual(bytes.fromhex(
            'a3666d6574686f64686765745f7870756262696462343266706172616d73a2676e6574776f726b676d61696e6e6574'
            '6470617468831a800000541a800000001a80000000'), cbor.dumps(request))
        log = {'log': b'I (1234) jade: hello'}
        reply = {'id': '42', 'result': 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'}
        error = {'id': '43', 'error': {'code': -32600, 'message': 'Invalid request', 'data': b''}}
        # the replies are read from a stream, without reading ahead
        stream = io.BytesIO(b''.join(cbor.dumps(m) for m in (log, reply, error)) + b'\xa1')
        for message in (log, reply, error):
            pos = stream.tell()
            self.assertEqual(message, cbor.load(stream))
            self.assertEqual(pos + len(cbor.dumps(message)), stream.tell())
        with self.assertRaises(EOFError):  # incomplete message, e.g. timeout
            cbor.load(stream)

    def test_random(self):
        rng = random.Random(0)
        for _ in range(1000):
            obj = random_object(rng)
            data = cbor.dumps(obj)
            self.assertEqual(data, cbor.dumps(cbor.loads(data)))
            # corrupted input either decodes or raises CBORDecodeError
            for _ in range(10):
                pos = rng.randrange(len(data))
                corrupted = data[:pos] + rng.randbytes(rng.randrange(3)) + data[pos + rng.randrange(3):]
                try:
                    cbor.loads(corrupted)
                except CBORDecodeError:
                    pass
