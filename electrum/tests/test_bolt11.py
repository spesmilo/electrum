from hashlib import sha256
from decimal import Decimal
from binascii import unhexlify, hexlify
import pprint
import unittest

from electrum.lnaddr import shorten_amount, unshorten_amount, LnAddr, lnencode, lndecode, u5_to_bitarray, bitarray_to_u5
from electrum.segwit_addr import bech32_encode, bech32_decode
from electrum.lnutil import UnknownEvenFeatureBits, derive_payment_secret_from_payment_preimage

from . import ElectrumTestCase


RHASH=unhexlify('0001020304050607080900010203040506070809000102030405060708090102')
CONVERSION_RATE=1200
PRIVKEY=unhexlify('e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734')
PUBKEY=unhexlify('03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad')


class TestBolt11(ElectrumTestCase):
    def test_shorten_amount(self):
        tests = {
            Decimal(10)/10**12: '10p',
            Decimal(1000)/10**12: '1n',
            Decimal(1200)/10**12: '1200p',
            Decimal(123)/10**6: '123u',
            Decimal(123)/1000: '123m',
            Decimal(3): '3',
        }

        for i, o in tests.items():
            assert shorten_amount(i) == o
            assert unshorten_amount(shorten_amount(i)) == i

    @staticmethod
    def compare(a, b):

        if len([t[1] for t in a.tags if t[0] == 'h']) == 1:
            h1 = sha256([t[1] for t in a.tags if t[0] == 'h'][0].encode('utf-8')).digest()
            h2 = [t[1] for t in b.tags if t[0] == 'h'][0]
            assert h1 == h2

        # Need to filter out these, since they are being modified during
        # encoding, i.e., hashed
        a.tags = [t for t in a.tags if t[0] != 'h' and t[0] != 'n']
        b.tags = [t for t in b.tags if t[0] != 'h' and t[0] != 'n']

        assert b.pubkey.serialize() == PUBKEY, (hexlify(b.pubkey.serialize()), hexlify(PUBKEY))
        assert b.signature != None

        # Unset these, they are generated during encoding/decoding
        b.pubkey = None
        b.signature = None

        assert a.__dict__ == b.__dict__, (pprint.pformat([a.__dict__, b.__dict__]))

    def test_roundtrip(self):
        longdescription = ('One piece of chocolate cake, one icecream cone, one'
                          ' pickle, one slice of swiss cheese, one slice of salami,'
                          ' one lollypop, one piece of cherry pie, one sausage, one'
                          ' cupcake, and one slice of watermelon')


        tests = [
            LnAddr(paymenthash=RHASH, tags=[('d', '')]),
            LnAddr(paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60)]),
            LnAddr(paymenthash=RHASH, amount=Decimal('1'), tags=[('h', longdescription)]),
            LnAddr(paymenthash=RHASH, currency='tb', tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[
                ('r', [(unhexlify('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('0102030405060708'), 1, 20, 3),
                       (unhexlify('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('030405060708090a'), 2, 30, 4)]),
                ('f', '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'),
                ('h', longdescription)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('f', '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'), ('h', longdescription)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('f', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), ('h', longdescription)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('f', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'), ('h', longdescription)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('n', PUBKEY), ('h', longdescription)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 514)]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 8))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 7) + (1 << 11))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 12))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 13))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 14))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 15))]),
            LnAddr(paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 33282)], payment_secret=b"\x11" * 32),
        ]

        # Roundtrip
        for t in tests:
            o = lndecode(lnencode(t, PRIVKEY), expected_hrp=t.currency)
            self.compare(t, o)

    def test_n_decoding(self):
        # We flip the signature recovery bit, which would normally give a different
        # pubkey.
        hrp, data = bech32_decode(lnencode(LnAddr(paymenthash=RHASH, amount=24, tags=[('d', '')]), PRIVKEY), True)
        databits = u5_to_bitarray(data)
        databits.invert(-1)
        lnaddr = lndecode(bech32_encode(hrp, bitarray_to_u5(databits)), verbose=True)
        assert lnaddr.pubkey.serialize() != PUBKEY

        # But not if we supply expliciy `n` specifier!
        hrp, data = bech32_decode(lnencode(LnAddr(paymenthash=RHASH, amount=24,
                                                  tags=[('d', ''),
                                                        ('n', PUBKEY)]),
                                           PRIVKEY), True)
        databits = u5_to_bitarray(data)
        databits.invert(-1)
        lnaddr = lndecode(bech32_encode(hrp, bitarray_to_u5(databits)), verbose=True)
        assert lnaddr.pubkey.serialize() == PUBKEY

    def test_min_final_cltv_expiry_decoding(self):
        lnaddr = lndecode("lnsb500u1pdsgyf3pp5nmrqejdsdgs4n9ukgxcp2kcq265yhrxd4k5dyue58rxtp5y83s3qdqqcqzystrggccm9yvkr5yqx83jxll0qjpmgfg9ywmcd8g33msfgmqgyfyvqhku80qmqm8q6v35zvck2y5ccxsz5avtrauz8hgjj3uahppyq20qp6dvwxe",
                          expected_hrp="sb")
        self.assertEqual(144, lnaddr.get_min_final_cltv_expiry())

    def test_min_final_cltv_expiry_roundtrip(self):
        lnaddr = LnAddr(paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('c', 150)])
        invoice = lnencode(lnaddr, PRIVKEY)
        self.assertEqual(150, lndecode(invoice).get_min_final_cltv_expiry())

    def test_features(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzsze992adudgku8p05pstl6zh7av6rx2f297pv89gu5q93a0hf3g7lynl3xq56t23dpvah6u7y9qey9lccrdml3gaqwc6nxsl5ktzm464sq73t7cl")
        self.assertEqual(514, lnaddr.get_tag('9'))

        with self.assertRaises(UnknownEvenFeatureBits):
            lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9q4pqqqqqqqqqqqqqqqqqqszk3ed62snp73037h4py4gry05eltlp0uezm2w9ajnerhmxzhzhsu40g9mgyx5v3ad4aqwkmvyftzk4k9zenz90mhjcy9hcevc7r3lx2sphzfxz7")

    def test_payment_secret(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsqvvh7ut50r00p3pg34ea68k7zfw64f8yx9jcdk35lh5ft8qdr8g4r0xzsdcrmcy9hex8un8d8yraewvhqc9l0sh8l0e0yvmtxde2z0hgpzsje5l")
        self.assertEqual((1 << 9) + (1 << 15) + (1 << 99), lnaddr.get_tag('9'))
        self.assertEqual(b"\x11" * 32, lnaddr.payment_secret)

    def test_derive_payment_secret_from_payment_preimage(self):
        preimage = bytes.fromhex("cc3fc000bdeff545acee53ada12ff96060834be263f77d645abbebc3a8d53b92")
        self.assertEqual("bfd660b559b3f452c6bb05b8d2906f520c151c107b733863ed0cc53fc77021a8",
                         derive_payment_secret_from_payment_preimage(preimage).hex())
