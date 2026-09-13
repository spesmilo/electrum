from hashlib import sha256
from decimal import Decimal
from binascii import unhexlify, hexlify
import pprint
import unittest

import electrum_ecc as ecc

from electrum.bolt11 import (shorten_amount, unshorten_amount, BOLT11Addr, encode_bolt11_invoice,
                             decode_bolt11_invoice, parse_fallback_addr, int_to_data5, tagged5, tagged8,
                             BOLT11DecodeException, BOLT11InvoiceException, TIMESTAMP_SANE_MAX)
from electrum.segwit_addr import bech32_encode, bech32_decode, convertbits, CHARSET_INVERSE
from electrum import segwit_addr
from electrum.lnutil import UnknownEvenFeatureBits, LnFeatures, IncompatibleLightningFeatures
from electrum import constants
from electrum.util import bfh, ShortID

from . import ElectrumTestCase


RHASH=unhexlify('0001020304050607080900010203040506070809000102030405060708090102')
PAYMENT_SECRET=unhexlify('1111111111111111111111111111111111111111111111111111111111111111')
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
            Decimal(1000): '1000',
        }

        for i, o in tests.items():
            self.assertEqual(shorten_amount(i), o)
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
        assert b.signature is not None

        # Unset these, they are generated during encoding/decoding
        b.pubkey = None
        b.signature = None

        assert a.__dict__ == b.__dict__, (pprint.pformat([a.__dict__, b.__dict__]))

    def test_roundtrip(self):
        longdescription = ('One piece of chocolate cake, one icecream cone, one'
                          ' pickle, one slice of swiss cheese, one slice of salami,'
                          ' one lollypop, one piece of cherry pie, one sausage, one'
                          ' cupcake, and one slice of watermelon')

        timestamp = 1615922274
        tests = [
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, tags=[('d', ''), ('9', 33282)]),
             "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('9', 0x28200)]),
             "lnbc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5xysxxatsyp3k7enxv4jsxqzpu9qy9qsqw8l2pulslacwjt86vle3sgfdmcct5v34gtcpfnujsf6ufqa7v7jzdpddnwgte82wkscdlwfwucrgn8z36rv9hzk5mukltteh0yqephqpk5vegu"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=Decimal('1'), tags=[('h', longdescription), ('9', 0x28200)]),
             "lnbc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsq0jnua6dc4p984aeafs6ss7tjjj7553ympvg82qrjq0zgdqgtdvt5wlwkvw4ds5sn96nazp6ct9ts37tcw708kzkk4p8znahpsgp9tnspnycsf7"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription), ('9', 0x28200)]),
             "lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqy5826t0z3sn29z396pmr4kv73lcx0v7y6vas6h3pysmqllmzwgm5ps2t468gm4psj52usjy6y4xcry4k84n2zggs6f9agwg95454v6gqrwmh4f"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[
                ('r', [(unhexlify('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('0102030405060708'), 1, 20, 3),
                       (unhexlify('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('030405060708090a'), 2, 30, 4)]),
                ('f', '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'),
                ('h', longdescription),
                ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqfnk063vsrgjx7l6td6v42skuxql7epn5tmrl4qte2e78nqnsjlgjg3sgkxreqex5fw4c9chnvtc2hykqnyxr84zwfr8f3d9q3h0nfdgqenlzvj"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('f', '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfppj3a24vwu6r8ejrss3axul8rxldph2q7z9hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqqf6z4r7ruzr5txm5ln4netwa2f4x233tud7jy8gxrynyx07rxt7qm92yk2krlgwr7d8jknglur75sujeyapmda5nf3femrk2mep8a2cp4hlvup"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('f', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfppqw508d6qejxtdg4y5r3zarvary0c5xw7khp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqy4wp73jma5uktd9y7yha56f98n2k0hxgnvp2qdcury00dapps3k3urgfy8tvv8jzwcafpy576msk5xx2hladf06m3s5mgx5msn4elfqqaaqjhk"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('f', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqgt4gg9uktlpgnnuvczazusp5uwjv78na305ucsw06c8uk58e5stjqj9sz7fgavw0z688alt364js72mc9mg8yumhpes2dsmq5k9nr5qqddykxy"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('n', PUBKEY), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsq2y235rxw7v0gkn2t9ehc742tm3p22q2yjjykq4d85ze6g62yk60navxqz0ga96sqrszju8nlfajthem4gngxvyz4hwy39j4nqm8kv0qq9znxs7"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('h', longdescription), ('9', 2 + (1 << 9) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqszrwfgrl5k3rt4q4mclc8t00p2tcjsf9pmpcq6lu5zhmampyvk43fk30eqpdm8t5qmdpzan25aqxqaqdzmy0smrtduazjcxx975vz78ccpx0qhev"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 8) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqg2wans8f6vkfd3l7zjv547hlc7wd7eqyxfwhtdudnkkgrpk6p9ffykwrvdtwm0aakaxujurdxgd7cllnfypmj22cvy7z333udg6zncgacqzmd2z9"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqs2dr525u5f4kjxdv0hq5c822qwxrtttjl4u586yl84x0kvvx66gz9ygy76005s5sjwgr7fp55ccsae47vpl4gqvwhc3exps964g743j5gqwtt68t"),
            (BOLT11Addr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 14))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrss2f8kr98446xls02yndup2ynwjh46u8kdeuuncexx2hnets0j0064nyq25gkd6jnttldzt5qqtszum5dufvuvryxt204w2p24557udxgcp0nlwtw"),
        ]

        # Roundtrip
        for lnaddr1, invoice_str1 in tests:
            invoice_str2 = encode_bolt11_invoice(lnaddr1, PRIVKEY)
            self.assertEqual(invoice_str1, invoice_str2)
            lnaddr2 = decode_bolt11_invoice(invoice_str2, net=lnaddr1.net)
            self.compare(lnaddr1, lnaddr2)

    def test_n_decoding(self):
        # We flip the signature recovery bit, which would normally give a different
        # pubkey.
        _, hrp, data = bech32_decode(
            encode_bolt11_invoice(BOLT11Addr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('d', ''), ('9', 33282)]), PRIVKEY),
            ignore_long_length=True)
        data[-1] ^= 1
        lnaddr = decode_bolt11_invoice(bech32_encode(segwit_addr.Encoding.BECH32, hrp, data), verbose=True)
        self.assertNotEqual(lnaddr.pubkey.serialize(), PUBKEY)

        # But not if we supply expliciy `n` specifier!
        _, hrp, data = bech32_decode(
            encode_bolt11_invoice(BOLT11Addr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('d', ''), ('n', PUBKEY), ('9', 33282)]), PRIVKEY),
            ignore_long_length=True)
        data[-1] ^= 1
        lnaddr = decode_bolt11_invoice(bech32_encode(segwit_addr.Encoding.BECH32, hrp, data), verbose=True)
        self.assertEqual(lnaddr.pubkey.serialize(), PUBKEY)

    @staticmethod
    def _encode_invoice_with_raw_tags(tags5, *, net=None, date=1615922274, amountstr='') -> str:
        """Builds a correctly signed invoice containing exactly the given (tag, data5) fields."""
        net = net or constants.BitcoinMainnet
        hrp = 'ln' + net.BOLT11_HRP + amountstr
        data5 = list(int_to_data5(date, bit_len=35))
        for tag, tagdata5 in tags5:
            data5 += list(tagged5(tag, list(tagdata5)))
        msg32 = sha256(hrp.encode('ascii') + bytes(convertbits(data5, 5, 8))).digest()
        sig = ecc.ECPrivkey(PRIVKEY).ecdsa_sign_recoverable(msg32, is_compressed=False)
        sig = bytes(sig[1:]) + bytes([sig[0] - 27])
        return bech32_encode(segwit_addr.Encoding.BECH32, hrp, data5 + list(convertbits(sig, 8, 5, False)))

    @staticmethod
    def _encode_invoice_with_raw_tag(tag, tagdata5, *, net=None, date=1615922274, expiry=None) -> str:
        """Builds a correctly signed invoice with one arbitrary (possibly malformed) tagged field."""
        tags5 = []
        if tag != 'p':
            tags5.append(('p', convertbits(RHASH, 8, 5)))
        if tag != 's':
            tags5.append(('s', convertbits(PAYMENT_SECRET, 8, 5)))
        if tag not in ('d', 'h'):  # exactly one of 'd'/'h' must be present
            tags5.append(('d', convertbits(b'test', 8, 5)))
        if expiry is not None:
            tags5.append(('x', int_to_data5(expiry)))
        tags5.append((tag, tagdata5))
        return TestBolt11._encode_invoice_with_raw_tags(tags5, net=net, date=date)

    @staticmethod
    def _encode_invoice_with_raw_sig(sig65, *, net=None) -> str:
        """Builds an invoice with an arbitrary (possibly invalid) 65-byte signature.
        Note: no 'n' field, so decoding goes through pubkey recovery."""
        net = net or constants.BitcoinMainnet
        hrp = 'ln' + net.BOLT11_HRP
        data5 = list(int_to_data5(1615922274, bit_len=35))
        data5 += list(tagged8('p', RHASH))
        data5 += list(tagged8('d', b'test'))
        return bech32_encode(segwit_addr.Encoding.BECH32, hrp, data5 + list(convertbits(sig65, 8, 5, False)))

    def test_parse_fallback_addr(self):
        net = constants.BitcoinMainnet

        def parse(wver, data8):
            return parse_fallback_addr([wver] + list(convertbits(data8, 8, 5)), net)

        # p2pkh/p2sh: the payload must be a hash160
        self.assertEqual('1111111111111111111114oLvT2', parse(17, bytes(20)))
        self.assertEqual('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST', parse(18, bytes(20)))
        for nbytes in (0, 1, 19, 21, 32, 40):
            self.assertIsNone(parse(17, bytes(nbytes)))
            self.assertIsNone(parse(18, bytes(nbytes)))
        # segwit v0: the witness program must be 20 or 32 bytes
        self.assertEqual('bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs', parse(0, bytes(20)))
        self.assertEqual('bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8', parse(0, bytes(32)))
        for nbytes in (0, 1, 19, 21, 40, 41):
            self.assertIsNone(parse(0, bytes(nbytes)))
        # segwit v1-v16: the witness program must be 2-40 bytes
        for wver in (1, 16):
            self.assertIsNotNone(parse(wver, bytes(2)))
            self.assertIsNotNone(parse(wver, bytes(40)))
            for nbytes in (0, 1, 41):
                self.assertIsNone(parse(wver, bytes(nbytes)))
        # unknown witness versions
        self.assertIsNone(parse(19, bytes(20)))
        self.assertIsNone(parse(31, bytes(20)))
        # truncated/malformed frames
        self.assertIsNone(parse_fallback_addr([], net))
        self.assertIsNone(parse_fallback_addr(bytearray(), net))
        self.assertIsNone(parse_fallback_addr([16, 1], net))  # non-zero padding bits
        self.assertIsNone(parse_fallback_addr([17, 1], net))

    def test_malformed_fallback_addr_is_skipped(self):
        # BOLT #11: "A reader MUST skip over [...] an `f` field with unknown `version`".
        # A malformed 'f' field must not abort decoding of the whole invoice.
        for tagdata5 in ([],                # empty payload
                         [16, 1],           # non-zero padding bits
                         [17] + [0] * 4,    # p2pkh with a too-short hash160
                         [0] + [0] * 4,     # p2wpkh with a too-short witness program
                         [19, 0, 0]):       # unknown witness version
            lnaddr = decode_bolt11_invoice(self._encode_invoice_with_raw_tag('f', tagdata5))
            self.assertIsNone(lnaddr.get_tag('f'))
            self.assertEqual('', lnaddr.get_fallback_address())
            self.assertEqual(['f'], [tag for tag, _ in lnaddr.unknown_tags])
        # sanity: a well-formed 'f' field is still parsed
        lnaddr = decode_bolt11_invoice(
            self._encode_invoice_with_raw_tag('f', [17] + list(convertbits(bytes(20), 8, 5))))
        self.assertEqual('1111111111111111111114oLvT2', lnaddr.get_fallback_address())
        self.assertEqual([], lnaddr.unknown_tags)

    def test_tag_padding_errors(self):
        # A tag whose 5->8 bit conversion has non-zero padding bits (or a length that cannot
        # be converted at all) is malformed: it must be rejected, not crash the parser.
        for tag, tagdata5 in (('d', [1]),               # 5 bits left over: no valid conversion
                              ('d', [0, 1]),            # non-zero padding bits
                              ('h', [0] * 51 + [1]),    # data_length 52, non-zero padding bits
                              ('p', [0] * 51 + [1]),
                              ('s', [0] * 51 + [1]),
                              ('n', [0] * 52 + [1]),    # data_length 53, non-zero padding bit
                              ('r', [1]),
                              ('r', [0, 1]),
                              ('t', [1]),
                              ('t', [0, 1])):
            with self.subTest(tag=tag, tagdata5=tagdata5):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(self._encode_invoice_with_raw_tag(tag, tagdata5))

        # control: the same lengths with zero padding bits decode fine
        for tag, tagdata5 in (('d', [0, 0]),
                              ('h', [0] * 51 + [16]),
                              ('p', [0] * 51 + [16]),
                              ('s', [0] * 51 + [16]),
                              ('n', list(convertbits(PUBKEY, 8, 5))),
                              ('r', [0] * 8),
                              ('t', [0] * 8)):
            with self.subTest(tag=tag):
                decode_bolt11_invoice(self._encode_invoice_with_raw_tag(tag, tagdata5))

        # 'h', 'p', 's' and 'n' have a fixed data_length: a wrong length rejects the invoice
        for tag, data_length in (('h', 52), ('p', 52), ('s', 52), ('n', 53)):
            for wrong_length in (data_length - 1, data_length + 1):
                with self.subTest(tag=tag, data_length=wrong_length):
                    with self.assertRaises(BOLT11DecodeException):
                        decode_bolt11_invoice(
                            self._encode_invoice_with_raw_tag(tag, [0] * wrong_length))

        # 'r' and 't': an empty payload converts to b'' instead of failing, so it is skipped
        for tag in ('r', 't'):
            with self.subTest(tag=tag, tagdata5=[]):
                lnaddr = decode_bolt11_invoice(self._encode_invoice_with_raw_tag(tag, []))
                self.assertIsNone(lnaddr.get_tag(tag))
                self.assertEqual([], lnaddr.unknown_tags)

        # control: a well-formed hop is parsed
        r_hop = bytes(33) + bytes(8) + (1).to_bytes(4, 'big') + (2).to_bytes(4, 'big') + (3).to_bytes(2, 'big')
        t_hop = bytes(33) + (1).to_bytes(4, 'big') + (2).to_bytes(4, 'big') + (3).to_bytes(2, 'big')
        for tag, hop in (('r', r_hop), ('t', t_hop)):
            with self.subTest(tag=tag):
                invoice = self._encode_invoice_with_raw_tag(tag, list(convertbits(hop, 8, 5)))
                self.assertEqual(1, len(decode_bolt11_invoice(invoice).get_routing_info(tag)))

    def test_invalid_signature(self):
        # The trailing 65 bytes of an invoice are attacker-controlled: every way the ecc lib
        # can reject them must surface as BOLT11DecodeException, not leak out of the parser.
        r_ok = (1).to_bytes(32, 'big')
        s_ok = (1).to_bytes(32, 'big')

        # the recovery id (the last byte) must be 0-3
        for recid in (4, 27, 255):
            with self.subTest(recid=recid):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(self._encode_invoice_with_raw_sig(r_ok + s_ok + bytes([recid])))

        # r and s must be below the curve order
        for label, sig64 in (('r == n', ecc.CURVE_ORDER.to_bytes(32, 'big') + s_ok),
                             ('r == n+1', (ecc.CURVE_ORDER + 1).to_bytes(32, 'big') + s_ok),
                             ('r == 2**256-1', b'\xff' * 32 + s_ok),
                             ('s == n', r_ok + ecc.CURVE_ORDER.to_bytes(32, 'big')),
                             ('s == n+1', r_ok + (ecc.CURVE_ORDER + 1).to_bytes(32, 'big')),
                             ('s == 2**256-1', r_ok + b'\xff' * 32)):
            with self.subTest(sig=label):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(self._encode_invoice_with_raw_sig(sig64 + b'\x00'))

        # in-range but unrecoverable signature
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(self._encode_invoice_with_raw_sig(r_ok + s_ok + b'\x03'))

        # an 'n' field that is not a valid curve point (this path uses ecdsa_verify, not recovery)
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(self._encode_invoice_with_raw_tag('n', list(convertbits(bytes(33), 8, 5))))

    def test_mandatory_tags(self):
        # BOLT #11: a reader MUST fail the payment if a 'p' or 's' field is missing, and MUST
        # fail if neither a 'd' nor an 'h' field is present, or if both are present.
        p5 = convertbits(RHASH, 8, 5)
        s5 = convertbits(PAYMENT_SECRET, 8, 5)
        d5 = convertbits(b'test', 8, 5)
        h5 = convertbits(sha256(b'test').digest(), 8, 5)
        # control: 'd' and 'h' are each enough on their own
        lnaddr = decode_bolt11_invoice(self._encode_invoice_with_raw_tags([('p', p5), ('s', s5), ('d', d5)]))
        self.assertEqual('test', lnaddr.get_description())
        self.assertEqual(RHASH, lnaddr.paymenthash)
        self.assertEqual(PAYMENT_SECRET, lnaddr.payment_secret)
        decode_bolt11_invoice(self._encode_invoice_with_raw_tags([('p', p5), ('s', s5), ('h', h5)]))

        for label, tags5 in (("no 'p' field", [('s', s5), ('d', d5)]),
                             ("no 's' field", [('p', p5), ('d', d5)]),
                             ("neither 'd' nor 'h'", [('p', p5), ('s', s5)]),
                             ("both 'd' and 'h'", [('p', p5), ('s', s5), ('d', d5), ('h', h5)]),
                             ("no tagged fields at all", [])):
            with self.subTest(label):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(self._encode_invoice_with_raw_tags(tags5))

    def test_duplicate_tags(self):
        p5 = convertbits(RHASH, 8, 5)
        s5 = convertbits(PAYMENT_SECRET, 8, 5)
        d5 = convertbits(b'test', 8, 5)
        h5 = convertbits(sha256(b'test').digest(), 8, 5)
        # a second copy of a field we only keep one value for is rejected
        for tag, tags5 in (('p', [('p', p5), ('p', p5), ('s', s5), ('d', d5)]),
                           ('s', [('p', p5), ('s', s5), ('s', s5), ('d', d5)]),
                           ('d', [('p', p5), ('s', s5), ('d', d5), ('d', d5)]),
                           ('h', [('p', p5), ('s', s5), ('h', h5), ('h', h5)])):
            with self.subTest(tag=tag):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(self._encode_invoice_with_raw_tags(tags5))

        # 'n' is the exception: BOLT #11 has writers put the most-preferred field first, so the
        # first one is kept and the rest ignored. Note the invoice is signed by PUBKEY, so if
        # the second 'n' were the one kept, signature validation against it would fail.
        other_pubkey = ecc.ECPrivkey(bytes(31) + b'\x02').get_public_key_bytes(compressed=True)
        self.assertNotEqual(PUBKEY, other_pubkey)
        lnaddr = decode_bolt11_invoice(self._encode_invoice_with_raw_tags(
            [('p', p5), ('s', s5), ('d', d5),
             ('n', convertbits(PUBKEY, 8, 5)), ('n', convertbits(other_pubkey, 8, 5))]))
        self.assertEqual(PUBKEY, lnaddr.pubkey.serialize())

    def test_invalid_utf8_description(self):
        # the 'd' field is UTF-8: an invalid encoding must be rejected, not crash the parser
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(self._encode_invoice_with_raw_tag('d', convertbits(b'\xff\xfe', 8, 5)))
        # control: non-ASCII UTF-8 decodes fine
        description = 'ナンセンス 1杯'
        lnaddr = decode_bolt11_invoice(
            self._encode_invoice_with_raw_tag('d', convertbits(description.encode('utf-8'), 8, 5)))
        self.assertEqual(description, lnaddr.get_description())

    def test_non_minimal_data_length(self):
        # BOLT #11: a 'c', 'x' or '9' field "MUST use the minimum `data_length` possible, i.e.
        # no leading 0 field-elements"; a reader SHOULD treat a non-minimal one as invalid.
        for tag in ('x', 'c', '9'):
            for tagdata5 in ([0],               # zero, which is minimally encoded as an empty field
                             [0, 1, 28],        # 60, left-padded with one 0 element
                             [0] * 50 + [1]):   # 1, left-padded all the way
                with self.subTest(tag=tag, tagdata5=tagdata5):
                    with self.assertRaises(BOLT11DecodeException):
                        decode_bolt11_invoice(self._encode_invoice_with_raw_tag(tag, tagdata5))
            # control: minimally encoded values, zero (i.e. an empty field) included
            for tagdata5, value in (([], 0), ([31], 31), ([1, 28], 60)):
                with self.subTest(tag=tag, tagdata5=tagdata5):
                    lnaddr = decode_bolt11_invoice(self._encode_invoice_with_raw_tag(tag, tagdata5))
                    self.assertEqual(value, lnaddr.get_tag(tag))

        # the accessors see the decoded values
        self.assertEqual(60, decode_bolt11_invoice(
            self._encode_invoice_with_raw_tag('x', [1, 28])).get_expiry())
        self.assertEqual(31, decode_bolt11_invoice(
            self._encode_invoice_with_raw_tag('c', [31])).get_min_final_cltv_delta())

        # ... and whatever our own encoder emits is minimal, so it still roundtrips
        for tag in ('x', 'c', '9'):
            for value in (1, 31, 32, 60, 3600, 2 ** 40):
                with self.subTest(tag=tag, value=value):
                    addr = BOLT11Addr(date=1615922274, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,
                                      tags=[('d', ''), (tag, value)])
                    lnaddr = decode_bolt11_invoice(encode_bolt11_invoice(addr, PRIVKEY))
                    self.assertEqual(value, lnaddr.get_tag(tag))
        # zero: 'x' and 'c' are written as an empty (still minimal) field, '9' is omitted entirely
        for tag, expected in (('x', 0), ('c', 0), ('9', None)):
            with self.subTest(tag=tag, value=0):
                addr = BOLT11Addr(date=1615922274, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,
                                  tags=[('d', ''), (tag, 0)])
                lnaddr = decode_bolt11_invoice(encode_bolt11_invoice(addr, PRIVKEY))
                self.assertEqual(expected, lnaddr.get_tag(tag))

    def test_corrupt_tag_data(self):
        # A tagged field whose data_length runs past the end of the data part must be rejected.
        # Note the signature is split off the end first, so what is left for the tag loop is
        # attacker-controlled in length as well as content.
        hrp = 'ln' + constants.BitcoinMainnet.BOLT11_HRP
        body = list(int_to_data5(1615922274, bit_len=35))
        body += list(tagged8('p', RHASH)) + list(tagged8('s', PAYMENT_SECRET)) + list(tagged8('d', b'test'))
        sig5 = [0] * (65 * 8 // 5)

        def encode(data5):
            return bech32_encode(segwit_addr.Encoding.BECH32, hrp, data5)

        for label, trailer in (("data_length past end of data", [CHARSET_INVERSE['x'], 0, 20]),
                               ("1 stray data element", [CHARSET_INVERSE['x']]),
                               ("2 stray data elements", [CHARSET_INVERSE['x'], 0])):
            with self.subTest(label):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(encode(body + trailer + sig5))
        # an invoice that is all tags and no signature: the last 65 bytes are taken to be the
        # signature regardless, which leaves a truncated tag behind
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(encode(body))
        # ... and one shorter than a signature is rejected outright
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(encode(list(int_to_data5(1615922274, bit_len=35))))
        # control: the same body followed by a signature-sized (if bogus) trailer gets all the
        # way past the tag loop, and fails on the signature instead
        with self.assertRaisesRegex(BOLT11DecodeException, 'signature'):
            decode_bolt11_invoice(encode(body + sig5))

    def test_bech32_errors(self):
        invoice = self._encode_invoice_with_raw_tag('x', int_to_data5(60))
        self.assertEqual(60, decode_bolt11_invoice(invoice).get_expiry())  # control

        for label, bad_invoice in (("corrupt checksum", invoice[:-1] + ('q' if invoice[-1] != 'q' else 'p')),
                                   ("mixed case", invoice[:8].upper() + invoice[8:]),
                                   ("empty string", ''),
                                   ("no separator", 'lnbc'),
                                   ("not an invoice", 'not an invoice')):
            with self.subTest(label):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(bad_invoice)

        decoded = bech32_decode(invoice, ignore_long_length=True)
        # bolt11 uses vanilla bech32; the same data encoded as bech32m must be rejected
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(bech32_encode(segwit_addr.Encoding.BECH32M, decoded.hrp, decoded.data))
        # hrp of another network, and one that is not a lightning invoice at all
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(invoice, net=constants.BitcoinTestnet)
        with self.assertRaises(BOLT11DecodeException):
            decode_bolt11_invoice(bech32_encode(segwit_addr.Encoding.BECH32, 'bc', decoded.data))

    def test_invalid_amount(self):
        # the amount is part of the hrp; amounts the BOLT11Addr.amount setter rejects must
        # surface as BOLT11DecodeException, not as a bare BOLT11InvoiceException
        tags5 = [('p', convertbits(RHASH, 8, 5)),
                 ('s', convertbits(PAYMENT_SECRET, 8, 5)),
                 ('d', convertbits(b'test', 8, 5))]
        self.assertEqual(  # control
            Decimal('0.0025'),
            decode_bolt11_invoice(self._encode_invoice_with_raw_tags(tags5, amountstr='2500u')).amount)
        for amountstr in ('21000001',  # more than the total coin supply
                          '1p',        # sub-millisatoshi precision
                          '25y',       # invalid multiplier
                          '-1',
                          'nan',
                          '1e3'):
            with self.subTest(amountstr=amountstr):
                with self.assertRaises(BOLT11DecodeException):
                    decode_bolt11_invoice(self._encode_invoice_with_raw_tags(tags5, amountstr=amountstr))

    def test_amount_validation(self):
        addr = BOLT11Addr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, tags=[('d', '')])
        for label, value in (("str", '1'),
                             ("float", 1.5),
                             ("bytes", b'1'),
                             ("NaN", Decimal('nan')),
                             ("negative", Decimal(-1)),
                             ("more than the coin supply", Decimal(21_000_001)),
                             ("sub-millisatoshi", Decimal('0.0000000000001'))):
            with self.subTest(label):
                with self.assertRaises(BOLT11InvoiceException):
                    addr.amount = value
        addr.amount = 1  # an int is accepted and converted
        self.assertEqual(Decimal(1), addr.amount)
        addr.amount = Decimal('0.00000000001')  # 1 msat, the smallest encodable amount
        self.assertEqual(Decimal('0.00000000001'), addr.amount)
        addr.amount = None
        self.assertIsNone(addr.amount)

    def test_date_validation(self):
        addr = BOLT11Addr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, tags=[('d', '')])
        for label, value in (("str", '123'),
                             ("bytes", b'123'),
                             ("None", None),
                             ("above TIMESTAMP_SANE_MAX", TIMESTAMP_SANE_MAX + 1)):
            with self.subTest(label):
                with self.assertRaises(BOLT11InvoiceException):
                    addr.date = value
        with self.assertRaises(BOLT11InvoiceException):
            BOLT11Addr(date=TIMESTAMP_SANE_MAX + 1)
        # a float (e.g. straight from time.time()) is truncated to an int
        addr.date = 1615922274.9
        self.assertEqual(1615922274, addr.date)
        # the largest timestamp the 35-bit bolt11 field can hold is still accepted
        addr.date = 2 ** 35 - 1
        self.assertEqual(2 ** 35 - 1, addr.date)
        self.assertLessEqual(2 ** 35 - 1, TIMESTAMP_SANE_MAX)

    def test_min_final_cltv_expiry_decoding(self):
        lnaddr = decode_bolt11_invoice("lnsb500u1pdsgyf3pp5nmrqejdsdgs4n9ukgxcp2kcq265yhrxd4k5dyue58rxtp5y83s3qsp5qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsdqqcqzys9qypqsqp2h6a5xeytuc3fad2ed4gxvhd593lwjdna3dxsyeem0qkzjx6guk44jend0xq4zzvp6f3fy07wnmxezazzsxgmvqee8shxjuqu2eu0qpnvc95x",
                                       net=constants.BitcoinSimnet)
        self.assertEqual(144, lnaddr.get_min_final_cltv_delta())

        lnaddr = decode_bolt11_invoice("lntb15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2s8tut3jqumepu42azyyjpgqa4w9w03204zp9h4clk499y2umstl6s29hqyj8vv4as6zt5567ux7l3f66m8pjhk65zjaq2esezk7ll2kcpljewkg",
                                       net=constants.BitcoinTestnet)
        self.assertEqual(30, lnaddr.get_min_final_cltv_delta())

    def test_min_final_cltv_expiry_roundtrip(self):
        for cltv in (1, 15, 16, 31, 32, 33, 150, 511, 512, 513, 1023, 1024, 1025):
            lnaddr = BOLT11Addr(
                paymenthash=RHASH, payment_secret=b"\x01"*32, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('c', cltv), ('9', 33282)])
            self.assertEqual(cltv, lnaddr.get_min_final_cltv_delta())
            invoice = encode_bolt11_invoice(lnaddr, PRIVKEY)
            self.assertEqual(cltv, decode_bolt11_invoice(invoice).get_min_final_cltv_delta())

    def test_features(self):
        lnaddr = decode_bolt11_invoice("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9qypqsztrz5v3jfnxskfv7g8chmyzyrfhf2vupcavuq5rce96kyt6g0zh337h206awccwp335zarqrud4wccgdn39vur44d8um4hmgv06aj0sgpdrv73z")
        self.assertEqual(33282, lnaddr.get_tag('9'))
        self.assertEqual(LnFeatures(33282), lnaddr.get_features())

    def test_payment_secret(self):
        lnaddr = decode_bolt11_invoice("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsqvvh7ut50r00p3pg34ea68k7zfw64f8yx9jcdk35lh5ft8qdr8g4r0xzsdcrmcy9hex8un8d8yraewvhqc9l0sh8l0e0yvmtxde2z0hgpzsje5l")
        self.assertEqual((1 << 9) + (1 << 15) + (1 << 99), lnaddr.get_tag('9'))
        self.assertEqual(b"\x11" * 32, lnaddr.payment_secret)

    def test_validate_and_compare_features(self):
        lnaddr = decode_bolt11_invoice("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsqvvh7ut50r00p3pg34ea68k7zfw64f8yx9jcdk35lh5ft8qdr8g4r0xzsdcrmcy9hex8un8d8yraewvhqc9l0sh8l0e0yvmtxde2z0hgpzsje5l")
        lnaddr.validate_and_compare_features(LnFeatures((1 << 8) + (1 << 14) + (1 << 15)))
        with self.assertRaises(IncompatibleLightningFeatures):
            lnaddr.validate_and_compare_features(LnFeatures((1 << 8) + (1 << 14) + (1 << 16)))

    def test_format_bolt11_routing_info_as_human_readable(self):
        r_tags_expl = [
            ['r', [(bfh('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), bfh('0102030405060708'), 1, 20, 3),
                   (bfh('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), bfh('030405060708090a'), 2, 30, 4)]],
            ['r', [(bfh('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9'), bfh('f4240000000002cd'), 0, 1, 40)]],
        ]
        self.assertEqual(
            [
                ('r', [('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                        '66051x263430x1800', 1, 20, 3),
                       ('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                        '197637x395016x2314', 2, 30, 4)]
                 ),
                ('r', [('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9',
                        '16000000x0x717', 0, 1, 40),]
                 ),
            ],
            BOLT11Addr.format_bolt11_routing_info_as_human_readable(r_tags_expl, has_explicit_r_tagtype=True))

        r_tags_impl = [
            [(bfh('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), bfh('0102030405060708'), 1, 20, 3),
                   (bfh('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), bfh('030405060708090a'), 2, 30, 4)],
            [(bfh('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9'), bfh('f4240000000002cd'), 0, 1, 40)],
        ]
        self.assertEqual(
            [
                [('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                  '66051x263430x1800', 1, 20, 3),
                 ('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                  '197637x395016x2314', 2, 30, 4)],
                [('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9',
                  '16000000x0x717', 0, 1, 40),],
            ],
            BOLT11Addr.format_bolt11_routing_info_as_human_readable(r_tags_impl, has_explicit_r_tagtype=False))

        for has_explicit_r_tagtype in (False, True):
            self.assertEqual(
                [],
                BOLT11Addr.format_bolt11_routing_info_as_human_readable([], has_explicit_r_tagtype=has_explicit_r_tagtype))
