from hashlib import sha256
from decimal import Decimal
from binascii import unhexlify, hexlify
import pprint
import unittest

from electrum.lnaddr import shorten_amount, unshorten_amount, LnAddr, lnencode, lndecode
from electrum.segwit_addr import bech32_encode, bech32_decode
from electrum import segwit_addr
from electrum.lnutil import UnknownEvenFeatureBits, derive_payment_secret_from_payment_preimage, LnFeatures, IncompatibleLightningFeatures
from electrum import constants

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
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, tags=[('d', ''), ('9', 33282)]),
             "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('9', 0x28200)]),
             "lnbc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5xysxxatsyp3k7enxv4jsxqzpu9qy9qsqw8l2pulslacwjt86vle3sgfdmcct5v34gtcpfnujsf6ufqa7v7jzdpddnwgte82wkscdlwfwucrgn8z36rv9hzk5mukltteh0yqephqpk5vegu"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=Decimal('1'), tags=[('h', longdescription), ('9', 0x28200)]),
             "lnbc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsq0jnua6dc4p984aeafs6ss7tjjj7553ympvg82qrjq0zgdqgtdvt5wlwkvw4ds5sn96nazp6ct9ts37tcw708kzkk4p8znahpsgp9tnspnycsf7"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription), ('9', 0x28200)]),
             "lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqy5826t0z3sn29z396pmr4kv73lcx0v7y6vas6h3pysmqllmzwgm5ps2t468gm4psj52usjy6y4xcry4k84n2zggs6f9agwg95454v6gqrwmh4f"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[
                ('r', [(unhexlify('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('0102030405060708'), 1, 20, 3),
                       (unhexlify('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('030405060708090a'), 2, 30, 4)]),
                ('f', '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'),
                ('h', longdescription),
                ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqfnk063vsrgjx7l6td6v42skuxql7epn5tmrl4qte2e78nqnsjlgjg3sgkxreqex5fw4c9chnvtc2hykqnyxr84zwfr8f3d9q3h0nfdgqenlzvj"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('f', '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfppj3a24vwu6r8ejrss3axul8rxldph2q7z9hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqqf6z4r7ruzr5txm5ln4netwa2f4x233tud7jy8gxrynyx07rxt7qm92yk2krlgwr7d8jknglur75sujeyapmda5nf3femrk2mep8a2cp4hlvup"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('f', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfppqw508d6qejxtdg4y5r3zarvary0c5xw7khp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqy4wp73jma5uktd9y7yha56f98n2k0hxgnvp2qdcury00dapps3k3urgfy8tvv8jzwcafpy576msk5xx2hladf06m3s5mgx5msn4elfqqaaqjhk"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('f', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqgt4gg9uktlpgnnuvczazusp5uwjv78na305ucsw06c8uk58e5stjqj9sz7fgavw0z688alt364js72mc9mg8yumhpes2dsmq5k9nr5qqddykxy"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('n', PUBKEY), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsq2y235rxw7v0gkn2t9ehc742tm3p22q2yjjykq4d85ze6g62yk60navxqz0ga96sqrszju8nlfajthem4gngxvyz4hwy39j4nqm8kv0qq9znxs7"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 2 + (1 << 9) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqszrwfgrl5k3rt4q4mclc8t00p2tcjsf9pmpcq6lu5zhmampyvk43fk30eqpdm8t5qmdpzan25aqxqaqdzmy0smrtduazjcxx975vz78ccpx0qhev"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 8) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqg2wans8f6vkfd3l7zjv547hlc7wd7eqyxfwhtdudnkkgrpk6p9ffykwrvdtwm0aakaxujurdxgd7cllnfypmj22cvy7z333udg6zncgacqzmd2z9"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqs2dr525u5f4kjxdv0hq5c822qwxrtttjl4u586yl84x0kvvx66gz9ygy76005s5sjwgr7fp55ccsae47vpl4gqvwhc3exps964g743j5gqwtt68t"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 14))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrss2f8kr98446xls02yndup2ynwjh46u8kdeuuncexx2hnets0j0064nyq25gkd6jnttldzt5qqtszum5dufvuvryxt204w2p24557udxgcp0nlwtw"),
        ]
        # Some old tests follow that do not have payment_secret. Note that if the parser raised due to the lack of features/payment_secret,
        # old wallets that have these invoices saved (as paid/expired), could not be opened (though we could do a db upgrade and delete them).
        tests.extend([
            (LnAddr(date=timestamp, paymenthash=RHASH, tags=[('d', '')]),
             "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqqd9n3kwjjwglnfne5p4rvkze998m3xcxrc8kunl5khkchlaqhwhlyztuuwkrglv47mqg96mcqjjx70hh9luaj4te0u4ww6aclxwve3fqpkmdxlj"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60)]),
             "lnbc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9rflz25dx0qw6kdg05u0c5hdc30yq6ga6ew4pz86n244va45nchns9zrs3wjxznsqnt37hz7pswvc56wvuhxcjyd6k3lqf4ujynyxuspmvr078"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('1'), tags=[('h', longdescription)]),
             "lnbc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs2qjafckq94q3js6lvqz2kmenn9ysjejyj8fm4hlx0xtqhaxfzlxjappkgp0hmm40dnuan4v3jy83lqjup2n0fdzgysg049y9l9uc98qq07kfd3"),
            (LnAddr(date=timestamp, paymenthash=RHASH, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription)]),
             "lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsr9zktgu78k8p9t8555ve37qwfvqn6ga37fnfwhgexmf20nzdpmuhwvuv7zra3xrh8y2ggxxuemqfsgka9x7uzsrcx8rfv85c8pmhq9gq4sampn"),

        ])

        # Roundtrip
        for lnaddr1, invoice_str1 in tests:
            invoice_str2 = lnencode(lnaddr1, PRIVKEY)
            self.assertEqual(invoice_str1, invoice_str2)
            lnaddr2 = lndecode(invoice_str2, net=lnaddr1.net)
            self.compare(lnaddr1, lnaddr2)

    def test_n_decoding(self):
        # We flip the signature recovery bit, which would normally give a different
        # pubkey.
        _, hrp, data = bech32_decode(
            lnencode(LnAddr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('d', ''), ('9', 33282)]), PRIVKEY),
            ignore_long_length=True)
        data[-1] ^= 1
        lnaddr = lndecode(bech32_encode(segwit_addr.Encoding.BECH32, hrp, data), verbose=True)
        self.assertNotEqual(lnaddr.pubkey.serialize(), PUBKEY)

        # But not if we supply expliciy `n` specifier!
        _, hrp, data = bech32_decode(
            lnencode(LnAddr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('d', ''), ('n', PUBKEY), ('9', 33282)]), PRIVKEY),
            ignore_long_length=True)
        data[-1] ^= 1
        lnaddr = lndecode(bech32_encode(segwit_addr.Encoding.BECH32, hrp, data), verbose=True)
        self.assertEqual(lnaddr.pubkey.serialize(), PUBKEY)

    def test_min_final_cltv_expiry_decoding(self):
        lnaddr = lndecode("lnsb500u1pdsgyf3pp5nmrqejdsdgs4n9ukgxcp2kcq265yhrxd4k5dyue58rxtp5y83s3qsp5qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsdqqcqzys9qypqsqp2h6a5xeytuc3fad2ed4gxvhd593lwjdna3dxsyeem0qkzjx6guk44jend0xq4zzvp6f3fy07wnmxezazzsxgmvqee8shxjuqu2eu0qpnvc95x",
                          net=constants.BitcoinSimnet)
        self.assertEqual(144, lnaddr.get_min_final_cltv_delta())

        lnaddr = lndecode("lntb15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2s8tut3jqumepu42azyyjpgqa4w9w03204zp9h4clk499y2umstl6s29hqyj8vv4as6zt5567ux7l3f66m8pjhk65zjaq2esezk7ll2kcpljewkg",
                          net=constants.BitcoinTestnet)
        self.assertEqual(30, lnaddr.get_min_final_cltv_delta())

    def test_min_final_cltv_expiry_roundtrip(self):
        for cltv in (1, 15, 16, 31, 32, 33, 150, 511, 512, 513, 1023, 1024, 1025):
            lnaddr = LnAddr(
                paymenthash=RHASH, payment_secret=b"\x01"*32, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('c', cltv), ('9', 33282)])
            self.assertEqual(cltv, lnaddr.get_min_final_cltv_delta())
            invoice = lnencode(lnaddr, PRIVKEY)
            self.assertEqual(cltv, lndecode(invoice).get_min_final_cltv_delta())

    def test_features(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9qypqsztrz5v3jfnxskfv7g8chmyzyrfhf2vupcavuq5rce96kyt6g0zh337h206awccwp335zarqrud4wccgdn39vur44d8um4hmgv06aj0sgpdrv73z")
        self.assertEqual(33282, lnaddr.get_tag('9'))
        self.assertEqual(LnFeatures(33282), lnaddr.get_features())

    def test_payment_secret(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsqvvh7ut50r00p3pg34ea68k7zfw64f8yx9jcdk35lh5ft8qdr8g4r0xzsdcrmcy9hex8un8d8yraewvhqc9l0sh8l0e0yvmtxde2z0hgpzsje5l")
        self.assertEqual((1 << 9) + (1 << 15) + (1 << 99), lnaddr.get_tag('9'))
        self.assertEqual(b"\x11" * 32, lnaddr.payment_secret)

    def test_derive_payment_secret_from_payment_preimage(self):
        preimage = bytes.fromhex("cc3fc000bdeff545acee53ada12ff96060834be263f77d645abbebc3a8d53b92")
        self.assertEqual("bfd660b559b3f452c6bb05b8d2906f520c151c107b733863ed0cc53fc77021a8",
                         derive_payment_secret_from_payment_preimage(preimage).hex())

    def test_validate_and_compare_features(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsqvvh7ut50r00p3pg34ea68k7zfw64f8yx9jcdk35lh5ft8qdr8g4r0xzsdcrmcy9hex8un8d8yraewvhqc9l0sh8l0e0yvmtxde2z0hgpzsje5l")
        lnaddr.validate_and_compare_features(LnFeatures((1 << 8) + (1 << 14) + (1 << 15)))
        with self.assertRaises(IncompatibleLightningFeatures):
            lnaddr.validate_and_compare_features(LnFeatures((1 << 8) + (1 << 14) + (1 << 16)))
