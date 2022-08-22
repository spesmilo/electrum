from hashlib import sha256
from decimal import Decimal
from binascii import unhexlify, hexlify
import pprint
import unittest

from electrum.lnaddr import shorten_amount, unshorten_amount, LnAddr, lnencode, lndecode, u5_to_bitarray, bitarray_to_u5
from electrum.segwit_addr import bech32_encode, bech32_decode
from electrum import segwit_addr
from electrum.lnutil import UnknownEvenFeatureBits, derive_payment_secret_from_payment_preimage, LnFeatures
from electrum import constants

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
            (LnAddr(date=timestamp, paymenthash=RHASH, tags=[('d', '')]),
             "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqqd9n3kwjjwglnfne5p4rvkze998m3xcxrc8kunl5khkchlaqhwhlyztuuwkrglv47mqg96mcqjjx70hh9luaj4te0u4ww6aclxwve3fqpkmdxlj"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60)]),
             "lnbc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9rflz25dx0qw6kdg05u0c5hdc30yq6ga6ew4pz86n244va45nchns9zrs3wjxznsqnt37hz7pswvc56wvuhxcjyd6k3lqf4ujynyxuspmvr078"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('1'), tags=[('h', longdescription)]),
             "lnbc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs2qjafckq94q3js6lvqz2kmenn9ysjejyj8fm4hlx0xtqhaxfzlxjappkgp0hmm40dnuan4v3jy83lqjup2n0fdzgysg049y9l9uc98qq07kfd3"),
            (LnAddr(date=timestamp, paymenthash=RHASH, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription)]),
             "lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsr9zktgu78k8p9t8555ve37qwfvqn6ga37fnfwhgexmf20nzdpmuhwvuv7zra3xrh8y2ggxxuemqfsgka9x7uzsrcx8rfv85c8pmhq9gq4sampn"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[
                ('r', [(unhexlify('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('0102030405060708'), 1, 20, 3),
                       (unhexlify('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('030405060708090a'), 2, 30, 4)]),
                ('f', '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'),
                ('h', longdescription)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsq68hmxx9ar8eh9nq6gcafxd4vn4mqy458f744t0lms3anm2svydxx2lv84ardcks83u0h34u3lvflh0x9y8qdgjj3q3lxqp5kzqueygqema2z9"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('f', '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'), ('h', longdescription)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfa9a608cewefn0n6wflmd27s4nvevru262k2uj34wq58c4y5tqjrs77kvd5umnjgpndxfchde0h0mc07l65agyh9dqlgz5ujhpe8ewspsve8hh"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('f', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), ('h', longdescription)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7khp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqstrtguf9h6ur3n3dchft84q46yy50gf0vugq8g3n88txqcn25dhg98tt4wvlhy967cdarj6cznwn3uyssqeu0e3jgdt9mh5nz9xyqsggpnp2hht"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('f', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'), ('h', longdescription)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsvv679nlk4m93cahuxv04qqv6q8gshqu5f5tcgcasayuejxny4t4rpugqh4fy4zrma23ts93zclhsm694pu9ll0qlfaqkpstu7u02l8gq6fr4jy"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('n', PUBKEY), ('h', longdescription)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqst7hmgl7lmqxaael9g7w3e43acceyz93920457yv2egsfkcpnxqf9p0wu8x6dy34k580rulrtvt77f757g2k9lkf7ggph4pyux6e8wksq5ejkr3"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 514)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qzsz20x48k6dgxsrrsqhccvuwtsjny2flcyhlpyuz5lufn4wvjml7wwkaaxfyxpkk2j84hq4xdvm2pt265hm7jy97p5f34gu2tcwgvd9j4gqcam6kj"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 8))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qzg2f9ep5rqksjjdjzq20eqkwvsd0gx0llf2lv6x395l3ph82naeqkg3slj7s326sqnk4ql32acs2fft4p5tyjt8ujxtnhauu4mp7w4xgaqpp7a6ha"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qzs2035s0h84dfv9lykfcscuh5phy8mmq53nyu9szwln7d02xaz57t59p22pkzavenfa8qetvtkf27l9h9n3k55puvx6573d7fwhmwp6cvcqjvjqe7"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 7) + (1 << 11))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrzy2tq24ful9ktl7dsnpr8y53dg5w6g2cak8q4pchzjepedmrxhv7qm3z5hhca5c3yjd34cvcc0qd7ntwgefrxxn0cmcsn4cxlnkvrmx5gcp3mmpw5"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 12))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qryq226vdxsf8jq83t80fmunnlkj3va9nmw54x9ze0tqnyvvqch675y29pm978ppkhgp6hnwj98g4zalgecpqkckr9x90ugq44e5tnfe7kxqplr63uz"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 13))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrgq2f4fm9v4qzp3072d6vaslq99m0rhmfa7plx6wumu6rpdpz53l2zuhc56xekrzwqwsdaahsl8jg0vh3zhpvc78ywc9cas859mvs28xfpgpgn8usc"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 14))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrss2y8hzphx329clpfz86r60zd3ctn2q0uuakge6qws075r7sf43r8wpmrv36ujj68mzdw6rhkxy4mal5zullec8v6yjnnsh093qjwc5cuspz34uag"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqs2gc0fc84x29vk0pmq6p4qcn2ttn9azxtfrf2xqz00e79cfvf4nqvx96hz94uqsh4j4hnyywp63nagddwm0zdscprvkqlhltysa478x3sqkee5v9"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 33282)], payment_secret=b"\x11" * 32),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqszrwfgrl5k3rt4q4mclc8t00p2tcjsf9pmpcq6lu5zhmampyvk43fk30eqpdm8t5qmdpzan25aqxqaqdzmy0smrtduazjcxx975vz78ccpx0qhev"),
        ]

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
            lnencode(LnAddr(paymenthash=RHASH, amount=24, tags=[('d', '')]), PRIVKEY),
            ignore_long_length=True)
        databits = u5_to_bitarray(data)
        databits.invert(-1)
        lnaddr = lndecode(bech32_encode(segwit_addr.Encoding.BECH32, hrp, bitarray_to_u5(databits)), verbose=True)
        assert lnaddr.pubkey.serialize() != PUBKEY

        # But not if we supply expliciy `n` specifier!
        _, hrp, data = bech32_decode(
            lnencode(LnAddr(paymenthash=RHASH, amount=24, tags=[('d', ''), ('n', PUBKEY)]), PRIVKEY),
            ignore_long_length=True)
        databits = u5_to_bitarray(data)
        databits.invert(-1)
        lnaddr = lndecode(bech32_encode(segwit_addr.Encoding.BECH32, hrp, bitarray_to_u5(databits)), verbose=True)
        assert lnaddr.pubkey.serialize() == PUBKEY

    def test_min_final_cltv_expiry_decoding(self):
        lnaddr = lndecode("lnsb500u1pdsgyf3pp5nmrqejdsdgs4n9ukgxcp2kcq265yhrxd4k5dyue58rxtp5y83s3qdqqcqzystrggccm9yvkr5yqx83jxll0qjpmgfg9ywmcd8g33msfgmqgyfyvqhku80qmqm8q6v35zvck2y5ccxsz5avtrauz8hgjj3uahppyq20qp6dvwxe",
                          net=constants.BitcoinSimnet)
        self.assertEqual(144, lnaddr.get_min_final_cltv_expiry())

        lnaddr = lndecode("lntb15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2s8tut3jqumepu42azyyjpgqa4w9w03204zp9h4clk499y2umstl6s29hqyj8vv4as6zt5567ux7l3f66m8pjhk65zjaq2esezk7ll2kcpljewkg",
                          net=constants.BitcoinTestnet)
        self.assertEqual(30, lnaddr.get_min_final_cltv_expiry())

    def test_min_final_cltv_expiry_roundtrip(self):
        for cltv in (1, 15, 16, 31, 32, 33, 150, 511, 512, 513, 1023, 1024, 1025):
            lnaddr = LnAddr(paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('c', cltv)])
            invoice = lnencode(lnaddr, PRIVKEY)
            self.assertEqual(cltv, lndecode(invoice).get_min_final_cltv_expiry())

    def test_features(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzsze992adudgku8p05pstl6zh7av6rx2f297pv89gu5q93a0hf3g7lynl3xq56t23dpvah6u7y9qey9lccrdml3gaqwc6nxsl5ktzm464sq73t7cl")
        self.assertEqual(514, lnaddr.get_tag('9'))
        self.assertEqual(LnFeatures(514), lnaddr.get_features())

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
