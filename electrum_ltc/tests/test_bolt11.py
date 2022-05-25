from hashlib import sha256
from decimal import Decimal
from binascii import unhexlify, hexlify
import pprint
import unittest

from electrum_ltc.lnaddr import shorten_amount, unshorten_amount, LnAddr, lnencode, lndecode, u5_to_bitarray, bitarray_to_u5
from electrum_ltc.segwit_addr import bech32_encode, bech32_decode
from electrum_ltc import segwit_addr
from electrum_ltc.lnutil import UnknownEvenFeatureBits, derive_payment_secret_from_payment_preimage, LnFeatures
from electrum_ltc import constants

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
             "lnltc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqqtxf4xmgwm6d57t2u47xcknw8mcmxgnx24c4vq3uxft5f0sgx4kv478rt4j350n2hjlq0qqwgkwqv54ujrjtmw2gahwyrzfqq572r64qpsrpjy4"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60)]),
             "lnltc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuve3yl8e96v8ccdy5lgf4z8vdpmkzj228v2qxknwws2r00cwvqwhp2agvlqw4eklf8sjnvkeama0ke8nrlrc6nd4twspv5zhuy7hzqxgqd8tsep"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('1'), tags=[('h', longdescription)]),
             "lnltc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsz9dyzv7qgv60vrvj6hu8cyhj4epls6hwtgzgew82sqyhv0cjhnmjrr627cdjp4ejce0fps0q83505fjrh43enpwje3hty4kpu244trqp8snnu3"),
            (LnAddr(date=timestamp, paymenthash=RHASH, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription)]),
             "lntltc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9pqjahusc5f4737qr4ke4tf6mnswpt689y07jhw8usmus07q2pd43f7ya5t82d9aq8ay2e7kwuat0wzp7hhfla9ghg9ytt38r8pynrgqdt4rpe"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[
                ('r', [(unhexlify('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('0102030405060708'), 1, 20, 3),
                       (unhexlify('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('030405060708090a'), 2, 30, 4)]),
                ('f', 'LKes97HFbh3dxrvhiMohYXyzYJPTK37n7u'),
                ('h', longdescription)]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsgrh5ds6jq65tly9q0rm43r09gpt7u7z56rksadhzrz66jqauxgvqffqmkwytlxvdamkfhvsy9p52zfum9ae6g3twas5euq75yz2wnugpwm2dm6"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('f', 'MLy36ApB4YZb2cBtTc1uYJhYsP2JkYokaf'), ('h', longdescription)]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfdpk2gswds3zw9jud4drk8auayp2rrar2vj9ku2u90jy53s3s9cnnd8ulqe5z6989amdkf6q2sdun0zxuuej65rj0zgdum9kewl6xvgqls5kcn"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('f', 'ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9'), ('h', longdescription)]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7khp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsx62fjmp3a3alh6wz6jvdnnhgn22r39c6y05y6z994wyr24x9h3tkpmncc0w5e7xkskx5ce70zyeue5jvhst5ra4sfu6xffcaqumnvdsp3ushrl"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('f', 'ltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qmu8tk5'), ('h', longdescription)]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsppnxg8agzaze483el3cay2c3vkw44qn7js06234yn6xw2z006f3jxhqqwelf7r6vq35hpnws9t99lkkzrhnnpaq0yaqz298d4zxvcrqqawfwf9"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('n', PUBKEY), ('h', longdescription)]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfypgxsuxk3fau4ukql3d4xv8a5m7rj4rnhv74qwm04t5tzmvdf6hfkqywdg6xxam6xq9ugn789exnhvzrh8skt2c3wahr0u6raqjw3spcdsjmp"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 514)]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qzszpr8mych58cqnmntv99ydz0x82llruk6uq56vc03xhrantv3sq5hhhtuevn34ygfxqwrgnfw84psukufz2py5s8p8pczlzxpk9cx4twqpznf9x5"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 8))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qzg2tqw82hj5vjmyjzmr3235ff9a8xvxgvw70gj8nfa7ld2ukukmxet4d7nhgmxs4rl6fuvdlq0q35sq3ahqz6dl4akufdsnalvzrvzjh2qp8kxwnx"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qzs2qlljt3pj65yflxr6rn3u04kd3dd0hq7javh9dp3d5cdly6ktr08spxnxnrdpgg008ddn2e85k4740fwlth60ccz7r004hep97rrpptqq0ex938"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 7) + (1 << 11))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrzy2fv7yushe94fn00a0pz9wwmhcqhlnjjwnlf7wvev899jajmjq3qlqcvea0kcl6mr7v3fhf5yyhc6xg0f5l6zcwndeh5rcdw4pq28c5eqqg95ywn"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 12))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qryq2p49wj470xych6a9qhzlgmhuyf6hntj3tznj3netm5c3c7nzytdjj2cafly9wrkmccqfnenknydfhaxzualdp5490k70y6u5amzmfwdsqa7yuu2"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 13))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrgq2gxz07cm2v66xftk0wyey0cgddn9j6kxxr8tfx6p0nmzs7p3ypwxxa78m5ez4gf4lzjusnflfkhfa8s9hzelrgx5h3t6s8562g6xgwpqqsx7rh4"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 14))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrss2fr9507w72ylxmngwkxdeexm2utfjvl5z0lz28jap7c5p32k4kt9pl727gz0df93h9d2c83w6wl7wz28lv52psmgmyjc6qklkuvx7a6qqd8qs4s"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 15))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqs2qp2e0nuq5a7llrdc7ftqczzkfajkazjzmn20dg2qucmghnwuhutpa6tk6dfdjukanzngzvzhnzhmucujfpu7fv5ekvwx2jh2mkwne9gq02clpv"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=24, tags=[('h', longdescription), ('9', 33282)], payment_secret=b"\x11" * 32),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqszxkdza3c2a8mx7htenxyj28tl9uhs6zd8pz8nec3n2s7k0zzas4cn6jcgnk4j49zu552kwlg6nz4lcl847d8g26nf6lxn4c0y7jmkkjsqt2wsey"),
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

        lnaddr = lndecode("lntltc15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2sd9wnsselxlsqyz5ktk0dafjj77ag862qqeqmldxd6nzx7z2q2ttsu073xujdvjjzwcullaxh5mfz3qmd558cf7l8m0e4rkq227cnsvcp2lx59z",
                          net=constants.BitcoinTestnet)
        self.assertEqual(30, lnaddr.get_min_final_cltv_expiry())

    def test_min_final_cltv_expiry_roundtrip(self):
        for cltv in (1, 15, 16, 31, 32, 33, 150, 511, 512, 513, 1023, 1024, 1025):
            lnaddr = LnAddr(paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('c', cltv)])
            invoice = lnencode(lnaddr, PRIVKEY)
            self.assertEqual(cltv, lndecode(invoice).get_min_final_cltv_expiry())

    def test_features(self):
        lnaddr = lndecode("lnltc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzsz8p4tmzjmcmlrt42zq8g2lka20sx3f0hxjj0gjat25aw8kq56gtp9t5gcf5wkzun7dh2dphgwy3xd6xh685lytskh59vwnu3cfuv4adqp9l3fwu")
        self.assertEqual(514, lnaddr.get_tag('9'))
        self.assertEqual(LnFeatures(514), lnaddr.get_features())

        with self.assertRaises(UnknownEvenFeatureBits):
            lndecode("lnltc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9q4pqqqqqqqqqqqqqqqqqqsz9n64wqwnhljw6d2vll705dqzf3f9nmyzmzgp790atrk6fm4ln9jj256fll2zwwem7clflgaj0g0qs090frqdkc7vun76gs5dgck2udqqnvz4yx")

    def test_payment_secret(self):
        lnaddr = lndecode("lnltc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsq8da9nsp6wq9ugrglqwvgzqn6tj6wr0u0fzwg57trnjd070ef6f6ykh6kykgtdg9umljul8ah85sy80jgz7f3jr5y2uu756s4a8pq80qpxe4kez")
        self.assertEqual((1 << 9) + (1 << 15) + (1 << 99), lnaddr.get_tag('9'))
        self.assertEqual(b"\x11" * 32, lnaddr.payment_secret)

    def test_derive_payment_secret_from_payment_preimage(self):
        preimage = bytes.fromhex("cc3fc000bdeff545acee53ada12ff96060834be263f77d645abbebc3a8d53b92")
        self.assertEqual("bfd660b559b3f452c6bb05b8d2906f520c151c107b733863ed0cc53fc77021a8",
                         derive_payment_secret_from_payment_preimage(preimage).hex())
