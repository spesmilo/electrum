import io
import json
import time
from dataclasses import fields
from pathlib import Path

from electrum_ecc import ECPrivkey

from electrum import segwit_addr, lnutil
from electrum.bolt12 import (
    is_offer, bolt12_bech32_to_bytes, BOLT12Offer, BOLT12InvoiceRequest, BOLT12Invoice, NoMatchingChainError
)
from electrum.crypto import privkey_to_pubkey
from electrum.lnmsg import UnknownMandatoryTLVRecordType, MsgInvalidSignature, OnionWireSerializer, \
    MsgInvalidFieldOrder, MalformedMsg
from electrum.lnonion import OnionHopsDataSingle
from electrum.lnutil import LnFeatures, UnknownEvenFeatureBits
from electrum.segwit_addr import INVALID_BECH32, bech32_encode, Encoding, convertbits
from electrum.util import bfh

from . import ElectrumTestCase


def bech32_decode(x):
    return segwit_addr.bech32_decode(x, ignore_long_length=True, with_checksum=False)


class TestBolt12(ElectrumTestCase):

    def test_bolt12_bech32_to_bytes(self):
        valid_bolt12_strings = (
            ("lno1pqpzacq2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3up5nwlwchur9zukwx743mvm0rvftrhskna22pcvtkyhufn5rc97j3gzqffs859lkadpfasgwxj47xvml7jgekez0lpfuwzhegyxsn2lzdx86qpny7xrmgwj6lphxcfauu22kenqnty4tqdlgnh8tyg87lamqe84nmh2vn0a2n908l7z7cfjghjsuusv7k079upfw0x7dpzavqpwj8swx9ee9q9cumg07fk4gvlajyhy6lfjv0cfe9gqxg0gykehtgjkxwzz24rqdssj4fjcm8xhv2rwel04ed4up2h5sf8n6y7scr0q5rt65k06s6u3mvefzer7qq",
             "08022ee00a0010ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f0349bbeec5f8328b9671bd58ed9b78d8958ef0b4faa5070c5d897e26741e0be94502025303d0bfb75a14f60871a55f199bffa48cdb227fc29e3857ca08684d5f134c7d0033278c3da1d2d7c373613de714ab66609ac95581bf44ee759107f7fbb064f59eeea64dfd54caf3ffc2f613245e50e720cf59fe2f02973cde6845d6002e91e0e31739280b8e6d0ff26d5433fd912e4d7d3263f09c9500321e825b375a25633842554606c212aa658d9cd76286ecfdf5cb6bc0aaf4824f3d13d0c0de0a0d7aa59fa86b91db3291647e00"),
            ("lno1pqpzacq2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3uprukkghkdufdz6adxl0ejhy0lmzfykj08u6df9v4v2c93qknz8eggzq2jyyszrrt35mmkyl7efrv5x8a3wspk07pghey4a5kcm4ef76p0ksqpnh7fqgmq9eaf7ntqspcksqkqk8ngvjtjp585mqw3qata3xe8aycgkpprk87yqcxhh705dxauxkghsc9xywqpez7lt5gw67kqwejl83unmuc7r44h32durffs4rmpcgrhxa8x8y9gqxgy9w2tqgpxqk0tl487a9ssuchyh5p9t3le3n5ylhevggk6ly8wzxvds0jawct4spe2tzqfp5d34kah9ss",
             "08022ee00a0010ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f023e5ac8bd9bc4b45aeb4df7e65723ffb1249693cfcd35256558ac1620b4c47ca10202a44240431ae34deec4ffb291b2863f62e806cff0517c92bda5b1bae53ed05f680033bf92046c05cf53e9ac100e2d0058163cd0c92e41a1e9b03a20eafb1364fd26116084763f880c1af7f3e8d37786b22f0c14c47003917beba21daf580eccbe78f27be63c3ad6f1537834a6151ec3840ee6e9cc7215003208572960404c0b3d7fa9fdd2c21cc5c97a04ab8ff319d09fbe58845b5f21dc2331b07cbaec2eb00e54b10121a3635b76e584"),
            ("lno1qsgve2uaxjsvf885prfgawzf6d09vzsqpczxnzdgesgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upc0taarq42pfspgzxdytktyf8jmx8symyy4p3w6wr26m3c3l3munszqwpuu8l2fxnf0awqf3fq069lw2ple9zlxuqx0whmxnl6sjavs98h6qpngsrfw245mh995tw4qlkh87ulgg00fm8p90s70sslvm23yv77qk6e70dq6a9c5fa9qg74w8gpfd2tqs3eavpaedey0agxmzacdrcd9vwrmgjemeym4ge0p5unp66tkz47wh7x4asqxtv35cx0sc23qkgt27az82w7n6tngn4r9wzuam3ztpps7q3sd60d42dltr37gagfy2asevymltrchy43zgtzzq68dcmv6rprk4yzfv4wl65vw6q2uz8tzc0d40v4ltdcuwnw9t3eyq",
             "0410ccab9d34a0c49cf408d28eb849d35e560a000e046989a8cc10ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f0387afbd182aa0a601408cd22ecb224f2d98f026c84a862ed386ad6e388fe3be4e020383ce1fea49a697f5c04c5207e8bf7283fc945f370067bafb34ffa84bac814f7d00334406972ab4ddca5a2dd507ed73fb9f421ef4ece12be1e7c21f66d51233de05b59f3da0d74b8a27a5023d571d014b54b04239eb03dcb7247f506d8bb868f0d2b1c3da259de49baa32f0d3930eb4bb0abe75fc6af60032d91a60cf861510590b57ba23a9de9e97344ea32b85ceee2258430f02306e9edaa9bf58e3e4750922bb0cb09bfac78b92b112162103476e36cd0c23b54824b2aefea8c7680ae08eb161edabd95fadb8e3a6e2ae3920"),
            ("lno1pqpq05q2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upgkdz0l3yd0yt3u9kmp5cg6kfw65kh0n0q9m022xe8y0mq69wmm9gzq0ckt2qqs73uyx2pe3tcmrhf7hszkh3393gwc420x2uew4846tgk5qpn0clyjyaa0cfxc9ryff0qfx48wv8u65w4a7fxfsqeln9ahjz9qcf0t0umrgxnzcly4es6ct97ddjcvgcehvpc09sqwsjc0cusxrwvx44j62pskt9t75ex5px84294a48c0h5jx8gqx20wkjusrgktsa53c23ksrhpuncrmdvetfjhdpgmnu9tej3m9nlm9m9tzhnl39mje2gxdsu2zlejvp63xy",
             "080207d00a0010ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f028b344ffc48d79171e16db0d308d592ed52d77cde02edea51b2723f60d15dbd950203f165a80087a3c21941cc578d8ee9f5e02b5e312c50ec554f32b99754f5d2d16a00337e3e4913bd7e126c14644a5e049aa7730fcd51d5ef9264c019fccbdbc8450612f5bf9b1a0d3163e4ae61ac2cbe6b65862319bb03879600742587e39030dcc356b2d2830b2cabf5326a04c7aa8b5ed4f87de9231d00329eeb4b901a2cb87691c2a3680ee1e4f03db5995a6576851b9f0abcca3b2cffb2ecab15e7f89772ca9066c38a17f326075131")
        )
        for bolt12_str, expected_bytes_hex in valid_bolt12_strings:
            result = bolt12_bech32_to_bytes(bolt12_str)
            self.assertEqual(result.hex(), expected_bytes_hex)

    def test_bolt12_string_formatting(self):
        """
        Test if we handle string formatting according to bolt 12 using the format-string-test.json
        test vector.
        https://github.com/lightning/bolts/blob/5f31faa0b6e2cdbe32171d79464305f90bda9585/bolt12/format-string-test.json
        """
        with open(Path(__file__).parent / 'bolt12_format_string_test.json', 'r') as f:
            tests = json.load(f)
        for test in tests:
            valid, string, msg = test['valid'], test['string'], f"{test['comment']}: {test['string']}"
            if valid:
                self.assertTrue(is_offer(string), msg=msg)
                result = BOLT12Offer.decode(string)
                self.assertIsInstance(result, BOLT12Offer)
            else:
                self.assertFalse(is_offer(string), msg=msg)
                with self.assertRaises(ValueError, msg=msg):
                    BOLT12Offer.decode(string)

    def test_decode(self):
        # https://bootstrap.bolt12.org/examples
        offer = 'lno1pg257enxv4ezqcneype82um50ynhxgrwdajx293pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmc'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))
        od = BOLT12Offer.decode(offer)
        self.assertEqual(od.offer_description, "Offer by rusty's node")
        self.assertEqual(od.offer_issuer_id, bfh('023f3219da03ee29a12de4107e6c5c364f607382f065f2bfed91ddd6b91079bfbc'))

        offer = 'lno1pqqnyzsmx5cx6umpwssx6atvw35j6ut4v9h8g6t50ysx7enxv4epyrmjw4ehgcm0wfczucm0d5hxzag5qqtzzq3lxgva5qlw9xsjmeqs0ek9cdj0vpec9ur972l7mywa66u3q7dlhs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        od = BOLT12Offer.decode(offer)
        self.assertEqual(od.offer_amount, 50)
        self.assertEqual(od.offer_description, '50msat multi-quantity offer')
        self.assertEqual(od.offer_issuer, 'rustcorp.com.au')
        self.assertEqual(od.offer_quantity_max, 0)
        self.assertEqual(od.offer_issuer_id, bfh('023f3219da03ee29a12de4107e6c5c364f607382f065f2bfed91ddd6b91079bfbc'))

        # TODO: tests below use recurrence (tlv record type 26) which is not supported/generated from wire specs
        # (c-lightning carries patches re-adding these, but for now we ignore them)

        offer = 'lno1pqqkgzs5xycrqmtnv96zqetkv4e8jgrdd9h82ar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqq7q'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            BOLT12Offer.decode(offer)

        offer = 'lno1pqqkgz38xycrqmtnv96zqetkv4e8jgrdd9h82ar99ss82upqw3hjqargwfjk2gr5d9kk2ucjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qsq8s0qzqs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            BOLT12Offer.decode(offer)

        offer = 'lno1pqqkgz3zxycrqmtnv96zqetkv4e8jgryv9ujcgrxwfhk6gp3949xzm3dxgcryvgjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qspqysq2q2laenqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            BOLT12Offer.decode(offer)

        offer = 'lno1pqpq86q2fgcnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qcteyqcksu3qvfjkvmmjv5s8gmeqxcczqum9vdhkuernypkxzar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pcpsqqq8pqqpuyqzszhlwvcqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            BOLT12Offer.decode(offer)

        offer = 'lno1pqpq86q2xycnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qun094exzarpzgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pczqqp5hsqqgd9uqzqpgptlhxvqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            BOLT12Offer.decode(offer)

        offer = 'lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yfpqun4wd68jtn00fkxzcnn9ehhyeckyypr7vsemgp7u2dp9hjpqlnvtsmy7crnstcxtu4lakgam44ezpuml0q6qgqsz'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            BOLT12Offer.decode(offer)

    def test_decode_offer(self):
        # default test
        offer = 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))

        od = BOLT12Offer.decode(offer)
        self.assertEqual(od.offer_description, 'first test offer')
        self.assertEqual(od.offer_issuer_id, bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'))

        # now test the bolt12 test vectors
        # https://github.com/lightning/bolts/blob/34455ffe28b308dd7ac7552234d565890af8605b/bolt12/offers-test.json
        with open(Path(__file__).parent / 'bolt12_offers_test.json', 'r') as f:
            tests = json.load(f)
        for test in tests:
            valid, string, msg = test['valid'], test['bolt12'], f"{test['description']}: {test['bolt12']}"
            try:
                if valid:
                    self.assertTrue(is_offer(string), msg=msg)
                    try:
                        BOLT12Offer.decode(string)
                    except NoMatchingChainError:
                        continue  # this unittest runs on mainnet, there are some testnet vectors
                else:
                    expected_exc = (ValueError, MsgInvalidFieldOrder, UnknownMandatoryTLVRecordType, NoMatchingChainError, MalformedMsg, UnknownEvenFeatureBits)
                    with self.assertRaises(expected_exc, msg=msg):
                        BOLT12Offer.decode(string)
            except Exception as e:
                raise Exception(msg) from e

    def test_decode_invreq(self):
        invreq_bech32 = "lnr1qqyqqqqqqqqqqqqqqcp4256ypqqkgzshgysy6ct5dpjk6ct5d93kzmpq23ex2ct5d9ek293pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpjkppqvjx204vgdzgsqpvcp4mldl3plscny0rt707gvpdh6ndydfacz43euzqhrurageg3n7kafgsek6gz3e9w52parv8gs2hlxzk95tzeswywffxlkeyhml0hh46kndmwf4m6xma3tkq2lu04qz3slje2rfthc89vss"
        with self.assertRaises(NotImplementedError):
            # TODO: no currency conversion support
            BOLT12InvoiceRequest.decode(invreq_bech32)

        # minimal invreq from eclair repo
        privkey = ECPrivkey(bfh("527d410ec920b626ece685e8af9abc976a48dbf2fe698c1b35d90a1c5fa2fbca"))
        invreq_bech32 = "lnr1qqp6hn00zcssxr0juddeytv7nwawhk9nq9us0arnk8j8wnsq8r2e86vzgtfneupe2gp9yzzcyypymkt4c0n6rhcdw9a7ay2ptuje2gvehscwcchlvgntump3x7e7tc0sgp9k43qeu892gfnz2hrr7akh2x8erh7zm2tv52884vyl462dm5tfcahgtuzt7j0npy7getf4trv5d4g78a9fkwu3kke6hcxdr6t2n7vz"
        invreq = BOLT12InvoiceRequest.decode(invreq_bech32)

        self.assertEqual(invreq.invreq_amount, 21_000)
        self.assertEqual(invreq.invreq_metadata, bfh("abcdef"))
        self.assertEqual(invreq.invreq_payer_id, privkey.get_public_key_bytes())

        data = {
            'offer_issuer_id': {'id': invreq.offer_issuer_id},
            'invreq_amount': {'msat': invreq.invreq_amount},
            'invreq_metadata': {'blob': invreq.invreq_metadata},
            'invreq_payer_id': {'key': privkey.get_public_key_bytes()},
        }
        self.assertEqual(invreq.serialize(with_signature=False), data)

    def test_invreq_offer_quantity_max(self):
        """Tests the offer_quantity_max/invreq_quantity checks"""
        def make_invreq(*, offer_quantity_max=None, invreq_quantity=None):
            return BOLT12InvoiceRequest(
                offer_issuer_id=bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'),
                invreq_amount=5555,
                invreq_payer_id=privkey_to_pubkey(bfh('42' * 32)),
                invreq_metadata=bfh('deadbeef'),
                offer_quantity_max=offer_quantity_max,
                invreq_quantity=invreq_quantity,
            )

        # 0 offer_quantity_max allows arbitrary invreq_quantity
        self.assertEqual(7, make_invreq(offer_quantity_max=0, invreq_quantity=7).invreq_quantity)

        # non-zero max: quantity in [1, max] is accepted, zero or above max is rejected
        self.assertEqual(3, make_invreq(offer_quantity_max=5, invreq_quantity=3).invreq_quantity)
        with self.assertRaises(ValueError):
            make_invreq(offer_quantity_max=5, invreq_quantity=6)
        with self.assertRaises(ValueError):
            make_invreq(offer_quantity_max=5, invreq_quantity=0)

        # max present requires an invreq_quantity; max absent forbids one
        with self.assertRaises(ValueError):
            make_invreq(offer_quantity_max=0, invreq_quantity=None)
        with self.assertRaises(ValueError):
            make_invreq(offer_quantity_max=None, invreq_quantity=2)

    def test_encode_offer(self):
        data = {
            'offer_description': {'description': 'first test offer'},
            'offer_issuer_id': {'id': bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a')}
        }
        offer_tlv = BOLT12Offer.deserialize(data).encode(as_bech32=False)
        self.assertEqual(offer_tlv, bfh('0a1066697273742074657374206f66666572162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'))
        offer_tlv_5bit = convertbits(list(offer_tlv), 8, 5)
        bech32_offer = bech32_encode(Encoding.BECH32, 'lno', offer_tlv_5bit, with_checksum=False)
        self.assertEqual(bech32_offer, 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495')
        self.assertEqual(BOLT12Offer.decode(bech32_offer).serialize(with_signature=False), data)

    def test_encode_invreq(self):
        payer_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        kp = lnutil.Keypair(privkey_to_pubkey(payer_key), payer_key)

        data = {
            'offer_description': {'description': 'first test offer'},
            'offer_issuer_id': {'id': bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a')},
            'invreq_amount': {'msat': 5555},
            'invreq_payer_note': {'note': 'invreq for first test offer'},
            'invreq_payer_id': {'key': kp.pubkey},
            'invreq_metadata': {'blob': bfh('deadbeef')}
        }
        invreq_tlv = BOLT12InvoiceRequest.deserialize(data).encode(signing_key=payer_key, as_bech32=False)
        self.assertEqual(invreq_tlv, bfh('0004deadbeef0a1066697273742074657374206f66666572162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a520215b358210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c591b696e7672657120666f722066697273742074657374206f66666572f0406b3de34892023353e1d0f5765e7c34b5e952e6d6a9492b91a2f98c0817434362bd07a6c216dce7709bd16a2b533dec22cf8a9303310a29b7621e090d27f9dfb1'))
        self.assertEqual(BOLT12InvoiceRequest.decode(invreq_tlv).serialize(with_signature=False), data)

    def test_encode_invoice(self):
        signing_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        kp = lnutil.Keypair(privkey_to_pubkey(signing_key), signing_key)

        data = {
            'offer_metadata': {'data': bfh('01020304050607')},
            'offer_amount': {'amount': 1},
            'offer_description': {'description': 'test_encode_invoice'},
            'offer_issuer_id': {'id': kp.pubkey},
            'invreq_payer_id': {'key': kp.pubkey},
            'invreq_metadata': {'blob': bfh('deadbeef')},
            'invoice_node_id': {'node_id': kp.pubkey},
            'invoice_amount': {'msat': 21_000},
            'invoice_created_at': {'timestamp': 1770883131},
            'invoice_payment_hash': {'payment_hash': bfh('cab10c2a10467d7dc4512a910530ef35d1028662b65c8a30656136ff957c6589')},
            'invoice_relative_expiry': {'seconds_from_creation': 7200},
            'invoice_paths': {'paths': [
                {
                    'first_node_id': kp.pubkey,
                    'first_path_key': kp.pubkey,
                    'num_hops': bytes([1]),
                    'path': [{
                        'blinded_node_id': kp.pubkey,
                        'enclen': 5,
                        'encrypted_recipient_data': b'12345',
                    }],
                }
            ]},
            'invoice_blindedpay': {'payinfo': [
                {
                    'fee_base_msat': 100,
                    'fee_proportional_millionths': 1000,
                    'cltv_expiry_delta': 200,
                    'htlc_minimum_msat': 1,
                    'htlc_maximum_msat': 1_000_000,
                    'flen': len(LnFeatures(0).to_tlv_bytes()),
                    'features': LnFeatures(0).to_tlv_bytes(),
                }
            ]}
        }
        invoice = BOLT12Invoice.deserialize(data)
        invoice_tlv = invoice.encode(signing_key=kp.privkey, as_bech32=False)
        self.assertEqual(invoice_tlv, bfh('0004deadbeef0407010203040506070801010a13746573745f656e636f64655f696e766f696365162102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619582102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619a06b02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661902eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866190102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661900053132333435a21c00000064000003e800c8000000000000000100000000000f42400000a404698d883ba6021c20a820cab10c2a10467d7dc4512a910530ef35d1028662b65c8a30656136ff957c6589aa025208b02102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f040d4541fa9209eea9e31ce9acaff42314e0de12adc85b2b64fef6ae954295cbe023d85023a9b53ca18e17de17df3b8431723554d182e271545edb6b8519c8eb35b'))
        # also test decoding back
        invoice = BOLT12Invoice.decode(invoice_tlv)
        self.assertEqual(invoice.serialize(with_signature=False), data)
        self.assertEqual(invoice.invoice_blindedpay[0].fee_base_msat, data['invoice_blindedpay']['payinfo'][0]['fee_base_msat'])

    def test_subtype_encode_decode(self):
        invreq_bech32 = "lnr1qqp6hn00zcssxr0juddeytv7nwawhk9nq9us0arnk8j8wnsq8r2e86vzgtfneupe2gp9yzzcyypymkt4c0n6rhcdw9a7ay2ptuje2gvehscwcchlvgntump3x7e7tc0sgp9k43qeu892gfnz2hrr7akh2x8erh7zm2tv52884vyl462dm5tfcahgtuzt7j0npy7getf4trv5d4g78a9fkwu3kke6hcxdr6t2n7vz"
        invreq = BOLT12InvoiceRequest.decode(invreq_bech32)
        invreq_pl_tlv = invreq.encode(signing_key=bfh('4141414141414141414141414141414141414141414141414141414141414141'), as_bech32=False)

        ohds = OnionHopsDataSingle(
            tlv_stream_name='onionmsg_tlv',
            payload={
                'invoice_request': {'invoice_request': invreq_pl_tlv},
                'reply_path': {
                    'path': {
                        'first_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                        'first_path_key': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                        'num_hops': 2,
                        'path': [
                            {
                                'blinded_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                'enclen': 5,
                                'encrypted_recipient_data': bfh('0000000000'),
                            },
                            {
                                'blinded_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                'enclen': 6,
                                'encrypted_recipient_data': bfh('001111222233'),
                            }
                        ]
                    }
                },
            },
            blind_fields={
                'padding': {'padding': b''},
            }
        )

        ohds_b = ohds.to_bytes()
        self.assertEqual(ohds_b, bfh('fd012902940309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e50309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5020309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5000500000000000309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5000600111122223340910003abcdef1621030df2e35b922d9e9bbaebd8b3017907f473b1e4774e0038d593e98242d33cf039520252085821024dd975c3e7a1df0d717bee91415f25952199bc30ec62ff6226be6c3137b3e5e1f040dc8f84d6ba1a027766c3412e5c9f44d8a265818e584e5220b509d387dd127d27975dbb93c2f3a072af735b5ed4000ae32dda9075f34894bb58eaf25cb1aeab630000000000000000000000000000000000000000000000000000000000000000'))

        with io.BytesIO(ohds_b) as fd:
            ohds2 = OnionHopsDataSingle.from_fd(fd, tlv_stream_name='onionmsg_tlv')
            self.assertEqual(ohds2.payload['invoice_request']['invoice_request'], invreq_pl_tlv)
            self.assertTrue('reply_path' in ohds2.payload)

        # test nested complex types with count > 1
        offer_data = {
            "offer_absolute_expiry": {"seconds_from_epoch": 1763136094},
            "offer_amount": {"amount": 1000},
            "offer_description": {"description": "ABCD"},
            "offer_issuer_id": {"id": bfh("0325c5bc9c9b4fe688e82784f17bc14e81e3f786e9a8c663e9bbec2412af0c0339")},
            "offer_paths": {"paths": [
                {
                    "first_node_id": bfh("02d4ad66692f3e39773a5917d55db2c8b81839425c4489532fd5d166466fce56d4"),
                    "first_path_key": bfh("02b4d2e30315f7a6322fb57ed420ef8f9c541d7331a8b3a086c2692c49209be811"),
                    "num_hops": bytes([2]),  # num_hops is defined as byte, not int
                    "path": [
                        {
                            "blinded_node_id": bfh("034b1da9c0afa084c604f74f839de006d550422facc3b4be83323702892f7f5949"),
                            "enclen": 51,
                            "encrypted_recipient_data": bfh("42f0018dcfe5185602618b718f7aa72b1b97d8e85b97f88b8fdad95b80fd93a21d9a975cf544e8c4b5c2f519bc83bab84bda6b")
                        },
                        {
                            "blinded_node_id": bfh("021a4900c95fcb5ef59284203e005b505d17cdaa066b13134d98930fb4ff1425f4"),
                            "enclen": 50,
                            "encrypted_recipient_data": bfh("9b66a56801a3da6b3149d8b5df0ce9f25df7605b689dd662c40fc5782cbee2786903e83f6827fa52c93af2acdb8e123c72e0")
                        }
                    ]
                },
                {
                    "first_node_id": bfh("031a10cc4d1aea5a59e7888f3eb2f0509e3fc58dae63deff87ba34f217ae419cf7"),
                    "first_path_key": bfh("029a5a12f3b9c0132176ab5347f49486f3d2572aa9d9c3d8ebf622e80a4131f268"),
                    "num_hops": bytes([2]),  # num_hops is defined as byte, not int
                    "path": [
                        {
                            "blinded_node_id": bfh("0250fce42de743a914b821de93c0033713e9b27c8ada26424c0e75c461c1337e1a"),
                            "enclen": 51,
                            "encrypted_recipient_data": bfh("c2e291a9bcf57b57e115d161f49bd8682044bcd11db3adb96ba4d8d99827650aa5691d48c78822c9ae26c446ffa03a41fbc1de")
                        },
                        {
                            "blinded_node_id": bfh("02718474dc3bd8fb42af40c27ff98da911008f4020b90835d4a39ffea084406614"),
                            "enclen": 50,
                            "encrypted_recipient_data": bfh("9b0fc9045ff50ea82babad699c610e14607343dd70ca12dc5575edb28b5673e3660a3eb1b62fd5b6b7d14fd651d5bbee3ad3")
                        }
                    ]
                }
            ]}
        }

        offer = BOLT12Offer.deserialize(offer_data).encode(as_bech32=True)
        decoded = BOLT12Offer.decode(offer).serialize()
        self.assertEqual(offer_data, decoded)

    def test_invoice_request_schnorr_signature(self):
        invreq = 'lnr1qqp6hn00zcssxr0juddeytv7nwawhk9nq9us0arnk8j8wnsq8r2e86vzgtfneupe2gp9yzzcyypymkt4c0n6rhcdw9a7ay2ptuje2gvehscwcchlvgntump3x7e7tc0sgp9k43qeu892gfnz2hrr7akh2x8erh7zm2tv52884vyl462dm5tfcahgtuzt7j0npy7getf4trv5d4g78a9fkwu3kke6hcxdr6t2n7vz'
        data = BOLT12InvoiceRequest.decode(invreq)

        payer_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        invreq_pl_tlv = data.encode(signing_key=payer_key, as_bech32=False)

        self.assertEqual(invreq_pl_tlv, bfh('0003abcdef1621030df2e35b922d9e9bbaebd8b3017907f473b1e4774e0038d593e98242d33cf039520252085821024dd975c3e7a1df0d717bee91415f25952199bc30ec62ff6226be6c3137b3e5e1f0406f02f053bc4186dc980ece06c57e6fa867d61839700fa0f58fc383bfd8e40c428b942a7c157dc77b49a2172fa44aeb0a6e77194fe87df4a7575b71011bbe0332'))

    def test_schnorr_signature(self):
        """encode+decode invoice to test signature validation"""
        # the signing key is different from the encoded node_id, so the signature is invalid
        signing_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        with self.assertRaises(MsgInvalidSignature):
            invoice = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yq35cmzpm5cppcg9gyr9tzrp2zpr86lwy2y4fzpfsau6azq5xv2m9ez3sv4sndlu403jcn2sz2gytqggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvlqsq2smesfhwpr27j0kpgk7prlvewkk639e2c080wyc43epy04hegwgv8kwm04v8ey9t6lxkp5rv65dz9w0xly26mu8rl42hheq0h98y0z')
            encoded = invoice.encode(signing_key=signing_key, as_bech32=False)
            BOLT12Invoice.decode(encoded)

        # now use the same key as used inside the Invoice payload
        signing_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        invoice = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yq35cmzpm5cppcg9gyr9tzrp2zpr86lwy2y4fzpfsau6azq5xv2m9ez3sv4sndlu403jcn2sz2gytqggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvlqsq2smesfhwpr27j0kpgk7prlvewkk639e2c080wyc43epy04hegwgv8kwm04v8ey9t6lxkp5rv65dz9w0xly26mu8rl42hheq0h98y0z')
        encoded = invoice.encode(signing_key=signing_key, as_bech32=False)
        BOLT12Invoice.decode(encoded)

    def test_fallback_address(self):
        # invoice without fallback address
        invoice = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yq35cmzpm5cppcg9gyr9tzrp2zpr86lwy2y4fzpfsau6azq5xv2m9ez3sv4sndlu403jcn2sz2gytqggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvlqsq2smesfhwpr27j0kpgk7prlvewkk639e2c080wyc43epy04hegwgv8kwm04v8ey9t6lxkp5rv65dz9w0xly26mu8rl42hheq0h98y0z')
        self.assertIsNone(invoice.fallback_address)

        # invoice with fallback address
        invoice = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yq35cmzpm5cppcg9gyr9tzrp2zpr86lwy2y4fzpfsau6azq5xv2m9ez3sv4sndlu403jcn2sz2gy2c9cqqq29vsj0npht2n230kazsz9ymxypzhzn04umqggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvlqsqp9r3ynq3f88wwcc5hsy6as87txrnse8tmhay4dkkz36rcncj2dleazl4pg7j2tzzqazk37ztmztm75fspm4fwkvut2uzehsjd750jw')
        fallback_address = {
            'version': bytes([0]),
            'address': bfh('56424f986eb54d517dba2808a4d988115c537d79'),
            'len': len(bfh('56424f986eb54d517dba2808a4d988115c537d79')),
        }
        self.assertEqual(invoice.invoice_fallbacks[0], fallback_address)
        self.assertEqual(invoice.fallback_address, 'bc1q2epylxrwk4x4zld69qy2fkvgz9w9xltef9uv0h')

    def test_is_expired(self):
        offer_expired = BOLT12Offer.decode('lno1qsqszzqzq05q5ptyv4ekxuswq9u3ypr5v4ehg93pq02w80w8hqqpleka0d5j3usclz8mhtgmm6228k9t63hccc9snhrnw')
        self.assertTrue(offer_expired.is_expired)
        offer_no_expiry = BOLT12Offer.decode('lno1qsqszzqzq05q5ptyv4ekxusjq36x2um5zcssxjvgvuq4xn8frm3alch8h0lwfeh78expwcy4h2zvdzq2d57d2n3u')
        self.assertFalse(offer_no_expiry.is_expired)
        invreq_doesnt_expire = BOLT12InvoiceRequest.decode("lnr1qqp6hn00zcssxr0juddeytv7nwawhk9nq9us0arnk8j8wnsq8r2e86vzgtfneupe2gp9yzzcyypymkt4c0n6rhcdw9a7ay2ptuje2gvehscwcchlvgntump3x7e7tc0sgp9k43qeu892gfnz2hrr7akh2x8erh7zm2tv52884vyl462dm5tfcahgtuzt7j0npy7getf4trv5d4g78a9fkwu3kke6hcxdr6t2n7vz")
        self.assertFalse(invreq_doesnt_expire.is_expired)
        invoice_expired = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yq35cmzpm5cppcg9gyr9tzrp2zpr86lwy2y4fzpfsau6azq5xv2m9ez3sv4sndlu403jcn2sz2gytqggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvlqsq2smesfhwpr27j0kpgk7prlvewkk639e2c080wyc43epy04hegwgv8kwm04v8ey9t6lxkp5rv65dz9w0xly26mu8rl42hheq0h98y0z')
        self.assertTrue(invoice_expired.is_expired)
        invoice_not_expired = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yq35cmzpm5czrhxkfl75zpj43ps4pq3na0hz9z253q5cw7dw3q2rx9dju3gcx2cfkl72hcevf4gp9yz9syypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx0sgpp90znnmygs2r9ynxdz63etw3xp28lh2lhf3wpn9g86l57w5cl3evgltx0xjl6yal4taxn4p6z3kzxy6qm2s46qtaauf6y8yvdm035p')
        self.assertFalse(invoice_not_expired.is_expired)
        with self.assertRaises(ValueError):
            _invoice_created_in_the_future = BOLT12Invoice.decode('lni1qqzdatd7auzqwqgzqvzq2ps8pqqszzsnw3jhxazlv4hxxmmyv40kjmnkda5kxegkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx2cyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxdqdvpwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvszqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxryqq2vfjxv6rtgsaqqqqqeqqqqp7sqxgqqqqqqqqqqqqzqqqqqqqqr6zgqqqzq9yqj3q26275cppcg9gyr9tzrp2zpr86lwy2y4fzpfsau6azq5xv2m9ez3sv4sndlu403jcn2sz2gytqggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvlqsqp09v7ll0jmwe52hf45calr0e2wyzyxljautwshuazc7z60shrtz8nk5vuez686cnp5aqpmk39c6k8u8ptg9hxn8jlmlcqkx4grq7hv')

    def test_serde_complex_fields(self):
        payer_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')

        invreq_bech32 = "lnr1qqp6hn00zcssxr0juddeytv7nwawhk9nq9us0arnk8j8wnsq8r2e86vzgtfneupe2gp9yzzcyypymkt4c0n6rhcdw9a7ay2ptuje2gvehscwcchlvgntump3x7e7tc0sgp9k43qeu892gfnz2hrr7akh2x8erh7zm2tv52884vyl462dm5tfcahgtuzt7j0npy7getf4trv5d4g78a9fkwu3kke6hcxdr6t2n7vz"
        invreq = BOLT12InvoiceRequest.decode(invreq_bech32).serialize(with_signature=False)
        dummy_path = {
            "blinded_node_id": bfh("034b1da9c0afa084c604f74f839de006d550422facc3b4be83323702892f7f5949"),
            "enclen": 51,
            "encrypted_recipient_data": bfh(
                "42f0018dcfe5185602618b718f7aa72b1b97d8e85b97f88b8fdad95b80fd93a21d9a975cf544e8c4b5c2f519bc83bab84bda6b")
        }

        # test complex field cardinality
        invreq['offer_paths'] = {
            'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': bytes([1]),
                 'path': [dummy_path]},
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': bytes([1]),
                 'path': [dummy_path]},
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': bytes([1]),
                 'path': [dummy_path]}
            ]
        }

        invreq_pl_tlv = BOLT12InvoiceRequest.deserialize(invreq).encode(signing_key=payer_key, as_bech32=False)

        with io.BytesIO(invreq_pl_tlv) as f:
            deser = OnionWireSerializer.read_tlv_stream(fd=f, tlv_stream_name='invoice_request')
            self.assertEqual(len(deser['offer_paths']['paths']), 3)

        # test complex field all members required
        invreq = {'offer_paths': {'paths': [
            {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
             'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
             'num_hops': bytes([1])}
        ]}}

        # assertRaises on generic Exception used in lnmsg encode/write_tlv_stream makes flake8 complain
        # so work around this for now (TODO: refactor lnmsg generic exceptions)
        # with self.assertRaises(Exception):
        try:
            with io.BytesIO() as fd:
                OnionWireSerializer.write_tlv_stream(
                    fd=fd,
                    tlv_stream_name='invoice_request',
                    signing_key=payer_key,
                    **invreq,
                )
        except Exception as e:
            pass
        else:
            raise Exception('Exception expected')

        # test complex field count matches parameters
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': bytes([1]),
                 'path': []}
            ]}
        }

        with self.assertRaises(AssertionError):
            with io.BytesIO() as fd:
                OnionWireSerializer.write_tlv_stream(
                    fd=fd,
                    tlv_stream_name='invoice_request',
                    signing_key=payer_key,
                    **invreq,
                )
