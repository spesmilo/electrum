import io

from electrum_ecc import ECPrivkey

from electrum import segwit_addr
from electrum import bolt12
from electrum.bolt12 import is_offer, decode_offer, encode_invoice_request, decode_invoice_request, encode_invoice, \
    decode_invoice
from electrum.lnmsg import UnknownMandatoryTLVRecordType, _tlv_merkle_root, OnionWireSerializer
from electrum.lnonion import OnionHopsDataSingle
from electrum.segwit_addr import INVALID_BECH32
from electrum.util import bfh

from . import ElectrumTestCase


def bech32_decode(x):
    return segwit_addr.bech32_decode(x, ignore_long_length=True, with_checksum=False)


class TestBolt12(ElectrumTestCase):
    def test_decode(self):
        # https://bootstrap.bolt12.org/examples
        offer = 'lno1pg257enxv4ezqcneype82um50ynhxgrwdajx293pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmc'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))
        od = decode_offer(offer)
        self.assertEqual(od, {'offer_description': {'description': "Offer by rusty's node"},
                              'offer_issuer_id':
                                  {'id': bfh('023f3219da03ee29a12de4107e6c5c364f607382f065f2bfed91ddd6b91079bfbc')}
                              })

        offer = 'lno1pqqnyzsmx5cx6umpwssx6atvw35j6ut4v9h8g6t50ysx7enxv4epyrmjw4ehgcm0wfczucm0d5hxzag5qqtzzq3lxgva5qlw9xsjmeqs0ek9cdj0vpec9ur972l7mywa66u3q7dlhs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        od = decode_offer(offer)
        self.assertEqual(od, {'offer_amount': {'amount': 50},
                              'offer_description': {'description': '50msat multi-quantity offer'},
                              'offer_issuer': {'issuer': 'rustcorp.com.au'},
                              'offer_quantity_max': {'max': 0},
                              'offer_issuer_id':
                                  {'id': bfh('023f3219da03ee29a12de4107e6c5c364f607382f065f2bfed91ddd6b91079bfbc')}
                              })

        # TODO: tests below use recurrence (tlv record type 26) which is not supported/generated from wire specs
        # (c-lightning carries patches re-adding these, but for now we ignore them)

        offer = 'lno1pqqkgzs5xycrqmtnv96zqetkv4e8jgrdd9h82ar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqq7q'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqqkgz38xycrqmtnv96zqetkv4e8jgrdd9h82ar99ss82upqw3hjqargwfjk2gr5d9kk2ucjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qsq8s0qzqs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqqkgz3zxycrqmtnv96zqetkv4e8jgryv9ujcgrxwfhk6gp3949xzm3dxgcryvgjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qspqysq2q2laenqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqpq86q2fgcnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qcteyqcksu3qvfjkvmmjv5s8gmeqxcczqum9vdhkuernypkxzar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pcpsqqq8pqqpuyqzszhlwvcqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqpq86q2xycnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qun094exzarpzgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pczqqp5hsqqgd9uqzqpgptlhxvqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yfpqun4wd68jtn00fkxzcnn9ehhyeckyypr7vsemgp7u2dp9hjpqlnvtsmy7crnstcxtu4lakgam44ezpuml0q6qgqsz'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

    def test_decode_offer(self):
        offer = 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))

        od = decode_offer(offer)
        self.assertEqual(od['offer_description']['description'], 'first test offer')
        self.assertEqual(od['offer_issuer_id']['id'], bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'))

    def test_decode_invreq(self):
        invreq = 'lnr1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495'
        d = bech32_decode(invreq)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lnr', "wrong hrp")

        od = decode_invoice_request(invreq)
        self.assertEqual(od['offer_description']['description'], 'first test offer')
        self.assertEqual(od['offer_issuer_id']['id'], bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'))

    def test_encode_invoice(self):
        data = {'offer_metadata': {'data': bfh('01020304050607')},
                'offer_amount': {'amount': 1},
                'offer_description': {'description': 'test_encode_invoice'}}
        invoice_tlv = encode_invoice(data, signing_key=bfh('4141414141414141414141414141414141414141414141414141414141414141'))
        self.assertEqual(invoice_tlv, bfh('0407010203040506070801010a13746573745f656e636f64655f696e766f696365f04013b55efc08ebd43b8971d98d2c8cb9f404e674d6f8842fad7347a7f2e2b1fe52c4a59774e7ede6e585ad6a089adb003e1ee24a9f50b27b871855c1ca0a2272c2'))

    def test_subtype_encode_decode(self):
        offer = 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495'
        od = decode_offer(offer)
        data = {'offer_issuer_id': od['offer_issuer_id']}
        invreq_pl_tlv = encode_invoice_request(data, payer_key=bfh('4141414141414141414141414141414141414141414141414141414141414141'))

        ohds = OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                            payload={'invoice_request': {'invoice_request': invreq_pl_tlv},
                                         'reply_path': {'path': {
                                             'first_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                             'blinding': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                             'num_hops': 2,
                                             'path': [
                                                 {'blinded_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                                  'enclen': 5,
                                                  'encrypted_recipient_data': bfh('0000000000')},
                                                 {'blinded_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                                  'enclen': 6,
                                                  'encrypted_recipient_data': bfh('001111222233')}
                                             ]
                                         }},
                                     },
                            blind_fields={'padding': {'padding': b''},
                                          #'path_id': {'data': bfh('deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0')}
                                          }
                            )

        ohds_b = ohds.to_bytes()

        self.assertEqual(ohds_b, bfh('fd00fd02940309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e50309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5020309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5000500000000000309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e500060011112222334065162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5af04078205e3d9d3cf87b743bcad5bca89f12f868ce638fbb4051d9570bac1a79d90ae3650ebcf15603b9349697edf71bf78ecb802aafe146d9118fe387bdb36ed26e0000000000000000000000000000000000000000000000000000000000000000'))

        with io.BytesIO(ohds_b) as fd:
            ohds2 = OnionHopsDataSingle.from_fd(fd, tlv_stream_name='onionmsg_tlv')
            self.assertTrue('invoice_request' in ohds2.payload)  # TODO
            self.assertTrue('reply_path' in ohds2.payload)  # TODO

    def test_merkle_root(self):
        # test vectors in https://github.com/lightning/bolts/pull/798
        tlvs = [
            (1, bfh('010203e8')),
            (2, bfh('02080000010000020003')),
            (3, bfh('03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002'))
        ]

        self.assertEqual(_tlv_merkle_root(tlvs[:1]), bfh('b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93'))
        self.assertEqual(_tlv_merkle_root(tlvs[:2]), bfh('c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1'))
        self.assertEqual(_tlv_merkle_root(tlvs[:3]), bfh('ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d'))

    def test_invoice_request_schnorr_signature(self):
        # use invoice request in https://github.com/lightning/bolts/pull/798 to match test vectors
        invreq = 'lnr1qqyqqqqqqqqqqqqqqcp4256ypqqkgzshgysy6ct5dpjk6ct5d93kzmpq23ex2ct5d9ek293pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpjkppqvjx204vgdzgsqpvcp4mldl3plscny0rt707gvpdh6ndydfacz43euzqhrurageg3n7kafgsek6gz3e9w52parv8gs2hlxzk95tzeswywffxlkeyhml0hh46kndmwf4m6xma3tkq2lu04qz3slje2rfthc89vss'
        data = decode_invoice_request(invreq)
        del data['signature']  # remove signature, we regenerate it

        payer_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        invreq_pl_tlv = encode_invoice_request(data, payer_key)

        self.assertEqual(invreq_pl_tlv, bfh('0008000000000000000006035553440801640a1741204d617468656d61746963616c205472656174697365162102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661958210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cf040b8f83ea3288cfd6ea510cdb481472575141e8d8744157f98562d162cc1c472526fdb24befefbdebab4dbb726bbd1b7d8aec057f8fa805187e5950d2bbe0e5642'))

    def test_schnorr_signature(self):
        # encode+decode invoice to test signature
        signing_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        signing_pubkey = ECPrivkey(signing_key).get_public_key_bytes()
        invoice_tlv = encode_invoice({
            'offer_amount': {'amount': 1},
            'offer_description': {'description': 'test'},
            'invoice_node_id': {'node_id': signing_pubkey}
        }, signing_key)
        decode_invoice(invoice_tlv)

    def test_serde_complex_fields(self):
        payer_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')

        # test complex field cardinality without explicit count
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'blinding': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0,
                 'path': []},
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'blinding': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0,
                 'path': []},
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'blinding': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0,
                 'path': []}
            ]}
        }

        invreq_pl_tlv = encode_invoice_request(invreq, payer_key=payer_key)

        with io.BytesIO() as fd:
            f = io.BytesIO(invreq_pl_tlv)
            deser = OnionWireSerializer.read_tlv_stream(fd=f, tlv_stream_name='invoice_request')
            self.assertEqual(len(deser['offer_paths']['paths']), 3)

        # test complex field all members required
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'blinding': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0}
            ]}
        }

        # assertRaises on generic Exception used in lnmsg encode/write_tlv_stream makes flake8 complain
        # so work around this for now (TODO: refactor lnmsg generic exceptions)
        #with self.assertRaises(Exception):
        try:
            invreq_pl_tlv = encode_invoice_request(invreq, payer_key=payer_key)
        except Exception as e:
            pass
        else:
            raise Exception('Exception expected')

        # test complex field count matches parameters
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'blinding': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 1,
                 'path': []}
            ]}
        }

        with self.assertRaises(AssertionError):
            invreq_pl_tlv = encode_invoice_request(invreq, payer_key=payer_key)
