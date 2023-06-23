from electrum import segwit_addr
from electrum import bolt12
from electrum.lnmsg import UnknownMandatoryTLVRecordType
from electrum.lnonion import get_shared_secrets_along_route, get_shared_secrets_along_route2, OnionHopsDataSingle, \
    new_onion_packet
from electrum.util import bfh

from . import ElectrumTestCase

INVALID_BECH32 = segwit_addr.DecodedBech32(None, None, None)


def bech32_decode(x):
    return segwit_addr.bech32_decode(x, ignore_long_length=True, with_checksum=False)


class TestBolt12(ElectrumTestCase):
    def test_decode(self):
        # https://bootstrap.bolt12.org/examples
        d = bech32_decode('lno1pg257enxv4ezqcneype82um50ynhxgrwdajx293pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmc')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))
        self.assertEqual(od, { 'offer_description': { 'description': b"Offer by rusty's node"},
                                'offer_node_id':
                                    {'node_id': b'\x02?2\x19\xda\x03\xee)\xa1-\xe4\x10~l\\6O`s\x82\xf0e\xf2\xbf\xed\x91\xdd\xd6\xb9\x10y\xbf\xbc'}
                             })

        d = bech32_decode('lno1pqqnyzsmx5cx6umpwssx6atvw35j6ut4v9h8g6t50ysx7enxv4epyrmjw4ehgcm0wfczucm0d5hxzag5qqtzzq3lxgva5qlw9xsjmeqs0ek9cdj0vpec9ur972l7mywa66u3q7dlhs')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))
        self.assertEqual(od, {'offer_amount': {'amount': 50},
                              'offer_description': {'description': b'50msat multi-quantity offer'},
                              'offer_issuer': {'issuer': b'rustcorp.com.au'},
                              'offer_quantity_max': {'max': 0},
                              'offer_node_id':
                                  {'node_id': b'\x02?2\x19\xda\x03\xee)\xa1-\xe4\x10~l\\6O`s\x82\xf0e\xf2\xbf\xed\x91\xdd\xd6\xb9\x10y\xbf\xbc'}
                              })

        # TODO: tests below use recurrence (tlv record type 26) which is not supported/generated from wire specs
        # (c-lightning carries patches re-adding these, but for now we ignore these)

        d = bech32_decode('lno1pqqkgzs5xycrqmtnv96zqetkv4e8jgrdd9h82ar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqq7q')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))

        d = bech32_decode('lno1pqqkgz38xycrqmtnv96zqetkv4e8jgrdd9h82ar99ss82upqw3hjqargwfjk2gr5d9kk2ucjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qsq8s0qzqs')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))

        d = bech32_decode('lno1pqqkgz3zxycrqmtnv96zqetkv4e8jgryv9ujcgrxwfhk6gp3949xzm3dxgcryvgjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qspqysq2q2laenqq')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))

        d = bech32_decode('lno1pqpq86q2fgcnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qcteyqcksu3qvfjkvmmjv5s8gmeqxcczqum9vdhkuernypkxzar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pcpsqqq8pqqpuyqzszhlwvcqq')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))

        d = bech32_decode('lno1pqpq86q2xycnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qun094exzarpzgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pczqqp5hsqqgd9uqzqpgptlhxvqq')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))

        d = bech32_decode('lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yfpqun4wd68jtn00fkxzcnn9ehhyeckyypr7vsemgp7u2dp9hjpqlnvtsmy7crnstcxtu4lakgam44ezpuml0q6qgqsz')
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(bytes(segwit_addr.convertbits(d.data, 5, 8)))

    def test_path_pubkeys_blinded_path_appended(self):
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),   # Alice
            (bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),  # Bob w blinding secret override
             bfh('0101010101010101010101010101010101010101010101010101010101010101')),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),   # Carol
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')    # Dave
        ]
        session_key = bfh('6363636363636363636363636363636363636363636363636363636363636363')
        hop_shared_secrets = get_shared_secrets_along_route2(payment_path_pubkeys, session_key)
        h = list(map(lambda x: x.hex(), hop_shared_secrets))
        pass
