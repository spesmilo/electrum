import os

from electrum.lnonion import get_shared_secrets_along_route, OnionHopsDataSingle, encrypt_hops_recipient_data
from electrum.lnutil import LnFeatures
from electrum.util import read_json_file, bfh

from tests import ElectrumTestCase

# test vectors https://github.com/lightning/bolts/pull/765/files
path = os.path.join(os.path.dirname(__file__), 'route-blinding-test.json')
test_vectors = read_json_file(path)
HOPS = test_vectors['generate']['hops']
BOB =   HOPS[0]
CAROL = HOPS[1]
DAVE =  HOPS[2]
EVE =   HOPS[3]

BOB_TLVS =   BOB['tlvs']
CAROL_TLVS = CAROL['tlvs']
DAVE_TLVS =  DAVE['tlvs']
EVE_TLVS =   EVE['tlvs']

BOB_PUBKEY =  bfh(test_vectors['route']['first_node_id'])
CAROL_PUBKEY = bfh(CAROL['node_id'])
DAVE_PUBKEY =  bfh(DAVE['node_id'])
EVE_PUBKEY =   bfh(EVE['node_id'])


class TestPaymentRouteBlinding(ElectrumTestCase):

    def test_blinded_path_payload_tlv_concat(self):

        hop_shared_secrets1, blinded_node_ids1 = get_shared_secrets_along_route([BOB_PUBKEY, CAROL_PUBKEY], bfh(BOB['session_key']))
        hop_shared_secrets2, blinded_node_ids2 = get_shared_secrets_along_route([DAVE_PUBKEY, EVE_PUBKEY], bfh(DAVE['session_key']))
        hop_shared_secrets = hop_shared_secrets1 + hop_shared_secrets2
        blinded_node_ids = blinded_node_ids1 + blinded_node_ids2

        for i, ss in enumerate(hop_shared_secrets):
            self.assertEqual(ss, bfh(HOPS[i]['shared_secret']))
        for i, ss in enumerate(blinded_node_ids):
            self.assertEqual(ss, bfh(HOPS[i]['blinded_node_id']))

        hops_data = [
            OnionHopsDataSingle(
                tlv_stream_name='payload',
                blind_fields={
                    'padding': {'padding': bfh(BOB_TLVS['padding'])},
                    'short_channel_id': {'short_channel_id': 1729},  # FIXME scid from "0x0x1729" testvector repr
                    'payment_relay': {
                        'cltv_expiry_delta': BOB_TLVS['payment_relay']['cltv_expiry_delta'],
                        'fee_proportional_millionths': BOB_TLVS['payment_relay']['fee_proportional_millionths'],
                        'fee_base_msat': BOB_TLVS['payment_relay']['fee_base_msat'],
                    },
                    'payment_constraints': {
                        'max_cltv_expiry': BOB_TLVS['payment_constraints']['max_cltv_expiry'],
                        'htlc_minimum_msat': BOB_TLVS['payment_constraints']['htlc_minimum_msat'],
                    },
                    'allowed_features': {'features': b''},
                    'unknown_tag_561': {'data': bfh(BOB_TLVS['unknown_tag_561'])},
                }
            ),
            OnionHopsDataSingle(
                tlv_stream_name='payload',
                blind_fields={
                    'short_channel_id': {'short_channel_id': 1105},
                    'next_path_key_override': {'path_key': bfh(CAROL_TLVS['next_path_key_override'])},
                    'payment_relay': {
                        'cltv_expiry_delta': CAROL_TLVS['payment_relay']['cltv_expiry_delta'],
                        'fee_proportional_millionths': CAROL_TLVS['payment_relay']['fee_proportional_millionths'],
                        'fee_base_msat': CAROL_TLVS['payment_relay']['fee_base_msat'],
                    },
                    'payment_constraints': {
                        'max_cltv_expiry': CAROL_TLVS['payment_constraints']['max_cltv_expiry'],
                        'htlc_minimum_msat': CAROL_TLVS['payment_constraints']['htlc_minimum_msat'],
                    },
                    'allowed_features': {'features': b''},
                }
            ),
            OnionHopsDataSingle(
                tlv_stream_name='payload',
                blind_fields={
                    'padding': {'padding': bfh(DAVE_TLVS['padding'])},
                    'short_channel_id': {'short_channel_id': 561},
                    'payment_relay': {
                        'cltv_expiry_delta': DAVE_TLVS['payment_relay']['cltv_expiry_delta'],
                        'fee_proportional_millionths': DAVE_TLVS['payment_relay']['fee_proportional_millionths'],
                        # 'fee_base_msat': DAVE_TLVS['payment_relay']['fee_base_msat'],
                        # FIXME: mandatory but not in test vectors ?
                        'fee_base_msat': 0
                    },
                    'payment_constraints': {
                        'max_cltv_expiry': DAVE_TLVS['payment_constraints']['max_cltv_expiry'],
                        'htlc_minimum_msat': DAVE_TLVS['payment_constraints']['htlc_minimum_msat'],
                    },
                    'allowed_features': {'features': b''},
                }
            ),
            OnionHopsDataSingle(
                tlv_stream_name='payload',
                blind_fields={
                    'padding': {'padding': bfh(EVE_TLVS['padding'])},
                    'path_id': {'data': bfh(EVE_TLVS['path_id'])},
                    'payment_constraints': {
                        'max_cltv_expiry': EVE_TLVS['payment_constraints']['max_cltv_expiry'],
                        'htlc_minimum_msat': EVE_TLVS['payment_constraints']['htlc_minimum_msat'],
                    },
                    'allowed_features': {'features': bfh('0' + str(LnFeatures(1 << 113))[2:])},  # FIXME, proper features bit representation
                    'unknown_tag_65535': {'data': bfh(EVE_TLVS['unknown_tag_65535'])},
                }
            ),
        ]

        encrypt_hops_recipient_data('payload', hops_data, hop_shared_secrets)

        for i, hop in enumerate(hops_data):
            self.assertEqual(hop.payload['encrypted_recipient_data']['encrypted_data'],
                             bfh(HOPS[i]['encrypted_data']), f'hop {i} not matching')
