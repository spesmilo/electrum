import os

from electrum.lnonion import (
    new_onion_packet, calc_hops_data_for_blinded_payment, OnionPacket, BlindedPathInfo, BlindedPath,
    BlindedPathHop, BlindedPayInfo,
)
from electrum.lnutil import LnFeatures, ShortChannelID
from electrum.util import read_json_file, bfh
from electrum.lnrouter import RouteEdge

from tests import ElectrumTestCase

# test vectors https://github.com/lightning/bolts/pull/765/files
path = os.path.join(os.path.dirname(__file__), 'blinded-payment-onion-test.json')
test_vectors = read_json_file(path)
generate = test_vectors['generate']
full_route = generate['full_route']
alice_hop = full_route['hops'][0]

first_node_id = bfh(generate['blinded_route']['first_node_id'])
first_path_key = bfh(generate['blinded_route']['first_path_key'])
blinded_route_hops = generate['blinded_route']['hops']

blinded_path_hops = [BlindedPathHop(
    blinded_node_id=bfh(hop['blinded_node_id']),
    encrypted_recipient_data=bfh(hop['encrypted_data']),
    enclen=len(bfh(hop['encrypted_data'])),
) for hop in blinded_route_hops]

blinded_path = BlindedPath(
    path=blinded_path_hops,
    first_path_key=first_path_key,
    first_node_id=bytes(32),
    num_hops=bytes([len(blinded_path_hops)])
)

# blinded_payinfo = BlindedPayInfo.from_dict(generate['blinded_payinfo'])
blinded_payinfo = BlindedPayInfo(
    fee_base_msat=generate['blinded_payinfo']['fee_base_msat'],
    fee_proportional_millionths=generate['blinded_payinfo']['fee_proportional_millionths'],
    cltv_expiry_delta=generate['blinded_payinfo']['cltv_expiry_delta'],
    htlc_minimum_msat=0,
    htlc_maximum_msat=999999999999999,
    features=LnFeatures(0),
)

ONION_MESSAGE_PACKET = bfh(generate['onion'])
session_key = bfh(generate['session_key'])
associated_data = bfh(generate['associated_data'])


class TestPaymentRouteBlinding(ElectrumTestCase):

    def test_blinded_payment_onion(self):
        # us -> alice -> bob (introduction point) -> remaining blinded path hops
        # route[0] is us -> alice edge, skipped by calc_hops_data_for_blinded_payment as we don't need a payload for ourselves
        alice_outgoing_channel_id = ShortChannelID.from_str(alice_hop["tlvs"]["outgoing_channel_id"])
        route = [
            RouteEdge(
                start_node=bytes(33),  # our (sender's) pubkey
                end_node=bfh(alice_hop['pubkey']),
                short_channel_id=ShortChannelID(0),  # sender's channel, not used in payloads
                fee_base_msat=0,
                fee_proportional_millionths=0,
                cltv_delta=0,
                node_features=0),
            RouteEdge(
                start_node=bfh(alice_hop['pubkey']),
                end_node=first_node_id,  # Bob (introduction point)
                short_channel_id=alice_outgoing_channel_id,
                fee_base_msat=0,
                fee_proportional_millionths=0,
                cltv_delta=0,
                node_features=0),
        ]
        total_msat = 150000
        amount_msat = generate["final_amount_msat"]
        final_cltv = generate["final_cltv"]
        hops_data, blinded_hops_pubkeys, amt, cltv_abs = calc_hops_data_for_blinded_payment(
            route_to_introduction_point=route,
            recipient_amount_msat=amount_msat,
            final_cltv_abs=final_cltv,
            total_msat=total_msat,
            invoice_blinded_path_info=BlindedPathInfo(path=blinded_path, payinfo=blinded_payinfo),
        )

        # route provides unblinded pubkeys (Alice, Bob)
        payment_path_pubkeys = [x.node_id for x in route] + blinded_hops_pubkeys

        # assert payloads
        for i, h in enumerate(hops_data):
            payload = h.to_bytes().hex()[0:-64]
            ref_payload = generate['full_route']['hops'][i]['payload']
            self.assertEqual(payload, ref_payload)

        packet = new_onion_packet(
            payment_path_pubkeys,
            session_key,
            hops_data,
            associated_data=associated_data,
        )
        # test final packet
        ref_packet = OnionPacket.from_bytes(ONION_MESSAGE_PACKET)
        self.assertEqual(packet.to_bytes(), ONION_MESSAGE_PACKET)
