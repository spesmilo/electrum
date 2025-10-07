import os

from electrum.lnonion import new_onion_packet, calc_hops_data_for_blinded_payment, calc_hops_data_for_payment, OnionPacket
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
blinded_path = [
    {
        'blinded_node_id': bfh(hop['blinded_node_id']),
        'encrypted_recipient_data': bfh(hop['encrypted_data'])
    } for hop in blinded_route_hops
]
blinded_payinfo = generate['blinded_payinfo']

ONION_MESSAGE_PACKET = bfh(generate['onion'])
session_key = bfh(generate['session_key'])
associated_data = bfh(generate['associated_data'])

bolt12_invoice = {
    'invoice_paths': {
        'paths': [
            {
                'path': blinded_path,
                'first_path_key': first_path_key
            }
        ]
    },
    'invoice_blindedpay': {
        'payinfo': [blinded_payinfo]
    }
}


class TestPaymentRouteBlinding(ElectrumTestCase):

    def test_blinded_payment_onion(self):
        # route contains only the non-blinded hop
        alice_outgoing_channel_id = ShortChannelID.from_str(alice_hop["tlvs"]["outgoing_channel_id"])
        route = [
            RouteEdge(
                start_node=bytes(33), # our pubkey, not used
                end_node=bfh(alice_hop['pubkey']),
                short_channel_id=alice_outgoing_channel_id,
                fee_base_msat=0,
                fee_proportional_millionths=0,
                cltv_delta=0,
                node_features=0)
        ]
        total_msat = 150000
        amount_msat = generate["final_amount_msat"]
        final_cltv = generate["final_cltv"]
        hops_data, hops_pubkeys, amt, cltv_abs = calc_hops_data_for_blinded_payment(
            route=route,
            amount_msat=amount_msat,
            final_cltv_abs=final_cltv,
            total_msat=total_msat,
            bolt12_invoice=bolt12_invoice,
        )

        # bob pubkey is not blinded
        payment_path_pubkeys = [x.node_id for x in route] + [first_node_id] + hops_pubkeys[1:]

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
