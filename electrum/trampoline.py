import os
import bitstring
import random

from typing import Mapping, DefaultDict, Tuple, Optional, Dict, List

from .lnutil import LnFeatures
from .lnonion import calc_hops_data_for_payment, new_onion_packet
from .lnrouter import RouteEdge, TrampolineEdge, LNPaymentRoute, is_route_sane_to_use
from .lnutil import NoPathFound, LNPeerAddr
from . import constants

# trampoline nodes are supposed to advertise their fee and cltv in node_update message
TRAMPOLINE_FEES = [
    {
        'fee_base_msat': 0,
        'fee_proportional_millionths': 0,
        'cltv_expiry_delta': 576,
    },
    {
        'fee_base_msat': 1000,
        'fee_proportional_millionths': 100,
        'cltv_expiry_delta': 576,
    },
    {
        'fee_base_msat': 3000,
        'fee_proportional_millionths': 100,
        'cltv_expiry_delta': 576,
    },
    {
        'fee_base_msat': 5000,
        'fee_proportional_millionths': 500,
        'cltv_expiry_delta': 576,
    },
    {
        'fee_base_msat': 7000,
        'fee_proportional_millionths': 1000,
        'cltv_expiry_delta': 576,
    },
    {
        'fee_base_msat': 12000,
        'fee_proportional_millionths': 3000,
        'cltv_expiry_delta': 576,
    },
    {
        'fee_base_msat': 100000,
        'fee_proportional_millionths': 3000,
        'cltv_expiry_delta': 576,
    },
]

# hardcoded list
# TODO for some pubkeys, there are multiple network addresses we could try
TRAMPOLINE_NODES_MAINNET = {
    'ACINQ':                  LNPeerAddr(host='node.acinq.co',           port=9735, pubkey=bytes.fromhex('03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f')),
    'Electrum trampoline':    LNPeerAddr(host='lightning.electrum.org',  port=9740, pubkey=bytes.fromhex('03ecef675be448b615e6176424070673ef8284e0fd19d8be062a6cb5b130a0a0d1')),
    'trampoline hodlisterco': LNPeerAddr(host='trampoline.hodlister.co', port=9740, pubkey=bytes.fromhex('02ce014625788a61411398f83c945375663972716029ef9d8916719141dc109a1c')),
}

TRAMPOLINE_NODES_TESTNET = {
    'endurance': LNPeerAddr(host='34.250.234.192', port=9735, pubkey=bytes.fromhex('03933884aaf1d6b108397e5efe5c86bcf2d8ca8d2f700eda99db9214fc2712b134')),
    'Electrum trampoline': LNPeerAddr(host='lightning.electrum.org', port=9739, pubkey=bytes.fromhex('02bf82e22f99dcd7ac1de4aad5152ce48f0694c46ec582567f379e0adbf81e2d0f')),
}

TRAMPOLINE_NODES_SIGNET = {
    'lnd wakiyamap.dev': LNPeerAddr(host='signet-electrumx.wakiyamap.dev', port=9735, pubkey=bytes.fromhex('02dadf6c28f3284d591cd2a4189d1530c1ff82c07059ebea150a33ab76e7364b4a')),
    'eclair wakiyamap.dev': LNPeerAddr(host='signet-eclair.wakiyamap.dev', port=9735, pubkey=bytes.fromhex('0271cf3881e6eadad960f47125434342e57e65b98a78afa99f9b4191c02dd7ab3b')),
}

_TRAMPOLINE_NODES_UNITTESTS = {}  # used in unit tests

def hardcoded_trampoline_nodes() -> Mapping[str, LNPeerAddr]:
    if _TRAMPOLINE_NODES_UNITTESTS:
        return _TRAMPOLINE_NODES_UNITTESTS
    elif constants.net.NET_NAME == "mainnet":
        return TRAMPOLINE_NODES_MAINNET
    elif constants.net.NET_NAME == "testnet":
        return TRAMPOLINE_NODES_TESTNET
    elif constants.net.NET_NAME == "signet":
        return TRAMPOLINE_NODES_SIGNET
    else:
        return {}

def trampolines_by_id():
    return dict([(x.pubkey, x) for x in hardcoded_trampoline_nodes().values()])

def is_hardcoded_trampoline(node_id: bytes) -> bool:
    return node_id in trampolines_by_id()

def encode_routing_info(r_tags):
    result = bitstring.BitArray()
    for route in r_tags:
        result.append(bitstring.pack('uint:8', len(route)))
        for step in route:
            pubkey, channel, feebase, feerate, cltv = step
            result.append(bitstring.BitArray(pubkey) + bitstring.BitArray(channel) + bitstring.pack('intbe:32', feebase) + bitstring.pack('intbe:32', feerate) + bitstring.pack('intbe:16', cltv))
    return result.tobytes()


def is_legacy_relay(invoice_features, r_tags) -> Tuple[bool, List[bytes]]:
    """Returns if we deal with a legacy payment and the list of trampoline pubkeys in the invoice.
    """
    invoice_features = LnFeatures(invoice_features)
    # trampoline-supporting wallets:
    if invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ECLAIR)\
       or invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM):
        # If there are no r_tags (routing hints) included, the wallet doesn't have
        # private channels and is probably directly connected to a trampoline node.
        # Any trampoline node should be able to figure out a path to the receiver and
        # we can use an e2e payment.
        if not r_tags:
            return False, []
        else:
            # - We choose one routing hint at random, and
            #   use end-to-end trampoline if that node is a trampoline-forwarder (TF).
            # - In case of e2e, the route will have either one or two TFs (one neighbour of sender,
            #   and one neighbour of recipient; and these might coincide). Note that there are some
            #   channel layouts where two TFs are needed for a payment to succeed, e.g. both
            #   endpoints connected to T1 and T2, and sender only has send-capacity with T1, while
            #   recipient only has recv-capacity with T2.
            singlehop_r_tags = [x for x in r_tags if len(x) == 1]
            invoice_trampolines = [x[0][0] for x in singlehop_r_tags if is_hardcoded_trampoline(x[0][0])]
            return False, invoice_trampolines
    # if trampoline receiving is not supported or the forwarder is not known as a trampoline,
    # we send a legacy payment
    return True, []


def trampoline_policy(
        trampoline_fee_level: int,
) -> Dict:
    """Return the fee policy for all trampoline nodes.

    Raises NoPathFound if the fee level is exhausted."""
    # TODO: ideally we want to use individual fee levels for each trampoline node,
    #  but because at the moment we can't attribute insufficient fee errors to
    #  downstream trampolines we need to use a global fee level here
    if trampoline_fee_level < len(TRAMPOLINE_FEES):
        return TRAMPOLINE_FEES[trampoline_fee_level]
    else:
        raise NoPathFound()


def extend_trampoline_route(
        route: List,
        start_node: bytes,
        end_node: bytes,
        trampoline_fee_level: int,
        pay_fees=True
):
    """Extends the route and modifies it in place."""
    trampoline_features = LnFeatures.VAR_ONION_OPT
    policy = trampoline_policy(trampoline_fee_level)
    route.append(
        TrampolineEdge(
            start_node=start_node,
            end_node=end_node,
            fee_base_msat=policy['fee_base_msat'] if pay_fees else 0,
            fee_proportional_millionths=policy['fee_proportional_millionths'] if pay_fees else 0,
            cltv_expiry_delta=policy['cltv_expiry_delta'] if pay_fees else 0,
            node_features=trampoline_features))


def choose_second_trampoline(my_trampoline, trampolines, failed_routes):
    if my_trampoline in trampolines:
        trampolines.remove(my_trampoline)
    for r in failed_routes:
        if len(r) > 2:
            t2 = bytes.fromhex(r[1])
            if t2 in trampolines:
                trampolines.remove(t2)
    if not trampolines:
        raise NoPathFound('all routes have failed')
    return random.choice(trampolines)

def create_trampoline_route(
        *,
        amount_msat: int,
        min_cltv_expiry: int,
        invoice_pubkey: bytes,
        invoice_features: int,
        my_pubkey: bytes,
        my_trampoline: bytes,  # the first trampoline in the path; which we are directly connected to
        r_tags,
        trampoline_fee_level: int,
        use_two_trampolines: bool,
        failed_routes: list,
) -> LNPaymentRoute:
    # we decide whether to convert to a legacy payment
    is_legacy, invoice_trampolines = is_legacy_relay(invoice_features, r_tags)

    # we build a route of trampoline hops and extend the route list in place
    route = []
    second_trampoline = None

    # our first trampoline hop is decided by the channel we use
    extend_trampoline_route(route, my_pubkey, my_trampoline, trampoline_fee_level)

    if is_legacy:
        # we add another different trampoline hop for privacy
        if use_two_trampolines:
            trampolines = trampolines_by_id()
            second_trampoline = choose_second_trampoline(my_trampoline, list(trampolines.keys()), failed_routes)
            extend_trampoline_route(route, my_trampoline, second_trampoline, trampoline_fee_level)
        # the last trampoline onion must contain routing hints for the last trampoline
        # node to find the recipient
        invoice_routing_info = encode_routing_info(r_tags)
        route[-1].invoice_routing_info = invoice_routing_info
        route[-1].invoice_features = invoice_features
        route[-1].outgoing_node_id = invoice_pubkey
    else:
        if invoice_trampolines:
            if my_trampoline in invoice_trampolines:
                short_route = [my_trampoline.hex(), invoice_pubkey.hex()]
                if short_route in failed_routes:
                    add_trampoline = True
                else:
                    add_trampoline = False
            else:
                add_trampoline = True
            if add_trampoline:
                second_trampoline = choose_second_trampoline(my_trampoline, invoice_trampolines, failed_routes)
                extend_trampoline_route(route, my_trampoline, second_trampoline, trampoline_fee_level)

    # final edge (not part of the route if payment is legacy, but eclair requires an encrypted blob)
    extend_trampoline_route(route, route[-1].end_node, invoice_pubkey, trampoline_fee_level, pay_fees=False)
    # check that we can pay amount and fees
    for edge in route[::-1]:
        amount_msat += edge.fee_for_edge(amount_msat)
    if not is_route_sane_to_use(route, amount_msat, min_cltv_expiry):
        raise NoPathFound("We cannot afford to pay the fees.")
    return route


def create_trampoline_onion(*, route, amount_msat, final_cltv, total_msat, payment_hash, payment_secret):
    # all edges are trampoline
    hops_data, amount_msat, cltv = calc_hops_data_for_payment(
        route,
        amount_msat,
        final_cltv,
        total_msat=total_msat,
        payment_secret=payment_secret)
    # detect trampoline hops.
    payment_path_pubkeys = [x.node_id for x in route]
    num_hops = len(payment_path_pubkeys)
    for i in range(num_hops):
        route_edge = route[i]
        assert route_edge.is_trampoline()
        payload = hops_data[i].payload
        if i < num_hops - 1:
            payload.pop('short_channel_id')
            next_edge = route[i+1]
            assert next_edge.is_trampoline()
            hops_data[i].payload["outgoing_node_id"] = {"outgoing_node_id":next_edge.node_id}
        # only for final
        if i == num_hops - 1:
            payload["payment_data"] = {
                "payment_secret": payment_secret,
                "total_msat": total_msat
            }
        # legacy
        if i == num_hops - 2 and route_edge.invoice_features:
            payload["invoice_features"] = {"invoice_features":route_edge.invoice_features}
            payload["invoice_routing_info"] = {"invoice_routing_info":route_edge.invoice_routing_info}
            payload["payment_data"] = {
                "payment_secret": payment_secret,
                "total_msat": total_msat
            }
    trampoline_session_key = os.urandom(32)
    trampoline_onion = new_onion_packet(payment_path_pubkeys, trampoline_session_key, hops_data, associated_data=payment_hash, trampoline=True)
    return trampoline_onion, amount_msat, cltv


def create_trampoline_route_and_onion(
        *,
        amount_msat,
        total_msat,
        min_cltv_expiry,
        invoice_pubkey,
        invoice_features,
        my_pubkey: bytes,
        node_id,
        r_tags,
        payment_hash,
        payment_secret,
        local_height: int,
        trampoline_fee_level: int,
        use_two_trampolines: bool,
        failed_routes: list):
    # create route for the trampoline_onion
    trampoline_route = create_trampoline_route(
        amount_msat=amount_msat,
        min_cltv_expiry=min_cltv_expiry,
        my_pubkey=my_pubkey,
        invoice_pubkey=invoice_pubkey,
        invoice_features=invoice_features,
        my_trampoline=node_id,
        r_tags=r_tags,
        trampoline_fee_level=trampoline_fee_level,
        use_two_trampolines=use_two_trampolines,
        failed_routes=failed_routes)
    # compute onion and fees
    final_cltv = local_height + min_cltv_expiry
    trampoline_onion, amount_with_fees, bucket_cltv = create_trampoline_onion(
        route=trampoline_route,
        amount_msat=amount_msat,
        final_cltv=final_cltv,
        total_msat=total_msat,
        payment_hash=payment_hash,
        payment_secret=payment_secret)
    bucket_cltv_delta = bucket_cltv - local_height
    bucket_cltv_delta += trampoline_route[0].cltv_expiry_delta
    # trampoline fee for this very trampoline
    trampoline_fee = trampoline_route[0].fee_for_edge(amount_with_fees)
    amount_with_fees += trampoline_fee
    return trampoline_route, trampoline_onion, amount_with_fees, bucket_cltv_delta
