import os
import bitstring

from .lnutil import LnFeatures
from .lnonion import calc_hops_data_for_payment, new_onion_packet
from .lnrouter import RouteEdge, TrampolineEdge, LNPaymentRoute, is_route_sane_to_use
from .lnutil import NoPathFound

from .logging import get_logger, Logger

_logger = get_logger(__name__)

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


def encode_routing_info(r_tags):
    result = bitstring.BitArray()
    for route in r_tags:
        result.append(bitstring.pack('uint:8', len(route)))
        for step in route:
            pubkey, channel, feebase, feerate, cltv = step
            result.append(bitstring.BitArray(pubkey) + bitstring.BitArray(channel) + bitstring.pack('intbe:32', feebase) + bitstring.pack('intbe:32', feerate) + bitstring.pack('intbe:16', cltv))
    return result.tobytes()


def create_trampoline_route(
        *,
        amount_msat:int,
        min_cltv_expiry:int,
        invoice_pubkey:bytes,
        invoice_features:int,
        my_pubkey: bytes,
        trampoline_node_id,
        r_tags, t_tags,
        trampoline_fee_level,
        trampoline2_list) -> LNPaymentRoute:

    invoice_features = LnFeatures(invoice_features)
    # We do not set trampoline_routing_opt in our invoices, because the spec is not ready
    # Do not use t_tags if the flag is set, because we the format is not decided yet
    if invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT):
        is_legacy = False
        if len(r_tags) > 0 and len(r_tags[0]) == 1:
            pubkey, scid, feebase, feerate, cltv = r_tags[0][0]
            t_tag = pubkey, feebase, feerate, cltv
        else:
            t_tag = None
    elif len(t_tags) > 0:
        is_legacy = False
        t_tag = t_tags[0]
    else:
        is_legacy = True

    # fee level. the same fee is used for all trampolines
    if trampoline_fee_level < len(TRAMPOLINE_FEES):
        params = TRAMPOLINE_FEES[trampoline_fee_level]
    else:
        raise NoPathFound()
    # add optional second trampoline
    trampoline2 = None
    if is_legacy:
        for node_id in trampoline2_list:
            if node_id != trampoline_node_id:
                trampoline2 = node_id
                break
    # node_features is only used to determine is_tlv
    trampoline_features = LnFeatures.VAR_ONION_OPT
    # hop to trampoline
    route = []
    # trampoline hop
    route.append(
        TrampolineEdge(
            start_node=my_pubkey,
            end_node=trampoline_node_id,
            fee_base_msat=params['fee_base_msat'],
            fee_proportional_millionths=params['fee_proportional_millionths'],
            cltv_expiry_delta=params['cltv_expiry_delta'],
            node_features=trampoline_features))
    if trampoline2:
        route.append(
            TrampolineEdge(
                start_node=trampoline_node_id,
                end_node=trampoline2,
                fee_base_msat=params['fee_base_msat'],
                fee_proportional_millionths=params['fee_proportional_millionths'],
                cltv_expiry_delta=params['cltv_expiry_delta'],
                node_features=trampoline_features))
    # add routing info
    if is_legacy:
        invoice_routing_info = encode_routing_info(r_tags)
        route[-1].invoice_routing_info = invoice_routing_info
        route[-1].invoice_features = invoice_features
    else:
        if t_tag:
            pubkey, feebase, feerate, cltv = t_tag
            if route[-1].node_id != pubkey:
                route.append(
                    TrampolineEdge(
                        start_node=route[-1].node_id,
                        end_node=pubkey,
                        fee_base_msat=feebase,
                        fee_proportional_millionths=feerate,
                        cltv_expiry_delta=cltv,
                        node_features=trampoline_features))
    # Fake edge (not part of actual route, needed by calc_hops_data)
    route.append(
        TrampolineEdge(
            start_node=route[-1].end_node,
            end_node=invoice_pubkey,
            fee_base_msat=0,
            fee_proportional_millionths=0,
            cltv_expiry_delta=0,
            node_features=trampoline_features))
    # check that we can pay amount and fees
    for edge in route[::-1]:
        amount_msat += edge.fee_for_edge(amount_msat)
    if not is_route_sane_to_use(route, amount_msat, min_cltv_expiry):
        raise NoPathFound()
    _logger.info(f'created route with trampoline: fee_level={trampoline_fee_level}, is legacy: {is_legacy}')
    _logger.info(f'first trampoline: {trampoline_node_id.hex()}')
    _logger.info(f'second trampoline: {trampoline2.hex() if trampoline2 else None}')
    _logger.info(f'params: {params}')
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
    for i in range(num_hops-1):
        route_edge = route[i]
        next_edge = route[i+1]
        assert route_edge.is_trampoline()
        assert next_edge.is_trampoline()
        hops_data[i].payload["outgoing_node_id"] = {"outgoing_node_id":next_edge.node_id}
        if route_edge.invoice_features:
            hops_data[i].payload["invoice_features"] = {"invoice_features":route_edge.invoice_features}
        if route_edge.invoice_routing_info:
            hops_data[i].payload["invoice_routing_info"] = {"invoice_routing_info":route_edge.invoice_routing_info}
        # only for final, legacy
        if i == num_hops - 2:
            hops_data[i].payload["payment_data"] = {
                "payment_secret":payment_secret,
                "total_msat": total_msat,
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
        r_tags, t_tags,
        payment_hash,
        payment_secret,
        local_height:int,
        trampoline_fee_level,
        trampoline2_list):
    # create route for the trampoline_onion
    trampoline_route = create_trampoline_route(
        amount_msat=amount_msat,
        min_cltv_expiry=min_cltv_expiry,
        my_pubkey=my_pubkey,
        invoice_pubkey=invoice_pubkey,
        invoice_features=invoice_features,
        trampoline_node_id=node_id,
        r_tags=r_tags,
        t_tags=t_tags,
        trampoline_fee_level=trampoline_fee_level,
        trampoline2_list=trampoline2_list)
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
    return trampoline_onion, trampoline_fee, amount_with_fees, bucket_cltv_delta
