import io
import os
import random
from typing import Mapping, DefaultDict, Tuple, Optional, Dict, List, Iterable, Sequence, Set, Any

from .lnutil import LnFeatures, PaymentFeeBudget
from .lnonion import calc_hops_data_for_payment, new_onion_packet, OnionPacket
from .lnrouter import RouteEdge, TrampolineEdge, LNPaymentRoute, is_route_within_budget, LNPaymentTRoute
from .lnutil import NoPathFound, LNPeerAddr
from . import constants
from .logging import get_logger


_logger = get_logger(__name__)

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

def encode_routing_info(r_tags: Sequence[Sequence[Sequence[Any]]]) -> bytes:
    result = bytearray()
    for route in r_tags:
        result += bytes([len(route)])
        for step in route:
            pubkey, scid, feebase, feerate, cltv = step
            result += pubkey
            result += scid
            result += int.to_bytes(feebase, length=4, byteorder="big", signed=False)
            result += int.to_bytes(feerate, length=4, byteorder="big", signed=False)
            result += int.to_bytes(cltv, length=2, byteorder="big", signed=False)
    return bytes(result)


def decode_routing_info(rinfo: bytes) -> Sequence[Sequence[Sequence[Any]]]:
    if not rinfo:
        return []
    r_tags = []
    with io.BytesIO(bytes(rinfo)) as s:
        while True:
            route = []
            route_len = s.read(1)
            if not route_len:
                break
            for step in range(route_len[0]):
                pubkey = s.read(33)
                scid = s.read(8)
                feebase = int.from_bytes(s.read(4), byteorder="big")
                feerate = int.from_bytes(s.read(4), byteorder="big")
                cltv = int.from_bytes(s.read(2), byteorder="big")
                route.append((pubkey, scid, feebase, feerate, cltv))
            r_tags.append(route)
    return r_tags


def is_legacy_relay(invoice_features, r_tags) -> Tuple[bool, Set[bytes]]:
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
            return False, set()
        else:
            # - We choose one routing hint at random, and
            #   use end-to-end trampoline if that node is a trampoline-forwarder (TF).
            # - In case of e2e, the route will have either one or two TFs (one neighbour of sender,
            #   and one neighbour of recipient; and these might coincide). Note that there are some
            #   channel layouts where two TFs are needed for a payment to succeed, e.g. both
            #   endpoints connected to T1 and T2, and sender only has send-capacity with T1, while
            #   recipient only has recv-capacity with T2.
            singlehop_r_tags = [x for x in r_tags if len(x) == 1]
            invoice_trampolines = [x[0][0] for x in singlehop_r_tags]
            invoice_trampolines = set(invoice_trampolines)
            if invoice_trampolines:
                return False, invoice_trampolines
    # if trampoline receiving is not supported or the forwarder is not known as a trampoline,
    # we send a legacy payment
    return True, set()


PLACEHOLDER_FEE = None
def _extend_trampoline_route(
        route: List[TrampolineEdge],
        *,
        start_node: bytes = None,
        end_node: bytes,
        pay_fees: bool = True,
):
    """Extends the route and modifies it in place."""
    if start_node is None:
        assert route
        start_node = route[-1].end_node
    trampoline_features = LnFeatures.VAR_ONION_OPT
    # get policy for *start_node*
    # note: trampoline nodes are supposed to advertise their fee and cltv in node_update message.
    #       However, in the temporary spec, they do not.
    #       They also don't send their fee policy in the error message if we lowball the fee...
    route.append(
        TrampolineEdge(
            start_node=start_node,
            end_node=end_node,
            fee_base_msat=PLACEHOLDER_FEE if pay_fees else 0,
            fee_proportional_millionths=PLACEHOLDER_FEE if pay_fees else 0,
            cltv_delta=576 if pay_fees else 0,
            node_features=trampoline_features))


def _allocate_fee_along_route(
    route: List[TrampolineEdge],
    *,
    budget: PaymentFeeBudget,
    trampoline_fee_level: int,
) -> None:
    # calculate budget_to_use, based on given max available "budget"
    if trampoline_fee_level == 0:
        budget_to_use = 0
    else:
        assert trampoline_fee_level > 0
        MAX_LEVEL = 6
        if trampoline_fee_level > MAX_LEVEL:
            raise NoPathFound()
        budget_to_use = budget.fee_msat // (2 ** (MAX_LEVEL - trampoline_fee_level))
    _logger.debug(f"_allocate_fee_along_route(). {trampoline_fee_level=}, {budget.fee_msat=}, {budget_to_use=}")
    # replace placeholder fees
    for edge in route:
        assert edge.fee_base_msat in (0, PLACEHOLDER_FEE), edge.fee_base_msat
        assert edge.fee_proportional_millionths in (0, PLACEHOLDER_FEE), edge.fee_proportional_millionths
    edges_to_update = [
        edge for edge in route
        if edge.fee_base_msat == PLACEHOLDER_FEE]
    for edge in edges_to_update:
        edge.fee_base_msat = budget_to_use // len(edges_to_update)
        edge.fee_proportional_millionths = 0


def _choose_second_trampoline(
    my_trampoline: bytes,
    trampolines: Iterable[bytes],
    failed_routes: Iterable[Sequence[str]],
) -> bytes:
    trampolines = set(trampolines)
    if my_trampoline in trampolines:
        trampolines.discard(my_trampoline)
    for r in failed_routes:
        if len(r) > 2:
            t2 = bytes.fromhex(r[1])
            if t2 in trampolines:
                trampolines.discard(t2)
    if not trampolines:
        raise NoPathFound('all routes have failed')
    return random.choice(list(trampolines))


def create_trampoline_route(
        *,
        amount_msat: int,
        min_final_cltv_delta: int,
        invoice_pubkey: bytes,
        invoice_features: int,
        my_pubkey: bytes,
        my_trampoline: bytes,  # the first trampoline in the path; which we are directly connected to
        r_tags,
        trampoline_fee_level: int,
        use_two_trampolines: bool,
        failed_routes: Iterable[Sequence[str]],
        budget: PaymentFeeBudget,
) -> LNPaymentTRoute:
    # we decide whether to convert to a legacy payment
    is_legacy, invoice_trampolines = is_legacy_relay(invoice_features, r_tags)

    # we build a route of trampoline hops and extend the route list in place
    route = []

    # our first trampoline hop is decided by the channel we use
    _extend_trampoline_route(
        route, start_node=my_pubkey, end_node=my_trampoline,
        pay_fees=False,
    )

    if is_legacy:
        # we add another different trampoline hop for privacy
        if use_two_trampolines:
            trampolines = trampolines_by_id()
            second_trampoline = _choose_second_trampoline(my_trampoline, list(trampolines.keys()), failed_routes)
            _extend_trampoline_route(route, end_node=second_trampoline)
        # the last trampoline onion must contain routing hints for the last trampoline
        # node to find the recipient
        invoice_routing_info = encode_routing_info(r_tags)
        assert invoice_routing_info == encode_routing_info(decode_routing_info(invoice_routing_info))
        # lnwire invoice_features for trampoline is u64
        invoice_features = invoice_features & 0xffffffffffffffff
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
                second_trampoline = _choose_second_trampoline(my_trampoline, invoice_trampolines, failed_routes)
                _extend_trampoline_route(route, end_node=second_trampoline)

    # Add final edge. note: eclair requires an encrypted t-onion blob even in legacy case.
    # Also needed for fees for last TF!
    if route[-1].end_node != invoice_pubkey:
        _extend_trampoline_route(route, end_node=invoice_pubkey)

    # replace placeholder fees in route
    _allocate_fee_along_route(route, budget=budget, trampoline_fee_level=trampoline_fee_level)

    # check that we can pay amount and fees
    if not is_route_within_budget(
        route=route,
        budget=budget,
        amount_msat_for_dest=amount_msat,
        cltv_delta_for_dest=min_final_cltv_delta,
    ):
        raise NoPathFound("route exceeds budget")
    return route


def create_trampoline_onion(
    *,
    route: LNPaymentTRoute,
    amount_msat: int,
    final_cltv_abs: int,
    total_msat: int,
    payment_hash: bytes,
    payment_secret: bytes,
) -> Tuple[OnionPacket, int, int]:
    # all edges are trampoline
    hops_data, amount_msat, cltv_abs = calc_hops_data_for_payment(
        route,
        amount_msat,
        final_cltv_abs=final_cltv_abs,
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
    trampoline_onion._debug_hops_data = hops_data
    trampoline_onion._debug_route = route
    return trampoline_onion, amount_msat, cltv_abs


def create_trampoline_route_and_onion(
        *,
        amount_msat: int,  # that final receiver gets
        total_msat: int,
        min_final_cltv_delta: int,
        invoice_pubkey: bytes,
        invoice_features,
        my_pubkey: bytes,
        node_id: bytes,
        r_tags,
        payment_hash: bytes,
        payment_secret: bytes,
        local_height: int,
        trampoline_fee_level: int,
        use_two_trampolines: bool,
        failed_routes: Iterable[Sequence[str]],
        budget: PaymentFeeBudget,
) -> Tuple[LNPaymentTRoute, OnionPacket, int, int]:
    # create route for the trampoline_onion
    trampoline_route = create_trampoline_route(
        amount_msat=amount_msat,
        min_final_cltv_delta=min_final_cltv_delta,
        my_pubkey=my_pubkey,
        invoice_pubkey=invoice_pubkey,
        invoice_features=invoice_features,
        my_trampoline=node_id,
        r_tags=r_tags,
        trampoline_fee_level=trampoline_fee_level,
        use_two_trampolines=use_two_trampolines,
        failed_routes=failed_routes,
        budget=budget,
    )
    # compute onion and fees
    final_cltv_abs = local_height + min_final_cltv_delta
    trampoline_onion, amount_with_fees, bucket_cltv_abs = create_trampoline_onion(
        route=trampoline_route,
        amount_msat=amount_msat,
        final_cltv_abs=final_cltv_abs,
        total_msat=total_msat,
        payment_hash=payment_hash,
        payment_secret=payment_secret)
    bucket_cltv_delta = bucket_cltv_abs - local_height
    return trampoline_route, trampoline_onion, amount_with_fees, bucket_cltv_delta
