import asyncio
import copy
import os
from pprint import pformat
from typing import NamedTuple, Tuple, Dict, Mapping, TYPE_CHECKING, Sequence

import electrum
import electrum.trampoline
from electrum import (
    bitcoin, lnpeer, lnchannel, lnutil, util,
)
from electrum.coinchooser import PRNG
from electrum.network import ProxySettings
from electrum.bolt11 import BOLT11Addr
from electrum.lnpeer import Peer
from electrum.lnutil import (
    LnFeatures, PaymentFeeBudget, LOCAL, REMOTE, ChannelType, LocalConfig, RemoteConfig,
    OnlyPubkeyKeypair, secret_to_pubkey,
)
from electrum.lnchannel import ChannelState, Channel
from electrum.lnrouter import LNPathFinder
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNWallet, PaySession
from electrum.simple_config import SimpleConfig
from electrum.stored_dict import StoredDict
from electrum.fee_policy import FeeTimeEstimates, FEE_ETA_TARGETS
from electrum.wallet import  Standard_Wallet

from . import restore_wallet_from_text__for_unittest

if TYPE_CHECKING:
    from . import ElectrumTestCase


class MockNetwork:
    def __init__(self, *, config: SimpleConfig):
        self.lnwatcher = None
        self.interface = None
        self.fee_estimates = FeeTimeEstimates()
        self.populate_fee_estimates()
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.channel_db = ChannelDB(self)
        self.channel_db.data_loaded.set()
        self.path_finder = LNPathFinder(self.channel_db)
        self.lngossip = MockLNGossip()
        self.tx_queue = asyncio.Queue()
        self.proxy = ProxySettings()
        self.is_proxy_tor = None
        self._blockchain = MockBlockchain()

    def get_local_height(self):
        return self.blockchain().height()

    def blockchain(self):
        return self._blockchain

    async def broadcast_transaction(self, tx):
        await self.tx_queue.put(tx)

    async def try_broadcasting(self, tx, name):
        await self.broadcast_transaction(tx)

    def populate_fee_estimates(self):
        for target in FEE_ETA_TARGETS[:-1]:
            self.fee_estimates.set_data(target, 50000 // target)


class MockBlockchain:
    def __init__(self):
        # Let's return a non-zero, realistic height.
        # 0 might hide relative vs abs locktime confusion bugs.
        self._height = 600_000

    def height(self):
       return self._height

    def is_tip_stale(self):
        return False


class MockLNGossip:
    def get_sync_progress_estimate(self):
        return None, None, None


class MockWalletFactory(electrum.wallet.Wallet):

    @staticmethod
    def wallet_class(wallet_type):
        real_wallet_class = electrum.wallet.Wallet.wallet_class(wallet_type)
        if real_wallet_class is Standard_Wallet:
            return MockStandardWallet
        return real_wallet_class


class MockStandardWallet(Standard_Wallet):
    def _init_lnworker(self):
        ln_xprv = self.db.get('lightning_xprv') or self.db.get('lightning_privkey2')
        assert ln_xprv
        self.lnworker = MockLNWallet(self, ln_xprv)

    def basename(self):
        passphrase = self.db.get("keystore").get("passphrase")
        assert passphrase
        return passphrase  # lol, super secure name


def _create_mock_lnwallet(*, name: str, has_anchors: bool, data_dir: str) -> 'MockLNWallet':
    config = SimpleConfig({}, read_user_dir_function=lambda: data_dir)
    config.TEST_LN_OPEN_SRK_CHANNELS = not has_anchors
    config.INITIAL_TRAMPOLINE_FEE_LEVEL = 0

    network = MockNetwork(config=config)

    wallet = restore_wallet_from_text__for_unittest(
        "9dk", path=None, passphrase=name, config=config,
        wallet_factory=MockWalletFactory,
    )['wallet']  # type: MockStandardWallet
    wallet.is_up_to_date = lambda: True
    wallet.adb.network = wallet.network = network

    lnworker = wallet.lnworker
    assert isinstance(lnworker, MockLNWallet), f"{lnworker=!r}"
    lnworker.lnpeermgr.network = network
    lnworker.logger.info(f"created LNWallet[{name}] with nodeID={lnworker.node_keypair.pubkey.hex()}")
    return lnworker


class MockLNWallet(LNWallet):
    MPP_EXPIRY = 2  # HTLC timestamps are cast to int, so this cannot be 1
    TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 0
    MPP_SPLIT_PART_FRACTION = 1  # this disables the forced splitting

    def __init__(self, *args, **kwargs):
        LNWallet.__init__(self, *args, **kwargs)
        self.features &= ~LnFeatures.BASIC_MPP_OPT  # by default, disable MPP

    def _add_channel(self, chan: Channel):
        self._channels[chan.channel_id] = chan
        # assert chan.lnworker == self  # this fails as some tests are reusing chans in a weird way
        chan.lnworker = self

    @LNWallet.features.setter
    def features(self, value):
        self.lnpeermgr.features = value

    @property
    def name(self):
        return self.wallet.basename()

    async def stop(self):
        await LNWallet.stop(self)
        if self.channel_db:
            self.channel_db.stop()
            await self.channel_db.stopped_event.wait()

    async def create_routes_from_invoice(self, amount_msat: int, decoded_invoice: BOLT11Addr, *, full_path=None):
        paysession = PaySession(
            payment_hash=decoded_invoice.paymenthash,
            payment_secret=decoded_invoice.payment_secret,
            initial_trampoline_fee_level=0,
            invoice_features=decoded_invoice.get_features(),
            r_tags=decoded_invoice.get_routing_info('r'),
            min_final_cltv_delta=decoded_invoice.get_min_final_cltv_delta(),
            amount_to_pay=amount_msat,
            invoice_pubkey=decoded_invoice.pubkey.serialize(),
            uses_trampoline=False,
        )
        payment_key = decoded_invoice.paymenthash + decoded_invoice.payment_secret
        self._paysessions[payment_key] = paysession
        return [r async for r in self.create_routes_for_payment(
            amount_msat=amount_msat,
            paysession=paysession,
            full_path=full_path,
            budget=PaymentFeeBudget.from_invoice_amount(invoice_amount_msat=amount_msat, config=self.config),
        )]


class PeerInTests(Peer):
    DELAY_INC_MSG_PROCESSING_SLEEP = 0  # disable rate-limiting


class Graph(NamedTuple):
    workers: Dict[str, 'MockLNWallet']
    peers: Dict[Tuple[str, str], Peer]
    channels: Dict[Tuple[str, str], list[Channel]]


class MockTransport:
    def __init__(self, name):
        self.queue = asyncio.Queue()  # incoming messages
        self._name = name
        self.peer_addr = None

    def name(self):
        return self._name

    async def read_messages(self):
        while True:
            data = await self.queue.get()
            if isinstance(data, asyncio.Event):  # to artificially delay messages
                await data.wait()
                continue
            yield data


class PutIntoOthersQueueTransport(MockTransport):
    def __init__(self, keypair, name):
        super().__init__(name)
        self.other_mock_transport = None
        self.privkey = keypair.privkey

    def send_bytes(self, data):
        self.other_mock_transport.queue.put_nowait(data)

    async def send_bytes_and_drain(self, data):
        self.send_bytes(data)


def transport_pair(k1, k2, name1, name2):
    t1 = PutIntoOthersQueueTransport(k1, name1)
    t2 = PutIntoOthersQueueTransport(k2, name2)
    t1.other_mock_transport = t2
    t2.other_mock_transport = t1
    return t1, t2


def prepare_lnwallets(elec_test_case: 'ElectrumTestCase', graph_definition) -> Mapping[str, MockLNWallet]:
    workers = {}  # type: Dict[str, MockLNWallet]
    for a, definition in graph_definition.items():
        workers[a] = elec_test_case.create_mock_lnwallet(name=a)
    return workers


def prepare_chans_and_peers_in_graph(
    elec_test_case: 'ElectrumTestCase',
    graph_definition=None,
    *,
    workers: Dict[str, MockLNWallet] = None,
    channels: dict[Tuple[str, str], list[Channel]] = None,
) -> Graph:
    from . import test_lnpeer

    if graph_definition is None:
        graph_definition = test_lnpeer._GRAPH_DEFINITIONS['single_chan']
    graph_definition = copy.deepcopy(graph_definition)  # paranoia

    # create workers
    if workers is None:
        workers = prepare_lnwallets(elec_test_case, graph_definition=graph_definition)
    keys = {name: w.node_keypair for name, w in workers.items()}

    if channels is None:
        channels = {}  # type: Dict[Tuple[str, str], list[Channel]]
    transports = {}
    peers = {}  # type: Dict[Tuple[str, str], Peer]

    # create channels
    for a, definition in graph_definition.items():
        for b, channel_def_list in definition.get('channels', {}).items():
            if (a, b) not in channels:
                channels[(a, b)] = []
            if (b, a) not in channels:
                channels[(b, a)] = []
            assert len(channels[(a, b)]) == len(channels[(b, a)])
            for chan_idx, channel_def in enumerate(channel_def_list):
                if chan_idx < len(channels[(a, b)]):  # chan already exists
                    # if either chan direction is present, both must be present
                    channel_ab = channels[(a, b)][chan_idx]
                    channel_ba = channels[(b, a)][chan_idx]
                else:  # create new chans now
                    channel_ab, channel_ba = create_test_channels(
                        alice_lnwallet=workers[a],
                        bob_lnwallet=workers[b],
                        local_msat=channel_def['local_balance_msat'],
                        remote_msat=channel_def['remote_balance_msat'],
                    )
                    assert chan_idx == len(channels[(a, b)]) == len(channels[(b, a)])
                    channels[(a, b)].append(channel_ab)
                    channels[(b, a)].append(channel_ba)
                workers[a]._add_channel(channel_ab)
                workers[b]._add_channel(channel_ba)
                transport_ab, transport_ba = transport_pair(keys[a], keys[b], channel_ab.name, channel_ba.name)
                transports[(a, b)], transports[(b, a)] = transport_ab, transport_ba
                # set fees
                if 'local_fee_rate_millionths' in channel_def:
                    channel_ab.forwarding_fee_proportional_millionths = channel_def['local_fee_rate_millionths']
                if 'local_base_fee_msat' in channel_def:
                    channel_ab.forwarding_fee_base_msat = channel_def['local_base_fee_msat']
                if 'remote_fee_rate_millionths' in channel_def:
                    channel_ba.forwarding_fee_proportional_millionths = channel_def['remote_fee_rate_millionths']
                if 'remote_base_fee_msat' in channel_def:
                    channel_ba.forwarding_fee_base_msat = channel_def['remote_base_fee_msat']

    # create peers
    for ab in channels.keys():
        peers[ab] = PeerInTests(workers[ab[0]], keys[ab[1]].pubkey, transports[ab])

    # add peers to workers
    for a, w in workers.items():
        for ab, peer_ab in peers.items():
            if ab[0] == a:
                w.lnpeermgr._peers[peer_ab.pubkey] = peer_ab

    # set forwarding properties
    for a, definition in graph_definition.items():
        for property in definition.get('config', {}).items():
            workers[a].network.config.set_key(*property)

    # mark_open won't work if state is already OPEN.
    # so set it to FUNDED
    for chan_list in channels.values():
        for chan in chan_list:
            chan._state = ChannelState.FUNDED

    # this populates the channel graph:
    for ab, peer_ab in peers.items():
        for chan in channels[ab]:
            peer_ab.mark_open(chan)

    graph = Graph(
        workers=workers,
        peers=peers,
        channels=channels,
    )
    for a in workers:
        print(f"{a:5s}: {keys[a].pubkey}")
        print(f"       {keys[a].pubkey.hex()}")
    return graph


def _convert_to_rconfig_from_lconfig(lconfig: LocalConfig) -> RemoteConfig:
    """converts Alice's local config to Bob's remote config (neutering private keys, etc)"""
    ctn = 0
    pcp_secret = lnutil.get_per_commitment_secret_from_seed(
        lconfig.per_commitment_secret_seed,
        lnutil.RevocationStore.START_INDEX - ctn)
    pcp_point = secret_to_pubkey(int.from_bytes(pcp_secret, 'big'))
    rconfig = RemoteConfig(
        payment_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.payment_basepoint.pubkey),
        multisig_key=OnlyPubkeyKeypair(pubkey=lconfig.multisig_key.pubkey),
        htlc_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.htlc_basepoint.pubkey),
        delayed_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.delayed_basepoint.pubkey),
        revocation_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.revocation_basepoint.pubkey),
        to_self_delay=lconfig.to_self_delay,
        dust_limit_sat=lconfig.dust_limit_sat,
        max_htlc_value_in_flight_msat=lconfig.max_htlc_value_in_flight_msat,
        max_accepted_htlcs=lconfig.max_accepted_htlcs,
        initial_msat=lconfig.initial_msat,
        reserve_sat=lconfig.reserve_sat,
        htlc_minimum_msat=lconfig.htlc_minimum_msat,
        upfront_shutdown_script=lconfig.upfront_shutdown_script,
        announcement_node_sig=lconfig.announcement_node_sig,
        announcement_bitcoin_sig=lconfig.announcement_bitcoin_sig,
        next_per_commitment_point=pcp_point,
        current_per_commitment_point=None,
    )
    return rconfig


def _create_channel_state(
    *,
    funding_txid: str,
    funding_index: int,
    funding_sat: int,
    is_initiator: bool,
    other_node_id: bytes,
    channel_type: ChannelType,
    local_config: LocalConfig,
    remote_config: RemoteConfig,
):
    channel_id, _ = lnpeer.channel_id_from_funding_tx(funding_txid, funding_index)
    state = {
            "channel_id":channel_id.hex(),
            "short_channel_id":channel_id[:8],
            "funding_outpoint":lnpeer.Outpoint(funding_txid, funding_index),
            "remote_config": remote_config,
            "local_config": local_config,
            "constraints":lnpeer.ChannelConstraints(
                flags=lnchannel.CF_ANNOUNCE_CHANNEL,
                capacity=funding_sat,
                is_initiator=is_initiator,
                funding_txn_minimum_depth=3,
            ),
            "node_id":other_node_id.hex(),
            'onion_keys': {},
            'data_loss_protect_remote_pcp': {},
            'state': 'PREOPENING',
            'log': {},
            'unfulfilled_htlcs': {},
            'revocation_store': {},
            'channel_type': channel_type,
    }
    return StoredDict(state, None)


def create_test_channels(
    *,
    alice_lnwallet: 'MockLNWallet',
    bob_lnwallet: 'MockLNWallet',
    feerate=6000,
    local_msat=None,
    remote_msat=None,
    random_seed=None,
    local_max_inflight=None,
    remote_max_inflight=None,
    max_accepted_htlcs=5,
) -> tuple[Channel, Channel]:
    if random_seed is None:  # needed for deterministic randomness
        random_seed = os.urandom(32)
    random_gen = PRNG(random_seed)
    alice_name = alice_lnwallet.name
    bob_name = bob_lnwallet.name
    alice_pubkey = alice_lnwallet.node_keypair.pubkey
    bob_pubkey = bob_lnwallet.node_keypair.pubkey
    funding_txid = random_gen.get_bytes(32).hex()
    funding_index = 0
    funding_sat = ((local_msat + remote_msat) // 1000) if local_msat is not None and remote_msat is not None else (bitcoin.COIN * 10)
    local_msat = local_msat if local_msat is not None else (funding_sat * 1000 // 2)
    remote_msat = remote_msat if remote_msat is not None else (funding_sat * 1000 // 2)
    local_max_inflight = funding_sat * 1000 if local_max_inflight is None else local_max_inflight
    remote_max_inflight = funding_sat * 1000 if remote_max_inflight is None else remote_max_inflight

    for config in [alice_lnwallet.config, bob_lnwallet.config]:
        config.LIGHTNING_MAX_FUNDING_SAT = max(config.LIGHTNING_MAX_FUNDING_SAT, funding_sat)

    peer_features = alice_lnwallet.features | LnFeatures.OPTION_SUPPORT_LARGE_CHANNEL_OPT
    assert alice_lnwallet.config.TEST_LN_OPEN_SRK_CHANNELS == bob_lnwallet.config.TEST_LN_OPEN_SRK_CHANNELS
    if alice_lnwallet.config.TEST_LN_OPEN_SRK_CHANNELS:
        channel_type = ChannelType.OPTION_STATIC_REMOTEKEY
    else:
        channel_type = ChannelType.OPTION_STATIC_REMOTEKEY | ChannelType.OPTION_ANCHORS
    # create alice's local config
    alice_lconfig = alice_lnwallet.make_local_config_for_new_channel(
        funding_sat=funding_sat,
        push_msat=remote_msat,
        initiator=LOCAL,
        channel_type=channel_type,
        multisig_funding_keypair=None,
        peer_features=peer_features,
        channel_seed=random_gen.get_bytes(32),
    )
    alice_lconfig.funding_locked_received = True
    alice_lconfig.dust_limit_sat = 200
    alice_lconfig.to_self_delay = 5
    alice_lconfig.reserve_sat = 0
    alice_lconfig.max_accepted_htlcs = max_accepted_htlcs
    alice_lconfig.max_htlc_value_in_flight_msat = local_max_inflight
    # create bob's local config
    bob_lconfig = bob_lnwallet.make_local_config_for_new_channel(
        funding_sat=funding_sat,
        push_msat=remote_msat,
        initiator=REMOTE,
        channel_type=channel_type,
        multisig_funding_keypair=None,
        peer_features=peer_features,
        channel_seed=random_gen.get_bytes(32),
    )
    bob_lconfig.funding_locked_received = True
    bob_lconfig.dust_limit_sat = 1300
    bob_lconfig.to_self_delay = 4
    bob_lconfig.reserve_sat = 0
    bob_lconfig.max_accepted_htlcs = max_accepted_htlcs
    bob_lconfig.max_htlc_value_in_flight_msat = remote_max_inflight

    alice, bob = (
        lnchannel.Channel(
            _create_channel_state(
                funding_txid=funding_txid,
                funding_index=funding_index,
                funding_sat=funding_sat,
                is_initiator=True,
                other_node_id=bob_pubkey,
                channel_type=channel_type,
                local_config=alice_lconfig,
                remote_config=_convert_to_rconfig_from_lconfig(bob_lconfig),
            ),
            name=f"{alice_name}->{bob_name}",
            initial_feerate=feerate,
            lnworker=alice_lnwallet,
        ),
        lnchannel.Channel(
            _create_channel_state(
                funding_txid=funding_txid,
                funding_index=funding_index,
                funding_sat=funding_sat,
                is_initiator=False,
                other_node_id=alice_pubkey,
                channel_type=channel_type,
                local_config=bob_lconfig,
                remote_config=_convert_to_rconfig_from_lconfig(alice_lconfig),
            ),
            name=f"{bob_name}->{alice_name}",
            initial_feerate=feerate,
            lnworker=bob_lnwallet,
        )
    )

    alice.hm.log[LOCAL]['ctn'] = 0
    bob.hm.log[LOCAL]['ctn'] = 0

    alice._state = ChannelState.OPEN
    bob._state = ChannelState.OPEN

    a_out = alice.get_latest_commitment(LOCAL).outputs()
    b_out = bob.get_next_commitment(REMOTE).outputs()
    assert a_out == b_out, "\n" + pformat((a_out, b_out))

    sig_from_bob, a_htlc_sigs = bob.sign_next_commitment()
    sig_from_alice, b_htlc_sigs = alice.sign_next_commitment()

    assert len(a_htlc_sigs) == 0
    assert len(b_htlc_sigs) == 0

    alice.open_with_first_pcp(alice.config[REMOTE].next_per_commitment_point, sig_from_bob)
    bob.open_with_first_pcp(bob.config[REMOTE].next_per_commitment_point, sig_from_alice)

    alice_second = lnutil.secret_to_pubkey(int.from_bytes(
        lnutil.get_per_commitment_secret_from_seed(alice.config[LOCAL].per_commitment_secret_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))
    bob_second = lnutil.secret_to_pubkey(int.from_bytes(
        lnutil.get_per_commitment_secret_from_seed(bob.config[LOCAL].per_commitment_secret_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))

    # from funding_locked:
    alice.config[REMOTE].next_per_commitment_point = bob_second
    bob.config[REMOTE].next_per_commitment_point = alice_second

    alice._fallback_sweep_address = bitcoin.pubkey_to_address('p2wpkh', alice.config[LOCAL].payment_basepoint.pubkey.hex())
    bob._fallback_sweep_address = bitcoin.pubkey_to_address('p2wpkh', bob.config[LOCAL].payment_basepoint.pubkey.hex())

    assert alice.channel_id == bob.channel_id

    return alice, bob
