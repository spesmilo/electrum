#!/usr/bin/env python3
#
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import zlib
from collections import OrderedDict, defaultdict
import json
import asyncio
import os
import time
from functools import partial
from typing import List, Tuple, Dict, TYPE_CHECKING, Optional, Callable, Union
import traceback
import sys
from datetime import datetime

import aiorpcx

from .crypto import sha256, sha256d
from . import bitcoin
from . import ecc
from .ecc import sig_string_from_r_and_s, get_r_and_s_from_sig_string, der_sig_from_sig_string
from . import constants
from .util import bh2u, bfh, log_exceptions, list_enabled_bits, ignore_exceptions, chunks, SilentTaskGroup
from .transaction import Transaction, TxOutput, PartialTxOutput
from .logging import Logger
from .lnonion import (new_onion_packet, decode_onion_error, OnionFailureCode, calc_hops_data_for_payment,
                      process_onion_packet, OnionPacket, construct_onion_error, OnionRoutingFailureMessage,
                      ProcessedOnionPacket)
from .lnchannel import Channel, RevokeAndAck, htlcsum, RemoteCtnTooFarInFuture, channel_states, peer_states
from . import lnutil
from .lnutil import (Outpoint, LocalConfig, RECEIVED, UpdateAddHtlc,
                     RemoteConfig, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore,
                     funding_output_script, get_per_commitment_secret_from_seed,
                     secret_to_pubkey, PaymentFailure, LnLocalFeatures,
                     LOCAL, REMOTE, HTLCOwner, generate_keypair, LnKeyFamily,
                     get_ln_flag_pair_of_bit, privkey_to_pubkey, UnknownPaymentHash, MIN_FINAL_CLTV_EXPIRY_ACCEPTED,
                     LightningPeerConnectionClosed, HandshakeFailed, NotFoundChanAnnouncementForUpdate,
                     MINIMUM_MAX_HTLC_VALUE_IN_FLIGHT_ACCEPTED, MAXIMUM_HTLC_MINIMUM_MSAT_ACCEPTED,
                     MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED, RemoteMisbehaving, DEFAULT_TO_SELF_DELAY,
                     NBLOCK_OUR_CLTV_EXPIRY_DELTA, format_short_channel_id, ShortChannelID)
from .lnutil import FeeUpdate
from .lntransport import LNTransport, LNTransportBase
from .lnmsg import encode_msg, decode_msg
from .interface import GracefulDisconnect, NetworkException
from .lnrouter import fee_for_edge_msat
from .lnutil import ln_dummy_address

if TYPE_CHECKING:
    from .lnworker import LNWorker, LNGossip, LNWallet
    from .lnrouter import RouteEdge, LNPaymentRoute
    from .transaction import PartialTransaction


LN_P2P_NETWORK_TIMEOUT = 20


def channel_id_from_funding_tx(funding_txid: str, funding_index: int) -> Tuple[bytes, bytes]:
    funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
    i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
    return i.to_bytes(32, 'big'), funding_txid_bytes

class Peer(Logger):

    def __init__(self, lnworker: Union['LNGossip', 'LNWallet'], pubkey:bytes, transport: LNTransportBase):
        self._sent_init = False  # type: bool
        self._received_init = False  # type: bool
        self.initialized = asyncio.Event()
        self.querying = asyncio.Event()
        self.transport = transport
        self.pubkey = pubkey  # remote pubkey
        self.lnworker = lnworker
        self.privkey = lnworker.node_keypair.privkey  # local privkey
        self.localfeatures = self.lnworker.localfeatures
        self.node_ids = [self.pubkey, privkey_to_pubkey(self.privkey)]
        self.network = lnworker.network
        self.channel_db = lnworker.network.channel_db
        self.ping_time = 0
        self.reply_channel_range = asyncio.Queue()
        # gossip uses a single queue to preserve message order
        self.gossip_queue = asyncio.Queue()
        # channel messsage queues
        self.shutdown_received = defaultdict(asyncio.Future)
        self.channel_accepted = defaultdict(asyncio.Queue)
        self.channel_reestablished = defaultdict(asyncio.Queue)
        self.funding_signed = defaultdict(asyncio.Queue)
        self.funding_created = defaultdict(asyncio.Queue)
        self.announcement_signatures = defaultdict(asyncio.Queue)
        self.closing_signed = defaultdict(asyncio.Queue)
        #
        self.orphan_channel_updates = OrderedDict()
        self._local_changed_events = defaultdict(asyncio.Event)
        self._remote_changed_events = defaultdict(asyncio.Event)
        Logger.__init__(self)
        self.group = SilentTaskGroup()

    def send_message(self, message_name: str, **kwargs):
        assert type(message_name) is str
        self.logger.debug(f"Sending {message_name.upper()}")
        if message_name.upper() != "INIT" and not self.initialized.is_set():
            raise Exception("tried to send message before we are initialized")
        raw_msg = encode_msg(message_name, **kwargs)
        self._store_raw_msg_if_local_update(raw_msg, message_name=message_name, channel_id=kwargs.get("channel_id"))
        self.transport.send_bytes(raw_msg)

    def _store_raw_msg_if_local_update(self, raw_msg: bytes, *, message_name: str, channel_id: Optional[bytes]):
        is_commitment_signed = message_name == "commitment_signed"
        if not (message_name.startswith("update_") or is_commitment_signed):
            return
        assert channel_id
        chan = self.lnworker.channels[channel_id]  # type: Channel
        chan.hm.store_local_update_raw_msg(raw_msg, is_commitment_signed=is_commitment_signed)
        if is_commitment_signed:
            # saving now, to ensure replaying updates works (in case of channel reestablishment)
            self.lnworker.save_channel(chan)

    async def initialize(self):
        if isinstance(self.transport, LNTransport):
            await self.transport.handshake()
        self.send_message("init", gflen=0, lflen=1, localfeatures=self.localfeatures)
        self._sent_init = True

    @property
    def channels(self) -> Dict[bytes, Channel]:
        return self.lnworker.channels_for_peer(self.pubkey)

    def diagnostic_name(self):
        return self.transport.name()

    def ping_if_required(self):
        if time.time() - self.ping_time > 120:
            self.send_message('ping', num_pong_bytes=4, byteslen=4)
            self.ping_time = time.time()

    def process_message(self, message):
        message_type, payload = decode_msg(message)
        try:
            f = getattr(self, 'on_' + message_type)
        except AttributeError:
            #self.logger.info("Received '%s'" % message_type.upper(), payload)
            return
        # raw message is needed to check signature
        if message_type in ['node_announcement', 'channel_announcement', 'channel_update']:
            payload['raw'] = message
        execution_result = f(payload)
        if asyncio.iscoroutinefunction(f):
            asyncio.ensure_future(execution_result)

    def on_error(self, payload):
        self.logger.info(f"on_error: {payload['data'].decode('ascii')}")
        chan_id = payload.get("channel_id")
        for d in [ self.channel_accepted, self.funding_signed,
                   self.funding_created, self.channel_reestablished,
                   self.announcement_signatures, self.closing_signed ]:
            if chan_id in d:
                d[chan_id].put_nowait({'error':payload['data']})

    def on_ping(self, payload):
        l = int.from_bytes(payload['num_pong_bytes'], 'big')
        self.send_message('pong', byteslen=l)

    def on_pong(self, payload):
        pass

    def on_accept_channel(self, payload):
        temp_chan_id = payload["temporary_channel_id"]
        if temp_chan_id not in self.channel_accepted:
            raise Exception("Got unknown accept_channel")
        self.channel_accepted[temp_chan_id].put_nowait(payload)

    def on_funding_signed(self, payload):
        channel_id = payload['channel_id']
        if channel_id not in self.funding_signed: raise Exception("Got unknown funding_signed")
        self.funding_signed[channel_id].put_nowait(payload)

    def on_funding_created(self, payload):
        channel_id = payload['temporary_channel_id']
        if channel_id not in self.funding_created: raise Exception("Got unknown funding_created")
        self.funding_created[channel_id].put_nowait(payload)

    def on_init(self, payload):
        if self._received_init:
            self.logger.info("ALREADY INITIALIZED BUT RECEIVED INIT")
            return
        # if they required some even flag we don't have, they will close themselves
        # but if we require an even flag they don't have, we close
        their_localfeatures = int.from_bytes(payload['localfeatures'], byteorder="big")
        our_flags = set(list_enabled_bits(self.localfeatures))
        their_flags = set(list_enabled_bits(their_localfeatures))
        for flag in our_flags:
            if flag not in their_flags and get_ln_flag_pair_of_bit(flag) not in their_flags:
                # they don't have this feature we wanted :(
                if flag % 2 == 0:  # even flags are compulsory
                    raise GracefulDisconnect("remote does not have even flag {}"
                                             .format(str(LnLocalFeatures(1 << flag))))
                self.localfeatures ^= 1 << flag  # disable flag
            else:
                # They too have this flag.
                # For easier feature-bit-testing, if this is an even flag, we also
                # set the corresponding odd flag now.
                if flag % 2 == 0 and self.localfeatures & (1 << flag):
                    self.localfeatures |= 1 << get_ln_flag_pair_of_bit(flag)
        if isinstance(self.transport, LNTransport):
            self.channel_db.add_recent_peer(self.transport.peer_addr)
        self._received_init = True
        if self._sent_init and self._received_init:
            self.initialized.set()

    def on_node_announcement(self, payload):
        self.gossip_queue.put_nowait(('node_announcement', payload))

    def on_channel_announcement(self, payload):
        self.gossip_queue.put_nowait(('channel_announcement', payload))

    def on_channel_update(self, payload):
        self.maybe_save_remote_update(payload)
        self.gossip_queue.put_nowait(('channel_update', payload))

    def maybe_save_remote_update(self, payload):
        for chan in self.channels.values():
            if chan.short_channel_id == payload['short_channel_id']:
                chan.remote_update = payload['raw']
                self.logger.info("saved remote_update")

    def on_announcement_signatures(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels[payload['channel_id']]
        if chan.config[LOCAL].was_announced:
            h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        else:
            self.announcement_signatures[channel_id].put_nowait(payload)

    def handle_disconnect(func):
        async def wrapper_func(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except GracefulDisconnect as e:
                self.logger.log(e.log_level, f"Disconnecting: {repr(e)}")
            except LightningPeerConnectionClosed as e:
                self.logger.info(f"Disconnecting: {repr(e)}")
            finally:
                self.close_and_cleanup()
        return wrapper_func

    @ignore_exceptions  # do not kill main_taskgroup
    @log_exceptions
    @handle_disconnect
    async def main_loop(self):
        async with self.group as group:
            await group.spawn(self._message_loop())
            await group.spawn(self.query_gossip())
            await group.spawn(self.process_gossip())

    async def process_gossip(self):
        await self.channel_db.data_loaded.wait()
        # verify in peer's TaskGroup so that we fail the connection
        while True:
            await asyncio.sleep(5)
            chan_anns = []
            chan_upds = []
            node_anns = []
            while True:
                name, payload = await self.gossip_queue.get()
                if name == 'channel_announcement':
                    chan_anns.append(payload)
                elif name == 'channel_update':
                    chan_upds.append(payload)
                elif name == 'node_announcement':
                    node_anns.append(payload)
                else:
                    raise Exception('unknown message')
                if self.gossip_queue.empty():
                    break
            self.logger.debug(f'process_gossip {len(chan_anns)} {len(node_anns)} {len(chan_upds)}')
            # note: data processed in chunks to avoid taking sql lock for too long
            # channel announcements
            for chan_anns_chunk in chunks(chan_anns, 300):
                self.verify_channel_announcements(chan_anns_chunk)
                self.channel_db.add_channel_announcement(chan_anns_chunk)
            # node announcements
            for node_anns_chunk in chunks(node_anns, 100):
                self.verify_node_announcements(node_anns_chunk)
                self.channel_db.add_node_announcement(node_anns_chunk)
            # channel updates
            for chan_upds_chunk in chunks(chan_upds, 1000):
                categorized_chan_upds = self.channel_db.add_channel_updates(
                    chan_upds_chunk, max_age=self.network.lngossip.max_age)
                orphaned = categorized_chan_upds.orphaned
                if orphaned:
                    self.logger.info(f'adding {len(orphaned)} unknown channel ids')
                    orphaned_ids = [c['short_channel_id'] for c in orphaned]
                    await self.network.lngossip.add_new_ids(orphaned_ids)
                    # Save (some bounded number of) orphan channel updates for later
                    # as it might be for our own direct channel with this peer
                    # (and we might not yet know the short channel id for that)
                    for chan_upd_payload in orphaned:
                        short_channel_id = ShortChannelID(chan_upd_payload['short_channel_id'])
                        self.orphan_channel_updates[short_channel_id] = chan_upd_payload
                        while len(self.orphan_channel_updates) > 25:
                            self.orphan_channel_updates.popitem(last=False)
                if categorized_chan_upds.good:
                    self.logger.debug(f'on_channel_update: {len(categorized_chan_upds.good)}/{len(chan_upds_chunk)}')

    def verify_channel_announcements(self, chan_anns):
        for payload in chan_anns:
            h = sha256d(payload['raw'][2+256:])
            pubkeys = [payload['node_id_1'], payload['node_id_2'], payload['bitcoin_key_1'], payload['bitcoin_key_2']]
            sigs = [payload['node_signature_1'], payload['node_signature_2'], payload['bitcoin_signature_1'], payload['bitcoin_signature_2']]
            for pubkey, sig in zip(pubkeys, sigs):
                if not ecc.verify_signature(pubkey, sig, h):
                    raise Exception('signature failed')

    def verify_node_announcements(self, node_anns):
        for payload in node_anns:
            pubkey = payload['node_id']
            signature = payload['signature']
            h = sha256d(payload['raw'][66:])
            if not ecc.verify_signature(pubkey, signature, h):
                raise Exception('signature failed')

    async def query_gossip(self):
        try:
            await asyncio.wait_for(self.initialized.wait(), LN_P2P_NETWORK_TIMEOUT)
        except asyncio.TimeoutError as e:
            raise GracefulDisconnect("initialize timed out") from e
        if self.lnworker == self.lnworker.network.lngossip:
            try:
                ids, complete = await asyncio.wait_for(self.get_channel_range(), LN_P2P_NETWORK_TIMEOUT)
            except asyncio.TimeoutError as e:
                raise GracefulDisconnect("query_channel_range timed out") from e
            self.logger.info('Received {} channel ids. (complete: {})'.format(len(ids), complete))
            await self.lnworker.add_new_ids(ids)
            while True:
                todo = self.lnworker.get_ids_to_query()
                if not todo:
                    await asyncio.sleep(1)
                    continue
                await self.get_short_channel_ids(todo)

    async def get_channel_range(self):
        first_block = constants.net.BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS
        num_blocks = self.lnworker.network.get_local_height() - first_block
        self.query_channel_range(first_block, num_blocks)
        intervals = []
        ids = set()
        # note: implementations behave differently...
        # "sane implementation that follows BOLT-07" example:
        #   query_channel_range. <<< first_block 497000, num_blocks 79038
        #   on_reply_channel_range. >>> first_block 497000, num_blocks 39516, num_ids 4648, complete True
        #   on_reply_channel_range. >>> first_block 536516, num_blocks 19758, num_ids 5734, complete True
        #   on_reply_channel_range. >>> first_block 556274, num_blocks 9879, num_ids 13712, complete True
        #   on_reply_channel_range. >>> first_block 566153, num_blocks 9885, num_ids 18114, complete True
        # lnd example:
        #   query_channel_range. <<< first_block 497000, num_blocks 79038
        #   on_reply_channel_range. >>> first_block 497000, num_blocks 79038, num_ids 8000, complete False
        #   on_reply_channel_range. >>> first_block 497000, num_blocks 79038, num_ids 8000, complete False
        #   on_reply_channel_range. >>> first_block 497000, num_blocks 79038, num_ids 8000, complete False
        #   on_reply_channel_range. >>> first_block 497000, num_blocks 79038, num_ids 8000, complete False
        #   on_reply_channel_range. >>> first_block 497000, num_blocks 79038, num_ids 5344, complete True
        while True:
            index, num, complete, _ids = await self.reply_channel_range.get()
            ids.update(_ids)
            intervals.append((index, index+num))
            intervals.sort()
            while len(intervals) > 1:
                a,b = intervals[0]
                c,d = intervals[1]
                if not (a <= c and a <= b and c <= d):
                    raise Exception(f"insane reply_channel_range intervals {(a,b,c,d)}")
                if b >= c:
                    intervals = [(a,d)] + intervals[2:]
                else:
                    break
            if len(intervals) == 1 and complete:
                a, b = intervals[0]
                if a <= first_block and b >= first_block + num_blocks:
                    break
        return ids, complete

    def request_gossip(self, timestamp=0):
        if timestamp == 0:
            self.logger.info('requesting whole channel graph')
        else:
            self.logger.info(f'requesting channel graph since {datetime.fromtimestamp(timestamp).ctime()}')
        self.send_message(
            'gossip_timestamp_filter',
            chain_hash=constants.net.rev_genesis_bytes(),
            first_timestamp=timestamp,
            timestamp_range=b'\xff'*4)

    def query_channel_range(self, first_block, num_blocks):
        self.logger.info(f'query channel range {first_block} {num_blocks}')
        self.send_message(
            'query_channel_range',
            chain_hash=constants.net.rev_genesis_bytes(),
            first_blocknum=first_block,
            number_of_blocks=num_blocks)

    def encode_short_ids(self, ids):
        return chr(1) + zlib.compress(bfh(''.join(ids)))

    def decode_short_ids(self, encoded):
        if encoded[0] == 0:
            decoded = encoded[1:]
        elif encoded[0] == 1:
            decoded = zlib.decompress(encoded[1:])
        else:
            raise Exception(f'decode_short_ids: unexpected first byte: {encoded[0]}')
        ids = [decoded[i:i+8] for i in range(0, len(decoded), 8)]
        return ids

    def on_reply_channel_range(self, payload):
        first = int.from_bytes(payload['first_blocknum'], 'big')
        num = int.from_bytes(payload['number_of_blocks'], 'big')
        complete = bool(int.from_bytes(payload['complete'], 'big'))
        encoded = payload['encoded_short_ids']
        ids = self.decode_short_ids(encoded)
        #self.logger.info(f"on_reply_channel_range. >>> first_block {first}, num_blocks {num}, num_ids {len(ids)}, complete {repr(payload['complete'])}")
        self.reply_channel_range.put_nowait((first, num, complete, ids))

    async def get_short_channel_ids(self, ids):
        self.logger.info(f'Querying {len(ids)} short_channel_ids')
        assert not self.querying.is_set()
        self.query_short_channel_ids(ids)
        await self.querying.wait()
        self.querying.clear()

    def query_short_channel_ids(self, ids, compressed=True):
        ids = sorted(ids)
        s = b''.join(ids)
        encoded = zlib.compress(s) if compressed else s
        prefix = b'\x01' if compressed else b'\x00'
        self.send_message(
            'query_short_channel_ids',
            chain_hash=constants.net.rev_genesis_bytes(),
            len=1+len(encoded),
            encoded_short_ids=prefix+encoded)

    async def _message_loop(self):
        try:
            await asyncio.wait_for(self.initialize(), LN_P2P_NETWORK_TIMEOUT)
        except (OSError, asyncio.TimeoutError, HandshakeFailed) as e:
            raise GracefulDisconnect(f'initialize failed: {repr(e)}') from e
        if self._sent_init and self._received_init:
            self.initialized.set()
        async for msg in self.transport.read_messages():
            self.process_message(msg)
            await asyncio.sleep(.01)
            self.ping_if_required()

    def on_reply_short_channel_ids_end(self, payload):
        self.querying.set()

    def close_and_cleanup(self):
        try:
            if self.transport:
                self.transport.close()
        except:
            pass
        self.lnworker.peer_closed(self)

    def make_local_config(self, funding_sat: int, push_msat: int, initiator: HTLCOwner) -> LocalConfig:
        # key derivation
        channel_counter = self.lnworker.get_and_inc_counter_for_channel_keys()
        keypair_generator = lambda family: generate_keypair(self.lnworker.ln_keystore, family, channel_counter)
        if initiator == LOCAL:
            initial_msat = funding_sat * 1000 - push_msat
        else:
            initial_msat = push_msat
        local_config=LocalConfig(
            payment_basepoint=keypair_generator(LnKeyFamily.PAYMENT_BASE),
            multisig_key=keypair_generator(LnKeyFamily.MULTISIG),
            htlc_basepoint=keypair_generator(LnKeyFamily.HTLC_BASE),
            delayed_basepoint=keypair_generator(LnKeyFamily.DELAY_BASE),
            revocation_basepoint=keypair_generator(LnKeyFamily.REVOCATION_BASE),
            to_self_delay=DEFAULT_TO_SELF_DELAY,
            dust_limit_sat=546,
            max_htlc_value_in_flight_msat=funding_sat * 1000,
            max_accepted_htlcs=5,
            initial_msat=initial_msat,
            reserve_sat=546,
            per_commitment_secret_seed=keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey,
            funding_locked_received=False,
            was_announced=False,
            current_commitment_signature=None,
            current_htlc_signatures=b'',
        )
        return local_config

    @log_exceptions
    async def channel_establishment_flow(self, password: Optional[str], funding_tx: 'PartialTransaction', funding_sat: int, 
                                         push_msat: int, temp_channel_id: bytes) -> Tuple[Channel, 'PartialTransaction']:
        await asyncio.wait_for(self.initialized.wait(), LN_P2P_NETWORK_TIMEOUT)
        feerate = self.lnworker.current_feerate_per_kw()
        local_config = self.make_local_config(funding_sat, push_msat, LOCAL)
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(local_config.per_commitment_secret_seed,
                                                                          RevocationStore.START_INDEX)
        per_commitment_point_first = secret_to_pubkey(int.from_bytes(per_commitment_secret_first, 'big'))
        self.send_message(
            "open_channel",
            temporary_channel_id=temp_channel_id,
            chain_hash=constants.net.rev_genesis_bytes(),
            funding_satoshis=funding_sat,
            push_msat=push_msat,
            dust_limit_satoshis=local_config.dust_limit_sat,
            feerate_per_kw=feerate,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
            to_self_delay=local_config.to_self_delay,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_flags=0x00,  # not willing to announce channel
            channel_reserve_satoshis=local_config.reserve_sat,
            htlc_minimum_msat=1,
        )
        payload = await asyncio.wait_for(self.channel_accepted[temp_channel_id].get(), LN_P2P_NETWORK_TIMEOUT)
        if payload.get('error'):
            raise Exception('Remote Lightning peer reported error: ' + repr(payload.get('error')))
        remote_per_commitment_point = payload['first_per_commitment_point']
        funding_txn_minimum_depth = int.from_bytes(payload['minimum_depth'], 'big')
        if funding_txn_minimum_depth <= 0:
            raise Exception(f"minimum depth too low, {funding_txn_minimum_depth}")
        if funding_txn_minimum_depth > 30:
            raise Exception(f"minimum depth too high, {funding_txn_minimum_depth}")
        remote_dust_limit_sat = int.from_bytes(payload['dust_limit_satoshis'], byteorder='big')
        remote_reserve_sat = self.validate_remote_reserve(payload["channel_reserve_satoshis"], remote_dust_limit_sat, funding_sat)
        if remote_dust_limit_sat > remote_reserve_sat:
            raise Exception(f"Remote Lightning peer reports dust_limit_sat > reserve_sat which is a BOLT-02 protocol violation.")
        htlc_min = int.from_bytes(payload['htlc_minimum_msat'], 'big')
        if htlc_min > MAXIMUM_HTLC_MINIMUM_MSAT_ACCEPTED:
            raise Exception(f"Remote Lightning peer reports htlc_minimum_msat={htlc_min} mSAT," +
                    f" which is above Electrums required maximum limit of that parameter ({MAXIMUM_HTLC_MINIMUM_MSAT_ACCEPTED} mSAT).")
        remote_max = int.from_bytes(payload['max_htlc_value_in_flight_msat'], 'big')
        if remote_max < MINIMUM_MAX_HTLC_VALUE_IN_FLIGHT_ACCEPTED:
            raise Exception(f"Remote Lightning peer reports max_htlc_value_in_flight_msat at only {remote_max} mSAT" +
                    f" which is below Electrums required minimum ({MINIMUM_MAX_HTLC_VALUE_IN_FLIGHT_ACCEPTED} mSAT).")
        max_accepted_htlcs = int.from_bytes(payload["max_accepted_htlcs"], 'big')
        if max_accepted_htlcs > 483:
            raise Exception("Remote Lightning peer reports max_accepted_htlcs > 483, which is a BOLT-02 protocol violation.")
        remote_to_self_delay = int.from_bytes(payload['to_self_delay'], byteorder='big')
        if remote_to_self_delay > MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED:
            raise Exception(f"Remote Lightning peer reports to_self_delay={remote_to_self_delay}," +
                    f" which is above Electrums required maximum ({MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED})")
        their_revocation_store = RevocationStore()
        remote_config = RemoteConfig(
            payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
            multisig_key=OnlyPubkeyKeypair(payload["funding_pubkey"]),
            htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
            delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
            revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
            to_self_delay=remote_to_self_delay,
            dust_limit_sat=remote_dust_limit_sat,
            max_htlc_value_in_flight_msat=remote_max,
            max_accepted_htlcs=max_accepted_htlcs,
            initial_msat=push_msat,
            reserve_sat = remote_reserve_sat,
            htlc_minimum_msat = htlc_min,
            next_per_commitment_point=remote_per_commitment_point,
            current_per_commitment_point=None,
            revocation_store=their_revocation_store,
        )
        # replace dummy output in funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = PartialTxOutput.from_address_and_value(funding_address, funding_sat)
        dummy_output = PartialTxOutput.from_address_and_value(ln_dummy_address(), funding_sat)
        funding_tx.outputs().remove(dummy_output)
        funding_tx.add_outputs([funding_output])
        funding_tx.set_rbf(False)
        self.lnworker.wallet.sign_transaction(funding_tx, password)
        if not funding_tx.is_complete() and not funding_tx.is_segwit():
            raise Exception('Funding transaction is not complete')
        funding_txid = funding_tx.txid()
        assert funding_txid
        funding_index = funding_tx.outputs().index(funding_output)
        # remote commitment transaction
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_index)
        chan_dict = {
            "node_id": self.pubkey,
            "channel_id": channel_id,
            "short_channel_id": None,
            "funding_outpoint": Outpoint(funding_txid, funding_index),
            "remote_config": remote_config,
            "local_config": local_config,
            "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=True, funding_txn_minimum_depth=funding_txn_minimum_depth),
            "remote_update": None,
            "state": channel_states.PREOPENING.name,
        }
        chan = Channel(chan_dict,
                       sweep_address=self.lnworker.sweep_address,
                       lnworker=self.lnworker,
                       initial_feerate=feerate)
        sig_64, _ = chan.sign_next_commitment()
        self.send_message("funding_created",
            temporary_channel_id=temp_channel_id,
            funding_txid=funding_txid_bytes,
            funding_output_index=funding_index,
            signature=sig_64)
        payload = await asyncio.wait_for(self.funding_signed[channel_id].get(), LN_P2P_NETWORK_TIMEOUT)
        self.logger.info('received funding_signed')
        remote_sig = payload['signature']
        chan.receive_new_commitment(remote_sig, [])
        chan.open_with_first_pcp(remote_per_commitment_point, remote_sig)
        return chan, funding_tx

    async def on_open_channel(self, payload):
        # payload['channel_flags']
        if payload['chain_hash'] != constants.net.rev_genesis_bytes():
            raise Exception('wrong chain_hash')
        funding_sat = int.from_bytes(payload['funding_satoshis'], 'big')
        push_msat = int.from_bytes(payload['push_msat'], 'big')
        feerate = int.from_bytes(payload['feerate_per_kw'], 'big')

        temp_chan_id = payload['temporary_channel_id']
        local_config = self.make_local_config(funding_sat, push_msat, REMOTE)
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(local_config.per_commitment_secret_seed,
                                                                          RevocationStore.START_INDEX)
        per_commitment_point_first = secret_to_pubkey(int.from_bytes(per_commitment_secret_first, 'big'))
        min_depth = 3
        self.send_message('accept_channel',
            temporary_channel_id=temp_chan_id,
            dust_limit_satoshis=local_config.dust_limit_sat,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_reserve_satoshis=local_config.reserve_sat,
            htlc_minimum_msat=1000,
            minimum_depth=min_depth,
            to_self_delay=local_config.to_self_delay,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
        )
        funding_created = await self.funding_created[temp_chan_id].get()
        funding_idx = int.from_bytes(funding_created['funding_output_index'], 'big')
        funding_txid = bh2u(funding_created['funding_txid'][::-1])
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_idx)
        their_revocation_store = RevocationStore()
        remote_balance_sat = funding_sat * 1000 - push_msat
        remote_dust_limit_sat = int.from_bytes(payload['dust_limit_satoshis'], byteorder='big') # TODO validate
        remote_reserve_sat = self.validate_remote_reserve(payload['channel_reserve_satoshis'], remote_dust_limit_sat, funding_sat)
        chan_dict = {
                "node_id": self.pubkey,
                "channel_id": channel_id,
                "short_channel_id": None,
                "funding_outpoint": Outpoint(funding_txid, funding_idx),
                "remote_config": RemoteConfig(
                    payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
                    multisig_key=OnlyPubkeyKeypair(payload['funding_pubkey']),
                    htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
                    delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
                    revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
                    to_self_delay=int.from_bytes(payload['to_self_delay'], 'big'),
                    dust_limit_sat=remote_dust_limit_sat,
                    max_htlc_value_in_flight_msat=int.from_bytes(payload['max_htlc_value_in_flight_msat'], 'big'), # TODO validate
                    max_accepted_htlcs=int.from_bytes(payload['max_accepted_htlcs'], 'big'), # TODO validate
                    initial_msat=remote_balance_sat,
                    reserve_sat = remote_reserve_sat,
                    htlc_minimum_msat=int.from_bytes(payload['htlc_minimum_msat'], 'big'), # TODO validate
                    next_per_commitment_point=payload['first_per_commitment_point'],
                    current_per_commitment_point=None,
                    revocation_store=their_revocation_store,
                ),
                "local_config": local_config,
                "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=False, funding_txn_minimum_depth=min_depth),
                "remote_update": None,
                "state": channel_states.PREOPENING.name,
        }
        chan = Channel(chan_dict,
                       sweep_address=self.lnworker.sweep_address,
                       lnworker=self.lnworker,
                       initial_feerate=feerate)
        remote_sig = funding_created['signature']
        chan.receive_new_commitment(remote_sig, [])
        sig_64, _ = chan.sign_next_commitment()
        self.send_message('funding_signed',
            channel_id=channel_id,
            signature=sig_64,
        )
        chan.open_with_first_pcp(payload['first_per_commitment_point'], remote_sig)
        self.lnworker.save_channel(chan)
        self.lnworker.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())

    def validate_remote_reserve(self, payload_field: bytes, dust_limit: int, funding_sat: int) -> int:
        remote_reserve_sat = int.from_bytes(payload_field, 'big')
        if remote_reserve_sat < dust_limit:
            raise Exception('protocol violation: reserve < dust_limit')
        if remote_reserve_sat > funding_sat/100:
            raise Exception(f'reserve too high: {remote_reserve_sat}, funding_sat: {funding_sat}')
        return remote_reserve_sat

    def on_channel_reestablish(self, payload):
        chan_id = payload["channel_id"]
        chan = self.channels.get(chan_id)
        if not chan:
            self.logger.info(f"Received unknown channel_reestablish {bh2u(chan_id)} {payload}")
            raise Exception('Unknown channel_reestablish')
        self.channel_reestablished[chan_id].put_nowait(payload)

    def try_to_get_remote_to_force_close_with_their_latest(self, chan_id):
        self.logger.info(f"trying to get remote to force close {bh2u(chan_id)}")
        self.send_message(
            "channel_reestablish",
            channel_id=chan_id,
            next_local_commitment_number=0,
            next_remote_revocation_number=0)

    @log_exceptions
    async def reestablish_channel(self, chan: Channel):
        await self.initialized.wait()
        chan_id = chan.channel_id
        if chan.peer_state != peer_states.DISCONNECTED:
            self.logger.info('reestablish_channel was called but channel {} already in state {}'
                             .format(chan_id, chan.get_state()))
            return
        chan.peer_state = peer_states.REESTABLISHING
        self.network.trigger_callback('channel', chan)
        # BOLT-02: "A node [...] upon disconnection [...] MUST reverse any uncommitted updates sent by the other side"
        chan.hm.discard_unsigned_remote_updates()
        # ctns
        oldest_unrevoked_local_ctn = chan.get_oldest_unrevoked_ctn(LOCAL)
        latest_local_ctn = chan.get_latest_ctn(LOCAL)
        next_local_ctn = chan.get_next_ctn(LOCAL)
        oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
        latest_remote_ctn = chan.get_latest_ctn(REMOTE)
        next_remote_ctn = chan.get_next_ctn(REMOTE)
        # send message
        dlp_enabled = self.localfeatures & LnLocalFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        if dlp_enabled:
            if oldest_unrevoked_remote_ctn == 0:
                last_rev_secret = 0
            else:
                revocation_store = chan.config[REMOTE].revocation_store
                last_rev_index = oldest_unrevoked_remote_ctn - 1
                last_rev_secret = revocation_store.retrieve_secret(RevocationStore.START_INDEX - last_rev_index)
            latest_secret, latest_point = chan.get_secret_and_point(LOCAL, latest_local_ctn)
            self.send_message(
                "channel_reestablish",
                channel_id=chan_id,
                next_local_commitment_number=next_local_ctn,
                next_remote_revocation_number=oldest_unrevoked_remote_ctn,
                your_last_per_commitment_secret=last_rev_secret,
                my_current_per_commitment_point=latest_point)
        else:
            self.send_message(
                "channel_reestablish",
                channel_id=chan_id,
                next_local_commitment_number=next_local_ctn,
                next_remote_revocation_number=oldest_unrevoked_remote_ctn)
        self.logger.info(f'channel_reestablish: sent channel_reestablish with '
                         f'(next_local_ctn={next_local_ctn}, '
                         f'oldest_unrevoked_remote_ctn={oldest_unrevoked_remote_ctn})')

        channel_reestablish_msg = await self.channel_reestablished[chan_id].get()
        their_next_local_ctn = int.from_bytes(channel_reestablish_msg["next_local_commitment_number"], 'big')
        their_oldest_unrevoked_remote_ctn = int.from_bytes(channel_reestablish_msg["next_remote_revocation_number"], 'big')
        self.logger.info(f'channel_reestablish: received channel_reestablish with '
                         f'(their_next_local_ctn={their_next_local_ctn}, '
                         f'their_oldest_unrevoked_remote_ctn={their_oldest_unrevoked_remote_ctn})')
        their_local_pcp = channel_reestablish_msg.get("my_current_per_commitment_point")
        their_claim_of_our_last_per_commitment_secret = channel_reestablish_msg.get("your_last_per_commitment_secret")
        # sanity checks of received values
        if their_next_local_ctn < 0:
            raise RemoteMisbehaving(f"channel reestablish: their_next_local_ctn < 0")
        if their_oldest_unrevoked_remote_ctn < 0:
            raise RemoteMisbehaving(f"channel reestablish: their_oldest_unrevoked_remote_ctn < 0")
        # Replay un-acked local updates (including commitment_signed) byte-for-byte.
        # If we have sent them a commitment signature that they "lost" (due to disconnect),
        # we need to make sure we replay the same local updates, as otherwise they could
        # end up with two (or more) signed valid commitment transactions at the same ctn.
        # Multiple valid ctxs at the same ctn is a major headache for pre-signing spending txns,
        # e.g. for watchtowers, hence we must ensure these ctxs coincide.
        # We replay the local updates even if they were not yet committed.
        unacked = chan.hm.get_unacked_local_updates()
        n_replayed_msgs = 0
        for ctn, messages in unacked.items():
            if ctn < their_next_local_ctn:
                # They claim to have received these messages and the corresponding
                # commitment_signed, hence we must not replay them.
                continue
            for raw_upd_msg in messages:
                self.transport.send_bytes(raw_upd_msg)
                n_replayed_msgs += 1
        self.logger.info(f'channel_reestablish: replayed {n_replayed_msgs} unacked messages')

        should_close_we_are_ahead = False
        should_close_they_are_ahead = False
        # compare remote ctns
        if next_remote_ctn != their_next_local_ctn:
            if their_next_local_ctn == latest_remote_ctn and chan.hm.is_revack_pending(REMOTE):
                # We replayed the local updates (see above), which should have contained a commitment_signed
                # (due to is_revack_pending being true), and this should have remedied this situation.
                pass
            else:
                self.logger.warning(f"channel_reestablish: expected remote ctn {next_remote_ctn}, got {their_next_local_ctn}")
                if their_next_local_ctn < next_remote_ctn:
                    should_close_we_are_ahead = True
                else:
                    should_close_they_are_ahead = True
        # compare local ctns
        if oldest_unrevoked_local_ctn != their_oldest_unrevoked_remote_ctn:
            if oldest_unrevoked_local_ctn - 1 == their_oldest_unrevoked_remote_ctn:
                # A node:
                #    if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack
                #    the receiving node sent, AND the receiving node hasn't already received a closing_signed:
                #        MUST re-send the revoke_and_ack.
                last_secret, last_point = chan.get_secret_and_point(LOCAL, oldest_unrevoked_local_ctn - 1)
                next_secret, next_point = chan.get_secret_and_point(LOCAL, oldest_unrevoked_local_ctn + 1)
                self.send_message(
                    "revoke_and_ack",
                    channel_id=chan.channel_id,
                    per_commitment_secret=last_secret,
                    next_per_commitment_point=next_point)
            else:
                self.logger.warning(f"channel_reestablish: expected local ctn {oldest_unrevoked_local_ctn}, got {their_oldest_unrevoked_remote_ctn}")
                if their_oldest_unrevoked_remote_ctn < oldest_unrevoked_local_ctn:
                    should_close_we_are_ahead = True
                else:
                    should_close_they_are_ahead = True
        # option_data_loss_protect
        def are_datalossprotect_fields_valid() -> bool:
            if their_local_pcp is None or their_claim_of_our_last_per_commitment_secret is None:
                # if DLP was enabled, absence of fields is not OK
                return not dlp_enabled
            if their_oldest_unrevoked_remote_ctn > 0:
                our_pcs, __ = chan.get_secret_and_point(LOCAL, their_oldest_unrevoked_remote_ctn - 1)
            else:
                assert their_oldest_unrevoked_remote_ctn == 0
                our_pcs = bytes(32)
            if our_pcs != their_claim_of_our_last_per_commitment_secret:
                self.logger.error(f"channel_reestablish: (DLP) local PCS mismatch: {bh2u(our_pcs)} != {bh2u(their_claim_of_our_last_per_commitment_secret)}")
                return False
            try:
                __, our_remote_pcp = chan.get_secret_and_point(REMOTE, their_next_local_ctn - 1)
            except RemoteCtnTooFarInFuture:
                pass
            else:
                if our_remote_pcp != their_local_pcp:
                    self.logger.error(f"channel_reestablish: (DLP) remote PCP mismatch: {bh2u(our_remote_pcp)} != {bh2u(their_local_pcp)}")
                    return False
            return True

        if not are_datalossprotect_fields_valid():
            raise RemoteMisbehaving("channel_reestablish: data loss protect fields invalid")
        else:
            if dlp_enabled and should_close_they_are_ahead:
                self.logger.warning(f"channel_reestablish: remote is ahead of us! luckily DLP is enabled. remote PCP: {bh2u(their_local_pcp)}")
                chan.data_loss_protect_remote_pcp[their_next_local_ctn - 1] = their_local_pcp
                self.lnworker.save_channel(chan)
        if should_close_they_are_ahead:
            self.logger.warning(f"channel_reestablish: remote is ahead of us! trying to get them to force-close.")
            self.try_to_get_remote_to_force_close_with_their_latest(chan_id)
            return
        elif should_close_we_are_ahead:
            self.logger.warning(f"channel_reestablish: we are ahead of remote! trying to force-close.")
            await self.lnworker.force_close_channel(chan_id)
            return

        chan.peer_state = peer_states.GOOD
        # note: chan.short_channel_id being set implies the funding txn is already at sufficient depth
        if their_next_local_ctn == next_local_ctn == 1 and chan.short_channel_id:
            self.send_funding_locked(chan)
        # checks done
        if chan.config[LOCAL].funding_locked_received and chan.short_channel_id:
            self.mark_open(chan)
        self.network.trigger_callback('channel', chan)

    def send_funding_locked(self, chan: Channel):
        channel_id = chan.channel_id
        per_commitment_secret_index = RevocationStore.START_INDEX - 1
        per_commitment_point_second = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.config[LOCAL].per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        # note: if funding_locked was not yet received, we might send it multiple times
        self.send_message("funding_locked", channel_id=channel_id, next_per_commitment_point=per_commitment_point_second)
        if chan.config[LOCAL].funding_locked_received and chan.short_channel_id:
            self.mark_open(chan)

    def on_funding_locked(self, payload):
        channel_id = payload['channel_id']
        self.logger.info(f"on_funding_locked. channel: {bh2u(channel_id)}")
        chan = self.channels.get(channel_id)
        if not chan:
            print(self.channels)
            raise Exception("Got unknown funding_locked", channel_id)
        if not chan.config[LOCAL].funding_locked_received:
            our_next_point = chan.config[REMOTE].next_per_commitment_point
            their_next_point = payload["next_per_commitment_point"]
            new_remote_state = chan.config[REMOTE]._replace(next_per_commitment_point=their_next_point)
            new_local_state = chan.config[LOCAL]._replace(funding_locked_received = True)
            chan.config[REMOTE]=new_remote_state
            chan.config[LOCAL]=new_local_state
            self.lnworker.save_channel(chan)
        if chan.short_channel_id:
            self.mark_open(chan)

    def on_network_update(self, chan: Channel, funding_tx_depth: int):
        """
        Only called when the channel is OPEN.

        Runs on the Network thread.
        """
        if not chan.config[LOCAL].was_announced and funding_tx_depth >= 6:
            # don't announce our channels
            # FIXME should this be a field in chan.local_state maybe?
            return
            chan.config[LOCAL]=chan.config[LOCAL]._replace(was_announced=True)
            coro = self.handle_announcements(chan)
            self.lnworker.save_channel(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    @log_exceptions
    async def handle_announcements(self, chan):
        h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        announcement_signatures_msg = await self.announcement_signatures[chan.channel_id].get()
        remote_node_sig = announcement_signatures_msg["node_signature"]
        remote_bitcoin_sig = announcement_signatures_msg["bitcoin_signature"]
        if not ecc.verify_signature(chan.config[REMOTE].multisig_key.pubkey, remote_bitcoin_sig, h):
            raise Exception("bitcoin_sig invalid in announcement_signatures")
        if not ecc.verify_signature(self.pubkey, remote_node_sig, h):
            raise Exception("node_sig invalid in announcement_signatures")

        node_sigs = [remote_node_sig, local_node_sig]
        bitcoin_sigs = [remote_bitcoin_sig, local_bitcoin_sig]
        bitcoin_keys = [chan.config[REMOTE].multisig_key.pubkey, chan.config[LOCAL].multisig_key.pubkey]

        if self.node_ids[0] > self.node_ids[1]:
            node_sigs.reverse()
            bitcoin_sigs.reverse()
            node_ids = list(reversed(self.node_ids))
            bitcoin_keys.reverse()
        else:
            node_ids = self.node_ids

        self.send_message("channel_announcement",
            node_signatures_1=node_sigs[0],
            node_signatures_2=node_sigs[1],
            bitcoin_signature_1=bitcoin_sigs[0],
            bitcoin_signature_2=bitcoin_sigs[1],
            len=0,
            #features not set (defaults to zeros)
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=chan.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )

    def mark_open(self, chan: Channel):
        assert chan.short_channel_id is not None
        scid = chan.short_channel_id
        # only allow state transition from "FUNDED" to "OPEN"
        old_state = chan.get_state()
        if old_state == channel_states.OPEN:
            return
        if old_state != channel_states.FUNDED:
            self.logger.info(f"cannot mark open, current state: {repr(old_state)}")
            return
        assert chan.config[LOCAL].funding_locked_received
        chan.set_state(channel_states.OPEN)
        self.network.trigger_callback('channel', chan)
        self.add_own_channel(chan)
        self.logger.info(f"CHANNEL OPENING COMPLETED for {scid}")
        forwarding_enabled = self.network.config.get('lightning_forward_payments', False)
        if forwarding_enabled:
            # send channel_update of outgoing edge to peer,
            # so that channel can be used to to receive payments
            self.logger.info(f"sending channel update for outgoing edge of {scid}")
            chan_upd = self.get_outgoing_gossip_channel_update_for_chan(chan)
            self.transport.send_bytes(chan_upd)

    def add_own_channel(self, chan):
        # add channel to database
        bitcoin_keys = [chan.config[LOCAL].multisig_key.pubkey, chan.config[REMOTE].multisig_key.pubkey]
        sorted_node_ids = list(sorted(self.node_ids))
        if sorted_node_ids != self.node_ids:
            bitcoin_keys.reverse()
        # note: we inject a channel announcement, and a channel update (for outgoing direction)
        # This is atm needed for
        # - finding routes
        # - the ChanAnn is needed so that we can anchor to it a future ChanUpd
        #   that the remote sends, even if the channel was not announced
        #   (from BOLT-07: "MAY create a channel_update to communicate the channel
        #    parameters to the final node, even though the channel has not yet been announced")
        self.channel_db.add_channel_announcement(
            {
                "short_channel_id": chan.short_channel_id,
                "node_id_1": sorted_node_ids[0],
                "node_id_2": sorted_node_ids[1],
                'chain_hash': constants.net.rev_genesis_bytes(),
                'len': b'\x00\x00',
                'features': b'',
                'bitcoin_key_1': bitcoin_keys[0],
                'bitcoin_key_2': bitcoin_keys[1]
            },
            trusted=True)
        # only inject outgoing direction:
        chan_upd_bytes = self.get_outgoing_gossip_channel_update_for_chan(chan)
        chan_upd_payload = decode_msg(chan_upd_bytes)[1]
        self.channel_db.add_channel_update(chan_upd_payload)
        # peer may have sent us a channel update for the incoming direction previously
        pending_channel_update = self.orphan_channel_updates.get(chan.short_channel_id)
        if pending_channel_update:
            chan.remote_update = pending_channel_update['raw']
        # add remote update with a fresh timestamp
        if chan.remote_update:
            now = int(time.time())
            remote_update_decoded = decode_msg(chan.remote_update)[1]
            remote_update_decoded['timestamp'] = now.to_bytes(4, byteorder="big")
            self.channel_db.add_channel_update(remote_update_decoded)

    def get_outgoing_gossip_channel_update_for_chan(self, chan: Channel) -> bytes:
        if chan._outgoing_channel_update is not None:
            return chan._outgoing_channel_update
        sorted_node_ids = list(sorted(self.node_ids))
        channel_flags = b'\x00' if sorted_node_ids[0] == privkey_to_pubkey(self.privkey) else b'\x01'
        now = int(time.time())
        htlc_maximum_msat = min(chan.config[REMOTE].max_htlc_value_in_flight_msat, 1000 * chan.constraints.capacity)

        chan_upd = encode_msg(
            "channel_update",
            short_channel_id=chan.short_channel_id,
            channel_flags=channel_flags,
            message_flags=b'\x01',
            cltv_expiry_delta=lnutil.NBLOCK_OUR_CLTV_EXPIRY_DELTA.to_bytes(2, byteorder="big"),
            htlc_minimum_msat=chan.config[REMOTE].htlc_minimum_msat.to_bytes(8, byteorder="big"),
            htlc_maximum_msat=htlc_maximum_msat.to_bytes(8, byteorder="big"),
            fee_base_msat=lnutil.OUR_FEE_BASE_MSAT.to_bytes(4, byteorder="big"),
            fee_proportional_millionths=lnutil.OUR_FEE_PROPORTIONAL_MILLIONTHS.to_bytes(4, byteorder="big"),
            chain_hash=constants.net.rev_genesis_bytes(),
            timestamp=now.to_bytes(4, byteorder="big"),
        )
        sighash = sha256d(chan_upd[2 + 64:])
        sig = ecc.ECPrivkey(self.privkey).sign(sighash, sig_string_from_r_and_s, get_r_and_s_from_sig_string)
        message_type, payload = decode_msg(chan_upd)
        payload['signature'] = sig
        chan_upd = encode_msg(message_type, **payload)

        chan._outgoing_channel_update = chan_upd
        return chan_upd

    def send_announcement_signatures(self, chan: Channel):

        bitcoin_keys = [chan.config[REMOTE].multisig_key.pubkey,
                        chan.config[LOCAL].multisig_key.pubkey]

        sorted_node_ids = list(sorted(self.node_ids))
        if sorted_node_ids != self.node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()
        else:
            node_ids = self.node_ids

        chan_ann = encode_msg("channel_announcement",
            len=0,
            #features not set (defaults to zeros)
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=chan.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )
        to_hash = chan_ann[256+2:]
        h = sha256d(to_hash)
        bitcoin_signature = ecc.ECPrivkey(chan.config[LOCAL].multisig_key.privkey).sign(h, sig_string_from_r_and_s, get_r_and_s_from_sig_string)
        node_signature = ecc.ECPrivkey(self.privkey).sign(h, sig_string_from_r_and_s, get_r_and_s_from_sig_string)
        self.send_message("announcement_signatures",
            channel_id=chan.channel_id,
            short_channel_id=chan.short_channel_id,
            node_signature=node_signature,
            bitcoin_signature=bitcoin_signature
        )

        return h, node_signature, bitcoin_signature

    def on_update_fail_htlc(self, payload):
        channel_id = payload["channel_id"]
        htlc_id = int.from_bytes(payload["id"], "big")
        reason = payload["reason"]
        chan = self.channels[channel_id]
        self.logger.info(f"on_update_fail_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        chan.receive_fail_htlc(htlc_id)
        local_ctn = chan.get_latest_ctn(LOCAL)
        asyncio.ensure_future(self._on_update_fail_htlc(channel_id, htlc_id, local_ctn, reason))

    @log_exceptions
    async def _on_update_fail_htlc(self, channel_id, htlc_id, local_ctn, reason):
        chan = self.channels[channel_id]
        await self.await_local(chan, local_ctn)
        payment_hash = chan.get_payment_hash(htlc_id)
        self.lnworker.payment_failed(payment_hash, reason)

    def maybe_send_commitment(self, chan: Channel):
        # REMOTE should revoke first before we can sign a new ctx
        if chan.hm.is_revack_pending(REMOTE):
            return
        # if there are no changes, we will not (and must not) send a new commitment
        next_htlcs, latest_htlcs = chan.hm.get_htlcs_in_next_ctx(REMOTE), chan.hm.get_htlcs_in_latest_ctx(REMOTE)
        if next_htlcs == latest_htlcs and chan.get_next_feerate(REMOTE) == chan.get_latest_feerate(REMOTE):
            return
        self.logger.info(f'send_commitment. chan {chan.short_channel_id}. ctn: {chan.get_next_ctn(REMOTE)}. '
                         f'old number htlcs: {len(latest_htlcs)}, new number htlcs: {len(next_htlcs)}')
        sig_64, htlc_sigs = chan.sign_next_commitment()
        self.send_message("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs))

    async def await_remote(self, chan: Channel, ctn: int):
        self.maybe_send_commitment(chan)
        # TODO review this. I suspect some callers want updates irrevocably committed,
        #      so comparision should use chan.get_oldest_unrevoked_ctn(REMOTE)
        while chan.get_latest_ctn(REMOTE) <= ctn:
            await self._remote_changed_events[chan.channel_id].wait()

    async def await_local(self, chan: Channel, ctn: int):
        self.maybe_send_commitment(chan)
        while chan.get_latest_ctn(LOCAL) <= ctn:
            await self._local_changed_events[chan.channel_id].wait()

    async def pay(self, route: 'LNPaymentRoute', chan: Channel, amount_msat: int,
                  payment_hash: bytes, min_final_cltv_expiry: int) -> UpdateAddHtlc:
        if chan.get_state() != channel_states.OPEN:
            raise PaymentFailure('Channel not open')
        assert amount_msat > 0, "amount_msat is not greater zero"
        await asyncio.wait_for(self.initialized.wait(), LN_P2P_NETWORK_TIMEOUT)
        # create onion packet
        final_cltv = self.network.get_local_height() + min_final_cltv_expiry
        hops_data, amount_msat, cltv = calc_hops_data_for_payment(route, amount_msat, final_cltv)
        assert final_cltv <= cltv, (final_cltv, cltv)
        secret_key = os.urandom(32)
        onion = new_onion_packet([x.node_id for x in route], secret_key, hops_data, associated_data=payment_hash)
        # create htlc
        htlc = UpdateAddHtlc(amount_msat=amount_msat, payment_hash=payment_hash, cltv_expiry=cltv, timestamp=int(time.time()))
        htlc = chan.add_htlc(htlc)
        remote_ctn = chan.get_latest_ctn(REMOTE)
        chan.onion_keys[htlc.htlc_id] = secret_key
        self.logger.info(f"starting payment. len(route)={len(route)}. route: {route}. htlc: {htlc}")
        self.send_message("update_add_htlc",
                          channel_id=chan.channel_id,
                          id=htlc.htlc_id,
                          cltv_expiry=htlc.cltv_expiry,
                          amount_msat=htlc.amount_msat,
                          payment_hash=htlc.payment_hash,
                          onion_routing_packet=onion.to_bytes())
        await self.await_remote(chan, remote_ctn)
        return htlc

    def send_revoke_and_ack(self, chan: Channel):
        self.logger.info(f'send_revoke_and_ack. chan {chan.short_channel_id}. ctn: {chan.get_oldest_unrevoked_ctn(LOCAL)}')
        rev, _ = chan.revoke_current_commitment()
        self.lnworker.save_channel(chan)
        self._local_changed_events[chan.channel_id].set()
        self._local_changed_events[chan.channel_id].clear()
        self.send_message("revoke_and_ack",
            channel_id=chan.channel_id,
            per_commitment_secret=rev.per_commitment_secret,
            next_per_commitment_point=rev.next_per_commitment_point)
        self.maybe_send_commitment(chan)

    def on_commitment_signed(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels[channel_id]
        # make sure there were changes to the ctx, otherwise the remote peer is misbehaving
        next_htlcs, latest_htlcs = chan.hm.get_htlcs_in_next_ctx(LOCAL), chan.hm.get_htlcs_in_latest_ctx(LOCAL)
        self.logger.info(f'on_commitment_signed. chan {chan.short_channel_id}. ctn: {chan.get_next_ctn(LOCAL)}. '
                         f'old number htlcs: {len(latest_htlcs)}, new number htlcs: {len(next_htlcs)}')
        if (next_htlcs == latest_htlcs
                and chan.get_next_feerate(LOCAL) == chan.get_latest_feerate(LOCAL)):
            # TODO if feerate changed A->B->A; so there were updates but the value is identical,
            #      then it might be legal to send a commitment_signature
            #      see https://github.com/lightningnetwork/lightning-rfc/pull/618
            raise RemoteMisbehaving('received commitment_signed without pending changes')
        # REMOTE should wait until we have revoked
        if chan.hm.is_revack_pending(LOCAL):
            raise RemoteMisbehaving('received commitment_signed before we revoked previous ctx')
        data = payload["htlc_signature"]
        htlc_sigs = [data[i:i+64] for i in range(0, len(data), 64)]
        chan.receive_new_commitment(payload["signature"], htlc_sigs)
        self.send_revoke_and_ack(chan)

    def on_update_fulfill_htlc(self, update_fulfill_htlc_msg):
        chan = self.channels[update_fulfill_htlc_msg["channel_id"]]
        preimage = update_fulfill_htlc_msg["payment_preimage"]
        payment_hash = sha256(preimage)
        htlc_id = int.from_bytes(update_fulfill_htlc_msg["id"], "big")
        self.logger.info(f"on_update_fulfill_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        chan.receive_htlc_settle(preimage, htlc_id)
        self.lnworker.save_preimage(payment_hash, preimage)
        local_ctn = chan.get_latest_ctn(LOCAL)
        asyncio.ensure_future(self._on_update_fulfill_htlc(chan, local_ctn, payment_hash))

    @log_exceptions
    async def _on_update_fulfill_htlc(self, chan, local_ctn, payment_hash):
        await self.await_local(chan, local_ctn)
        self.lnworker.payment_sent(payment_hash)

    def on_update_fail_malformed_htlc(self, payload):
        self.logger.info(f"on_update_fail_malformed_htlc. error {payload['data'].decode('ascii')}")

    def on_update_add_htlc(self, payload):
        payment_hash = payload["payment_hash"]
        channel_id = payload['channel_id']
        chan = self.channels[channel_id]
        htlc_id = int.from_bytes(payload["id"], 'big')
        self.logger.info(f"on_update_add_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        cltv_expiry = int.from_bytes(payload["cltv_expiry"], 'big')
        amount_msat_htlc = int.from_bytes(payload["amount_msat"], 'big')
        onion_packet = OnionPacket.from_bytes(payload["onion_routing_packet"])
        processed_onion = process_onion_packet(onion_packet, associated_data=payment_hash, our_onion_private_key=self.privkey)
        if chan.get_state() != channel_states.OPEN:
            raise RemoteMisbehaving(f"received update_add_htlc while chan.get_state() != OPEN. state was {chan.get_state()}")
        if cltv_expiry >= 500_000_000:
            asyncio.ensure_future(self.lnworker.force_close_channel(channel_id))
            raise RemoteMisbehaving(f"received update_add_htlc with cltv_expiry >= 500_000_000. value was {cltv_expiry}")
        # add htlc
        htlc = UpdateAddHtlc(amount_msat=amount_msat_htlc,
                             payment_hash=payment_hash,
                             cltv_expiry=cltv_expiry,
                             timestamp=int(time.time()),
                             htlc_id=htlc_id)
        htlc = chan.receive_htlc(htlc)
        local_ctn = chan.get_latest_ctn(LOCAL)
        remote_ctn = chan.get_latest_ctn(REMOTE)
        if processed_onion.are_we_final:
            asyncio.ensure_future(self._maybe_fulfill_htlc(chan=chan,
                                                           htlc=htlc,
                                                           local_ctn=local_ctn,
                                                           remote_ctn=remote_ctn,
                                                           onion_packet=onion_packet,
                                                           processed_onion=processed_onion))
        else:
            asyncio.ensure_future(self._maybe_forward_htlc(chan=chan,
                                                           htlc=htlc,
                                                           local_ctn=local_ctn,
                                                           remote_ctn=remote_ctn,
                                                           onion_packet=onion_packet,
                                                           processed_onion=processed_onion))

    @log_exceptions
    async def _maybe_forward_htlc(self, chan: Channel, htlc: UpdateAddHtlc, *, local_ctn: int, remote_ctn: int,
                                  onion_packet: OnionPacket, processed_onion: ProcessedOnionPacket):
        await self.await_local(chan, local_ctn)
        await self.await_remote(chan, remote_ctn)
        # Forward HTLC
        # FIXME: this is not robust to us going offline before payment is fulfilled
        # FIXME: there are critical safety checks MISSING here
        forwarding_enabled = self.network.config.get('lightning_forward_payments', False)
        if not forwarding_enabled:
            self.logger.info(f"forwarding is disabled. failing htlc.")
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.PERMANENT_CHANNEL_FAILURE, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        dph = processed_onion.hop_data.per_hop
        next_chan = self.lnworker.get_channel_by_short_id(dph.short_channel_id)
        next_chan_scid = dph.short_channel_id
        next_peer = self.lnworker.peers[next_chan.node_id]
        local_height = self.network.get_local_height()
        if next_chan is None:
            self.logger.info(f"cannot forward htlc. cannot find next_chan {next_chan_scid}")
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.UNKNOWN_NEXT_PEER, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        outgoing_chan_upd = self.get_outgoing_gossip_channel_update_for_chan(next_chan)[2:]
        outgoing_chan_upd_len = len(outgoing_chan_upd).to_bytes(2, byteorder="big")
        if next_chan.get_state() != channel_states.OPEN:
            self.logger.info(f"cannot forward htlc. next_chan not OPEN: {next_chan_scid} in state {next_chan.get_state()}")
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.TEMPORARY_CHANNEL_FAILURE,
                                                data=outgoing_chan_upd_len+outgoing_chan_upd)
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        next_cltv_expiry = int.from_bytes(dph.outgoing_cltv_value, 'big')
        if htlc.cltv_expiry - next_cltv_expiry < NBLOCK_OUR_CLTV_EXPIRY_DELTA:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.INCORRECT_CLTV_EXPIRY,
                                                data=(htlc.cltv_expiry.to_bytes(4, byteorder="big")
                                                      + outgoing_chan_upd_len + outgoing_chan_upd))
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        if htlc.cltv_expiry - lnutil.NBLOCK_DEADLINE_BEFORE_EXPIRY_FOR_RECEIVED_HTLCS <= local_height \
                or next_cltv_expiry <= local_height:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.EXPIRY_TOO_SOON,
                                                data=outgoing_chan_upd_len+outgoing_chan_upd)
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        if max(htlc.cltv_expiry, next_cltv_expiry) > local_height + lnutil.NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.EXPIRY_TOO_FAR, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        next_amount_msat_htlc = int.from_bytes(dph.amt_to_forward, 'big')
        forwarding_fees = fee_for_edge_msat(forwarded_amount_msat=next_amount_msat_htlc,
                                            fee_base_msat=lnutil.OUR_FEE_BASE_MSAT,
                                            fee_proportional_millionths=lnutil.OUR_FEE_PROPORTIONAL_MILLIONTHS)
        if htlc.amount_msat - next_amount_msat_htlc < forwarding_fees:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.FEE_INSUFFICIENT,
                                                data=(next_amount_msat_htlc.to_bytes(8, byteorder="big")
                                                      + outgoing_chan_upd_len + outgoing_chan_upd))
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return

        self.logger.info(f'forwarding htlc to {next_chan.node_id}')
        next_htlc = UpdateAddHtlc(amount_msat=next_amount_msat_htlc, payment_hash=htlc.payment_hash, cltv_expiry=next_cltv_expiry, timestamp=int(time.time()))
        next_htlc = next_chan.add_htlc(next_htlc)
        next_remote_ctn = next_chan.get_latest_ctn(REMOTE)
        next_peer.send_message(
            "update_add_htlc",
            channel_id=next_chan.channel_id,
            id=next_htlc.htlc_id,
            cltv_expiry=dph.outgoing_cltv_value,
            amount_msat=dph.amt_to_forward,
            payment_hash=next_htlc.payment_hash,
            onion_routing_packet=processed_onion.next_packet.to_bytes()
        )
        await next_peer.await_remote(next_chan, next_remote_ctn)
        success, preimage, reason = await self.lnworker.await_payment(next_htlc.payment_hash)
        if success:
            await self._fulfill_htlc(chan, htlc.htlc_id, preimage)
            self.logger.info("htlc forwarded successfully")
        else:
            # TODO: test this
            self.logger.info(f"forwarded htlc has failed, {reason}")
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)

    @log_exceptions
    async def _maybe_fulfill_htlc(self, chan: Channel, htlc: UpdateAddHtlc, *, local_ctn: int, remote_ctn: int,
                                  onion_packet: OnionPacket, processed_onion: ProcessedOnionPacket):
        await self.await_local(chan, local_ctn)
        await self.await_remote(chan, remote_ctn)
        try:
            info = self.lnworker.get_payment_info(htlc.payment_hash)
            preimage = self.lnworker.get_preimage(htlc.payment_hash)
        except UnknownPaymentHash:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        expected_received_msat = int(info.amount * 1000) if info.amount is not None else None
        if expected_received_msat is not None and \
                not (expected_received_msat <= htlc.amount_msat <= 2 * expected_received_msat):
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        local_height = self.network.get_local_height()
        if local_height + MIN_FINAL_CLTV_EXPIRY_ACCEPTED > htlc.cltv_expiry:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.FINAL_EXPIRY_TOO_SOON, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        cltv_from_onion = int.from_bytes(processed_onion.hop_data.per_hop.outgoing_cltv_value, byteorder="big")
        if cltv_from_onion != htlc.cltv_expiry:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.FINAL_INCORRECT_CLTV_EXPIRY,
                                                data=htlc.cltv_expiry.to_bytes(4, byteorder="big"))
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        amount_from_onion = int.from_bytes(processed_onion.hop_data.per_hop.amt_to_forward, byteorder="big")
        if amount_from_onion > htlc.amount_msat:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.FINAL_INCORRECT_HTLC_AMOUNT,
                                                data=htlc.amount_msat.to_bytes(8, byteorder="big"))
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        #self.network.trigger_callback('htlc_added', htlc, invoice, RECEIVED)
        await asyncio.sleep(self.network.config.lightning_settle_delay)
        await self._fulfill_htlc(chan, htlc.htlc_id, preimage)

    async def _fulfill_htlc(self, chan: Channel, htlc_id: int, preimage: bytes):
        self.logger.info(f"_fulfill_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        chan.settle_htlc(preimage, htlc_id)
        payment_hash = sha256(preimage)
        self.lnworker.payment_received(payment_hash)
        remote_ctn = chan.get_latest_ctn(REMOTE)
        self.send_message("update_fulfill_htlc",
                          channel_id=chan.channel_id,
                          id=htlc_id,
                          payment_preimage=preimage)
        await self.await_remote(chan, remote_ctn)

    async def fail_htlc(self, chan: Channel, htlc_id: int, onion_packet: OnionPacket,
                        reason: OnionRoutingFailureMessage):
        self.logger.info(f"fail_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}. reason: {reason}")
        chan.fail_htlc(htlc_id)
        remote_ctn = chan.get_latest_ctn(REMOTE)
        error_packet = construct_onion_error(reason, onion_packet, our_onion_private_key=self.privkey)
        self.send_message("update_fail_htlc",
                          channel_id=chan.channel_id,
                          id=htlc_id,
                          len=len(error_packet),
                          reason=error_packet)
        await self.await_remote(chan, remote_ctn)

    def on_revoke_and_ack(self, payload):
        channel_id = payload["channel_id"]
        chan = self.channels[channel_id]
        self.logger.info(f'on_revoke_and_ack. chan {chan.short_channel_id}. ctn: {chan.get_oldest_unrevoked_ctn(REMOTE)}')
        rev = RevokeAndAck(payload["per_commitment_secret"], payload["next_per_commitment_point"])
        chan.receive_revocation(rev)
        self._remote_changed_events[chan.channel_id].set()
        self._remote_changed_events[chan.channel_id].clear()
        self.lnworker.save_channel(chan)
        self.maybe_send_commitment(chan)

    def on_update_fee(self, payload):
        channel_id = payload["channel_id"]
        feerate =int.from_bytes(payload["feerate_per_kw"], "big")
        chan = self.channels[channel_id]
        chan.update_fee(feerate, False)

    async def bitcoin_fee_update(self, chan: Channel):
        """
        called when our fee estimates change
        """
        if not chan.constraints.is_initiator:
            # TODO force close if initiator does not update_fee enough
            return
        feerate_per_kw = self.lnworker.current_feerate_per_kw()
        chan_fee = chan.get_next_feerate(REMOTE)
        self.logger.info(f"current pending feerate {chan_fee}")
        self.logger.info(f"new feerate {feerate_per_kw}")
        if feerate_per_kw < chan_fee / 2:
            self.logger.info("FEES HAVE FALLEN")
        elif feerate_per_kw > chan_fee * 2:
            self.logger.info("FEES HAVE RISEN")
        else:
            return
        chan.update_fee(feerate_per_kw, True)
        remote_ctn = chan.get_latest_ctn(REMOTE)
        self.send_message("update_fee",
                          channel_id=chan.channel_id,
                          feerate_per_kw=feerate_per_kw)
        await self.await_remote(chan, remote_ctn)

    def on_closing_signed(self, payload):
        chan_id = payload["channel_id"]
        if chan_id not in self.closing_signed: raise Exception("Got unknown closing_signed")
        self.closing_signed[chan_id].put_nowait(payload)

    @log_exceptions
    async def close_channel(self, chan_id: bytes):
        chan = self.channels[chan_id]
        self.shutdown_received[chan_id] = asyncio.Future()
        self.send_shutdown(chan)
        payload = await self.shutdown_received[chan_id]
        txid = await self._shutdown(chan, payload, True)
        self.logger.info(f'Channel closed {txid}')
        return txid

    @log_exceptions
    async def on_shutdown(self, payload):
        # length of scripts allowed in BOLT-02
        if int.from_bytes(payload['len'], 'big') not in (3+20+2, 2+20+1, 2+20, 2+32):
            raise Exception('scriptpubkey length in received shutdown message invalid: ' + str(payload['len']))
        chan_id = payload['channel_id']
        if chan_id in self.shutdown_received:
            self.shutdown_received[chan_id].set_result(payload)
        else:
            chan = self.channels[chan_id]
            self.send_shutdown(chan)
            txid = await self._shutdown(chan, payload, False)
            self.logger.info(f'Channel closed by remote peer {txid}')

    def send_shutdown(self, chan: Channel):
        scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        self.send_message('shutdown', channel_id=chan.channel_id, len=len(scriptpubkey), scriptpubkey=scriptpubkey)

    @log_exceptions
    async def _shutdown(self, chan: Channel, payload, is_local):
        # set state so that we stop accepting HTLCs
        chan.set_state(channel_states.CLOSING)
        # wait until no HTLCs remain in either commitment transaction
        while len(chan.hm.htlcs(LOCAL)) + len(chan.hm.htlcs(REMOTE)) > 0:
            self.logger.info('waiting for htlcs to settle...')
            await asyncio.sleep(1)
        our_fee = chan.pending_local_fee()
        scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        # negotiate fee
        while True:
            our_sig, closing_tx = chan.make_closing_tx(scriptpubkey, payload['scriptpubkey'], fee_sat=our_fee)
            self.send_message('closing_signed', channel_id=chan.channel_id, fee_satoshis=our_fee, signature=our_sig)
            cs_payload = await asyncio.wait_for(self.closing_signed[chan.channel_id].get(), LN_P2P_NETWORK_TIMEOUT)
            their_fee = int.from_bytes(cs_payload['fee_satoshis'], 'big')
            their_sig = cs_payload['signature']
            if our_fee == their_fee:
                break
            # TODO: negotiate better
            our_fee = their_fee
        # add signatures
        closing_tx.add_signature_to_txin(txin_idx=0,
                                         signing_pubkey=chan.config[LOCAL].multisig_key.pubkey.hex(),
                                         sig=bh2u(der_sig_from_sig_string(our_sig) + b'\x01'))
        closing_tx.add_signature_to_txin(txin_idx=0,
                                         signing_pubkey=chan.config[REMOTE].multisig_key.pubkey.hex(),
                                         sig=bh2u(der_sig_from_sig_string(their_sig) + b'\x01'))
        # broadcast
        await self.network.broadcast_transaction(closing_tx)
        return closing_tx.txid()
