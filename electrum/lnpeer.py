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
from typing import List, Tuple, Dict, TYPE_CHECKING, Optional, Callable
import traceback
import sys
from datetime import datetime

import aiorpcx

from .simple_config import get_config
from .crypto import sha256, sha256d
from . import bitcoin
from . import ecc
from .ecc import sig_string_from_r_and_s, get_r_and_s_from_sig_string, der_sig_from_sig_string
from . import constants
from .util import bh2u, bfh, log_exceptions, list_enabled_bits, ignore_exceptions
from .transaction import Transaction, TxOutput
from .logging import Logger
from .lnonion import (new_onion_packet, decode_onion_error, OnionFailureCode, calc_hops_data_for_payment,
                      process_onion_packet, OnionPacket, construct_onion_error, OnionRoutingFailureMessage,
                      ProcessedOnionPacket)
from .lnchannel import Channel, RevokeAndAck, htlcsum
from .lnutil import (Outpoint, LocalConfig, RECEIVED, UpdateAddHtlc,
                     RemoteConfig, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore,
                     funding_output_script, get_per_commitment_secret_from_seed,
                     secret_to_pubkey, PaymentFailure, LnLocalFeatures,
                     LOCAL, REMOTE, HTLCOwner, generate_keypair, LnKeyFamily,
                     get_ln_flag_pair_of_bit, privkey_to_pubkey, UnknownPaymentHash, MIN_FINAL_CLTV_EXPIRY_ACCEPTED,
                     LightningPeerConnectionClosed, HandshakeFailed, NotFoundChanAnnouncementForUpdate,
                     MINIMUM_MAX_HTLC_VALUE_IN_FLIGHT_ACCEPTED, MAXIMUM_HTLC_MINIMUM_MSAT_ACCEPTED,
                     MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED, RemoteMisbehaving)
from .lntransport import LNTransport, LNTransportBase
from .lnmsg import encode_msg, decode_msg
from .lnverifier import verify_sig_for_channel_update

if TYPE_CHECKING:
    from .lnworker import LNWorker
    from .lnrouter import RouteEdge


def channel_id_from_funding_tx(funding_txid: str, funding_index: int) -> Tuple[bytes, bytes]:
    funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
    i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
    return i.to_bytes(32, 'big'), funding_txid_bytes

class Peer(Logger):

    def __init__(self, lnworker: 'LNWorker', pubkey:bytes, transport: LNTransportBase):
        self.initialized = asyncio.Event()
        self.querying = asyncio.Event()
        self.transport = transport
        self.pubkey = pubkey
        self.lnworker = lnworker
        self.privkey = lnworker.node_keypair.privkey
        self.localfeatures = self.lnworker.localfeatures
        self.node_ids = [self.pubkey, privkey_to_pubkey(self.privkey)]
        self.network = lnworker.network
        self.lnwatcher = lnworker.network.lnwatcher
        self.channel_db = lnworker.network.channel_db
        self.ping_time = 0
        self.reply_channel_range = asyncio.Queue()
        # gossip uses a single queue to preserve message order
        self.gossip_queue = asyncio.Queue()
        # channel messsage queues
        self.shutdown_received = defaultdict(asyncio.Future)
        self.channel_accepted = defaultdict(asyncio.Queue)
        self.channel_reestablished = defaultdict(asyncio.Future)
        self.funding_signed = defaultdict(asyncio.Queue)
        self.funding_created = defaultdict(asyncio.Queue)
        self.announcement_signatures = defaultdict(asyncio.Queue)
        self.closing_signed = defaultdict(asyncio.Queue)
        self.payment_preimages = defaultdict(asyncio.Queue)
        #
        self.attempted_route = {}
        self.orphan_channel_updates = OrderedDict()
        self.sent_commitment_for_ctn_last = defaultdict(lambda: None)  # type: Dict[Channel, Optional[int]]
        self.recv_commitment_for_ctn_last = defaultdict(lambda: None)  # type: Dict[Channel, Optional[int]]
        self._local_changed_events = defaultdict(asyncio.Event)
        self._remote_changed_events = defaultdict(asyncio.Event)
        Logger.__init__(self)

    def send_message(self, message_name: str, **kwargs):
        assert type(message_name) is str
        self.logger.debug(f"Sending {message_name.upper()}")
        self.transport.send_bytes(encode_msg(message_name, **kwargs))

    async def initialize(self):
        if isinstance(self.transport, LNTransport):
            await self.transport.handshake()
        self.send_message("init", gflen=0, lflen=1, localfeatures=self.localfeatures)

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
        # todo: self.channel_reestablished is not a queue
        self.logger.info(f"error {payload['data'].decode('ascii')}")
        chan_id = payload.get("channel_id")
        for d in [ self.channel_accepted, self.funding_signed,
                   self.funding_created,
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
        if self.initialized.is_set():
            self.logger.info("ALREADY INITIALIZED BUT RECEIVED INIT")
            return
        # if they required some even flag we don't have, they will close themselves
        # but if we require an even flag they don't have, we close
        self.their_localfeatures = int.from_bytes(payload['localfeatures'], byteorder="big")
        our_flags = set(list_enabled_bits(self.localfeatures))
        their_flags = set(list_enabled_bits(self.their_localfeatures))
        for flag in our_flags:
            if flag not in their_flags and get_ln_flag_pair_of_bit(flag) not in their_flags:
                # they don't have this feature we wanted :(
                if flag % 2 == 0:  # even flags are compulsory
                    raise LightningPeerConnectionClosed("remote does not have even flag {}"
                                                        .format(str(LnLocalFeatures(1 << flag))))
                self.localfeatures ^= 1 << flag  # disable flag
        if isinstance(self.transport, LNTransport):
            self.channel_db.add_recent_peer(self.transport.peer_addr)
        self.initialized.set()

    def on_node_announcement(self, payload):
        self.gossip_queue.put_nowait(('node_announcement', payload))

    def on_channel_announcement(self, payload):
        self.gossip_queue.put_nowait(('channel_announcement', payload))

    def on_channel_update(self, payload):
        self.gossip_queue.put_nowait(('channel_update', payload))

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
            except Exception as e:
                self.logger.info("Disconnecting: {}".format(repr(e)))
            finally:
                self.close_and_cleanup()
        return wrapper_func

    @ignore_exceptions  # do not kill main_taskgroup
    @handle_disconnect
    async def main_loop(self):
        async with aiorpcx.TaskGroup() as group:
            await group.spawn(self._message_loop())
            await group.spawn(self.query_gossip())
            await group.spawn(self.process_gossip())

    @log_exceptions
    async def process_gossip(self):
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
            # channel announcements
            self.verify_channel_announcements(chan_anns)
            self.channel_db.on_channel_announcement(chan_anns)
            # node announcements
            self.verify_node_announcements(node_anns)
            self.channel_db.on_node_announcement(node_anns)
            # channel updates
            orphaned, expired, deprecated, good, to_delete = self.channel_db.filter_channel_updates(chan_upds, max_age=self.network.lngossip.max_age)
            if orphaned:
                self.logger.info(f'adding {len(orphaned)} unknown channel ids')
                self.network.lngossip.add_new_ids(orphaned)
            if good:
                self.logger.debug(f'on_channel_update: {len(good)}/{len(chan_upds)}')
                self.verify_channel_updates(good)
                self.channel_db.update_policies(good, to_delete)
            # refresh gui
            if chan_anns or node_anns or chan_upds:
                self.network.lngossip.refresh_gui()

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

    def verify_channel_updates(self, chan_upds):
        for payload in chan_upds:
            short_channel_id = payload['short_channel_id']
            if constants.net.rev_genesis_bytes() != payload['chain_hash']:
                raise Exception('wrong chain hash')
            if not verify_sig_for_channel_update(payload, payload['start_node']):
                raise BaseException('verify error')

    @log_exceptions
    async def query_gossip(self):
        await asyncio.wait_for(self.initialized.wait(), 10)
        if self.lnworker == self.lnworker.network.lngossip:
            ids, complete = await asyncio.wait_for(self.get_channel_range(), 10)
            self.logger.info('Received {} channel ids. (complete: {})'.format(len(ids), complete))
            self.lnworker.add_new_ids(ids)
            while True:
                todo = self.lnworker.get_ids_to_query()
                if not todo:
                    await asyncio.sleep(1)
                    continue
                await self.get_short_channel_ids(todo)

    async def get_channel_range(self):
        req_index = self.lnworker.first_block
        req_num = self.lnworker.network.get_local_height() - req_index
        self.query_channel_range(req_index, req_num)
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
                if a <= req_index and b >= req_index + req_num:
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

    def query_channel_range(self, index, num):
        self.logger.info(f'query channel range {index} {num}')
        self.send_message(
            'query_channel_range',
            chain_hash=constants.net.rev_genesis_bytes(),
            first_blocknum=index,
            number_of_blocks=num)

    def encode_short_ids(self, ids):
        return chr(1) + zlib.compress(bfh(''.join(ids)))

    def decode_short_ids(self, encoded):
        if encoded[0] == 0:
            decoded = encoded[1:]
        elif encoded[0] == 1:
            decoded = zlib.decompress(encoded[1:])
        else:
            raise BaseException('zlib')
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
            await asyncio.wait_for(self.initialize(), 10)
        except (OSError, asyncio.TimeoutError, HandshakeFailed) as e:
            self.logger.info('initialize failed, disconnecting: {}'.format(repr(e)))
            return
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
            to_self_delay=9,
            dust_limit_sat=546,
            max_htlc_value_in_flight_msat=funding_sat * 1000,
            max_accepted_htlcs=5,
            initial_msat=initial_msat,
            ctn=-1,
            next_htlc_id=0,
            reserve_sat=546,
            per_commitment_secret_seed=keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey,
            funding_locked_received=False,
            was_announced=False,
            current_commitment_signature=None,
            current_htlc_signatures=[],
            got_sig_for_next=False,
        )
        return local_config

    @log_exceptions
    async def channel_establishment_flow(self, password: Optional[str], funding_sat: int,
                                         push_msat: int, temp_channel_id: bytes) -> Channel:
        wallet = self.lnworker.wallet
        # dry run creating funding tx to see if we even have enough funds
        funding_tx_test = wallet.mktx([TxOutput(bitcoin.TYPE_ADDRESS, wallet.dummy_address(), funding_sat)],
                                      password, self.lnworker.config, nonlocal_only=True)
        await asyncio.wait_for(self.initialized.wait(), 1)
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
        payload = await asyncio.wait_for(self.channel_accepted[temp_channel_id].get(), 5)
        if payload.get('error'):
            raise Exception('Remote Lightning peer reported error: ' + repr(payload.get('error')))
        remote_per_commitment_point = payload['first_per_commitment_point']
        funding_txn_minimum_depth = int.from_bytes(payload['minimum_depth'], 'big')
        assert funding_txn_minimum_depth > 0, funding_txn_minimum_depth
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
            ctn = -1,
            next_htlc_id = 0,
            reserve_sat = remote_reserve_sat,
            htlc_minimum_msat = htlc_min,

            next_per_commitment_point=remote_per_commitment_point,
            current_per_commitment_point=None,
            revocation_store=their_revocation_store,
        )
        # create funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = TxOutput(bitcoin.TYPE_ADDRESS, funding_address, funding_sat)
        funding_tx = wallet.mktx([funding_output], password, self.lnworker.config, nonlocal_only=True)
        funding_txid = funding_tx.txid()
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
                "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=True, funding_txn_minimum_depth=funding_txn_minimum_depth, feerate=feerate),
                "remote_commitment_to_be_revoked": None,
        }
        chan = Channel(chan_dict,
                       sweep_address=self.lnworker.sweep_address,
                       lnworker=self.lnworker)
        chan.lnwatcher = self.lnwatcher
        sig_64, _ = chan.sign_next_commitment()
        self.send_message("funding_created",
            temporary_channel_id=temp_channel_id,
            funding_txid=funding_txid_bytes,
            funding_output_index=funding_index,
            signature=sig_64)
        payload = await asyncio.wait_for(self.funding_signed[channel_id].get(), 5)
        self.logger.info('received funding_signed')
        remote_sig = payload['signature']
        chan.receive_new_commitment(remote_sig, [])
        # broadcast funding tx
        await asyncio.wait_for(self.network.broadcast_transaction(funding_tx), 5)
        chan.open_with_first_pcp(remote_per_commitment_point, remote_sig)
        chan.set_remote_commitment()
        chan.set_local_commitment(chan.current_commitment(LOCAL))
        return chan

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
                    ctn = -1,
                    next_htlc_id = 0,
                    reserve_sat = remote_reserve_sat,
                    htlc_minimum_msat=int.from_bytes(payload['htlc_minimum_msat'], 'big'), # TODO validate
                    next_per_commitment_point=payload['first_per_commitment_point'],
                    current_per_commitment_point=None,
                    revocation_store=their_revocation_store,
                ),
                "local_config": local_config,
                "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=False, funding_txn_minimum_depth=min_depth, feerate=feerate),
                "remote_commitment_to_be_revoked": None,
        }
        chan = Channel(chan_dict,
                       sweep_address=self.lnworker.sweep_address,
                       lnworker=self.lnworker)
        chan.lnwatcher = self.lnwatcher
        remote_sig = funding_created['signature']
        chan.receive_new_commitment(remote_sig, [])
        sig_64, _ = chan.sign_next_commitment()
        self.send_message('funding_signed',
            channel_id=channel_id,
            signature=sig_64,
        )
        chan.open_with_first_pcp(payload['first_per_commitment_point'], remote_sig)
        self.lnworker.save_channel(chan)
        self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())
        self.lnworker.on_channels_updated()
        while True:
            try:
                funding_tx = Transaction(await self.network.get_transaction(funding_txid))
            except aiorpcx.jsonrpc.RPCError as e:
                print("sleeping", str(e))
                await asyncio.sleep(1)
            else:
                break
        outp = funding_tx.outputs()[funding_idx]
        redeem_script = funding_output_script(chan.config[REMOTE], chan.config[LOCAL])
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        if outp != TxOutput(bitcoin.TYPE_ADDRESS, funding_address, funding_sat):
            chan.set_state('DISCONNECTED')
            raise Exception('funding outpoint mismatch')

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
        self.channel_reestablished[chan_id].set_result(payload)

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
        if chan.get_state() != 'DISCONNECTED':
            self.logger.info('reestablish_channel was called but channel {} already in state {}'
                             .format(chan_id, chan.get_state()))
            return
        chan.set_state('REESTABLISHING')
        self.network.trigger_callback('channel', chan)
        current_remote_ctn = chan.config[REMOTE].ctn
        # send message
        if self.their_localfeatures & LnLocalFeatures.OPTION_DATA_LOSS_PROTECT_REQ:
            self.logger.info('peer requires data loss protect')
            if current_remote_ctn == 0:
                last_rev_secret = 0
            else:
                revocation_store = chan.config[REMOTE].revocation_store
                last_rev_index = current_remote_ctn - 1
                last_rev_secret = revocation_store.retrieve_secret(RevocationStore.START_INDEX - last_rev_index)
            last_secret, last_point = chan.local_points(offset=0)
            self.send_message(
                "channel_reestablish",
                channel_id=chan_id,
                next_local_commitment_number=chan.config[LOCAL].ctn+1,
                next_remote_revocation_number=current_remote_ctn,
                your_last_per_commitment_secret=last_rev_secret,
                my_current_per_commitment_point=last_point)
        else:
            self.send_message(
                "channel_reestablish",
                channel_id=chan_id,
                next_local_commitment_number=chan.config[LOCAL].ctn+1,
                next_remote_revocation_number=current_remote_ctn)

        channel_reestablish_msg = await self.channel_reestablished[chan_id]
        chan.set_state('OPENING')
        # compare remote ctns
        their_next_local_ctn = int.from_bytes(channel_reestablish_msg["next_local_commitment_number"], 'big')
        their_next_remote_ctn = int.from_bytes(channel_reestablish_msg["next_remote_revocation_number"], 'big')
        if their_next_local_ctn != chan.config[REMOTE].ctn + 1:
            self.logger.info("expected remote ctn {}, got {}".format(chan.config[REMOTE].ctn + 1, their_next_local_ctn))
            # TODO iff their ctn is lower than ours, we should force close instead
            self.try_to_get_remote_to_force_close_with_their_latest(chan_id)
            return
        # compare local ctns
        if chan.config[LOCAL].ctn != their_next_remote_ctn:
            if chan.config[LOCAL].ctn == their_next_remote_ctn + 1:
                # A node:
                #    if next_remote_revocation_number is equal to the
                #    commitment number of the last revoke_and_ack
                #    the receiving node sent, AND the receiving node
                #    hasn't already received a closing_signed:
                #        MUST re-send the revoke_and_ack.
                last_secret, last_point = chan.local_points(offset=-1)
                next_secret, next_point = chan.local_points(offset=1)
                self.send_message(
                    "revoke_and_ack",
                    channel_id=chan.channel_id,
                    per_commitment_secret=last_secret,
                    next_per_commitment_point=next_point)
            else:
                self.logger.info(f"expected local ctn {chan.config[LOCAL].ctn}, got {their_next_remote_ctn}")
                # TODO iff their ctn is lower than ours, we should force close instead
                self.try_to_get_remote_to_force_close_with_their_latest(chan_id)
                return
        # compare per commitment points (needs data_protect option)
        their_pcp = channel_reestablish_msg.get("my_current_per_commitment_point", None)
        if their_pcp is not None:
            our_pcp = chan.config[REMOTE].current_per_commitment_point
            if our_pcp is None:
                our_pcp = chan.config[REMOTE].next_per_commitment_point
            if our_pcp != their_pcp:
                self.logger.info(f"Remote PCP mismatch: {bh2u(our_pcp)} {bh2u(their_pcp)}")
                # FIXME ...what now?
                self.try_to_get_remote_to_force_close_with_their_latest(chan_id)
                return
        if their_next_local_ctn == chan.config[LOCAL].ctn+1 == 1 and chan.short_channel_id:
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

        print("SENT CHANNEL ANNOUNCEMENT")

    def mark_open(self, chan: Channel):
        assert chan.short_channel_id is not None
        if chan.get_state() == "OPEN":
            return
        # NOTE: even closed channels will be temporarily marked "OPEN"
        assert chan.config[LOCAL].funding_locked_received
        chan.set_state("OPEN")
        self.network.trigger_callback('channel', chan)
        # add channel to database
        bitcoin_keys = [chan.config[LOCAL].multisig_key.pubkey, chan.config[REMOTE].multisig_key.pubkey]
        sorted_node_ids = list(sorted(self.node_ids))
        if sorted_node_ids != self.node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()
        else:
            node_ids = self.node_ids
        # note: we inject a channel announcement, and a channel update (for outgoing direction)
        # This is atm needed for
        # - finding routes
        # - the ChanAnn is needed so that we can anchor to it a future ChanUpd
        #   that the remote sends, even if the channel was not announced
        #   (from BOLT-07: "MAY create a channel_update to communicate the channel
        #    parameters to the final node, even though the channel has not yet been announced")
        self.channel_db.on_channel_announcement(
            {
                "short_channel_id": chan.short_channel_id,
                "node_id_1": node_ids[0],
                "node_id_2": node_ids[1],
                'chain_hash': constants.net.rev_genesis_bytes(),
                'len': b'\x00\x00',
                'features': b'',
                'bitcoin_key_1': bitcoin_keys[0],
                'bitcoin_key_2': bitcoin_keys[1]
            },
            trusted=True)
        # only inject outgoing direction:
        channel_flags = b'\x00' if node_ids[0] == privkey_to_pubkey(self.privkey) else b'\x01'
        now = int(time.time())
        self.channel_db.add_channel_update(
            {
                "short_channel_id": chan.short_channel_id,
                'channel_flags': channel_flags,
                'cltv_expiry_delta': b'\x90',
                'htlc_minimum_msat': b'\x03\xe8',
                'fee_base_msat': b'\x03\xe8',
                'fee_proportional_millionths': b'\x01',
                'chain_hash': constants.net.rev_genesis_bytes(),
                'timestamp': now.to_bytes(4, byteorder="big")
            })
        # peer may have sent us a channel update for the incoming direction previously
        # note: if we were offline when the 3rd conf happened, lnd will never send us this channel_update
        # see https://github.com/lightningnetwork/lnd/issues/1347
        #self.send_message("query_short_channel_ids", chain_hash=constants.net.rev_genesis_bytes(),
        #                          len=9, encoded_short_ids=b'\x00'+chan.short_channel_id)
        pending_channel_update = self.orphan_channel_updates.get(chan.short_channel_id)
        if pending_channel_update:
            self.channel_db.add_channel_update(pending_channel_update)

        self.logger.info("CHANNEL OPENING COMPLETED")

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
        key = (channel_id, htlc_id)
        try:
            route = self.attempted_route[key]
        except KeyError:
            # the remote might try to fail an htlc after we restarted...
            # attempted_route is not persisted, so we will get here then
            self.logger.info("UPDATE_FAIL_HTLC. cannot decode! attempted route is MISSING. {}".format(key))
        else:
            try:
                self._handle_error_code_from_failed_htlc(payload["reason"], route, channel_id, htlc_id)
            except Exception:
                # exceptions are suppressed as failing to handle an error code
                # should not block us from removing the htlc
                traceback.print_exc(file=sys.stderr)
        # process update_fail_htlc on channel
        chan = self.channels[channel_id]
        chan.receive_fail_htlc(htlc_id)
        local_ctn = chan.get_current_ctn(LOCAL)
        asyncio.ensure_future(self._on_update_fail_htlc(chan, htlc_id, local_ctn))

    @log_exceptions
    async def _on_update_fail_htlc(self, chan, htlc_id, local_ctn):
        await self.await_local(chan, local_ctn)
        self.network.trigger_callback('ln_message', self.lnworker, 'Payment failed', htlc_id)

    def _handle_error_code_from_failed_htlc(self, error_reason, route: List['RouteEdge'], channel_id, htlc_id):
        chan = self.channels[channel_id]
        failure_msg, sender_idx = decode_onion_error(error_reason,
                                                     [x.node_id for x in route],
                                                     chan.onion_keys[htlc_id])
        code, data = failure_msg.code, failure_msg.data
        self.logger.info(f"UPDATE_FAIL_HTLC {repr(code)} {data}")
        self.logger.info(f"error reported by {bh2u(route[sender_idx].node_id)}")
        # handle some specific error codes
        failure_codes = {
            OnionFailureCode.TEMPORARY_CHANNEL_FAILURE: 2,
            OnionFailureCode.AMOUNT_BELOW_MINIMUM: 10,
            OnionFailureCode.FEE_INSUFFICIENT: 10,
            OnionFailureCode.INCORRECT_CLTV_EXPIRY: 6,
            OnionFailureCode.EXPIRY_TOO_SOON: 2,
            OnionFailureCode.CHANNEL_DISABLED: 4,
        }
        if code in failure_codes:
            offset = failure_codes[code]
            channel_update = (258).to_bytes(length=2, byteorder="big") + data[offset:]
            message_type, payload = decode_msg(channel_update)
            payload['raw'] = channel_update
            orphaned, expired, deprecated, good, to_delete = self.channel_db.filter_channel_updates([payload])
            blacklist = False
            if good:
                self.verify_channel_updates(good)
                self.channel_db.update_policies(good, to_delete)
                self.logger.info("applied channel update on our db")
            elif orphaned:
                # maybe it is a private channel (and data in invoice was outdated)
                self.logger.info("maybe channel update is for private channel?")
                start_node_id = route[sender_idx].node_id
                self.channel_db.add_channel_update_for_private_channel(payload, start_node_id)
            elif expired:
                blacklist = True
            elif deprecated:
                self.logger.info(f'channel update is not more recent.')
                blacklist = True
        else:
            blacklist = True
        if blacklist:
            # blacklist channel after reporter node
            # TODO this should depend on the error (even more granularity)
            # also, we need finer blacklisting (directed edges; nodes)
            try:
                short_chan_id = route[sender_idx + 1].short_channel_id
            except IndexError:
                self.logger.info("payment destination reported error")
            else:
                self.logger.info(f'blacklisting channel {bh2u(short_chan_id)}')
                self.network.path_finder.blacklist.add(short_chan_id)

    def maybe_send_commitment(self, chan: Channel):
        ctn_to_sign = chan.get_current_ctn(REMOTE) + 1
        # if there are no changes, we will not (and must not) send a new commitment
        pending, current = chan.hm.pending_htlcs(REMOTE), chan.hm.current_htlcs(REMOTE)
        if (pending == current
                and chan.pending_feerate(REMOTE) == chan.constraints.feerate) \
                or ctn_to_sign == self.sent_commitment_for_ctn_last[chan]:
            return
        self.logger.info(f'send_commitment. old number htlcs: {len(current)}, new number htlcs: {len(pending)}')
        sig_64, htlc_sigs = chan.sign_next_commitment()
        self.send_message("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs))
        self.sent_commitment_for_ctn_last[chan] = ctn_to_sign

    async def await_remote(self, chan: Channel, ctn: int):
        self.maybe_send_commitment(chan)
        while chan.get_current_ctn(REMOTE) <= ctn:
            await self._remote_changed_events[chan.channel_id].wait()

    async def await_local(self, chan: Channel, ctn: int):
        self.maybe_send_commitment(chan)
        while chan.get_current_ctn(LOCAL) <= ctn:
            await self._local_changed_events[chan.channel_id].wait()

    async def pay(self, route: List['RouteEdge'], chan: Channel, amount_msat: int,
                  payment_hash: bytes, min_final_cltv_expiry: int) -> UpdateAddHtlc:
        assert chan.get_state() == "OPEN", chan.get_state()
        assert amount_msat > 0, "amount_msat is not greater zero"
        # create onion packet
        final_cltv = self.network.get_local_height() + min_final_cltv_expiry
        hops_data, amount_msat, cltv = calc_hops_data_for_payment(route, amount_msat, final_cltv)
        assert final_cltv <= cltv, (final_cltv, cltv)
        secret_key = os.urandom(32)
        onion = new_onion_packet([x.node_id for x in route], secret_key, hops_data, associated_data=payment_hash)
        # create htlc
        htlc = UpdateAddHtlc(amount_msat=amount_msat, payment_hash=payment_hash, cltv_expiry=cltv, timestamp=int(time.time()))
        htlc = chan.add_htlc(htlc)
        remote_ctn = chan.get_current_ctn(REMOTE)
        chan.onion_keys[htlc.htlc_id] = secret_key
        self.attempted_route[(chan.channel_id, htlc.htlc_id)] = route
        self.logger.info(f"starting payment. route: {route}")
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
        self.logger.info("on_commitment_signed")
        channel_id = payload['channel_id']
        chan = self.channels[channel_id]
        ctn_to_recv = chan.get_current_ctn(LOCAL) + 1
        # make sure there were changes to the ctx, otherwise the remote peer is misbehaving
        if (chan.hm.pending_htlcs(LOCAL) == chan.hm.current_htlcs(LOCAL)
            and chan.pending_feerate(LOCAL) == chan.constraints.feerate) \
                or ctn_to_recv == self.recv_commitment_for_ctn_last[chan]:
            raise RemoteMisbehaving('received commitment_signed without any change')
        self.recv_commitment_for_ctn_last[chan] = ctn_to_recv

        data = payload["htlc_signature"]
        htlc_sigs = [data[i:i+64] for i in range(0, len(data), 64)]
        chan.receive_new_commitment(payload["signature"], htlc_sigs)
        self.send_revoke_and_ack(chan)

    def on_update_fulfill_htlc(self, update_fulfill_htlc_msg):
        self.logger.info("update_fulfill")
        chan = self.channels[update_fulfill_htlc_msg["channel_id"]]
        preimage = update_fulfill_htlc_msg["payment_preimage"]
        htlc_id = int.from_bytes(update_fulfill_htlc_msg["id"], "big")
        chan.receive_htlc_settle(preimage, htlc_id)
        local_ctn = chan.get_current_ctn(LOCAL)
        asyncio.ensure_future(self._on_update_fulfill_htlc(chan, htlc_id, preimage, local_ctn))

    @log_exceptions
    async def _on_update_fulfill_htlc(self, chan, htlc_id, preimage, local_ctn):
        await self.await_local(chan, local_ctn)
        self.network.trigger_callback('ln_message', self.lnworker, 'Payment sent', htlc_id)
        self.payment_preimages[sha256(preimage)].put_nowait(preimage)

    def on_update_fail_malformed_htlc(self, payload):
        self.logger.info(f"error {payload['data'].decode('ascii')}")

    def on_update_add_htlc(self, payload):
        # no onion routing for the moment: we assume we are the end node
        self.logger.info('on_update_add_htlc')
        # check if this in our list of requests
        payment_hash = payload["payment_hash"]
        channel_id = payload['channel_id']
        htlc_id = int.from_bytes(payload["id"], 'big')
        cltv_expiry = int.from_bytes(payload["cltv_expiry"], 'big')
        amount_msat_htlc = int.from_bytes(payload["amount_msat"], 'big')
        onion_packet = OnionPacket.from_bytes(payload["onion_routing_packet"])
        processed_onion = process_onion_packet(onion_packet, associated_data=payment_hash, our_onion_private_key=self.privkey)
        chan = self.channels[channel_id]
        assert chan.get_state() == "OPEN"
        assert htlc_id == chan.config[REMOTE].next_htlc_id, (htlc_id, chan.config[REMOTE].next_htlc_id)  # TODO fail channel instead
        if cltv_expiry >= 500_000_000:
            pass  # TODO fail the channel
        # add htlc
        htlc = UpdateAddHtlc(amount_msat=amount_msat_htlc, payment_hash=payment_hash, cltv_expiry=cltv_expiry, timestamp=int(time.time()))
        htlc = chan.receive_htlc(htlc)
        local_ctn = chan.get_current_ctn(LOCAL)
        remote_ctn = chan.get_current_ctn(REMOTE)
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
        dph = processed_onion.hop_data.per_hop
        next_chan = self.lnworker.get_channel_by_short_id(dph.short_channel_id)
        next_peer = self.lnworker.peers[next_chan.node_id]
        if next_chan is None or next_chan.get_state() != 'OPEN':
            self.logger.info(f"cannot forward htlc {next_chan.get_state() if next_chan else None}")
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.PERMANENT_CHANNEL_FAILURE, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        self.logger.info(f'forwarding htlc to {next_chan.node_id}')
        next_cltv_expiry = int.from_bytes(dph.outgoing_cltv_value, 'big')
        next_amount_msat_htlc = int.from_bytes(dph.amt_to_forward, 'big')
        next_htlc = UpdateAddHtlc(amount_msat=next_amount_msat_htlc, payment_hash=htlc.payment_hash, cltv_expiry=next_cltv_expiry, timestamp=int(time.time()))
        next_htlc = next_chan.add_htlc(next_htlc)
        next_remote_ctn = next_chan.get_current_ctn(REMOTE)
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
        # wait until we get paid
        preimage = await next_peer.payment_preimages[next_htlc.payment_hash].get()
        # fulfill the original htlc
        await self._fulfill_htlc(chan, htlc.htlc_id, preimage)
        self.logger.info("htlc forwarded successfully")

    @log_exceptions
    async def _maybe_fulfill_htlc(self, chan: Channel, htlc: UpdateAddHtlc, *, local_ctn: int, remote_ctn: int,
                                  onion_packet: OnionPacket, processed_onion: ProcessedOnionPacket):
        await self.await_local(chan, local_ctn)
        await self.await_remote(chan, remote_ctn)
        try:
            invoice = self.lnworker.get_invoice(htlc.payment_hash)
            preimage = self.lnworker.get_preimage(htlc.payment_hash)
        except UnknownPaymentHash:
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.UNKNOWN_PAYMENT_HASH, data=b'')
            await self.fail_htlc(chan, htlc.htlc_id, onion_packet, reason)
            return
        expected_received_msat = int(invoice.amount * bitcoin.COIN * 1000) if invoice.amount is not None else None
        if expected_received_msat is not None and \
                (htlc.amount_msat < expected_received_msat or htlc.amount_msat > 2 * expected_received_msat):
            reason = OnionRoutingFailureMessage(code=OnionFailureCode.INCORRECT_PAYMENT_AMOUNT, data=b'')
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
        self.network.trigger_callback('htlc_added', htlc, invoice, RECEIVED)
        if self.network.config.debug_lightning_do_not_settle:
            return
        await self._fulfill_htlc(chan, htlc.htlc_id, preimage)

    async def _fulfill_htlc(self, chan: Channel, htlc_id: int, preimage: bytes):
        chan.settle_htlc(preimage, htlc_id)
        remote_ctn = chan.get_current_ctn(REMOTE)
        self.send_message("update_fulfill_htlc",
                          channel_id=chan.channel_id,
                          id=htlc_id,
                          payment_preimage=preimage)
        await self.await_remote(chan, remote_ctn)
        self.network.trigger_callback('ln_message', self.lnworker, 'Payment received', htlc_id)

    async def fail_htlc(self, chan: Channel, htlc_id: int, onion_packet: OnionPacket,
                        reason: OnionRoutingFailureMessage):
        self.logger.info(f"failing received htlc {(bh2u(chan.channel_id), htlc_id)}. reason: {reason}")
        chan.fail_htlc(htlc_id)
        remote_ctn = chan.get_current_ctn(REMOTE)
        error_packet = construct_onion_error(reason, onion_packet, our_onion_private_key=self.privkey)
        self.send_message("update_fail_htlc",
                          channel_id=chan.channel_id,
                          id=htlc_id,
                          len=len(error_packet),
                          reason=error_packet)
        await self.await_remote(chan, remote_ctn)

    def on_revoke_and_ack(self, payload):
        self.logger.info("on_revoke_and_ack")
        channel_id = payload["channel_id"]
        chan = self.channels[channel_id]
        chan.receive_revocation(RevokeAndAck(payload["per_commitment_secret"], payload["next_per_commitment_point"]))
        self._remote_changed_events[chan.channel_id].set()
        self._remote_changed_events[chan.channel_id].clear()
        self.lnworker.save_channel(chan)

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
        chan_fee = chan.pending_feerate(REMOTE)
        self.logger.info(f"current pending feerate {chan_fee}")
        self.logger.info(f"new feerate {feerate_per_kw}")
        if feerate_per_kw < chan_fee / 2:
            self.logger.info("FEES HAVE FALLEN")
        elif feerate_per_kw > chan_fee * 2:
            self.logger.info("FEES HAVE RISEN")
        else:
            return
        chan.update_fee(feerate_per_kw, True)
        remote_ctn = chan.get_current_ctn(REMOTE)
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
        chan.set_state('CLOSING')
        while len(chan.hm.htlcs_by_direction(LOCAL, RECEIVED)) > 0:
            self.logger.info('waiting for htlcs to settle...')
            await asyncio.sleep(1)
        our_fee = chan.pending_local_fee()
        scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        # negociate fee
        while True:
            our_sig, closing_tx = chan.make_closing_tx(scriptpubkey, payload['scriptpubkey'], fee_sat=our_fee)
            self.send_message('closing_signed', channel_id=chan.channel_id, fee_satoshis=our_fee, signature=our_sig)
            cs_payload = await asyncio.wait_for(self.closing_signed[chan.channel_id].get(), 10)
            their_fee = int.from_bytes(cs_payload['fee_satoshis'], 'big')
            their_sig = cs_payload['signature']
            if our_fee == their_fee:
                break
            # TODO: negociate better
            our_fee = their_fee
        # index of our_sig
        i = chan.get_local_index()
        # add signatures
        closing_tx.add_signature_to_txin(0, i, bh2u(der_sig_from_sig_string(our_sig) + b'\x01'))
        closing_tx.add_signature_to_txin(0, 1-i, bh2u(der_sig_from_sig_string(their_sig) + b'\x01'))
        # broadcast
        await self.network.broadcast_transaction(closing_tx)
        return closing_tx.txid()
