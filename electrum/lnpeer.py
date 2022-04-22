#!/usr/bin/env python3
#
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import zlib
from collections import OrderedDict, defaultdict
import asyncio
import os
import time
from typing import Tuple, Dict, TYPE_CHECKING, Optional, Union, Set
from datetime import datetime
import functools

import aiorpcx
from aiorpcx import ignore_after

from .crypto import sha256, sha256d
from . import bitcoin, util
from . import ecc
from .ecc import sig_string_from_r_and_s, der_sig_from_sig_string
from . import constants
from .util import (bh2u, bfh, log_exceptions, ignore_exceptions, chunks, OldTaskGroup,
                   UnrelatedTransactionException)
from . import transaction
from .bitcoin import make_op_return
from .transaction import PartialTxOutput, match_script_against_template
from .logging import Logger
from .lnonion import (new_onion_packet, OnionFailureCode, calc_hops_data_for_payment,
                      process_onion_packet, OnionPacket, construct_onion_error, OnionRoutingFailure,
                      ProcessedOnionPacket, UnsupportedOnionPacketVersion, InvalidOnionMac, InvalidOnionPubkey,
                      OnionFailureCodeMetaFlag)
from .lnchannel import Channel, RevokeAndAck, RemoteCtnTooFarInFuture, ChannelState, PeerState
from . import lnutil
from .lnutil import (Outpoint, LocalConfig, RECEIVED, UpdateAddHtlc, ChannelConfig,
                     RemoteConfig, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore,
                     funding_output_script, get_per_commitment_secret_from_seed,
                     secret_to_pubkey, PaymentFailure, LnFeatures,
                     LOCAL, REMOTE, HTLCOwner,
                     ln_compare_features, privkey_to_pubkey, MIN_FINAL_CLTV_EXPIRY_ACCEPTED,
                     LightningPeerConnectionClosed, HandshakeFailed,
                     RemoteMisbehaving, ShortChannelID,
                     IncompatibleLightningFeatures, derive_payment_secret_from_payment_preimage,
                     ChannelType, LNProtocolWarning)
from .lnutil import FeeUpdate, channel_id_from_funding_tx
from .lntransport import LNTransport, LNTransportBase
from .lnmsg import encode_msg, decode_msg, UnknownOptionalMsgType
from .interface import GracefulDisconnect
from .lnrouter import fee_for_edge_msat
from .lnutil import ln_dummy_address
from .json_db import StoredDict
from .invoices import PR_PAID
from .simple_config import FEE_LN_ETA_TARGET

if TYPE_CHECKING:
    from .lnworker import LNGossip, LNWallet
    from .lnrouter import LNPaymentRoute
    from .transaction import PartialTransaction


LN_P2P_NETWORK_TIMEOUT = 20


class Peer(Logger):
    LOGGING_SHORTCUT = 'P'

    ORDERED_MESSAGES = (
        'accept_channel', 'funding_signed', 'funding_created', 'accept_channel', 'closing_signed')
    SPAMMY_MESSAGES = (
        'ping', 'pong', 'channel_announcement', 'node_announcement', 'channel_update',)

    DELAY_INC_MSG_PROCESSING_SLEEP = 0.01

    def __init__(
            self,
            lnworker: Union['LNGossip', 'LNWallet'],
            pubkey: bytes,
            transport: LNTransportBase,
            *, is_channel_backup= False):

        self.is_channel_backup = is_channel_backup
        self._sent_init = False  # type: bool
        self._received_init = False  # type: bool
        self.initialized = asyncio.Future()
        self.got_disconnected = asyncio.Event()
        self.querying = asyncio.Event()
        self.transport = transport
        self.pubkey = pubkey  # remote pubkey
        self.lnworker = lnworker
        self.privkey = self.transport.privkey  # local privkey
        self.features = self.lnworker.features  # type: LnFeatures
        self.their_features = LnFeatures(0)  # type: LnFeatures
        self.node_ids = [self.pubkey, privkey_to_pubkey(self.privkey)]
        assert self.node_ids[0] != self.node_ids[1]
        self.network = lnworker.network
        self.ping_time = 0
        self.reply_channel_range = asyncio.Queue()
        # gossip uses a single queue to preserve message order
        self.gossip_queue = asyncio.Queue()
        self.ordered_message_queues = defaultdict(asyncio.Queue)  # for messages that are ordered
        self.temp_id_to_id = {}  # type: Dict[bytes, Optional[bytes]]   # to forward error messages
        self.funding_created_sent = set() # for channels in PREOPENING
        self.funding_signed_sent = set()  # for channels in PREOPENING
        self.shutdown_received = {} # chan_id -> asyncio.Future()
        self.announcement_signatures = defaultdict(asyncio.Queue)
        self.channel_reestablish_msg = defaultdict(asyncio.Future)
        self.orphan_channel_updates = OrderedDict()  # type: OrderedDict[ShortChannelID, dict]
        Logger.__init__(self)
        self.taskgroup = OldTaskGroup()
        # HTLCs offered by REMOTE, that we started removing but are still active:
        self.received_htlcs_pending_removal = set()  # type: Set[Tuple[Channel, int]]
        self.received_htlc_removed_event = asyncio.Event()
        self._htlc_switch_iterstart_event = asyncio.Event()
        self._htlc_switch_iterdone_event = asyncio.Event()
        self._received_revack_event = asyncio.Event()
        self.downstream_htlc_resolved_event = asyncio.Event()

    def send_message(self, message_name: str, **kwargs):
        assert type(message_name) is str
        if message_name not in self.SPAMMY_MESSAGES:
            self.logger.debug(f"Sending {message_name.upper()}")
        if message_name.upper() != "INIT" and not self.is_initialized():
            raise Exception("tried to send message before we are initialized")
        raw_msg = encode_msg(message_name, **kwargs)
        self._store_raw_msg_if_local_update(raw_msg, message_name=message_name, channel_id=kwargs.get("channel_id"))
        self.transport.send_bytes(raw_msg)

    def _store_raw_msg_if_local_update(self, raw_msg: bytes, *, message_name: str, channel_id: Optional[bytes]):
        is_commitment_signed = message_name == "commitment_signed"
        if not (message_name.startswith("update_") or is_commitment_signed):
            return
        assert channel_id
        chan = self.get_channel_by_id(channel_id)
        if not chan:
            raise Exception(f"channel {channel_id.hex()} not found for peer {self.pubkey.hex()}")
        chan.hm.store_local_update_raw_msg(raw_msg, is_commitment_signed=is_commitment_signed)
        if is_commitment_signed:
            # saving now, to ensure replaying updates works (in case of channel reestablishment)
            self.lnworker.save_channel(chan)

    def maybe_set_initialized(self):
        if self.initialized.done():
            return
        if self._sent_init and self._received_init:
            self.initialized.set_result(True)

    def is_initialized(self) -> bool:
        return (self.initialized.done()
                and not self.initialized.cancelled()
                and self.initialized.exception() is None
                and self.initialized.result() is True)

    async def initialize(self):
        # If outgoing transport, do handshake now. For incoming, it has already been done.
        if isinstance(self.transport, LNTransport):
            await self.transport.handshake()
        self.logger.info(f"handshake done for {self.transport.peer_addr or self.pubkey.hex()}")
        features = self.features.for_init_message()
        b = int.bit_length(features)
        flen = b // 8 + int(bool(b % 8))
        self.send_message(
            "init", gflen=0, flen=flen,
            features=features,
            init_tlvs={
                'networks':
                {'chains': constants.net.rev_genesis_bytes()}
            })
        self._sent_init = True
        self.maybe_set_initialized()

    @property
    def channels(self) -> Dict[bytes, Channel]:
        return self.lnworker.channels_for_peer(self.pubkey)

    def get_channel_by_id(self, channel_id: bytes) -> Optional[Channel]:
        # note: this is faster than self.channels.get(channel_id)
        chan = self.lnworker.get_channel_by_id(channel_id)
        if not chan:
            return None
        if chan.node_id != self.pubkey:
            return None
        return chan

    def diagnostic_name(self):
        return self.lnworker.__class__.__name__ + ', ' + self.transport.name()

    def ping_if_required(self):
        if time.time() - self.ping_time > 120:
            self.send_message('ping', num_pong_bytes=4, byteslen=4)
            self.ping_time = time.time()

    def process_message(self, message):
        try:
            message_type, payload = decode_msg(message)
        except UnknownOptionalMsgType as e:
            self.logger.info(f"received unknown message from peer. ignoring: {e!r}")
            return
        if message_type not in self.SPAMMY_MESSAGES:
            self.logger.debug(f"Received {message_type.upper()}")
        # only process INIT if we are a backup
        if self.is_channel_backup is True and message_type != 'init':
            return
        if message_type in self.ORDERED_MESSAGES:
            chan_id = payload.get('channel_id') or payload["temporary_channel_id"]
            self.ordered_message_queues[chan_id].put_nowait((message_type, payload))
        else:
            if message_type not in ('error', 'warning') and 'channel_id' in payload:
                chan = self.get_channel_by_id(payload['channel_id'])
                if chan is None:
                    raise Exception('Got unknown '+ message_type)
                args = (chan, payload)
            else:
                args = (payload,)
            try:
                f = getattr(self, 'on_' + message_type)
            except AttributeError:
                #self.logger.info("Received '%s'" % message_type.upper(), payload)
                return
            # raw message is needed to check signature
            if message_type in ['node_announcement', 'channel_announcement', 'channel_update']:
                payload['raw'] = message
            execution_result = f(*args)
            if asyncio.iscoroutinefunction(f):
                asyncio.ensure_future(self.taskgroup.spawn(execution_result))

    def on_warning(self, payload):
        chan_id = payload.get("channel_id")
        self.logger.info(f"remote peer sent warning [DO NOT TRUST THIS MESSAGE]: "
                         f"{payload['data'].decode('ascii')}. chan_id={chan_id.hex()}")
        if chan_id in self.channels:
            self.ordered_message_queues[chan_id].put_nowait((None, {'warning': payload['data']}))
        elif chan_id in self.temp_id_to_id:
            chan_id = self.temp_id_to_id[chan_id] or chan_id
            self.ordered_message_queues[chan_id].put_nowait((None, {'warning': payload['data']}))
        else:
            # if no existing channel is referred to by channel_id:
            # - MUST ignore the message.
            return
        raise GracefulDisconnect

    def on_error(self, payload):
        chan_id = payload.get("channel_id")
        self.logger.info(f"remote peer sent error [DO NOT TRUST THIS MESSAGE]: "
                         f"{payload['data'].decode('ascii')}. chan_id={chan_id.hex()}")
        if chan_id in self.channels:
            self.schedule_force_closing(chan_id)
            self.ordered_message_queues[chan_id].put_nowait((None, {'error': payload['data']}))
        elif chan_id in self.temp_id_to_id:
            chan_id = self.temp_id_to_id[chan_id] or chan_id
            self.ordered_message_queues[chan_id].put_nowait((None, {'error': payload['data']}))
        elif chan_id == bytes(32):
            # if channel_id is all zero:
            # - MUST fail all channels with the sending node.
            for cid in self.channels:
                self.schedule_force_closing(cid)
                self.ordered_message_queues[cid].put_nowait((None, {'error': payload['data']}))
        else:
            # if no existing channel is referred to by channel_id:
            # - MUST ignore the message.
            return
        raise GracefulDisconnect

    async def send_warning(self, channel_id: bytes, message: str = None, *, close_connection=True):
        """Sends a warning and disconnects if close_connection.

        Note:
        * channel_id is the temporary channel id when the channel id is not yet available

        A sending node:
        MAY set channel_id to all zero if the warning is not related to a specific channel.

        when failure was caused by an invalid signature check:
        * SHOULD include the raw, hex-encoded transaction in reply to a funding_created,
          funding_signed, closing_signed, or commitment_signed message.
        """
        assert isinstance(channel_id, bytes)
        encoded_data = b'' if not message else message.encode('ascii')
        self.send_message('warning', channel_id=channel_id, data=encoded_data, len=len(encoded_data))
        if close_connection:
            raise GracefulDisconnect

    async def send_error(self, channel_id: bytes, message: str = None, *, force_close_channel=False):
        """Sends an error message and force closes the channel.

        Note:
        * channel_id is the temporary channel id when the channel id is not yet available

        A sending node:
        * SHOULD send error for protocol violations or internal errors that make channels
          unusable or that make further communication unusable.
        * SHOULD send error with the unknown channel_id in reply to messages of type
          32-255 related to unknown channels.
        * MUST fail the channel(s) referred to by the error message.
        * MAY set channel_id to all zero to indicate all channels.

        when failure was caused by an invalid signature check:
        * SHOULD include the raw, hex-encoded transaction in reply to a funding_created,
          funding_signed, closing_signed, or commitment_signed message.
        """
        assert isinstance(channel_id, bytes)
        encoded_data = b'' if not message else message.encode('ascii')
        self.send_message('error', channel_id=channel_id, data=encoded_data, len=len(encoded_data))
        # MUST fail the channel(s) referred to by the error message:
        #  we may violate this with force_close_channel
        if force_close_channel:
            if channel_id in self.channels:
                self.schedule_force_closing(channel_id)
            elif channel_id == bytes(32):
                for cid in self.channels:
                    self.schedule_force_closing(cid)
        raise GracefulDisconnect

    def on_ping(self, payload):
        l = payload['num_pong_bytes']
        self.send_message('pong', byteslen=l)

    def on_pong(self, payload):
        pass

    async def wait_for_message(self, expected_name, channel_id):
        q = self.ordered_message_queues[channel_id]
        name, payload = await asyncio.wait_for(q.get(), LN_P2P_NETWORK_TIMEOUT)
        # raise exceptions for errors/warnings, so that the caller sees them
        if payload.get('error'):
            raise GracefulDisconnect(
                f"remote peer sent error [DO NOT TRUST THIS MESSAGE]: {payload['error'].decode('ascii')}")
        elif payload.get('warning'):
            raise GracefulDisconnect(
                f"remote peer sent warning [DO NOT TRUST THIS MESSAGE]: {payload['warning'].decode('ascii')}")
        if name != expected_name:
            raise Exception(f"Received unexpected '{name}'")
        return payload

    def on_init(self, payload):
        if self._received_init:
            self.logger.info("ALREADY INITIALIZED BUT RECEIVED INIT")
            return
        self.their_features = LnFeatures(int.from_bytes(payload['features'], byteorder="big"))
        their_globalfeatures = int.from_bytes(payload['globalfeatures'], byteorder="big")
        self.their_features |= their_globalfeatures
        # check transitive dependencies for received features
        if not self.their_features.validate_transitive_dependencies():
            raise GracefulDisconnect("remote did not set all dependencies for the features they sent")
        # check if features are compatible, and set self.features to what we negotiated
        try:
            self.features = ln_compare_features(self.features, self.their_features)
        except IncompatibleLightningFeatures as e:
            self.initialized.set_exception(e)
            raise GracefulDisconnect(f"{str(e)}")
        # check that they are on the same chain as us, if provided
        their_networks = payload["init_tlvs"].get("networks")
        if their_networks:
            their_chains = list(chunks(their_networks["chains"], 32))
            if constants.net.rev_genesis_bytes() not in their_chains:
                raise GracefulDisconnect(f"no common chain found with remote. (they sent: {their_chains})")
        # all checks passed
        self.lnworker.on_peer_successfully_established(self)
        self._received_init = True
        self.maybe_set_initialized()

    def on_node_announcement(self, payload):
        if self.lnworker.channel_db:
            self.gossip_queue.put_nowait(('node_announcement', payload))

    def on_channel_announcement(self, payload):
        if self.lnworker.channel_db:
            self.gossip_queue.put_nowait(('channel_announcement', payload))

    def on_channel_update(self, payload):
        self.maybe_save_remote_update(payload)
        if self.lnworker.channel_db:
            self.gossip_queue.put_nowait(('channel_update', payload))

    def maybe_save_remote_update(self, payload):
        if not self.channels:
            return
        for chan in self.channels.values():
            if chan.short_channel_id == payload['short_channel_id']:
                chan.set_remote_update(payload)
                self.logger.info("saved remote_update")
                break
        else:
            # Save (some bounded number of) orphan channel updates for later
            # as it might be for our own direct channel with this peer
            # (and we might not yet know the short channel id for that)
            # Background: this code is here to deal with a bug in LND,
            # see https://github.com/lightningnetwork/lnd/issues/3651
            # and https://github.com/lightningnetwork/lightning-rfc/pull/657
            # This code assumes gossip_queries is set. BOLT7: "if the
            # gossip_queries feature is negotiated, [a node] MUST NOT
            # send gossip it did not generate itself"
            short_channel_id = ShortChannelID(payload['short_channel_id'])
            self.logger.info(f'received orphan channel update {short_channel_id}')
            self.orphan_channel_updates[short_channel_id] = payload
            while len(self.orphan_channel_updates) > 25:
                self.orphan_channel_updates.popitem(last=False)

    def on_announcement_signatures(self, chan: Channel, payload):
        if chan.config[LOCAL].was_announced:
            h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        else:
            self.announcement_signatures[chan.channel_id].put_nowait(payload)

    def handle_disconnect(func):
        @functools.wraps(func)
        async def wrapper_func(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except GracefulDisconnect as e:
                self.logger.log(e.log_level, f"Disconnecting: {repr(e)}")
            except (LightningPeerConnectionClosed, IncompatibleLightningFeatures,
                    aiorpcx.socks.SOCKSError) as e:
                self.logger.info(f"Disconnecting: {repr(e)}")
            finally:
                self.close_and_cleanup()
        return wrapper_func

    @ignore_exceptions  # do not kill outer taskgroup
    @log_exceptions
    @handle_disconnect
    async def main_loop(self):
        async with self.taskgroup as group:
            await group.spawn(self._message_loop())
            await group.spawn(self.htlc_switch())
            await group.spawn(self.query_gossip())
            await group.spawn(self.process_gossip())

    async def process_gossip(self):
        while True:
            await asyncio.sleep(5)
            if not self.network.lngossip:
                continue
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
            if self.network.lngossip:
                await self.network.lngossip.process_gossip(chan_anns, node_anns, chan_upds)

    async def query_gossip(self):
        try:
            await asyncio.wait_for(self.initialized, LN_P2P_NETWORK_TIMEOUT)
        except Exception as e:
            raise GracefulDisconnect(f"Failed to initialize: {e!r}") from e
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
        first = payload['first_blocknum']
        num = payload['number_of_blocks']
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
        async for msg in self.transport.read_messages():
            self.process_message(msg)
            if self.DELAY_INC_MSG_PROCESSING_SLEEP:
                # rate-limit message-processing a bit, to make it harder
                # for a single peer to bog down the event loop / cpu:
                await asyncio.sleep(self.DELAY_INC_MSG_PROCESSING_SLEEP)

    def on_reply_short_channel_ids_end(self, payload):
        self.querying.set()

    def close_and_cleanup(self):
        # note: This method might get called multiple times!
        #       E.g. if you call close_and_cleanup() to cause a disconnection from the peer,
        #       it will get called a second time in handle_disconnect().
        try:
            if self.transport:
                self.transport.close()
        except:
            pass
        self.lnworker.peer_closed(self)
        self.got_disconnected.set()

    def is_shutdown_anysegwit(self):
        return self.features.supports(LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_OPT)

    def is_static_remotekey(self):
        return self.features.supports(LnFeatures.OPTION_STATIC_REMOTEKEY_OPT)

    def is_channel_type(self):
        return self.features.supports(LnFeatures.OPTION_CHANNEL_TYPE_OPT)

    def is_upfront_shutdown_script(self):
        return self.features.supports(LnFeatures.OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT)

    def upfront_shutdown_script_from_payload(self, payload, msg_identifier: str) -> Optional[bytes]:
        if msg_identifier not in ['accept', 'open']:
            raise ValueError("msg_identifier must be either 'accept' or 'open'")

        uss_tlv = payload[msg_identifier + '_channel_tlvs'].get(
            'upfront_shutdown_script')

        if uss_tlv and self.is_upfront_shutdown_script():
            upfront_shutdown_script = uss_tlv['shutdown_scriptpubkey']
        else:
            upfront_shutdown_script = b''
        self.logger.info(f"upfront shutdown script received: {upfront_shutdown_script}")
        return upfront_shutdown_script

    def make_local_config(self, funding_sat: int, push_msat: int, initiator: HTLCOwner, channel_type: ChannelType) -> LocalConfig:
        channel_seed = os.urandom(32)
        initial_msat = funding_sat * 1000 - push_msat if initiator == LOCAL else push_msat

        # sending empty bytes as the upfront_shutdown_script will give us the
        # flexibility to decide an address at closing time
        upfront_shutdown_script = b''

        if channel_type & channel_type.OPTION_STATIC_REMOTEKEY:
            wallet = self.lnworker.wallet
            assert wallet.txin_type == 'p2wpkh'
            addr = wallet.get_new_sweep_address_for_channel()
            static_remotekey = bfh(wallet.get_public_key(addr))
        else:
            static_remotekey = None
        dust_limit_sat = bitcoin.DUST_LIMIT_P2PKH
        reserve_sat = max(funding_sat // 100, dust_limit_sat)
        # for comparison of defaults, see
        # https://github.com/ACINQ/eclair/blob/afa378fbb73c265da44856b4ad0f2128a88ae6c6/eclair-core/src/main/resources/reference.conf#L66
        # https://github.com/ElementsProject/lightning/blob/0056dd75572a8857cff36fcbdb1a2295a1ac9253/lightningd/options.c#L657
        # https://github.com/lightningnetwork/lnd/blob/56b61078c5b2be007d318673a5f3b40c6346883a/config.go#L81
        local_config = LocalConfig.from_seed(
            channel_seed=channel_seed,
            static_remotekey=static_remotekey,
            upfront_shutdown_script=upfront_shutdown_script,
            to_self_delay=self.network.config.get('lightning_to_self_delay', 7 * 144),
            dust_limit_sat=dust_limit_sat,
            max_htlc_value_in_flight_msat=funding_sat * 1000,
            max_accepted_htlcs=30,
            initial_msat=initial_msat,
            reserve_sat=reserve_sat,
            funding_locked_received=False,
            was_announced=False,
            current_commitment_signature=None,
            current_htlc_signatures=b'',
            htlc_minimum_msat=1,
        )
        local_config.validate_params(funding_sat=funding_sat)
        return local_config

    def temporarily_reserve_funding_tx_change_address(func):
        # During the channel open flow, if we initiated, we might have used a change address
        # of ours in the funding tx. The funding tx is not part of the wallet history
        # at that point yet, but we should already consider this change address as 'used'.
        @functools.wraps(func)
        async def wrapper(self: 'Peer', *args, **kwargs):
            funding_tx = kwargs['funding_tx']  # type: PartialTransaction
            wallet = self.lnworker.wallet
            change_addresses = [txout.address for txout in funding_tx.outputs()
                                if wallet.is_change(txout.address)]
            for addr in change_addresses:
                wallet.set_reserved_state_of_address(addr, reserved=True)
            try:
                return await func(self, *args, **kwargs)
            finally:
                for addr in change_addresses:
                    self.lnworker.wallet.set_reserved_state_of_address(addr, reserved=False)
        return wrapper

    @temporarily_reserve_funding_tx_change_address
    async def channel_establishment_flow(
            self, *,
            funding_tx: 'PartialTransaction',
            funding_sat: int,
            push_msat: int,
            temp_channel_id: bytes
    ) -> Tuple[Channel, 'PartialTransaction']:
        """Implements the channel opening flow.

        -> open_channel message
        <- accept_channel message
        -> funding_created message
        <- funding_signed message

        Channel configurations are initialized in this method.
        """
        # will raise if init fails
        await asyncio.wait_for(self.initialized, LN_P2P_NETWORK_TIMEOUT)
        # trampoline is not yet in features
        if not self.lnworker.channel_db and not self.lnworker.is_trampoline_peer(self.pubkey):
            raise Exception('Not a trampoline node: ' + str(self.their_features))

        feerate = self.lnworker.current_feerate_per_kw()
        # we set a channel type for internal bookkeeping
        open_channel_tlvs = {}
        if self.their_features.supports(LnFeatures.OPTION_STATIC_REMOTEKEY_OPT):
            our_channel_type = ChannelType(ChannelType.OPTION_STATIC_REMOTEKEY)
        else:
            our_channel_type = ChannelType(0)
        # if option_channel_type is negotiated: MUST set channel_type
        if self.is_channel_type():
            # if it includes channel_type: MUST set it to a defined type representing the type it wants.
            open_channel_tlvs['channel_type'] = {
                'type': our_channel_type.to_bytes_minimal()
            }

        local_config = self.make_local_config(funding_sat, push_msat, LOCAL, our_channel_type)
        # if it includes open_channel_tlvs: MUST include upfront_shutdown_script.
        open_channel_tlvs['upfront_shutdown_script'] = {
            'shutdown_scriptpubkey': local_config.upfront_shutdown_script
        }

        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(
            local_config.per_commitment_secret_seed,
            RevocationStore.START_INDEX
        )
        per_commitment_point_first = secret_to_pubkey(
            int.from_bytes(per_commitment_secret_first, 'big'))

        # store the temp id now, so that it is recognized for e.g. 'error' messages
        # TODO: this is never cleaned up; the dict grows unbounded until disconnect
        self.temp_id_to_id[temp_channel_id] = None
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
            htlc_minimum_msat=local_config.htlc_minimum_msat,
            open_channel_tlvs=open_channel_tlvs,
        )

        # <- accept_channel
        payload = await self.wait_for_message('accept_channel', temp_channel_id)
        remote_per_commitment_point = payload['first_per_commitment_point']
        funding_txn_minimum_depth = payload['minimum_depth']
        if funding_txn_minimum_depth <= 0:
            raise Exception(f"minimum depth too low, {funding_txn_minimum_depth}")
        if funding_txn_minimum_depth > 30:
            raise Exception(f"minimum depth too high, {funding_txn_minimum_depth}")

        upfront_shutdown_script = self.upfront_shutdown_script_from_payload(
            payload, 'accept')

        accept_channel_tlvs = payload.get('accept_channel_tlvs')
        their_channel_type = accept_channel_tlvs.get('channel_type') if accept_channel_tlvs else None
        if their_channel_type:
            their_channel_type = ChannelType.from_bytes(their_channel_type['type'], byteorder='big').discard_unknown_and_check()
            # if channel_type is set, and channel_type was set in open_channel,
            # and they are not equal types: MUST reject the channel.
            if open_channel_tlvs.get('channel_type') is not None and their_channel_type != our_channel_type:
                raise Exception("Channel type is not the one that we sent.")

        remote_config = RemoteConfig(
            payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
            multisig_key=OnlyPubkeyKeypair(payload["funding_pubkey"]),
            htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
            delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
            revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
            to_self_delay=payload['to_self_delay'],
            dust_limit_sat=payload['dust_limit_satoshis'],
            max_htlc_value_in_flight_msat=payload['max_htlc_value_in_flight_msat'],
            max_accepted_htlcs=payload["max_accepted_htlcs"],
            initial_msat=push_msat,
            reserve_sat=payload["channel_reserve_satoshis"],
            htlc_minimum_msat=payload['htlc_minimum_msat'],
            next_per_commitment_point=remote_per_commitment_point,
            current_per_commitment_point=None,
            upfront_shutdown_script=upfront_shutdown_script,
        )
        ChannelConfig.cross_validate_params(
            local_config=local_config,
            remote_config=remote_config,
            funding_sat=funding_sat,
            is_local_initiator=True,
            initial_feerate_per_kw=feerate,
        )

        # -> funding created
        # replace dummy output in funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = PartialTxOutput.from_address_and_value(funding_address, funding_sat)
        dummy_output = PartialTxOutput.from_address_and_value(ln_dummy_address(), funding_sat)
        if dummy_output not in funding_tx.outputs(): raise Exception("LN dummy output (err 1)")
        funding_tx._outputs.remove(dummy_output)
        if dummy_output in funding_tx.outputs(): raise Exception("LN dummy output (err 2)")
        funding_tx.add_outputs([funding_output])
        # find and encrypt op_return data associated to funding_address
        has_onchain_backup = self.lnworker and self.lnworker.has_recoverable_channels()
        if has_onchain_backup:
            backup_data = self.lnworker.cb_data(self.pubkey)
            dummy_scriptpubkey = make_op_return(backup_data)
            for o in funding_tx.outputs():
                if o.scriptpubkey == dummy_scriptpubkey:
                    encrypted_data = self.lnworker.encrypt_cb_data(backup_data, funding_address)
                    assert len(encrypted_data) == len(backup_data)
                    o.scriptpubkey = make_op_return(encrypted_data)
                    break
            else:
                raise Exception('op_return output not found in funding tx')
        # must not be malleable
        funding_tx.set_rbf(False)
        if not funding_tx.is_segwit():
            raise Exception('Funding transaction is not segwit')
        funding_txid = funding_tx.txid()
        assert funding_txid
        funding_index = funding_tx.outputs().index(funding_output)
        # build remote commitment transaction
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_index)
        outpoint = Outpoint(funding_txid, funding_index)
        constraints = ChannelConstraints(
            capacity=funding_sat,
            is_initiator=True,
            funding_txn_minimum_depth=funding_txn_minimum_depth
        )
        storage = self.create_channel_storage(
            channel_id, outpoint, local_config, remote_config, constraints, our_channel_type)
        chan = Channel(
            storage,
            sweep_address=self.lnworker.sweep_address,
            lnworker=self.lnworker,
            initial_feerate=feerate
        )
        chan.storage['funding_inputs'] = [txin.prevout.to_json() for txin in funding_tx.inputs()]
        chan.storage['has_onchain_backup'] = has_onchain_backup
        if isinstance(self.transport, LNTransport):
            chan.add_or_update_peer_addr(self.transport.peer_addr)
        sig_64, _ = chan.sign_next_commitment()
        self.temp_id_to_id[temp_channel_id] = channel_id

        self.send_message("funding_created",
            temporary_channel_id=temp_channel_id,
            funding_txid=funding_txid_bytes,
            funding_output_index=funding_index,
            signature=sig_64)
        self.funding_created_sent.add(channel_id)

        # <- funding signed
        payload = await self.wait_for_message('funding_signed', channel_id)
        self.logger.info('received funding_signed')
        remote_sig = payload['signature']
        try:
            chan.receive_new_commitment(remote_sig, [])
        except LNProtocolWarning as e:
            await self.send_warning(channel_id, message=str(e), close_connection=True)
        chan.open_with_first_pcp(remote_per_commitment_point, remote_sig)
        chan.set_state(ChannelState.OPENING)
        self.lnworker.add_new_channel(chan)
        return chan, funding_tx

    def create_channel_storage(self, channel_id, outpoint, local_config, remote_config, constraints, channel_type):
        chan_dict = {
            "node_id": self.pubkey.hex(),
            "channel_id": channel_id.hex(),
            "short_channel_id": None,
            "funding_outpoint": outpoint,
            "remote_config": remote_config,
            "local_config": local_config,
            "constraints": constraints,
            "remote_update": None,
            "state": ChannelState.PREOPENING.name,
            'onion_keys': {},
            'data_loss_protect_remote_pcp': {},
            "log": {},
            "fail_htlc_reasons": {},  # htlc_id -> onion_packet
            "unfulfilled_htlcs": {},  # htlc_id -> error_bytes, failure_message
            "revocation_store": {},
            "channel_type": channel_type,
        }
        return StoredDict(chan_dict, self.lnworker.db if self.lnworker else None, [])

    async def on_open_channel(self, payload):
        """Implements the channel acceptance flow.

        <- open_channel message
        -> accept_channel message
        <- funding_created message
        -> funding_signed message

        Channel configurations are initialized in this method.
        """
        if self.lnworker.has_recoverable_channels():
            # FIXME: we might want to keep the connection open
            raise Exception('not accepting channels')
        # <- open_channel
        if payload['chain_hash'] != constants.net.rev_genesis_bytes():
            raise Exception('wrong chain_hash')
        funding_sat = payload['funding_satoshis']
        push_msat = payload['push_msat']
        feerate = payload['feerate_per_kw']  # note: we are not validating this
        temp_chan_id = payload['temporary_channel_id']
        # store the temp id now, so that it is recognized for e.g. 'error' messages
        # TODO: this is never cleaned up; the dict grows unbounded until disconnect
        self.temp_id_to_id[temp_chan_id] = None

        open_channel_tlvs = payload.get('open_channel_tlvs')
        channel_type = open_channel_tlvs.get('channel_type') if open_channel_tlvs else None
        # The receiving node MAY fail the channel if:
        # option_channel_type was negotiated but the message doesn't include a channel_type
        if self.is_channel_type() and channel_type is None:
            raise Exception("sender has advertized option_channel_type, but hasn't sent the channel type")
        # MUST fail the channel if it supports channel_type,
        # channel_type was set, and the type is not suitable.
        elif self.is_channel_type() and channel_type is not None:
            channel_type = ChannelType.from_bytes(channel_type['type'], byteorder='big').discard_unknown_and_check()
            if not channel_type.complies_with_features(self.features):
                raise Exception("sender has sent a channel type we don't support")

        local_config = self.make_local_config(funding_sat, push_msat, REMOTE, channel_type)

        upfront_shutdown_script = self.upfront_shutdown_script_from_payload(
            payload, 'open')

        remote_config = RemoteConfig(
            payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
            multisig_key=OnlyPubkeyKeypair(payload['funding_pubkey']),
            htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
            delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
            revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
            to_self_delay=payload['to_self_delay'],
            dust_limit_sat=payload['dust_limit_satoshis'],
            max_htlc_value_in_flight_msat=payload['max_htlc_value_in_flight_msat'],
            max_accepted_htlcs=payload['max_accepted_htlcs'],
            initial_msat=funding_sat * 1000 - push_msat,
            reserve_sat=payload['channel_reserve_satoshis'],
            htlc_minimum_msat=payload['htlc_minimum_msat'],
            next_per_commitment_point=payload['first_per_commitment_point'],
            current_per_commitment_point=None,
            upfront_shutdown_script=upfront_shutdown_script,
        )
        ChannelConfig.cross_validate_params(
            local_config=local_config,
            remote_config=remote_config,
            funding_sat=funding_sat,
            is_local_initiator=False,
            initial_feerate_per_kw=feerate,
        )

        # note: we ignore payload['channel_flags'],  which e.g. contains 'announce_channel'.
        #       Notably, if the remote sets 'announce_channel' to True, we will ignore that too,
        #       but we will not play along with actually announcing the channel (so we keep it private).

        # -> accept channel
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(
            local_config.per_commitment_secret_seed,
            RevocationStore.START_INDEX
        )
        per_commitment_point_first = secret_to_pubkey(
            int.from_bytes(per_commitment_secret_first, 'big'))
        min_depth = 3
        accept_channel_tlvs = {
            'upfront_shutdown_script': {
                'shutdown_scriptpubkey': local_config.upfront_shutdown_script
            },
        }
        # The sender: if it sets channel_type: MUST set it to the channel_type from open_channel
        if self.is_channel_type():
            accept_channel_tlvs['channel_type'] = {
                'type': channel_type.to_bytes_minimal()
            }

        self.send_message(
            'accept_channel',
            temporary_channel_id=temp_chan_id,
            dust_limit_satoshis=local_config.dust_limit_sat,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_reserve_satoshis=local_config.reserve_sat,
            htlc_minimum_msat=local_config.htlc_minimum_msat,
            minimum_depth=min_depth,
            to_self_delay=local_config.to_self_delay,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
            accept_channel_tlvs=accept_channel_tlvs,
        )

        # <- funding created
        funding_created = await self.wait_for_message('funding_created', temp_chan_id)

        # -> funding signed
        funding_idx = funding_created['funding_output_index']
        funding_txid = bh2u(funding_created['funding_txid'][::-1])
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_idx)
        constraints = ChannelConstraints(
            capacity=funding_sat,
            is_initiator=False,
            funding_txn_minimum_depth=min_depth
        )
        outpoint = Outpoint(funding_txid, funding_idx)
        chan_dict = self.create_channel_storage(
            channel_id, outpoint, local_config, remote_config, constraints, channel_type)
        chan = Channel(
            chan_dict,
            sweep_address=self.lnworker.sweep_address,
            lnworker=self.lnworker,
            initial_feerate=feerate
        )
        chan.storage['init_timestamp'] = int(time.time())
        if isinstance(self.transport, LNTransport):
            chan.add_or_update_peer_addr(self.transport.peer_addr)
        remote_sig = funding_created['signature']
        try:
            chan.receive_new_commitment(remote_sig, [])
        except LNProtocolWarning as e:
            await self.send_warning(channel_id, message=str(e), close_connection=True)
        sig_64, _ = chan.sign_next_commitment()
        self.send_message('funding_signed',
            channel_id=channel_id,
            signature=sig_64,
        )
        self.temp_id_to_id[temp_chan_id] = channel_id
        self.funding_signed_sent.add(chan.channel_id)
        chan.open_with_first_pcp(payload['first_per_commitment_point'], remote_sig)
        chan.set_state(ChannelState.OPENING)
        self.lnworker.add_new_channel(chan)

    async def trigger_force_close(self, channel_id: bytes):
        await self.initialized
        latest_point = secret_to_pubkey(42) # we need a valid point (BOLT2)
        self.send_message(
            "channel_reestablish",
            channel_id=channel_id,
            next_commitment_number=0,
            next_revocation_number=0,
            your_last_per_commitment_secret=0,
            my_current_per_commitment_point=latest_point)

    def schedule_force_closing(self, channel_id: bytes):
        """ wrapper of lnworker's method, that raises if channel is not with this peer """
        channels_with_peer = list(self.channels.keys())
        channels_with_peer.extend(self.temp_id_to_id.values())
        if channel_id not in channels_with_peer:
            raise ValueError(f"channel {channel_id.hex()} does not belong to this peer")
        if channel_id in self.channels:
            self.lnworker.schedule_force_closing(channel_id)
        else:
            self.logger.warning(f"tried to force-close channel {channel_id.hex()} but it is not in self.channels yet")

    def on_channel_reestablish(self, chan, msg):
        their_next_local_ctn = msg["next_commitment_number"]
        their_oldest_unrevoked_remote_ctn = msg["next_revocation_number"]
        their_local_pcp = msg.get("my_current_per_commitment_point")
        their_claim_of_our_last_per_commitment_secret = msg.get("your_last_per_commitment_secret")
        self.logger.info(
            f'channel_reestablish ({chan.get_id_for_log()}): received channel_reestablish with '
            f'(their_next_local_ctn={their_next_local_ctn}, '
            f'their_oldest_unrevoked_remote_ctn={their_oldest_unrevoked_remote_ctn})')
        # sanity checks of received values
        if their_next_local_ctn < 0:
            raise RemoteMisbehaving(f"channel reestablish: their_next_local_ctn < 0")
        if their_oldest_unrevoked_remote_ctn < 0:
            raise RemoteMisbehaving(f"channel reestablish: their_oldest_unrevoked_remote_ctn < 0")
        # ctns
        oldest_unrevoked_local_ctn = chan.get_oldest_unrevoked_ctn(LOCAL)
        latest_local_ctn = chan.get_latest_ctn(LOCAL)
        next_local_ctn = chan.get_next_ctn(LOCAL)
        oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
        latest_remote_ctn = chan.get_latest_ctn(REMOTE)
        next_remote_ctn = chan.get_next_ctn(REMOTE)
        # compare remote ctns
        we_are_ahead = False
        they_are_ahead = False
        we_must_resend_revoke_and_ack = False
        if next_remote_ctn != their_next_local_ctn:
            if their_next_local_ctn == latest_remote_ctn and chan.hm.is_revack_pending(REMOTE):
                # We will replay the local updates (see reestablish_channel), which should contain a commitment_signed
                # (due to is_revack_pending being true), and this should remedy this situation.
                pass
            else:
                self.logger.warning(
                    f"channel_reestablish ({chan.get_id_for_log()}): "
                    f"expected remote ctn {next_remote_ctn}, got {their_next_local_ctn}")
                if their_next_local_ctn < next_remote_ctn:
                    we_are_ahead = True
                else:
                    they_are_ahead = True
        # compare local ctns
        if oldest_unrevoked_local_ctn != their_oldest_unrevoked_remote_ctn:
            if oldest_unrevoked_local_ctn - 1 == their_oldest_unrevoked_remote_ctn:
                # A node:
                #    if next_revocation_number is equal to the commitment number of the last revoke_and_ack
                #    the receiving node sent, AND the receiving node hasn't already received a closing_signed:
                #        MUST re-send the revoke_and_ack.
                we_must_resend_revoke_and_ack = True
            else:
                self.logger.warning(
                    f"channel_reestablish ({chan.get_id_for_log()}): "
                    f"expected local ctn {oldest_unrevoked_local_ctn}, got {their_oldest_unrevoked_remote_ctn}")
                if their_oldest_unrevoked_remote_ctn < oldest_unrevoked_local_ctn:
                    we_are_ahead = True
                else:
                    they_are_ahead = True
        # option_data_loss_protect
        assert self.features.supports(LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT)
        def are_datalossprotect_fields_valid() -> bool:
            if their_local_pcp is None or their_claim_of_our_last_per_commitment_secret is None:
                return False
            if their_oldest_unrevoked_remote_ctn > 0:
                our_pcs, __ = chan.get_secret_and_point(LOCAL, their_oldest_unrevoked_remote_ctn - 1)
            else:
                assert their_oldest_unrevoked_remote_ctn == 0
                our_pcs = bytes(32)
            if our_pcs != their_claim_of_our_last_per_commitment_secret:
                self.logger.error(
                    f"channel_reestablish ({chan.get_id_for_log()}): "
                    f"(DLP) local PCS mismatch: {bh2u(our_pcs)} != {bh2u(their_claim_of_our_last_per_commitment_secret)}")
                return False
            if chan.is_static_remotekey_enabled():
                return True
            try:
                __, our_remote_pcp = chan.get_secret_and_point(REMOTE, their_next_local_ctn - 1)
            except RemoteCtnTooFarInFuture:
                pass
            else:
                if our_remote_pcp != their_local_pcp:
                    self.logger.error(
                        f"channel_reestablish ({chan.get_id_for_log()}): "
                        f"(DLP) remote PCP mismatch: {bh2u(our_remote_pcp)} != {bh2u(their_local_pcp)}")
                    return False
            return True
        if not are_datalossprotect_fields_valid():
            raise RemoteMisbehaving("channel_reestablish: data loss protect fields invalid")
        fut = self.channel_reestablish_msg[chan.channel_id]
        if they_are_ahead:
            self.logger.warning(
                f"channel_reestablish ({chan.get_id_for_log()}): "
                f"remote is ahead of us! They should force-close. Remote PCP: {bh2u(their_local_pcp)}")
            # data_loss_protect_remote_pcp is used in lnsweep
            chan.set_data_loss_protect_remote_pcp(their_next_local_ctn - 1, their_local_pcp)
            self.lnworker.save_channel(chan)
            chan.peer_state = PeerState.BAD
            # raise after we send channel_reestablish, so the remote can realize they are ahead
            fut.set_exception(RemoteMisbehaving("remote ahead of us"))
        elif we_are_ahead:
            self.logger.warning(f"channel_reestablish ({chan.get_id_for_log()}): we are ahead of remote! trying to force-close.")
            self.schedule_force_closing(chan.channel_id)
            fut.set_exception(RemoteMisbehaving("we are ahead of remote"))
        else:
            # all good
            fut.set_result((we_must_resend_revoke_and_ack, their_next_local_ctn))

    async def reestablish_channel(self, chan: Channel):
        await self.initialized
        chan_id = chan.channel_id
        if chan.should_request_force_close:
            await self.trigger_force_close(chan_id)
            chan.should_request_force_close = False
            return
        assert ChannelState.PREOPENING < chan.get_state() < ChannelState.FORCE_CLOSING
        if chan.peer_state != PeerState.DISCONNECTED:
            self.logger.info(
                f'reestablish_channel was called but channel {chan.get_id_for_log()} '
                f'already in peer_state {chan.peer_state!r}')
            return
        chan.peer_state = PeerState.REESTABLISHING
        util.trigger_callback('channel', self.lnworker.wallet, chan)
        # ctns
        oldest_unrevoked_local_ctn = chan.get_oldest_unrevoked_ctn(LOCAL)
        latest_local_ctn = chan.get_latest_ctn(LOCAL)
        next_local_ctn = chan.get_next_ctn(LOCAL)
        oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
        latest_remote_ctn = chan.get_latest_ctn(REMOTE)
        next_remote_ctn = chan.get_next_ctn(REMOTE)
        # BOLT-02: "A node [...] upon disconnection [...] MUST reverse any uncommitted updates sent by the other side"
        chan.hm.discard_unsigned_remote_updates()
        # send message
        if chan.is_static_remotekey_enabled():
            latest_secret, latest_point = chan.get_secret_and_point(LOCAL, 0)
        else:
            latest_secret, latest_point = chan.get_secret_and_point(LOCAL, latest_local_ctn)
        if oldest_unrevoked_remote_ctn == 0:
            last_rev_secret = 0
        else:
            last_rev_index = oldest_unrevoked_remote_ctn - 1
            last_rev_secret = chan.revocation_store.retrieve_secret(RevocationStore.START_INDEX - last_rev_index)
        self.send_message(
            "channel_reestablish",
            channel_id=chan_id,
            next_commitment_number=next_local_ctn,
            next_revocation_number=oldest_unrevoked_remote_ctn,
            your_last_per_commitment_secret=last_rev_secret,
            my_current_per_commitment_point=latest_point)
        self.logger.info(
            f'channel_reestablish ({chan.get_id_for_log()}): sent channel_reestablish with '
            f'(next_local_ctn={next_local_ctn}, '
            f'oldest_unrevoked_remote_ctn={oldest_unrevoked_remote_ctn})')

        # wait until we receive their channel_reestablish
        fut = self.channel_reestablish_msg[chan_id]
        await fut
        we_must_resend_revoke_and_ack, their_next_local_ctn = fut.result()

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
        self.logger.info(f'channel_reestablish ({chan.get_id_for_log()}): replayed {n_replayed_msgs} unacked messages')
        if we_must_resend_revoke_and_ack:
            last_secret, last_point = chan.get_secret_and_point(LOCAL, oldest_unrevoked_local_ctn - 1)
            next_secret, next_point = chan.get_secret_and_point(LOCAL, oldest_unrevoked_local_ctn + 1)
            self.send_message(
                "revoke_and_ack",
                channel_id=chan.channel_id,
                per_commitment_secret=last_secret,
                next_per_commitment_point=next_point)
        chan.peer_state = PeerState.GOOD
        if chan.is_funded() and their_next_local_ctn == next_local_ctn == 1:
            self.send_funding_locked(chan)
        # checks done
        if chan.is_funded() and chan.config[LOCAL].funding_locked_received:
            self.mark_open(chan)
        util.trigger_callback('channel', self.lnworker.wallet, chan)
        # if we have sent a previous shutdown, it must be retransmitted (Bolt2)
        if chan.get_state() == ChannelState.SHUTDOWN:
            await self.send_shutdown(chan)

    def send_funding_locked(self, chan: Channel):
        channel_id = chan.channel_id
        per_commitment_secret_index = RevocationStore.START_INDEX - 1
        per_commitment_point_second = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.config[LOCAL].per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        # note: if funding_locked was not yet received, we might send it multiple times
        self.send_message("funding_locked", channel_id=channel_id, next_per_commitment_point=per_commitment_point_second)
        if chan.is_funded() and chan.config[LOCAL].funding_locked_received:
            self.mark_open(chan)

    def on_funding_locked(self, chan: Channel, payload):
        self.logger.info(f"on_funding_locked. channel: {bh2u(chan.channel_id)}")
        if not chan.config[LOCAL].funding_locked_received:
            their_next_point = payload["next_per_commitment_point"]
            chan.config[REMOTE].next_per_commitment_point = their_next_point
            chan.config[LOCAL].funding_locked_received = True
            self.lnworker.save_channel(chan)
        if chan.is_funded():
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
            chan.config[LOCAL].was_announced = True
            self.lnworker.save_channel(chan)
            coro = self.handle_announcements(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    @log_exceptions
    async def handle_announcements(self, chan: Channel):
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
        assert chan.is_funded()
        # only allow state transition from "FUNDED" to "OPEN"
        old_state = chan.get_state()
        if old_state == ChannelState.OPEN:
            if self.lnworker:
                self.lnworker.pay_scheduled_invoices()
            return
        if old_state != ChannelState.FUNDED:
            self.logger.info(f"cannot mark open ({chan.get_id_for_log()}), current state: {repr(old_state)}")
            return
        assert chan.config[LOCAL].funding_locked_received
        chan.set_state(ChannelState.OPEN)
        util.trigger_callback('channel', self.lnworker.wallet, chan)
        # peer may have sent us a channel update for the incoming direction previously
        pending_channel_update = self.orphan_channel_updates.get(chan.short_channel_id)
        if pending_channel_update:
            chan.set_remote_update(pending_channel_update)
        self.logger.info(f"CHANNEL OPENING COMPLETED ({chan.get_id_for_log()})")
        forwarding_enabled = self.network.config.get('lightning_forward_payments', False)
        if forwarding_enabled:
            # send channel_update of outgoing edge to peer,
            # so that channel can be used to to receive payments
            self.logger.info(f"sending channel update for outgoing edge ({chan.get_id_for_log()})")
            chan_upd = chan.get_outgoing_gossip_channel_update()
            self.transport.send_bytes(chan_upd)
        if self.lnworker:
            self.lnworker.pay_scheduled_invoices()

    def send_announcement_signatures(self, chan: Channel):
        chan_ann = chan.construct_channel_announcement_without_sigs()
        preimage = chan_ann[256+2:]
        msg_hash = sha256d(preimage)
        bitcoin_signature = ecc.ECPrivkey(chan.config[LOCAL].multisig_key.privkey).sign(msg_hash, sig_string_from_r_and_s)
        node_signature = ecc.ECPrivkey(self.privkey).sign(msg_hash, sig_string_from_r_and_s)
        self.send_message("announcement_signatures",
            channel_id=chan.channel_id,
            short_channel_id=chan.short_channel_id,
            node_signature=node_signature,
            bitcoin_signature=bitcoin_signature
        )
        return msg_hash, node_signature, bitcoin_signature

    def on_update_fail_htlc(self, chan: Channel, payload):
        htlc_id = payload["id"]
        reason = payload["reason"]
        self.logger.info(f"on_update_fail_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        chan.receive_fail_htlc(htlc_id, error_bytes=reason)  # TODO handle exc and maybe fail channel (e.g. bad htlc_id)
        self.maybe_send_commitment(chan)

    def maybe_send_commitment(self, chan: Channel) -> bool:
        # REMOTE should revoke first before we can sign a new ctx
        if chan.hm.is_revack_pending(REMOTE):
            return False
        # if there are no changes, we will not (and must not) send a new commitment
        if not chan.has_pending_changes(REMOTE):
            return False
        self.logger.info(f'send_commitment. chan {chan.short_channel_id}. ctn: {chan.get_next_ctn(REMOTE)}.')
        sig_64, htlc_sigs = chan.sign_next_commitment()
        self.send_message("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs))
        return True

    def pay(self, *,
            route: 'LNPaymentRoute',
            chan: Channel,
            amount_msat: int,
            total_msat: int,
            payment_hash: bytes,
            min_final_cltv_expiry: int,
            payment_secret: bytes = None,
            trampoline_onion=None) -> UpdateAddHtlc:

        assert amount_msat > 0, "amount_msat is not greater zero"
        assert len(route) > 0
        if not chan.can_send_update_add_htlc():
            raise PaymentFailure("Channel cannot send update_add_htlc")
        # add features learned during "init" for direct neighbour:
        route[0].node_features |= self.features
        local_height = self.network.get_local_height()
        final_cltv = local_height + min_final_cltv_expiry
        hops_data, amount_msat, cltv = calc_hops_data_for_payment(
            route,
            amount_msat,
            final_cltv,
            total_msat=total_msat,
            payment_secret=payment_secret)
        num_hops = len(hops_data)
        self.logger.info(f"lnpeer.pay len(route)={len(route)}")
        for i in range(len(route)):
            self.logger.info(f"  {i}: edge={route[i].short_channel_id} hop_data={hops_data[i]!r}")
        assert final_cltv <= cltv, (final_cltv, cltv)
        session_key = os.urandom(32) # session_key
        # if we are forwarding a trampoline payment, add trampoline onion
        if trampoline_onion:
            self.logger.info(f'adding trampoline onion to final payload')
            trampoline_payload = hops_data[num_hops-2].payload
            trampoline_payload["trampoline_onion_packet"] = {
                "version": trampoline_onion.version,
                "public_key": trampoline_onion.public_key,
                "hops_data": trampoline_onion.hops_data,
                "hmac": trampoline_onion.hmac
            }
        # create onion packet
        payment_path_pubkeys = [x.node_id for x in route]
        onion = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data=payment_hash) # must use another sessionkey
        self.logger.info(f"starting payment. len(route)={len(hops_data)}.")
        # create htlc
        if cltv > local_height + lnutil.NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE:
            raise PaymentFailure(f"htlc expiry too far into future. (in {cltv-local_height} blocks)")
        htlc = UpdateAddHtlc(amount_msat=amount_msat, payment_hash=payment_hash, cltv_expiry=cltv, timestamp=int(time.time()))
        htlc = chan.add_htlc(htlc)
        chan.set_onion_key(htlc.htlc_id, session_key) # should it be the outer onion secret?
        self.logger.info(f"starting payment. htlc: {htlc}")
        self.send_message(
            "update_add_htlc",
            channel_id=chan.channel_id,
            id=htlc.htlc_id,
            cltv_expiry=htlc.cltv_expiry,
            amount_msat=htlc.amount_msat,
            payment_hash=htlc.payment_hash,
            onion_routing_packet=onion.to_bytes())
        self.maybe_send_commitment(chan)
        return htlc

    def send_revoke_and_ack(self, chan: Channel):
        self.logger.info(f'send_revoke_and_ack. chan {chan.short_channel_id}. ctn: {chan.get_oldest_unrevoked_ctn(LOCAL)}')
        rev = chan.revoke_current_commitment()
        self.lnworker.save_channel(chan)
        self.send_message("revoke_and_ack",
            channel_id=chan.channel_id,
            per_commitment_secret=rev.per_commitment_secret,
            next_per_commitment_point=rev.next_per_commitment_point)
        self.maybe_send_commitment(chan)

    def on_commitment_signed(self, chan: Channel, payload):
        if chan.peer_state == PeerState.BAD:
            return
        self.logger.info(f'on_commitment_signed. chan {chan.short_channel_id}. ctn: {chan.get_next_ctn(LOCAL)}.')
        # make sure there were changes to the ctx, otherwise the remote peer is misbehaving
        if not chan.has_pending_changes(LOCAL):
            # TODO if feerate changed A->B->A; so there were updates but the value is identical,
            #      then it might be legal to send a commitment_signature
            #      see https://github.com/lightningnetwork/lightning-rfc/pull/618
            raise RemoteMisbehaving('received commitment_signed without pending changes')
        # REMOTE should wait until we have revoked
        if chan.hm.is_revack_pending(LOCAL):
            raise RemoteMisbehaving('received commitment_signed before we revoked previous ctx')
        data = payload["htlc_signature"]
        htlc_sigs = list(chunks(data, 64))
        chan.receive_new_commitment(payload["signature"], htlc_sigs)
        self.send_revoke_and_ack(chan)

    def on_update_fulfill_htlc(self, chan: Channel, payload):
        preimage = payload["payment_preimage"]
        payment_hash = sha256(preimage)
        htlc_id = payload["id"]
        self.logger.info(f"on_update_fulfill_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        chan.receive_htlc_settle(preimage, htlc_id)  # TODO handle exc and maybe fail channel (e.g. bad htlc_id)
        self.lnworker.save_preimage(payment_hash, preimage)
        self.maybe_send_commitment(chan)

    def on_update_fail_malformed_htlc(self, chan: Channel, payload):
        htlc_id = payload["id"]
        failure_code = payload["failure_code"]
        self.logger.info(f"on_update_fail_malformed_htlc. chan {chan.get_id_for_log()}. "
                         f"htlc_id {htlc_id}. failure_code={failure_code}")
        if failure_code & OnionFailureCodeMetaFlag.BADONION == 0:
            self.schedule_force_closing(chan.channel_id)
            raise RemoteMisbehaving(f"received update_fail_malformed_htlc with unexpected failure code: {failure_code}")
        reason = OnionRoutingFailure(code=failure_code, data=payload["sha256_of_onion"])
        chan.receive_fail_htlc(htlc_id, error_bytes=None, reason=reason)
        self.maybe_send_commitment(chan)

    def on_update_add_htlc(self, chan: Channel, payload):
        payment_hash = payload["payment_hash"]
        htlc_id = payload["id"]
        cltv_expiry = payload["cltv_expiry"]
        amount_msat_htlc = payload["amount_msat"]
        onion_packet = payload["onion_routing_packet"]
        htlc = UpdateAddHtlc(
            amount_msat=amount_msat_htlc,
            payment_hash=payment_hash,
            cltv_expiry=cltv_expiry,
            timestamp=int(time.time()),
            htlc_id=htlc_id)
        self.logger.info(f"on_update_add_htlc. chan {chan.short_channel_id}. htlc={str(htlc)}")
        if chan.get_state() != ChannelState.OPEN:
            raise RemoteMisbehaving(f"received update_add_htlc while chan.get_state() != OPEN. state was {chan.get_state()!r}")
        if cltv_expiry > bitcoin.NLOCKTIME_BLOCKHEIGHT_MAX:
            self.schedule_force_closing(chan.channel_id)
            raise RemoteMisbehaving(f"received update_add_htlc with cltv_expiry > BLOCKHEIGHT_MAX. value was {cltv_expiry}")
        # add htlc
        chan.receive_htlc(htlc, onion_packet)
        util.trigger_callback('htlc_added', chan, htlc, RECEIVED)

    def maybe_forward_htlc(
            self, *,
            htlc: UpdateAddHtlc,
            processed_onion: ProcessedOnionPacket) -> Tuple[bytes, int]:

        # Forward HTLC
        # FIXME: there are critical safety checks MISSING here
        #        - for example; atm we forward first and then persist "forwarding_info",
        #          so if we segfault in-between and restart, we might forward an HTLC twice...
        #          (same for trampoline forwarding)
        #        - we could check for the exposure to dust HTLCs, see:
        #          https://github.com/ACINQ/eclair/pull/1985
        forwarding_enabled = self.network.config.get('lightning_forward_payments', False)
        if not forwarding_enabled:
            self.logger.info(f"forwarding is disabled. failing htlc.")
            raise OnionRoutingFailure(code=OnionFailureCode.PERMANENT_CHANNEL_FAILURE, data=b'')
        chain = self.network.blockchain()
        if chain.is_tip_stale():
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')
        try:
            next_chan_scid = processed_onion.hop_data.payload["short_channel_id"]["short_channel_id"]
        except:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')
        next_chan = self.lnworker.get_channel_by_short_id(next_chan_scid)
        local_height = chain.height()
        if next_chan is None:
            self.logger.info(f"cannot forward htlc. cannot find next_chan {next_chan_scid}")
            raise OnionRoutingFailure(code=OnionFailureCode.UNKNOWN_NEXT_PEER, data=b'')
        outgoing_chan_upd = next_chan.get_outgoing_gossip_channel_update()[2:]
        outgoing_chan_upd_len = len(outgoing_chan_upd).to_bytes(2, byteorder="big")
        outgoing_chan_upd_message = outgoing_chan_upd_len + outgoing_chan_upd
        if not next_chan.can_send_update_add_htlc():
            self.logger.info(f"cannot forward htlc. next_chan {next_chan_scid} cannot send ctx updates. "
                             f"chan state {next_chan.get_state()!r}, peer state: {next_chan.peer_state!r}")
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, data=outgoing_chan_upd_message)
        try:
            next_amount_msat_htlc = processed_onion.hop_data.payload["amt_to_forward"]["amt_to_forward"]
        except:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')
        if not next_chan.can_pay(next_amount_msat_htlc):
            self.logger.info(f"cannot forward htlc due to transient errors (likely due to insufficient funds)")
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, data=outgoing_chan_upd_message)
        try:
            next_cltv_expiry = processed_onion.hop_data.payload["outgoing_cltv_value"]["outgoing_cltv_value"]
        except:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')
        if htlc.cltv_expiry - next_cltv_expiry < next_chan.forwarding_cltv_expiry_delta:
            data = htlc.cltv_expiry.to_bytes(4, byteorder="big") + outgoing_chan_upd_message
            raise OnionRoutingFailure(code=OnionFailureCode.INCORRECT_CLTV_EXPIRY, data=data)
        if htlc.cltv_expiry - lnutil.MIN_FINAL_CLTV_EXPIRY_ACCEPTED <= local_height \
                or next_cltv_expiry <= local_height:
            raise OnionRoutingFailure(code=OnionFailureCode.EXPIRY_TOO_SOON, data=outgoing_chan_upd_message)
        if max(htlc.cltv_expiry, next_cltv_expiry) > local_height + lnutil.NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE:
            raise OnionRoutingFailure(code=OnionFailureCode.EXPIRY_TOO_FAR, data=b'')
        forwarding_fees = fee_for_edge_msat(
            forwarded_amount_msat=next_amount_msat_htlc,
            fee_base_msat=next_chan.forwarding_fee_base_msat,
            fee_proportional_millionths=next_chan.forwarding_fee_proportional_millionths)
        if htlc.amount_msat - next_amount_msat_htlc < forwarding_fees:
            data = next_amount_msat_htlc.to_bytes(8, byteorder="big") + outgoing_chan_upd_message
            raise OnionRoutingFailure(code=OnionFailureCode.FEE_INSUFFICIENT, data=data)
        self.logger.info(f'forwarding htlc to {next_chan.node_id}')
        next_htlc = UpdateAddHtlc(
            amount_msat=next_amount_msat_htlc,
            payment_hash=htlc.payment_hash,
            cltv_expiry=next_cltv_expiry,
            timestamp=int(time.time()))
        next_htlc = next_chan.add_htlc(next_htlc)
        next_peer = self.lnworker.peers[next_chan.node_id]
        try:
            next_peer.send_message(
                "update_add_htlc",
                channel_id=next_chan.channel_id,
                id=next_htlc.htlc_id,
                cltv_expiry=next_cltv_expiry,
                amount_msat=next_amount_msat_htlc,
                payment_hash=next_htlc.payment_hash,
                onion_routing_packet=processed_onion.next_packet.to_bytes()
            )
        except BaseException as e:
            self.logger.info(f"failed to forward htlc: error sending message. {e}")
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, data=outgoing_chan_upd_message)
        next_peer.maybe_send_commitment(next_chan)
        return next_chan_scid, next_htlc.htlc_id

    def maybe_forward_trampoline(
            self, *,
            chan: Channel,
            htlc: UpdateAddHtlc,
            trampoline_onion: ProcessedOnionPacket):

        forwarding_enabled = self.network.config.get('lightning_forward_payments', False)
        forwarding_trampoline_enabled = self.network.config.get('lightning_forward_trampoline_payments', False)
        if not (forwarding_enabled and forwarding_trampoline_enabled):
            self.logger.info(f"trampoline forwarding is disabled. failing htlc.")
            raise OnionRoutingFailure(code=OnionFailureCode.PERMANENT_CHANNEL_FAILURE, data=b'')

        payload = trampoline_onion.hop_data.payload
        payment_hash = htlc.payment_hash
        payment_data = payload.get('payment_data')
        if payment_data:  # legacy case
            payment_secret = payment_data['payment_secret']
        else:
            payment_secret = os.urandom(32)

        try:
            outgoing_node_id = payload["outgoing_node_id"]["outgoing_node_id"]
            amt_to_forward = payload["amt_to_forward"]["amt_to_forward"]
            cltv_from_onion = payload["outgoing_cltv_value"]["outgoing_cltv_value"]
            if "invoice_features" in payload:
                self.logger.info('forward_trampoline: legacy')
                next_trampoline_onion = None
                invoice_features = payload["invoice_features"]["invoice_features"]
                invoice_routing_info = payload["invoice_routing_info"]["invoice_routing_info"]
                # TODO use invoice_routing_info
                # TODO legacy mpp payment, use total_msat from trampoline onion
            else:
                self.logger.info('forward_trampoline: end-to-end')
                invoice_features = LnFeatures.BASIC_MPP_OPT
                next_trampoline_onion = trampoline_onion.next_packet
        except Exception as e:
            self.logger.exception('')
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')

        # these are the fee/cltv paid by the sender
        # pay_to_node will raise if they are not sufficient
        trampoline_cltv_delta = htlc.cltv_expiry - cltv_from_onion
        trampoline_fee = htlc.amount_msat - amt_to_forward

        @log_exceptions
        async def forward_trampoline_payment():
            try:
                await self.lnworker.pay_to_node(
                    node_pubkey=outgoing_node_id,
                    payment_hash=payment_hash,
                    payment_secret=payment_secret,
                    amount_to_pay=amt_to_forward,
                    min_cltv_expiry=cltv_from_onion,
                    r_tags=[],
                    invoice_features=invoice_features,
                    fwd_trampoline_onion=next_trampoline_onion,
                    fwd_trampoline_fee=trampoline_fee,
                    fwd_trampoline_cltv_delta=trampoline_cltv_delta,
                    attempts=1)
            except OnionRoutingFailure as e:
                # FIXME: cannot use payment_hash as key
                self.lnworker.trampoline_forwarding_failures[payment_hash] = e
            except PaymentFailure as e:
                # FIXME: adapt the error code
                error_reason = OnionRoutingFailure(code=OnionFailureCode.UNKNOWN_NEXT_PEER, data=b'')
                self.lnworker.trampoline_forwarding_failures[payment_hash] = error_reason

        asyncio.ensure_future(forward_trampoline_payment())

    def maybe_fulfill_htlc(
            self, *,
            chan: Channel,
            htlc: UpdateAddHtlc,
            processed_onion: ProcessedOnionPacket,
            is_trampoline: bool = False) -> Tuple[Optional[bytes], Optional[OnionPacket]]:

        """As a final recipient of an HTLC, decide if we should fulfill it.
        Return (preimage, trampoline_onion_packet) with at most a single element not None
        """
        def log_fail_reason(reason: str):
            self.logger.info(f"maybe_fulfill_htlc. will FAIL HTLC: chan {chan.short_channel_id}. "
                             f"{reason}. htlc={str(htlc)}. onion_payload={processed_onion.hop_data.payload}")

        try:
            amt_to_forward = processed_onion.hop_data.payload["amt_to_forward"]["amt_to_forward"]
        except:
            log_fail_reason(f"'amt_to_forward' missing from onion")
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')

        # Check that our blockchain tip is sufficiently recent so that we have an approx idea of the height.
        # We should not release the preimage for an HTLC that its sender could already time out as
        # then they might try to force-close and it becomes a race.
        chain = self.network.blockchain()
        if chain.is_tip_stale():
            log_fail_reason(f"our chain tip is stale")
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')
        local_height = chain.height()
        exc_incorrect_or_unknown_pd = OnionRoutingFailure(
            code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
            data=amt_to_forward.to_bytes(8, byteorder="big") + local_height.to_bytes(4, byteorder="big"))
        if local_height + MIN_FINAL_CLTV_EXPIRY_ACCEPTED > htlc.cltv_expiry:
            log_fail_reason(f"htlc.cltv_expiry is unreasonably close")
            raise exc_incorrect_or_unknown_pd
        try:
            cltv_from_onion = processed_onion.hop_data.payload["outgoing_cltv_value"]["outgoing_cltv_value"]
        except:
            log_fail_reason(f"'outgoing_cltv_value' missing from onion")
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')

        if not is_trampoline:
            if cltv_from_onion != htlc.cltv_expiry:
                log_fail_reason(f"cltv_from_onion != htlc.cltv_expiry")
                raise OnionRoutingFailure(
                    code=OnionFailureCode.FINAL_INCORRECT_CLTV_EXPIRY,
                    data=htlc.cltv_expiry.to_bytes(4, byteorder="big"))
        try:
            total_msat = processed_onion.hop_data.payload["payment_data"]["total_msat"]
        except:
            total_msat = amt_to_forward # fall back to "amt_to_forward"

        if not is_trampoline and amt_to_forward != htlc.amount_msat:
            log_fail_reason(f"amt_to_forward != htlc.amount_msat")
            raise OnionRoutingFailure(
                code=OnionFailureCode.FINAL_INCORRECT_HTLC_AMOUNT,
                data=htlc.amount_msat.to_bytes(8, byteorder="big"))

        try:
            payment_secret_from_onion = processed_onion.hop_data.payload["payment_data"]["payment_secret"]
        except:
            if total_msat > amt_to_forward:
                # payment_secret is required for MPP
                log_fail_reason(f"'payment_secret' missing from onion")
                raise exc_incorrect_or_unknown_pd
            # TODO fail here if invoice has set PAYMENT_SECRET_REQ
            payment_secret_from_onion = None

        if total_msat > amt_to_forward:
            mpp_status = self.lnworker.check_received_mpp_htlc(payment_secret_from_onion, chan.short_channel_id, htlc, total_msat)
            if mpp_status is None:
                return None, None
            if mpp_status is False:
                log_fail_reason(f"MPP_TIMEOUT")
                raise OnionRoutingFailure(code=OnionFailureCode.MPP_TIMEOUT, data=b'')
            assert mpp_status is True

        # if there is a trampoline_onion, maybe_fulfill_htlc will be called again
        if processed_onion.trampoline_onion_packet:
            # TODO: we should check that all trampoline_onions are the same
            return None, processed_onion.trampoline_onion_packet

        # TODO don't accept payments twice for same invoice
        # TODO check invoice expiry
        info = self.lnworker.get_payment_info(htlc.payment_hash)
        if info is None:
            log_fail_reason(f"no payment_info found for RHASH {htlc.payment_hash.hex()}")
            raise exc_incorrect_or_unknown_pd
        preimage = self.lnworker.get_preimage(htlc.payment_hash)
        if payment_secret_from_onion:
            if payment_secret_from_onion != derive_payment_secret_from_payment_preimage(preimage):
                log_fail_reason(f'incorrect payment secret {payment_secret_from_onion.hex()} != {derive_payment_secret_from_payment_preimage(preimage).hex()}')
                raise exc_incorrect_or_unknown_pd
        invoice_msat = info.amount_msat
        if not (invoice_msat is None or invoice_msat <= total_msat <= 2 * invoice_msat):
            log_fail_reason(f"total_msat={total_msat} too different from invoice_msat={invoice_msat}")
            raise exc_incorrect_or_unknown_pd
        self.logger.info(f"maybe_fulfill_htlc. will FULFILL HTLC: chan {chan.short_channel_id}. htlc={str(htlc)}")
        self.lnworker.set_request_status(htlc.payment_hash, PR_PAID)
        return preimage, None

    def fulfill_htlc(self, chan: Channel, htlc_id: int, preimage: bytes):
        self.logger.info(f"_fulfill_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        assert chan.can_send_ctx_updates(), f"cannot send updates: {chan.short_channel_id}"
        assert chan.hm.is_htlc_irrevocably_added_yet(htlc_proposer=REMOTE, htlc_id=htlc_id)
        self.received_htlcs_pending_removal.add((chan, htlc_id))
        chan.settle_htlc(preimage, htlc_id)
        self.send_message(
            "update_fulfill_htlc",
            channel_id=chan.channel_id,
            id=htlc_id,
            payment_preimage=preimage)

    def fail_htlc(self, *, chan: Channel, htlc_id: int, error_bytes: bytes):
        self.logger.info(f"fail_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}.")
        assert chan.can_send_ctx_updates(), f"cannot send updates: {chan.short_channel_id}"
        self.received_htlcs_pending_removal.add((chan, htlc_id))
        chan.fail_htlc(htlc_id)
        self.send_message(
            "update_fail_htlc",
            channel_id=chan.channel_id,
            id=htlc_id,
            len=len(error_bytes),
            reason=error_bytes)

    def fail_malformed_htlc(self, *, chan: Channel, htlc_id: int, reason: OnionRoutingFailure):
        self.logger.info(f"fail_malformed_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}.")
        assert chan.can_send_ctx_updates(), f"cannot send updates: {chan.short_channel_id}"
        if not (reason.code & OnionFailureCodeMetaFlag.BADONION and len(reason.data) == 32):
            raise Exception(f"unexpected reason when sending 'update_fail_malformed_htlc': {reason!r}")
        self.received_htlcs_pending_removal.add((chan, htlc_id))
        chan.fail_htlc(htlc_id)
        self.send_message(
            "update_fail_malformed_htlc",
            channel_id=chan.channel_id,
            id=htlc_id,
            sha256_of_onion=reason.data,
            failure_code=reason.code)

    def on_revoke_and_ack(self, chan: Channel, payload):
        if chan.peer_state == PeerState.BAD:
            return
        self.logger.info(f'on_revoke_and_ack. chan {chan.short_channel_id}. ctn: {chan.get_oldest_unrevoked_ctn(REMOTE)}')
        rev = RevokeAndAck(payload["per_commitment_secret"], payload["next_per_commitment_point"])
        chan.receive_revocation(rev)
        self.lnworker.save_channel(chan)
        self.maybe_send_commitment(chan)
        self._received_revack_event.set()
        self._received_revack_event.clear()

    def on_update_fee(self, chan: Channel, payload):
        feerate = payload["feerate_per_kw"]
        chan.update_fee(feerate, False)

    async def maybe_update_fee(self, chan: Channel):
        """
        called when our fee estimates change
        """
        if not chan.can_send_ctx_updates():
            return
        feerate_per_kw = self.lnworker.current_feerate_per_kw()
        if not chan.constraints.is_initiator:
            if constants.net is not constants.BitcoinRegtest:
                chan_feerate = chan.get_latest_feerate(LOCAL)
                ratio = chan_feerate / feerate_per_kw
                if ratio < 0.5:
                    # Note that we trust the Electrum server about fee rates
                    # Thus, automated force-closing might not be a good idea
                    # Maybe we should display something in the GUI instead
                    self.logger.warning(
                        f"({chan.get_id_for_log()}) feerate is {chan_feerate} sat/kw, "
                        f"current recommended feerate is {feerate_per_kw} sat/kw, consider force closing!")
            return
        chan_fee = chan.get_next_feerate(REMOTE)
        if feerate_per_kw < chan_fee / 2:
            self.logger.info("FEES HAVE FALLEN")
        elif feerate_per_kw > chan_fee * 2:
            self.logger.info("FEES HAVE RISEN")
        elif chan.get_oldest_unrevoked_ctn(REMOTE) == 0:
            # workaround eclair issue https://github.com/ACINQ/eclair/issues/1730
            self.logger.info("updating fee to bump remote ctn")
            if feerate_per_kw == chan_fee:
                feerate_per_kw += 1
        else:
            return
        self.logger.info(f"(chan: {chan.get_id_for_log()}) current pending feerate {chan_fee}. "
                         f"new feerate {feerate_per_kw}")
        chan.update_fee(feerate_per_kw, True)
        self.send_message(
            "update_fee",
            channel_id=chan.channel_id,
            feerate_per_kw=feerate_per_kw)
        self.maybe_send_commitment(chan)

    @log_exceptions
    async def close_channel(self, chan_id: bytes):
        chan = self.channels[chan_id]
        self.shutdown_received[chan_id] = asyncio.Future()
        await self.send_shutdown(chan)
        payload = await self.shutdown_received[chan_id]
        try:
            txid = await self._shutdown(chan, payload, is_local=True)
            self.logger.info(f'({chan.get_id_for_log()}) Channel closed {txid}')
        except asyncio.TimeoutError:
            txid = chan.unconfirmed_closing_txid
            self.logger.info(f'({chan.get_id_for_log()}) did not send closing_signed, {txid}')
            if txid is None:
                raise Exception('The remote peer did not send their final signature. The channel may not have been be closed')
        return txid

    async def on_shutdown(self, chan: Channel, payload):
        # TODO: A receiving node: if it hasn't received a funding_signed (if it is a
        #  funder) or a funding_created (if it is a fundee):
        #  SHOULD send an error and fail the channel.
        their_scriptpubkey = payload['scriptpubkey']
        their_upfront_scriptpubkey = chan.config[REMOTE].upfront_shutdown_script
        # BOLT-02 check if they use the upfront shutdown script they advertized
        if self.is_upfront_shutdown_script() and their_upfront_scriptpubkey:
            if not (their_scriptpubkey == their_upfront_scriptpubkey):
                await self.send_warning(
                    chan.channel_id,
                    "remote didn't use upfront shutdown script it commited to in channel opening",
                    close_connection=True)
        else:
            # BOLT-02 restrict the scriptpubkey to some templates:
            if self.is_shutdown_anysegwit() and match_script_against_template(their_scriptpubkey, transaction.SCRIPTPUBKEY_TEMPLATE_ANYSEGWIT):
                pass
            elif match_script_against_template(their_scriptpubkey, transaction.SCRIPTPUBKEY_TEMPLATE_WITNESS_V0):
                pass
            else:
                await self.send_warning(
                    chan.channel_id,
                    f'scriptpubkey in received shutdown message does not conform to any template: {their_scriptpubkey.hex()}',
                    close_connection=True)

        chan_id = chan.channel_id
        if chan_id in self.shutdown_received:
            self.shutdown_received[chan_id].set_result(payload)
        else:
            chan = self.channels[chan_id]
            await self.send_shutdown(chan)
            txid = await self._shutdown(chan, payload, is_local=False)
            self.logger.info(f'({chan.get_id_for_log()}) Channel closed by remote peer {txid}')

    def can_send_shutdown(self, chan: Channel):
        if chan.get_state() >= ChannelState.OPENING:
            return True
        if chan.constraints.is_initiator and chan.channel_id in self.funding_created_sent:
            return True
        if not chan.constraints.is_initiator and chan.channel_id in self.funding_signed_sent:
            return True
        return False

    async def send_shutdown(self, chan: Channel):
        if not self.can_send_shutdown(chan):
            raise Exception('cannot send shutdown')
        if chan.config[LOCAL].upfront_shutdown_script:
            scriptpubkey = chan.config[LOCAL].upfront_shutdown_script
        else:
            scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        assert scriptpubkey
        # wait until no more pending updates (bolt2)
        chan.set_can_send_ctx_updates(False)
        while chan.has_pending_changes(REMOTE):
            await asyncio.sleep(0.1)
        self.send_message('shutdown', channel_id=chan.channel_id, len=len(scriptpubkey), scriptpubkey=scriptpubkey)
        chan.set_state(ChannelState.SHUTDOWN)
        # can fullfill or fail htlcs. cannot add htlcs, because state != OPEN
        chan.set_can_send_ctx_updates(True)

    def get_shutdown_fee_range(self, chan, closing_tx, is_local):
        """ return the closing fee and fee range we initially try to enforce """
        config = self.network.config
        if config.get('test_shutdown_fee'):
            our_fee = config.get('test_shutdown_fee')
        else:
            fee_rate_per_kb = config.eta_target_to_fee(FEE_LN_ETA_TARGET)
            if not fee_rate_per_kb:  # fallback
                fee_rate_per_kb = self.network.config.fee_per_kb()
            our_fee = fee_rate_per_kb * closing_tx.estimated_size() // 1000
            # TODO: anchors: remove this, as commitment fee rate can be below chain head fee rate?
            # BOLT2: The sending node MUST set fee less than or equal to the base fee of the final ctx
            max_fee = chan.get_latest_fee(LOCAL if is_local else REMOTE)
            our_fee = min(our_fee, max_fee)
        # config modern_fee_negotiation can be set in tests
        if config.get('test_shutdown_legacy'):
            our_fee_range = None
        elif config.get('test_shutdown_fee_range'):
            our_fee_range = config.get('test_shutdown_fee_range')
        else:
            # we aim at a fee between next block inclusion and some lower value
            our_fee_range = {'min_fee_satoshis': our_fee // 2, 'max_fee_satoshis': our_fee * 2}
        self.logger.info(f"Our fee range: {our_fee_range} and fee: {our_fee}")
        return our_fee, our_fee_range

    @log_exceptions
    async def _shutdown(self, chan: Channel, payload, *, is_local: bool):
        # wait until no HTLCs remain in either commitment transaction
        while len(chan.hm.htlcs(LOCAL)) + len(chan.hm.htlcs(REMOTE)) > 0:
            self.logger.info(f'(chan: {chan.short_channel_id}) waiting for htlcs to settle...')
            await asyncio.sleep(1)
        # if no HTLCs remain, we must not send updates
        chan.set_can_send_ctx_updates(False)
        their_scriptpubkey = payload['scriptpubkey']
        if chan.config[LOCAL].upfront_shutdown_script:
            our_scriptpubkey = chan.config[LOCAL].upfront_shutdown_script
        else:
            our_scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        assert our_scriptpubkey
        # estimate fee of closing tx
        dummy_sig, dummy_tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=0)
        our_sig = None
        closing_tx = None
        is_initiator = chan.constraints.is_initiator
        our_fee, our_fee_range = self.get_shutdown_fee_range(chan, dummy_tx, is_local)

        def send_closing_signed(our_fee, our_fee_range, drop_remote):
            nonlocal our_sig, closing_tx
            if our_fee_range:
                closing_signed_tlvs = {'fee_range': our_fee_range}
            else:
                closing_signed_tlvs = {}
            our_sig, closing_tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=our_fee, drop_remote=drop_remote)
            self.logger.info(f"Sending fee range: {closing_signed_tlvs} and fee: {our_fee}")
            self.send_message(
                'closing_signed',
                channel_id=chan.channel_id,
                fee_satoshis=our_fee,
                signature=our_sig,
                closing_signed_tlvs=closing_signed_tlvs,
            )

        def verify_signature(tx, sig):
            their_pubkey = chan.config[REMOTE].multisig_key.pubkey
            preimage_hex = tx.serialize_preimage(0)
            pre_hash = sha256d(bfh(preimage_hex))
            return ecc.verify_signature(their_pubkey, sig, pre_hash)

        async def receive_closing_signed():
            nonlocal our_sig, closing_tx
            try:
                cs_payload = await self.wait_for_message('closing_signed', chan.channel_id)
            except asyncio.exceptions.TimeoutError:
                self.schedule_force_closing(chan.channel_id)
                raise Exception("closing_signed not received, force closing.")
            their_fee = cs_payload['fee_satoshis']
            their_fee_range = cs_payload['closing_signed_tlvs'].get('fee_range')
            their_sig = cs_payload['signature']
            # perform checks
            our_sig, closing_tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=their_fee, drop_remote=False)
            if verify_signature(closing_tx, their_sig):
                drop_remote = False
            else:
                our_sig, closing_tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=their_fee, drop_remote=True)
                if verify_signature(closing_tx, their_sig):
                    drop_remote = True
                else:
                    # this can happen if we consider our output too valuable to drop,
                    # but the remote drops it because it violates their dust limit
                    raise Exception('failed to verify their signature')
            # at this point we know how the closing tx looks like
            # check that their output is above their scriptpubkey's network dust limit
            to_remote_set = closing_tx.get_output_idxs_from_scriptpubkey(their_scriptpubkey.hex())
            if not drop_remote and to_remote_set:
                to_remote_idx = to_remote_set.pop()
                to_remote_amount = closing_tx.outputs()[to_remote_idx].value
                transaction.check_scriptpubkey_template_and_dust(their_scriptpubkey, to_remote_amount)
            return their_fee, their_fee_range, their_sig, drop_remote

        def choose_new_fee(our_fee, our_fee_range, their_fee, their_fee_range, their_previous_fee):
            assert our_fee != their_fee
            fee_range_sent = our_fee_range and (is_initiator or (their_previous_fee is not None))

            # The sending node, if it is not the funder:
            if our_fee_range and their_fee_range and not is_initiator and not self.network.config.get('test_shutdown_fee_range'):
                # SHOULD set max_fee_satoshis to at least the max_fee_satoshis received
                our_fee_range['max_fee_satoshis'] = max(their_fee_range['max_fee_satoshis'], our_fee_range['max_fee_satoshis'])
                # SHOULD set min_fee_satoshis to a fairly low value
                our_fee_range['min_fee_satoshis'] = min(their_fee_range['min_fee_satoshis'], our_fee_range['min_fee_satoshis'])
                # Note: the BOLT describes what the sending node SHOULD do.
                # However, this assumes that we have decided to send 'funding_signed' in response to their fee_range.
                # In practice, we might prefer to fail the channel in some cases (TODO)

            # the receiving node, if fee_satoshis matches its previously sent fee_range,
            if fee_range_sent and (our_fee_range['min_fee_satoshis'] <= their_fee <= our_fee_range['max_fee_satoshis']):
                # SHOULD reply with a closing_signed with the same fee_satoshis value if it is different from its previously sent fee_satoshis
                our_fee = their_fee

            # the receiving node, if the message contains a fee_range
            elif our_fee_range and their_fee_range:
                overlap_min = max(our_fee_range['min_fee_satoshis'], their_fee_range['min_fee_satoshis'])
                overlap_max = min(our_fee_range['max_fee_satoshis'], their_fee_range['max_fee_satoshis'])
                # if there is no overlap between that and its own fee_range
                if overlap_min > overlap_max:
                    # TODO: the receiving node should first send a warning, and fail the channel
                    # only if it doesn't receive a satisfying fee_range after a reasonable amount of time
                    self.schedule_force_closing(chan.channel_id)
                    raise Exception("There is no overlap between between their and our fee range.")
                # otherwise, if it is the funder
                if is_initiator:
                    # if fee_satoshis is not in the overlap between the sent and received fee_range:
                    if not (overlap_min <= their_fee <= overlap_max):
                        # MUST fail the channel
                        self.schedule_force_closing(chan.channel_id)
                        raise Exception("Their fee is not in the overlap region, we force closed.")
                    # otherwise, MUST reply with the same fee_satoshis.
                    our_fee = their_fee
                # otherwise (it is not the funder):
                else:
                    # if it has already sent a closing_signed:
                    if fee_range_sent:
                        # fee_satoshis is not the same as the value we sent, we MUST fail the channel
                        self.schedule_force_closing(chan.channel_id)
                        raise Exception("Expected the same fee as ours, we force closed.")
                    # otherwise:
                    # MUST propose a fee_satoshis in the overlap between received and (about-to-be) sent fee_range.
                    our_fee = (overlap_min + overlap_max) // 2
            else:
                # otherwise, if fee_satoshis is not strictly between its last-sent fee_satoshis
                # and its previously-received fee_satoshis, UNLESS it has since reconnected:
                if their_previous_fee and not (min(our_fee, their_previous_fee) < their_fee < max(our_fee, their_previous_fee)):
                    # SHOULD fail the connection.
                    raise Exception('Their fee is not between our last sent and their last sent fee.')
                # accept their fee if they are very close
                if abs(their_fee - our_fee) < 2:
                    our_fee = their_fee
                else:
                    # this will be "strictly between" (as in BOLT2) previous values because of the above
                    our_fee = (our_fee + their_fee) // 2

            return our_fee, our_fee_range

        # Fee negotiation: both parties exchange 'funding_signed' messages.
        # The funder sends the first message, the non-funder sends the last message.
        # In the 'modern' case, at most 3 messages are exchanged, because choose_new_fee of the funder either returns their_fee or fails
        their_fee = None
        drop_remote = False  # does the peer drop its to_local output or not?
        if is_initiator:
            send_closing_signed(our_fee, our_fee_range, drop_remote)
        while True:
            their_previous_fee = their_fee
            their_fee, their_fee_range, their_sig, drop_remote = await receive_closing_signed()
            if our_fee == their_fee:
                break
            our_fee, our_fee_range = choose_new_fee(our_fee, our_fee_range, their_fee, their_fee_range, their_previous_fee)
            if not is_initiator and our_fee == their_fee:
                break
            send_closing_signed(our_fee, our_fee_range, drop_remote)
            if is_initiator and our_fee == their_fee:
                break
        if not is_initiator:
            send_closing_signed(our_fee, our_fee_range, drop_remote)

        # add signatures
        closing_tx.add_signature_to_txin(
            txin_idx=0,
            signing_pubkey=chan.config[LOCAL].multisig_key.pubkey.hex(),
            sig=bh2u(der_sig_from_sig_string(our_sig) + b'\x01'))
        closing_tx.add_signature_to_txin(
            txin_idx=0,
            signing_pubkey=chan.config[REMOTE].multisig_key.pubkey.hex(),
            sig=bh2u(der_sig_from_sig_string(their_sig) + b'\x01'))
        # save local transaction and set state
        try:
            self.lnworker.wallet.add_transaction(closing_tx)
        except UnrelatedTransactionException:
            pass  # this can happen if (~all the balance goes to REMOTE)
        chan.set_state(ChannelState.CLOSING)
        # broadcast
        await self.network.try_broadcasting(closing_tx, 'closing')
        return closing_tx.txid()

    async def htlc_switch(self):
        await self.initialized
        while True:
            self._htlc_switch_iterdone_event.set()
            self._htlc_switch_iterdone_event.clear()
            # We poll every 0.1 sec to check if there is work to do,
            # or we can also be triggered via events.
            # When forwarding an HTLC originating from this peer (the upstream),
            # we can get triggered for events that happen on the downstream peer.
            # TODO: trampoline forwarding relies on the polling
            async with ignore_after(0.1):
                async with OldTaskGroup(wait=any) as group:
                    await group.spawn(self._received_revack_event.wait())
                    await group.spawn(self.downstream_htlc_resolved_event.wait())
            self._htlc_switch_iterstart_event.set()
            self._htlc_switch_iterstart_event.clear()
            self.ping_if_required()
            self._maybe_cleanup_received_htlcs_pending_removal()
            for chan_id, chan in self.channels.items():
                if not chan.can_send_ctx_updates():
                    continue
                self.maybe_send_commitment(chan)
                done = set()
                unfulfilled = chan.unfulfilled_htlcs
                for htlc_id, (local_ctn, remote_ctn, onion_packet_hex, forwarding_info) in unfulfilled.items():
                    if forwarding_info:
                        self.lnworker.downstream_htlc_to_upstream_peer_map[forwarding_info] = self.pubkey
                    if not chan.hm.is_htlc_irrevocably_added_yet(htlc_proposer=REMOTE, htlc_id=htlc_id):
                        continue
                    htlc = chan.hm.get_htlc_by_id(REMOTE, htlc_id)
                    error_reason = None  # type: Optional[OnionRoutingFailure]
                    error_bytes = None  # type: Optional[bytes]
                    preimage = None
                    fw_info = None
                    onion_packet_bytes = bytes.fromhex(onion_packet_hex)
                    onion_packet = None
                    try:
                        onion_packet = OnionPacket.from_bytes(onion_packet_bytes)
                    except OnionRoutingFailure as e:
                        error_reason = e
                    else:
                        try:
                            preimage, fw_info, error_bytes = self.process_unfulfilled_htlc(
                                chan=chan,
                                htlc=htlc,
                                forwarding_info=forwarding_info,
                                onion_packet_bytes=onion_packet_bytes,
                                onion_packet=onion_packet)
                        except OnionRoutingFailure as e:
                            error_bytes = construct_onion_error(e, onion_packet, our_onion_private_key=self.privkey)
                    if fw_info:
                        unfulfilled[htlc_id] = local_ctn, remote_ctn, onion_packet_hex, fw_info
                        self.lnworker.downstream_htlc_to_upstream_peer_map[fw_info] = self.pubkey
                    elif preimage or error_reason or error_bytes:
                        if preimage:
                            if not self.lnworker.enable_htlc_settle:
                                continue
                            self.fulfill_htlc(chan, htlc.htlc_id, preimage)
                        elif error_bytes:
                            self.fail_htlc(
                                chan=chan,
                                htlc_id=htlc.htlc_id,
                                error_bytes=error_bytes)
                        else:
                            self.fail_malformed_htlc(
                                chan=chan,
                                htlc_id=htlc.htlc_id,
                                reason=error_reason)
                        done.add(htlc_id)
                # cleanup
                for htlc_id in done:
                    local_ctn, remote_ctn, onion_packet_hex, forwarding_info = unfulfilled.pop(htlc_id)
                    if forwarding_info:
                        self.lnworker.downstream_htlc_to_upstream_peer_map.pop(forwarding_info, None)
                self.maybe_send_commitment(chan)

    def _maybe_cleanup_received_htlcs_pending_removal(self) -> None:
        done = set()
        for chan, htlc_id in self.received_htlcs_pending_removal:
            if chan.hm.is_htlc_irrevocably_removed_yet(htlc_proposer=REMOTE, htlc_id=htlc_id):
                done.add((chan, htlc_id))
        if done:
            for key in done:
                self.received_htlcs_pending_removal.remove(key)
            self.received_htlc_removed_event.set()
            self.received_htlc_removed_event.clear()

    async def wait_one_htlc_switch_iteration(self) -> None:
        """Waits until the HTLC switch does a full iteration or the peer disconnects,
        whichever happens first.
        """
        async def htlc_switch_iteration():
            await self._htlc_switch_iterstart_event.wait()
            await self._htlc_switch_iterdone_event.wait()

        async with OldTaskGroup(wait=any) as group:
            await group.spawn(htlc_switch_iteration())
            await group.spawn(self.got_disconnected.wait())

    def process_unfulfilled_htlc(
            self, *,
            chan: Channel,
            htlc: UpdateAddHtlc,
            forwarding_info: Tuple[str, int],
            onion_packet_bytes: bytes,
            onion_packet: OnionPacket) -> Tuple[Optional[bytes], Union[bool, None, Tuple[str, int]], Optional[bytes]]:
        """
        return (preimage, fw_info, error_bytes) with at most a single element that is not None
        raise an OnionRoutingFailure if we need to fail the htlc
        """
        payment_hash = htlc.payment_hash
        processed_onion = self.process_onion_packet(
            onion_packet,
            payment_hash=payment_hash,
            onion_packet_bytes=onion_packet_bytes)
        if processed_onion.are_we_final:
            # either we are final recipient; or if trampoline, see cases below
            preimage, trampoline_onion_packet = self.maybe_fulfill_htlc(
                chan=chan,
                htlc=htlc,
                processed_onion=processed_onion)
            if trampoline_onion_packet:
                # trampoline- recipient or forwarding
                if not forwarding_info:
                    trampoline_onion = self.process_onion_packet(
                        trampoline_onion_packet,
                        payment_hash=htlc.payment_hash,
                        onion_packet_bytes=onion_packet_bytes,
                        is_trampoline=True)
                    if trampoline_onion.are_we_final:
                        # trampoline- we are final recipient of HTLC
                        preimage, _ = self.maybe_fulfill_htlc(
                            chan=chan,
                            htlc=htlc,
                            processed_onion=trampoline_onion,
                            is_trampoline=True)
                    else:
                        # trampoline- HTLC we are supposed to forward, but haven't forwarded yet
                        if not self.lnworker.enable_htlc_forwarding:
                            return None, None, None
                        self.maybe_forward_trampoline(
                            chan=chan,
                            htlc=htlc,
                            trampoline_onion=trampoline_onion)
                        # return True so that this code gets executed only once
                        return None, True, None
                else:
                    # trampoline- HTLC we are supposed to forward, and have already forwarded
                    preimage = self.lnworker.get_preimage(payment_hash)
                    error_reason = self.lnworker.trampoline_forwarding_failures.pop(payment_hash, None)
                    if error_reason:
                        self.logger.info(f'trampoline forwarding failure: {error_reason.code_name()}')
                        raise error_reason

        elif not forwarding_info:
            # HTLC we are supposed to forward, but haven't forwarded yet
            if not self.lnworker.enable_htlc_forwarding:
                return None, None, None
            next_chan_id, next_htlc_id = self.maybe_forward_htlc(
                htlc=htlc,
                processed_onion=processed_onion)
            fw_info = (next_chan_id.hex(), next_htlc_id)
            return None, fw_info, None
        else:
            # HTLC we are supposed to forward, and have already forwarded
            preimage = self.lnworker.get_preimage(payment_hash)
            next_chan_id_hex, htlc_id = forwarding_info
            next_chan = self.lnworker.get_channel_by_short_id(bytes.fromhex(next_chan_id_hex))
            if next_chan:
                error_bytes, error_reason = next_chan.pop_fail_htlc_reason(htlc_id)
                if error_bytes:
                    return None, None, error_bytes
                if error_reason:
                    raise error_reason
        if preimage:
            return preimage, None, None
        return None, None, None

    def process_onion_packet(
            self,
            onion_packet: OnionPacket, *,
            payment_hash: bytes,
            onion_packet_bytes: bytes,
            is_trampoline: bool = False) -> ProcessedOnionPacket:

        failure_data = sha256(onion_packet_bytes)
        try:
            processed_onion = process_onion_packet(
                onion_packet,
                associated_data=payment_hash,
                our_onion_private_key=self.privkey,
                is_trampoline=is_trampoline)
        except UnsupportedOnionPacketVersion:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_VERSION, data=failure_data)
        except InvalidOnionPubkey:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_KEY, data=failure_data)
        except InvalidOnionMac:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_HMAC, data=failure_data)
        except Exception as e:
            self.logger.info(f"error processing onion packet: {e!r}")
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_VERSION, data=failure_data)
        if self.network.config.get('test_fail_malformed_htlc'):
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_VERSION, data=failure_data)
        if self.network.config.get('test_fail_htlcs_with_temp_node_failure'):
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')
        return processed_onion
