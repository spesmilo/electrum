#!/usr/bin/env python3
#
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from collections import OrderedDict, defaultdict
import asyncio
import os
import time
from typing import Tuple, Dict, TYPE_CHECKING, Optional, Union, Set, Callable, Coroutine, List, Any
from datetime import datetime
import functools
from functools import partial
import inspect

import electrum_ecc as ecc
from electrum_ecc import ecdsa_sig64_from_r_and_s, ecdsa_der_sig_from_ecdsa_sig64, ECPubkey

import aiorpcx
from aiorpcx import ignore_after

from .lrucache import LRUCache
from .crypto import sha256, sha256d, privkey_to_pubkey
from . import bitcoin, util
from . import constants
from .util import (log_exceptions, ignore_exceptions, chunks, OldTaskGroup,
                   UnrelatedTransactionException, error_text_bytes_to_safe_str, AsyncHangDetector,
                   NoDynamicFeeEstimates, event_listener, EventListener)
from . import transaction
from .bitcoin import make_op_return, DummyAddress
from .transaction import PartialTxOutput, match_script_against_template, Sighash
from .logging import Logger
from . import lnonion
from .lnonion import (OnionFailureCode, OnionPacket, obfuscate_onion_error,
                      OnionRoutingFailure, ProcessedOnionPacket, UnsupportedOnionPacketVersion,
                      InvalidOnionMac, InvalidOnionPubkey, OnionFailureCodeMetaFlag,
                      OnionParsingError)
from .lnchannel import Channel, RevokeAndAck, ChannelState, PeerState, ChanCloseOption, CF_ANNOUNCE_CHANNEL
from . import lnutil
from .lnutil import (Outpoint, LocalConfig, RECEIVED, UpdateAddHtlc, ChannelConfig,
                     RemoteConfig, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore,
                     funding_output_script, get_per_commitment_secret_from_seed,
                     secret_to_pubkey, PaymentFailure, LnFeatures,
                     LOCAL, REMOTE, HTLCOwner,
                     ln_compare_features, MIN_FINAL_CLTV_DELTA_ACCEPTED,
                     RemoteMisbehaving, ShortChannelID,
                     IncompatibleLightningFeatures, ChannelType, LNProtocolWarning, validate_features,
                     IncompatibleOrInsaneFeatures, ReceivedMPPStatus, ReceivedMPPHtlc,
                     GossipForwardingMessage, GossipTimestampFilter, channel_id_from_funding_tx,
                     serialize_htlc_key, Keypair, RecvMPPResolution)
from .lntransport import LNTransport, LNTransportBase, LightningPeerConnectionClosed, HandshakeFailed
from .lnmsg import encode_msg, decode_msg, UnknownOptionalMsgType, FailedToParseMsg
from .interface import GracefulDisconnect
from .json_db import StoredDict
from .invoices import PR_PAID
from .fee_policy import FEE_LN_ETA_TARGET, FEERATE_PER_KW_MIN_RELAY_LIGHTNING

if TYPE_CHECKING:
    from .lnworker import LNGossip, LNWallet
    from .lnrouter import LNPaymentRoute
    from .transaction import PartialTransaction


LN_P2P_NETWORK_TIMEOUT = 20


class Peer(Logger, EventListener):
    # note: in general this class is NOT thread-safe. Most methods are assumed to be running on asyncio thread.

    ORDERED_MESSAGES = (
        'accept_channel', 'funding_signed', 'funding_created', 'accept_channel', 'closing_signed')
    SPAMMY_MESSAGES = (
        'ping', 'pong', 'channel_announcement', 'node_announcement', 'channel_update',
        'gossip_timestamp_filter', 'reply_channel_range', 'query_channel_range',
        'query_short_channel_ids', 'reply_short_channel_ids', 'reply_short_channel_ids_end')

    DELAY_INC_MSG_PROCESSING_SLEEP = 0.01
    RECV_GOSSIP_QUEUE_SOFT_MAXSIZE = 2000
    RECV_GOSSIP_QUEUE_HARD_MAXSIZE = 5000

    def __init__(
            self,
            lnworker: Union['LNWallet', 'LNGossip'],
            pubkey: bytes,
            transport: LNTransportBase,
            *, is_channel_backup= False):

        self.lnworker = lnworker
        self.network = lnworker.network
        self.asyncio_loop = self.network.asyncio_loop
        self.is_channel_backup = is_channel_backup
        self._sent_init = False  # type: bool
        self._received_init = False  # type: bool
        self.initialized = self.asyncio_loop.create_future()
        self.got_disconnected = asyncio.Event()
        self.querying = asyncio.Event()
        self.transport = transport
        self.pubkey = pubkey  # remote pubkey
        self.privkey = self.transport.privkey  # local privkey
        self.features = self.lnworker.features  # type: LnFeatures
        self.their_features = LnFeatures(0)  # type: LnFeatures
        self.node_ids = [self.pubkey, privkey_to_pubkey(self.privkey)]
        assert self.node_ids[0] != self.node_ids[1]
        self.last_message_time = 0
        self.pong_event = asyncio.Event()
        self.reply_channel_range = None  # type: Optional[asyncio.Queue]
        # gossip uses a single queue to preserve message order
        self.recv_gossip_queue = asyncio.Queue(maxsize=self.RECV_GOSSIP_QUEUE_HARD_MAXSIZE)
        self.our_gossip_timestamp_filter = None  # type: Optional[GossipTimestampFilter]
        self.their_gossip_timestamp_filter = None  # type: Optional[GossipTimestampFilter]
        self.outgoing_gossip_reply = False # type: bool
        self.ordered_message_queues = defaultdict(partial(asyncio.Queue, maxsize=10))  # type: Dict[bytes, asyncio.Queue] # for messages that are ordered
        self.temp_id_to_id = {}  # type: Dict[bytes, Optional[bytes]]   # to forward error messages
        self.funding_created_sent = set() # for channels in PREOPENING
        self.funding_signed_sent = set()  # for channels in PREOPENING
        self.shutdown_received = {} # chan_id -> asyncio.Future()
        self.channel_reestablish_msg = defaultdict(self.asyncio_loop.create_future)  # type: Dict[bytes, asyncio.Future]
        self._chan_reest_finished = defaultdict(asyncio.Event)  # type: Dict[bytes, asyncio.Event]
        self.orphan_channel_updates = OrderedDict()  # type: OrderedDict[ShortChannelID, dict]
        Logger.__init__(self)
        self.taskgroup = OldTaskGroup()
        # HTLCs offered by REMOTE, that we started removing but are still active:
        self.received_htlcs_pending_removal = set()  # type: Set[Tuple[Channel, int]]
        self.received_htlc_removed_event = asyncio.Event()
        self._htlc_switch_iterstart_event = asyncio.Event()
        self._htlc_switch_iterdone_event = asyncio.Event()
        self._received_revack_event = asyncio.Event()
        self.received_commitsig_event = asyncio.Event()
        self.downstream_htlc_resolved_event = asyncio.Event()
        self.register_callbacks()
        self._num_gossip_messages_forwarded = 0
        self._processed_onion_cache = LRUCache(maxsize=100)  # type: LRUCache[bytes, ProcessedOnionPacket]

    def send_message(self, message_name: str, **kwargs):
        assert util.get_running_loop() == util.get_asyncio_loop(), f"this must be run on the asyncio thread!"
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
        flen = features.min_len()
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

    async def ping_if_required(self):
        if time.time() - self.last_message_time > 30:
            self.send_message('ping', num_pong_bytes=4, byteslen=4)
            self.pong_event.clear()
            await self.pong_event.wait()

    async def _process_message(self, message: bytes) -> None:
        try:
            message_type, payload = decode_msg(message)
        except UnknownOptionalMsgType as e:
            self.logger.info(f"received unknown message from peer. ignoring: {e!r}")
            return
        except FailedToParseMsg as e:
            self.logger.info(
                f"failed to parse message from peer. disconnecting. "
                f"msg_type={e.msg_type_name}({e.msg_type_int}). exc={e!r}")
            #self.logger.info(f"failed to parse message: message(SECRET?)={message.hex()}")
            raise GracefulDisconnect() from e
        self.last_message_time = time.time()
        if message_type not in self.SPAMMY_MESSAGES:
            self.logger.debug(f"Received {message_type.upper()}")
        # only process INIT if we are a backup
        if self.is_channel_backup is True and message_type != 'init':
            return
        if message_type in self.ORDERED_MESSAGES:
            chan_id = payload.get('channel_id') or payload["temporary_channel_id"]
            if (
                chan_id not in self.channels
                and chan_id not in self.temp_id_to_id
                and chan_id not in self.temp_id_to_id.values()
            ):
                raise Exception(f"received {message_type} for unknown {chan_id.hex()=}")
            self.ordered_message_queues[chan_id].put_nowait((message_type, payload))
        else:
            if message_type not in ('error', 'warning') and 'channel_id' in payload:
                chan = self.get_channel_by_id(payload['channel_id'])
                if chan is None:
                    self.logger.info(f"Received {message_type} for unknown channel {payload['channel_id'].hex()}")
                    return
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
                payload['sender_node_id'] = self.pubkey
            # note: the message handler might be async or non-async. In either case, by default,
            #       we wait for it to complete before we return, i.e. before the next message is processed.
            if inspect.iscoroutinefunction(f):
                async with AsyncHangDetector(
                    message=f"message handler still running for {message_type.upper()}",
                    logger=self.logger,
                ):
                    await f(*args)
            else:
                f(*args)

    def non_blocking_msg_handler(func):
        """Makes a message handler non-blocking: while processing the message,
        the message_loop keeps processing subsequent incoming messages asynchronously.
        """
        assert inspect.iscoroutinefunction(func), 'func needs to be a coroutine'
        @functools.wraps(func)
        async def wrapper(self: 'Peer', *args, **kwargs):
            return await self.taskgroup.spawn(func(self, *args, **kwargs))
        return wrapper

    def on_warning(self, payload):
        chan_id = payload.get("channel_id")
        err_bytes = payload['data']
        is_known_chan_id = (chan_id in self.channels) or (chan_id in self.temp_id_to_id)
        self.logger.info(f"remote peer sent warning [DO NOT TRUST THIS MESSAGE]: "
                         f"{error_text_bytes_to_safe_str(err_bytes, max_len=None)}. chan_id={chan_id.hex()}. "
                         f"{is_known_chan_id=}")

    def on_error(self, payload):
        chan_id = payload.get("channel_id")
        err_bytes = payload['data']
        is_known_chan_id = (chan_id in self.channels) or (chan_id in self.temp_id_to_id)
        self.logger.info(f"remote peer sent error [DO NOT TRUST THIS MESSAGE]: "
                         f"{error_text_bytes_to_safe_str(err_bytes, max_len=None)}. chan_id={chan_id.hex()}. "
                         f"{is_known_chan_id=}")
        if chan := self.get_channel_by_id(chan_id):
            self.schedule_force_closing(chan_id)
            self.ordered_message_queues[chan_id].put_nowait((None, {'error': err_bytes}))
            chan.save_remote_peer_sent_error(err_bytes)
        elif chan_id in self.temp_id_to_id:
            chan_id = self.temp_id_to_id[chan_id] or chan_id
            self.ordered_message_queues[chan_id].put_nowait((None, {'error': err_bytes}))
        elif chan_id == bytes(32):
            # if channel_id is all zero:
            # - MUST fail all channels with the sending node.
            for cid in self.channels:
                self.schedule_force_closing(cid)
                self.ordered_message_queues[cid].put_nowait((None, {'error': err_bytes}))
        else:
            # if no existing channel is referred to by channel_id:
            # - MUST ignore the message.
            return
        raise GracefulDisconnect

    def send_warning(self, channel_id: bytes, message: str = None, *, close_connection=False):
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

    def send_error(self, channel_id: bytes, message: str = None, *, force_close_channel=False):
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
        self.pong_event.set()

    async def wait_for_message(self, expected_name: str, channel_id: bytes):
        q = self.ordered_message_queues[channel_id]
        name, payload = await util.wait_for2(q.get(), LN_P2P_NETWORK_TIMEOUT)
        # raise exceptions for errors, so that the caller sees them
        if (err_bytes := payload.get("error")) is not None:
            err_text = error_text_bytes_to_safe_str(err_bytes)
            raise GracefulDisconnect(
                f"remote peer sent error [DO NOT TRUST THIS MESSAGE]: {err_text}")
        if name != expected_name:
            raise Exception(f"Received unexpected '{name}'")
        return payload

    def on_init(self, payload):
        if self._received_init:
            self.logger.info("ALREADY INITIALIZED BUT RECEIVED INIT")
            return
        _their_features = int.from_bytes(payload['features'], byteorder="big")
        _their_features |= int.from_bytes(payload['globalfeatures'], byteorder="big")
        try:
            self.their_features = validate_features(_their_features)
        except IncompatibleOrInsaneFeatures as e:
            raise GracefulDisconnect(f"remote sent insane features: {repr(e)}")
        # check if features are compatible, and set self.features to what we negotiated
        try:
            self.features = ln_compare_features(self.features, self.their_features)
        except IncompatibleLightningFeatures as e:
            self.initialized.set_exception(e)
            raise GracefulDisconnect(f"{str(e)}")
        self.logger.info(
            f"received INIT with features={str(self.their_features.get_names())}. "
            f"negotiated={str(self.features)}")
        # check that they are on the same chain as us, if provided
        their_networks = payload["init_tlvs"].get("networks")
        if their_networks:
            their_chains = list(chunks(their_networks["chains"], 32))
            if constants.net.rev_genesis_bytes() not in their_chains:
                raise GracefulDisconnect(f"no common chain found with remote. (they sent: {their_chains})")
        # all checks passed
        self.lnworker.lnpeermgr.on_peer_successfully_established(self)
        self._received_init = True
        self.maybe_set_initialized()

    def on_node_announcement(self, payload):
        if self.lnworker.uses_trampoline():
            return
        if self.our_gossip_timestamp_filter is None:
            return  # why is the peer sending this? should we disconnect?
        self.recv_gossip_queue.put_nowait(('node_announcement', payload))

    def on_channel_announcement(self, payload):
        if self.lnworker.uses_trampoline():
            return
        if self.our_gossip_timestamp_filter is None:
            return  # why is the peer sending this? should we disconnect?
        self.recv_gossip_queue.put_nowait(('channel_announcement', payload))

    def on_channel_update(self, payload):
        self.maybe_save_remote_update(payload)
        if self.lnworker.uses_trampoline():
            return
        if self.our_gossip_timestamp_filter is None:
            return  # why is the peer sending this? should we disconnect?
        self.recv_gossip_queue.put_nowait(('channel_update', payload))

    def on_query_channel_range(self, payload):
        if self.lnworker == self.lnworker.network.lngossip or not self._should_forward_gossip():
            return
        if not self._is_valid_channel_range_query(payload):
            return self.send_warning(bytes(32), "received invalid query_channel_range")
        if self.outgoing_gossip_reply:
            return self.send_warning(bytes(32), "received multiple queries at the same time")
        self.outgoing_gossip_reply = True
        self.recv_gossip_queue.put_nowait(('query_channel_range', payload))

    def on_query_short_channel_ids(self, payload):
        if self.lnworker == self.lnworker.network.lngossip or not self._should_forward_gossip():
            return
        if self.outgoing_gossip_reply:
            return self.send_warning(bytes(32), "received multiple queries at the same time")
        if not self._is_valid_short_channel_id_query(payload):
            return self.send_warning(bytes(32), "invalid query_short_channel_ids")
        self.outgoing_gossip_reply = True
        self.recv_gossip_queue.put_nowait(('query_short_channel_ids', payload))

    def on_gossip_timestamp_filter(self, payload):
        if self._should_forward_gossip():
            self.set_gossip_timestamp_filter(payload)

    def set_gossip_timestamp_filter(self, payload: dict) -> None:
        """Set the gossip_timestamp_filter for this peer. If the peer requested historical gossip,
        the request is put on the queue, otherwise only the forwarding loop will check the filter"""
        if payload.get('chain_hash') != constants.net.rev_genesis_bytes():
            return
        filter = GossipTimestampFilter.from_payload(payload)
        self.their_gossip_timestamp_filter = filter
        self.logger.debug(f"got gossip_ts_filter from peer {self.pubkey.hex()}: "
                          f"{str(self.their_gossip_timestamp_filter)}")
        if filter and not filter.only_forwarding:
            self.recv_gossip_queue.put_nowait(('gossip_timestamp_filter', None))

    def maybe_save_remote_update(self, payload):
        if not self.channels:
            return
        for chan in self.channels.values():
            if payload['short_channel_id'] in [chan.short_channel_id, chan.get_local_scid_alias()]:
                chan.set_remote_update(payload)
                self.logger.info(f"saved remote channel_update gossip msg for chan {chan.get_id_for_log()}")
                break
        else:
            # Save (some bounded number of) orphan channel updates for later
            # as it might be for our own direct channel with this peer
            # (and we might not yet know the short channel id for that)
            # Background: this code is here to deal with a bug in LND,
            # see https://github.com/lightningnetwork/lnd/issues/3651 (closed 2022-08-13, lnd-v0.15.1)
            # and https://github.com/lightningnetwork/lightning-rfc/pull/657
            # This code assumes gossip_queries is set. BOLT7: "if the
            # gossip_queries feature is negotiated, [a node] MUST NOT
            # send gossip it did not generate itself"
            # NOTE: The definition of gossip_queries changed
            # https://github.com/lightning/bolts/commit/fce8bab931674a81a9ea895c9e9162e559e48a65
            short_channel_id = ShortChannelID(payload['short_channel_id'])
            self.logger.debug(f'received orphan channel update {short_channel_id}')
            self.orphan_channel_updates[short_channel_id] = payload
            while len(self.orphan_channel_updates) > 25:
                self.orphan_channel_updates.popitem(last=False)

    def on_announcement_signatures(self, chan: Channel, payload):
        h = chan.get_channel_announcement_hash()
        node_signature = payload["node_signature"]
        bitcoin_signature = payload["bitcoin_signature"]
        if not ECPubkey(chan.config[REMOTE].multisig_key.pubkey).ecdsa_verify(bitcoin_signature, h):
            raise Exception("bitcoin_sig invalid in announcement_signatures")
        if not ECPubkey(self.pubkey).ecdsa_verify(node_signature, h):
            raise Exception("node_sig invalid in announcement_signatures")
        chan.config[REMOTE].announcement_node_sig = node_signature
        chan.config[REMOTE].announcement_bitcoin_sig = bitcoin_signature
        self.lnworker.save_channel(chan)
        self.maybe_send_announcement_signatures(chan, is_reply=True)

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
            await group.spawn(self._message_loop())  # initializes connection
            try:
                await util.wait_for2(self.initialized, LN_P2P_NETWORK_TIMEOUT)
            except Exception as e:
                raise GracefulDisconnect(f"Failed to initialize: {e!r}") from e
            await group.spawn(self._query_gossip())
            await group.spawn(self._process_gossip())
            await group.spawn(self._send_own_gossip())
            await group.spawn(self._forward_gossip())
            if self.network.lngossip != self.lnworker:
                await group.spawn(self.htlc_switch())

    async def _process_gossip(self):
        while True:
            await asyncio.sleep(5)
            if not self.network.lngossip:
                continue
            chan_anns = []
            chan_upds = []
            node_anns = []
            while True:
                name, payload = await self.recv_gossip_queue.get()
                if name == 'channel_announcement':
                    chan_anns.append(payload)
                elif name == 'channel_update':
                    chan_upds.append(payload)
                elif name == 'node_announcement':
                    node_anns.append(payload)
                elif name == 'query_channel_range':
                    await self.taskgroup.spawn(self._send_reply_channel_range(payload))
                elif name == 'query_short_channel_ids':
                    await self.taskgroup.spawn(self._send_reply_short_channel_ids(payload))
                elif name == 'gossip_timestamp_filter':
                    await self.taskgroup.spawn(self._handle_historical_gossip_request())
                else:
                    raise Exception('unknown message')
                if self.recv_gossip_queue.empty():
                    break
            if self.network.lngossip:
                await self.network.lngossip.process_gossip(chan_anns, node_anns, chan_upds)

    async def _send_own_gossip(self):
        if self.lnworker == self.lnworker.network.lngossip:
            return
        assert self.is_initialized()
        await asyncio.sleep(10)
        while True:
            public_channels = [chan for chan in self.lnworker.channels.values() if chan.is_public()]
            if public_channels:
                alias = self.lnworker.config.LIGHTNING_NODE_ALIAS
                color = self.lnworker.config.LIGHTNING_NODE_COLOR_RGB
                self.send_node_announcement(alias, color)
                for chan in public_channels:
                    if chan.is_open() and chan.peer_state == PeerState.GOOD:
                        self.maybe_send_channel_announcement(chan)
            await asyncio.sleep(600)

    def _should_forward_gossip(self) -> bool:
        if (self.network.lngossip != self.lnworker
                and not self.lnworker.uses_trampoline()
                and self.features.supports(LnFeatures.GOSSIP_QUERIES_REQ)):
            return True
        return False

    async def _forward_gossip(self):
        assert self.is_initialized()
        if not self._should_forward_gossip():
            return

        async def send_new_gossip_with_semaphore(gossip: List[GossipForwardingMessage]):
            async with self.network.lngossip.gossip_request_semaphore:
                sent = await self._send_gossip_messages(gossip)
            if sent > 0:
                self.logger.debug(f"forwarded {sent} gossip messages to {self.pubkey.hex()}")

        lngossip = self.network.lngossip
        last_gossip_batch_ts = 0
        while True:
            await asyncio.sleep(10)
            if not self.their_gossip_timestamp_filter:
                continue  # peer didn't request gossip

            new_gossip, last_lngossip_refresh_ts = await lngossip.get_forwarding_gossip()
            if not last_lngossip_refresh_ts > last_gossip_batch_ts:
                continue  # no new batch available
            last_gossip_batch_ts = last_lngossip_refresh_ts

            await self.taskgroup.spawn(send_new_gossip_with_semaphore(new_gossip))

    async def _handle_historical_gossip_request(self):
        """Called when a peer requests historical gossip with a gossip_timestamp_filter query."""
        filter = self.their_gossip_timestamp_filter
        if not self._should_forward_gossip() or not filter or filter.only_forwarding:
            return
        async with self.network.lngossip.gossip_request_semaphore:
            requested_gossip = self.lnworker.channel_db.get_gossip_in_timespan(filter)
            filter.only_forwarding = True
            sent = await self._send_gossip_messages(requested_gossip)
            if sent > 0:
                self._num_gossip_messages_forwarded += sent
                #self.logger.debug(f"forwarded {sent} historical gossip messages to {self.pubkey.hex()}")

    async def _send_gossip_messages(self, messages: List[GossipForwardingMessage]) -> int:
        amount_sent = 0
        for msg in messages:
            if self.their_gossip_timestamp_filter.in_range(msg.timestamp) \
                and self.pubkey != msg.sender_node_id:
                await self.transport.send_bytes_and_drain(msg.msg)
                amount_sent += 1
                if amount_sent % 250 == 0:
                    # this can be a lot of messages, completely blocking the event loop
                    await asyncio.sleep(self.DELAY_INC_MSG_PROCESSING_SLEEP)
        return amount_sent

    async def _query_gossip(self):
        assert self.is_initialized()
        if self.lnworker == self.lnworker.network.lngossip:
            if not self.their_features.supports(LnFeatures.GOSSIP_QUERIES_OPT):
                raise GracefulDisconnect("remote does not support gossip_queries, which we need")
            try:
                ids, complete = await util.wait_for2(self.get_channel_range(), LN_P2P_NETWORK_TIMEOUT)
            except asyncio.TimeoutError as e:
                raise GracefulDisconnect("query_channel_range timed out") from e
            self.logger.info('Received {} channel ids. (complete: {})'.format(len(ids), complete))
            await self.lnworker.add_new_ids(ids)
            self.request_gossip(int(time.time()))
            while True:
                todo = self.lnworker.get_ids_to_query()
                if not todo:
                    await asyncio.sleep(1)
                    continue
                await self.get_short_channel_ids(todo)

    @staticmethod
    def _is_valid_channel_range_query(payload: dict) -> bool:
        if payload.get('chain_hash') != constants.net.rev_genesis_bytes():
            return False
        if payload.get('first_blocknum', -1) < constants.net.BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS:
            return False
        if payload.get('number_of_blocks', 0) < 1:
            return False
        return True

    def _is_valid_short_channel_id_query(self, payload: dict) -> bool:
        if payload.get('chain_hash') != constants.net.rev_genesis_bytes():
            return False
        enc_short_ids = payload['encoded_short_ids']
        if enc_short_ids[0] != 0:
            self.logger.debug(f"got query_short_channel_ids with invalid encoding: {repr(enc_short_ids[0])}")
            return False
        if (len(enc_short_ids) - 1) % 8 != 0:
            self.logger.debug(f"got query_short_channel_ids with invalid length")
            return False
        return True

    async def _send_reply_channel_range(self, payload: dict):
        """https://github.com/lightning/bolts/blob/acd383145dd8c3fecd69ce94e4a789767b984ac0/07-routing-gossip.md#requirements-5"""
        first_blockheight: int = payload['first_blocknum']

        async with self.network.lngossip.gossip_request_semaphore:
            sorted_scids: List[ShortChannelID] = self.lnworker.channel_db.get_channels_in_range(
                first_blockheight,
                payload['number_of_blocks']
            )
            self.logger.debug(f"reply_channel_range to request "
                              f"first_height={first_blockheight}, "
                              f"num_blocks={payload['number_of_blocks']}, "
                              f"sending {len(sorted_scids)} scids")

            complete: bool = False
            while not complete:
                # create a 64800 byte chunk of skids, split the remaining scids
                encoded_scids, sorted_scids = b''.join(sorted_scids[:8100]), sorted_scids[8100:]
                complete = len(sorted_scids) == 0  # if there are no scids remaining we are done
                # number of blocks covered by the scids in this chunk
                if complete:
                    # LAST MESSAGE MUST have first_blocknum plus number_of_blocks equal or greater than
                    # the query_channel_range first_blocknum plus number_of_blocks.
                    number_of_blocks = ((payload['first_blocknum'] + payload['number_of_blocks'])
                                        - first_blockheight)
                else:
                    # we cover the range until the height of the first scid in the next chunk
                    number_of_blocks = sorted_scids[0].block_height - first_blockheight
                self.send_message('reply_channel_range',
                    chain_hash=constants.net.rev_genesis_bytes(),
                    first_blocknum=first_blockheight,
                    number_of_blocks=number_of_blocks,
                    sync_complete=complete,
                    len=1+len(encoded_scids),
                    encoded_short_ids=b'\x00' + encoded_scids)
                if not complete:
                    first_blockheight = sorted_scids[0].block_height
                    await asyncio.sleep(self.DELAY_INC_MSG_PROCESSING_SLEEP)
            self.outgoing_gossip_reply = False

    async def get_channel_range(self):
        self.reply_channel_range = asyncio.Queue()
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
        # ADDENDUM (01/2025): now it's 'MUST set sync_complete to false if this is not the final reply_channel_range.'
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
        self.reply_channel_range = None
        return ids, complete

    def request_gossip(self, timestamp=0):
        if timestamp == 0:
            self.logger.info('requesting whole channel graph')
        else:
            self.logger.info(f'requesting channel graph since {datetime.fromtimestamp(timestamp).isoformat()}')
        timestamp_range = 0xFFFFFFFF
        self.our_gossip_timestamp_filter = GossipTimestampFilter(
            first_timestamp=timestamp,
            timestamp_range=timestamp_range,
        )
        self.send_message(
            'gossip_timestamp_filter',
            chain_hash=constants.net.rev_genesis_bytes(),
            first_timestamp=timestamp,
            timestamp_range=timestamp_range,
        )

    def query_channel_range(self, first_block, num_blocks):
        self.logger.info(f'query channel range {first_block} {num_blocks}')
        self.send_message(
            'query_channel_range',
            chain_hash=constants.net.rev_genesis_bytes(),
            first_blocknum=first_block,
            number_of_blocks=num_blocks)

    @staticmethod
    def decode_short_ids(encoded):
        if len(encoded) < 1 or (len(encoded) - 1) % 8 != 0:
            raise Exception(f'decode_short_ids: invalid size: {len(encoded)=}')
        elif encoded[0] != 0:
            raise Exception(f'decode_short_ids: unexpected first byte: {encoded[0]}')
        decoded = encoded[1:]
        ids = [decoded[i:i+8] for i in range(0, len(decoded), 8)]
        return ids

    async def on_reply_channel_range(self, payload):
        first = payload['first_blocknum']
        num = payload['number_of_blocks']
        complete = bool(int.from_bytes(payload['sync_complete'], 'big'))
        encoded = payload['encoded_short_ids']
        ids = self.decode_short_ids(encoded)
        # self.logger.info(f"on_reply_channel_range. >>> first_block {first}, num_blocks {num}, "
        #                  f"num_ids {len(ids)}, complete {complete}")
        if self.reply_channel_range is None:
            raise Exception("received 'reply_channel_range' without corresponding 'query_channel_range'")
        while self.reply_channel_range.qsize() > 10:
            # we block process_message until the queue gets consumed
            self.logger.info("reply_channel_range queue is overflowing. sleeping...")
            await asyncio.sleep(0.1)
        self.reply_channel_range.put_nowait((first, num, complete, ids))

    async def _send_reply_short_channel_ids(self, payload: dict):
        async with self.network.lngossip.gossip_request_semaphore:
            requested_scids = payload['encoded_short_ids']
            decoded_scids = [ShortChannelID.normalize(scid)
                             for scid in self.decode_short_ids(requested_scids)]
            self.logger.debug(f"serving query_short_channel_ids request: "
                              f"requested {len(decoded_scids)} scids")
            chan_db = self.lnworker.channel_db
            response: Set[bytes] = set()
            for scid in decoded_scids:
                requested_msgs = chan_db.get_gossip_for_scid_request(scid)
                response.update(requested_msgs)
            self.logger.debug(f"found {len(response)} gossip messages to serve scid request")
            for index, msg in enumerate(response):
                await self.transport.send_bytes_and_drain(msg)
                if index % 250 == 0:
                    await asyncio.sleep(self.DELAY_INC_MSG_PROCESSING_SLEEP)
            self.send_message(
                'reply_short_channel_ids_end',
                chain_hash=constants.net.rev_genesis_bytes(),
                full_information=self.network.lngossip.is_synced()
            )
            self.outgoing_gossip_reply = False

    async def get_short_channel_ids(self, ids):
        #self.logger.info(f'Querying {len(ids)} short_channel_ids')
        assert not self.querying.is_set()
        self.query_short_channel_ids(ids)
        await self.querying.wait()
        self.querying.clear()

    def query_short_channel_ids(self, ids):
        # compression MUST NOT be used according to updated bolt
        # (https://github.com/lightning/bolts/pull/981)
        ids = sorted(ids)
        s = b''.join(ids)
        prefix = b'\x00'  # uncompressed
        self.send_message(
            'query_short_channel_ids',
            chain_hash=constants.net.rev_genesis_bytes(),
            len=1+len(s),
            encoded_short_ids=prefix+s)

    async def _message_loop(self):
        try:
            await util.wait_for2(self.initialize(), LN_P2P_NETWORK_TIMEOUT)
        except (OSError, asyncio.TimeoutError, HandshakeFailed) as e:
            raise GracefulDisconnect(f'initialize failed: {repr(e)}') from e
        async for msg in self.transport.read_messages():
            await self._process_message(msg)
            if self.DELAY_INC_MSG_PROCESSING_SLEEP:
                # rate-limit message-processing a bit, to make it harder
                # for a single peer to bog down the event loop / cpu:
                await asyncio.sleep(self.DELAY_INC_MSG_PROCESSING_SLEEP)
            # If receiving too much gossip from this peer, we need to slow them down.
            # note: if the gossip queue gets full, we will disconnect from them
            #       and throw away unprocessed gossip.
            if self.recv_gossip_queue.qsize() > self.RECV_GOSSIP_QUEUE_SOFT_MAXSIZE:
                sleep = self.recv_gossip_queue.qsize() / 1000
                self.logger.debug(
                    f"message_loop sleeping due to getting much gossip. qsize={self.recv_gossip_queue.qsize()}. "
                    f"waiting for existing gossip data to be processed first.")
                await asyncio.sleep(sleep)

    def on_reply_short_channel_ids_end(self, payload):
        self.querying.set()

    def close_and_cleanup(self):
        # note: This method might get called multiple times!
        #       E.g. if you call close_and_cleanup() to cause a disconnection from the peer,
        #       it will get called a second time in handle_disconnect().
        self.unregister_callbacks()
        try:
            if self.transport:
                self.transport.close()
        except Exception:
            pass
        self.lnworker.lnpeermgr.peer_closed(self)
        self.got_disconnected.set()

    def is_shutdown_anysegwit(self):
        return self.features.supports(LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_OPT)

    def accepts_zeroconf(self):
        return self.features.supports(LnFeatures.OPTION_ZEROCONF_OPT)

    def is_upfront_shutdown_script(self):
        return self.features.supports(LnFeatures.OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT)

    def use_anchors(self) -> bool:
        return self.features.supports(LnFeatures.OPTION_ANCHORS_ZERO_FEE_HTLC_OPT)

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
            public: bool,
            zeroconf: bool = False,
            temp_channel_id: bytes,
            opening_fee: int = None,
    ) -> Tuple[Channel, 'PartialTransaction']:
        """Implements the channel opening flow.

        -> open_channel message
        <- accept_channel message
        -> funding_created message
        <- funding_signed message

        Channel configurations are initialized in this method.
        """

        if public and not self.lnworker.config.EXPERIMENTAL_LN_FORWARD_PAYMENTS:
            raise Exception('Cannot create public channels')

        if not self.lnworker.wallet.can_have_lightning():
            # old wallet that cannot have lightning anymore
            raise Exception('This wallet cannot create new channels')

        # will raise if init fails
        await util.wait_for2(self.initialized, LN_P2P_NETWORK_TIMEOUT)
        # trampoline is not yet in features
        if self.lnworker.uses_trampoline() and not self.lnworker.is_trampoline_peer(self.pubkey):
            raise Exception('Not a trampoline node: ' + str(self.their_features))

        channel_flags = CF_ANNOUNCE_CHANNEL if public else 0
        feerate: Optional[int] = self.lnworker.current_target_feerate_per_kw(
            has_anchors=self.use_anchors()
        )
        if feerate is None:
            raise NoDynamicFeeEstimates()
        # we set a channel type for internal bookkeeping
        open_channel_tlvs = {}
        assert self.their_features.supports(LnFeatures.OPTION_STATIC_REMOTEKEY_OPT)
        our_channel_type = ChannelType(ChannelType.OPTION_STATIC_REMOTEKEY)
        if self.use_anchors():
            our_channel_type |= ChannelType(ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX)
        if zeroconf:
            our_channel_type |= ChannelType(ChannelType.OPTION_ZEROCONF)
        # We do not set the option_scid_alias bit in channel_type because LND rejects it.
        # Eclair accepts channel_type with that bit, but does not require it.

        # if option_channel_type is negotiated: MUST set channel_type
        # if it includes channel_type: MUST set it to a defined type representing the type it wants.
        open_channel_tlvs['channel_type'] = {
            'type': our_channel_type.to_bytes_minimal()
        }

        if our_channel_type & ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX:
            multisig_funding_keypair = lnutil.derive_multisig_funding_key_if_we_opened(
                funding_root_secret=self.lnworker.funding_root_keypair.privkey,
                remote_node_id_or_prefix=self.pubkey,
                nlocktime=funding_tx.locktime,
            )
        else:
            multisig_funding_keypair = None
        local_config = self.lnworker.make_local_config_for_new_channel(
            funding_sat=funding_sat,
            push_msat=push_msat,
            initiator=LOCAL,
            channel_type=our_channel_type,
            multisig_funding_keypair=multisig_funding_keypair,
            peer_features=self.features,
        )
        # if it includes open_channel_tlvs: MUST include upfront_shutdown_script.
        open_channel_tlvs['upfront_shutdown_script'] = {
            'shutdown_scriptpubkey': local_config.upfront_shutdown_script
        }
        if opening_fee:
            # todo: maybe add payment hash
            open_channel_tlvs['channel_opening_fee'] = {
                'channel_opening_fee': opening_fee
            }
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(
            local_config.per_commitment_secret_seed,
            RevocationStore.START_INDEX
        )
        per_commitment_point_first = secret_to_pubkey(
            int.from_bytes(per_commitment_secret_first, 'big'))

        # store the temp id now, so that it is recognized for e.g. 'error' messages
        self.temp_id_to_id[temp_channel_id] = None
        self._cleanup_temp_channelids()
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
            channel_flags=channel_flags,
            channel_reserve_satoshis=local_config.reserve_sat,
            htlc_minimum_msat=local_config.htlc_minimum_msat,
            open_channel_tlvs=open_channel_tlvs,
        )

        # <- accept_channel
        payload = await self.wait_for_message('accept_channel', temp_channel_id)
        self.logger.debug(f"received accept_channel for temp_channel_id={temp_channel_id.hex()}. {payload=}")
        remote_per_commitment_point = payload['first_per_commitment_point']
        funding_txn_minimum_depth = payload['minimum_depth']
        if not zeroconf and funding_txn_minimum_depth <= 0:
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
            announcement_node_sig=b'',
            announcement_bitcoin_sig=b'',
        )
        ChannelConfig.cross_validate_params(
            local_config=local_config,
            remote_config=remote_config,
            funding_sat=funding_sat,
            is_local_initiator=True,
            initial_feerate_per_kw=feerate,
            config=self.network.config,
            peer_features=self.features,
            channel_type=our_channel_type,
        )

        # -> funding created
        # replace dummy output in funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = PartialTxOutput.from_address_and_value(funding_address, funding_sat)
        funding_tx.replace_output_address(DummyAddress.CHANNEL, funding_address)
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
            flags=channel_flags,
            capacity=funding_sat,
            is_initiator=True,
            funding_txn_minimum_depth=funding_txn_minimum_depth
        )
        storage = self.create_channel_storage(
            channel_id, outpoint, local_config, remote_config, constraints, our_channel_type)
        chan = Channel(
            storage,
            lnworker=self.lnworker,
            initial_feerate=feerate
        )
        chan.storage['funding_inputs'] = [txin.prevout.to_json() for txin in funding_tx.inputs()]
        chan.storage['has_onchain_backup'] = has_onchain_backup
        chan.storage['init_height'] = self.lnworker.network.get_local_height()
        chan.storage['init_timestamp'] = int(time.time())
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
            self.send_warning(channel_id, message=str(e), close_connection=True)
        chan.open_with_first_pcp(remote_per_commitment_point, remote_sig)
        chan.set_state(ChannelState.OPENING)
        if zeroconf:
            chan.set_state(ChannelState.FUNDED)
            self.send_channel_ready(chan)
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
            "unfulfilled_htlcs": {},
            "revocation_store": {},
            "channel_type": channel_type,
        }
        return StoredDict(chan_dict, self.lnworker.db)

    @non_blocking_msg_handler
    async def on_open_channel(self, payload):
        """Implements the channel acceptance flow.

        <- open_channel message
        -> accept_channel message
        <- funding_created message
        -> funding_signed message

        Channel configurations are initialized in this method.
        """

        # <- open_channel
        if payload['chain_hash'] != constants.net.rev_genesis_bytes():
            raise Exception('wrong chain_hash')

        open_channel_tlvs = payload.get('open_channel_tlvs')
        channel_type = open_channel_tlvs.get('channel_type') if open_channel_tlvs else None
        # The receiving node MAY fail the channel if:
        # option_channel_type was negotiated but the message doesn't include a channel_type
        if channel_type is None:
            raise Exception("sender has advertised option_channel_type, but hasn't sent the channel type")
        # MUST fail the channel if it supports channel_type,
        # channel_type was set, and the type is not suitable.
        else:
            channel_type = ChannelType.from_bytes(channel_type['type'], byteorder='big').discard_unknown_and_check()
            if not channel_type.complies_with_features(self.features):
                raise Exception("sender has sent a channel type we don't support")
        assert isinstance(channel_type, ChannelType)

        is_zeroconf = bool(channel_type & ChannelType.OPTION_ZEROCONF)
        if is_zeroconf and not self.network.config.ZEROCONF_TRUSTED_NODE.startswith(self.pubkey.hex()):
            raise Exception(f"not accepting zeroconf from node {self.pubkey}")

        if self.lnworker.has_recoverable_channels() and not is_zeroconf:
            # FIXME: we might want to keep the connection open
            raise Exception('not accepting channels')

        if not self.lnworker.wallet.can_have_lightning():
            # old wallet that cannot have lightning anymore
            raise Exception('This wallet does not accept new channels')

        funding_sat = payload['funding_satoshis']
        push_msat = payload['push_msat']
        feerate = payload['feerate_per_kw']  # note: we are not validating this
        temp_chan_id = payload['temporary_channel_id']
        # store the temp id now, so that it is recognized for e.g. 'error' messages
        self.temp_id_to_id[temp_chan_id] = None
        self._cleanup_temp_channelids()
        channel_opening_fee_tlv = open_channel_tlvs.get('channel_opening_fee', {})
        channel_opening_fee = channel_opening_fee_tlv.get('channel_opening_fee')
        if channel_opening_fee:
            # todo check that the fee is reasonable
            assert is_zeroconf
            self.logger.info(f"just-in-time opening fee: {channel_opening_fee} msat")
            pass

        if channel_type & ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX:
            multisig_funding_keypair = lnutil.derive_multisig_funding_key_if_they_opened(
                funding_root_secret=self.lnworker.funding_root_keypair.privkey,
                remote_node_id_or_prefix=self.pubkey,
                remote_funding_pubkey=payload['funding_pubkey'],
            )
        else:
            multisig_funding_keypair = None
        local_config = self.lnworker.make_local_config_for_new_channel(
            funding_sat=funding_sat,
            push_msat=push_msat,
            initiator=REMOTE,
            channel_type=channel_type,
            multisig_funding_keypair=multisig_funding_keypair,
            peer_features=self.features,
        )

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
            announcement_node_sig=b'',
            announcement_bitcoin_sig=b'',
        )
        ChannelConfig.cross_validate_params(
            local_config=local_config,
            remote_config=remote_config,
            funding_sat=funding_sat,
            is_local_initiator=False,
            initial_feerate_per_kw=feerate,
            config=self.network.config,
            peer_features=self.features,
            channel_type=channel_type,
        )

        channel_flags = ord(payload['channel_flags'])

        # -> accept channel
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(
            local_config.per_commitment_secret_seed,
            RevocationStore.START_INDEX
        )
        per_commitment_point_first = secret_to_pubkey(
            int.from_bytes(per_commitment_secret_first, 'big'))

        min_depth = 0 if is_zeroconf else 3

        accept_channel_tlvs = {
            'upfront_shutdown_script': {
                'shutdown_scriptpubkey': local_config.upfront_shutdown_script
            },
            'channel_type': {
                'type': channel_type.to_bytes_minimal(),
            },
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
        funding_txid = funding_created['funding_txid'][::-1].hex()
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_idx)
        constraints = ChannelConstraints(
            flags=channel_flags,
            capacity=funding_sat,
            is_initiator=False,
            funding_txn_minimum_depth=min_depth,
        )
        outpoint = Outpoint(funding_txid, funding_idx)
        chan_dict = self.create_channel_storage(
            channel_id, outpoint, local_config, remote_config, constraints, channel_type)
        chan = Channel(
            chan_dict,
            lnworker=self.lnworker,
            initial_feerate=feerate,
            jit_opening_fee = channel_opening_fee,
        )
        chan.storage['init_height'] = self.lnworker.network.get_local_height()
        chan.storage['init_timestamp'] = int(time.time())
        if isinstance(self.transport, LNTransport):
            chan.add_or_update_peer_addr(self.transport.peer_addr)
        remote_sig = funding_created['signature']
        try:
            chan.receive_new_commitment(remote_sig, [])
        except LNProtocolWarning as e:
            self.send_warning(channel_id, message=str(e), close_connection=True)
        sig_64, _ = chan.sign_next_commitment()
        self.send_message('funding_signed',
            channel_id=channel_id,
            signature=sig_64,
        )
        self.temp_id_to_id[temp_chan_id] = channel_id
        self.funding_signed_sent.add(chan.channel_id)
        chan.open_with_first_pcp(payload['first_per_commitment_point'], remote_sig)
        chan.set_state(ChannelState.OPENING)
        if is_zeroconf:
            chan.set_state(ChannelState.FUNDED)
            self.send_channel_ready(chan)
        self.lnworker.add_new_channel(chan)

    def _cleanup_temp_channelids(self) -> None:
        self.temp_id_to_id = {
            tmp_id: chan_id for (tmp_id, chan_id) in self.temp_id_to_id.items()
            if chan_id not in self.channels
        }
        if len(self.temp_id_to_id) > 25:
            # which one of us is opening all these chans?! let's disconnect
            raise Exception("temp_id_to_id is getting too large.")

    async def request_force_close(self, channel_id: bytes):
        """Try to trigger the remote peer to force-close."""
        await self.initialized
        self.logger.info(f"trying to get remote peer to force-close chan {channel_id.hex()}")
        # First, we intentionally send a "channel_reestablish" msg with an old state.
        # Many nodes (but not all) automatically force-close when seeing this.
        latest_point = secret_to_pubkey(42) # we need a valid point (BOLT2)
        self.send_message(
            "channel_reestablish",
            channel_id=channel_id,
            next_commitment_number=0,
            next_revocation_number=0,
            your_last_per_commitment_secret=0,
            my_current_per_commitment_point=latest_point)
        # Newish nodes that have lightning/bolts/pull/950 force-close upon receiving an "error" msg,
        # so send that too. E.g. old "channel_reestablish" is not enough for eclair 0.7+,
        # but "error" is. see https://github.com/ACINQ/eclair/pull/2036
        # The receiving node:
        #   - upon receiving `error`:
        #     - MUST fail the channel referred to by `channel_id`, if that channel is with the sending node.
        self.send_message("error", channel_id=channel_id, data=b"", len=0)

    def schedule_force_closing(self, channel_id: bytes):
        """ wrapper of lnworker's method, that raises if channel is not with this peer """
        channels_with_peer = list(self.channels.keys())
        channels_with_peer.extend(self.temp_id_to_id.values())
        if channel_id not in channels_with_peer:
            raise ValueError(f"channel {channel_id.hex()} does not belong to this peer")
        chan = self.get_channel_by_id(channel_id)
        if not chan:
            self.logger.warning(f"tried to force-close channel {channel_id.hex()} but it is not in self.channels yet")
        if ChanCloseOption.LOCAL_FCLOSE in chan.get_close_options():
            self.lnworker.schedule_force_closing(channel_id)
        else:
            self.logger.info(f"tried to force-close channel {chan.get_id_for_log()} "
                             f"but close option is not allowed. {chan.get_state()=!r}")

    async def on_channel_reestablish(self, chan: Channel, msg):
        # Note: it is critical for this message handler to block processing of further messages,
        #       until this msg is processed. If we are behind (lost state), and send chan_reest to the remote,
        #       when the remote realizes we are behind, they might send an "error" message - but the spec mandates
        #       they send chan_reest first. If we processed the error first, we might force-close and lose money!
        their_next_local_ctn = msg["next_commitment_number"]
        their_oldest_unrevoked_remote_ctn = msg["next_revocation_number"]
        their_local_pcp = msg.get("my_current_per_commitment_point")
        their_claim_of_our_last_per_commitment_secret = msg.get("your_last_per_commitment_secret")
        self.logger.info(
            f'channel_reestablish ({chan.get_id_for_log()}): received channel_reestablish with '
            f'(their_next_local_ctn={their_next_local_ctn}, '
            f'their_oldest_unrevoked_remote_ctn={their_oldest_unrevoked_remote_ctn})')
        if chan.get_state() >= ChannelState.CLOSED:
            self.logger.warning(
                f"on_channel_reestablish. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
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
                    f"(DLP) local PCS mismatch: {our_pcs.hex()} != {their_claim_of_our_last_per_commitment_secret.hex()}")
                return False
            assert chan.is_static_remotekey_enabled()
            return True
        if not are_datalossprotect_fields_valid():
            raise RemoteMisbehaving("channel_reestablish: data loss protect fields invalid")
        fut = self.channel_reestablish_msg[chan.channel_id]
        if they_are_ahead:
            self.logger.warning(
                f"channel_reestablish ({chan.get_id_for_log()}): "
                f"remote is ahead of us! They should force-close. Remote PCP: {their_local_pcp.hex()}")
            # data_loss_protect_remote_pcp is used in lnsweep
            chan.set_data_loss_protect_remote_pcp(their_next_local_ctn - 1, their_local_pcp)
            chan.set_state(ChannelState.WE_ARE_TOXIC)
            self.lnworker.save_channel(chan)
            chan.peer_state = PeerState.BAD
            # raise after we send channel_reestablish, so the remote can realize they are ahead
            # FIXME what if we have multiple chans with peer? timing...
            fut.set_exception(GracefulDisconnect("remote ahead of us"))
        elif we_are_ahead:
            self.logger.warning(f"channel_reestablish ({chan.get_id_for_log()}): we are ahead of remote! trying to force-close.")
            self.schedule_force_closing(chan.channel_id)
            # FIXME what if we have multiple chans with peer? timing...
            fut.set_exception(GracefulDisconnect("we are ahead of remote"))
        else:
            # all good
            fut.set_result((we_must_resend_revoke_and_ack, their_next_local_ctn))
            # Block processing of further incoming messages until we finished our part of chan-reest.
            # This is needed for the replaying of our local unacked updates to be sane (if the peer
            # also replays some messages we must not react to them until we finished replaying our own).
            # (it would be sufficient to only block messages related to this channel, but this is easier)
            await self._chan_reest_finished[chan.channel_id].wait()
            # Note: if the above event is never set, we won't detect if the connection was closed by remote...

    def _send_channel_reestablish(self, chan: Channel):
        assert self.is_initialized()
        chan_id = chan.channel_id
        # ctns
        next_local_ctn = chan.get_next_ctn(LOCAL)
        oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
        # send message
        assert chan.is_static_remotekey_enabled()
        latest_secret, latest_point = chan.get_secret_and_point(LOCAL, 0)
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

    async def reestablish_channel(self, chan: Channel):
        await self.initialized
        chan_id = chan.channel_id
        if chan.should_request_force_close:
            if chan.get_state() != ChannelState.WE_ARE_TOXIC:
                chan.set_state(ChannelState.REQUESTED_FCLOSE)
            await self.request_force_close(chan_id)
            chan.should_request_force_close = False
            return
        if chan.get_state() == ChannelState.WE_ARE_TOXIC:
            # Depending on timing, the remote might not know we are behind.
            # We should let them know, so that they force-close.
            # We do "request force-close" with ctn=0, instead of leaking our actual ctns,
            # to decrease the remote's confidence of actual data loss on our part.
            await self.request_force_close(chan_id)
            return
        if chan.get_state() == ChannelState.FORCE_CLOSING:
            # We likely got here because we found out that we are ahead (i.e. remote lost state).
            # Depending on timing, the remote might not know they are behind.
            # We should let them know:
            self._send_channel_reestablish(chan)
            return
        if self.network.blockchain().is_tip_stale() \
                or not self.lnworker.wallet.is_up_to_date() \
                or self.lnworker.current_target_feerate_per_kw(has_anchors=chan.has_anchors()) \
            is None:
            # don't try to reestablish until we can do fee estimation and are up-to-date
            return
        # if we get here, we will try to do a proper reestablish
        if not (ChannelState.PREOPENING < chan.get_state() < ChannelState.FORCE_CLOSING):
            raise Exception(f"unexpected {chan.get_state()=} for reestablish")
        if chan.peer_state != PeerState.DISCONNECTED:
            self.logger.info(
                f'reestablish_channel was called but channel {chan.get_id_for_log()} '
                f'already in peer_state {chan.peer_state!r}')
            return
        chan.peer_state = PeerState.REESTABLISHING
        util.trigger_callback('channel', self.lnworker.wallet, chan)
        # ctns
        oldest_unrevoked_local_ctn = chan.get_oldest_unrevoked_ctn(LOCAL)
        next_local_ctn = chan.get_next_ctn(LOCAL)
        oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
        # BOLT-02: "A node [...] upon disconnection [...] MUST reverse any uncommitted updates sent by the other side"
        chan.hm.discard_unsigned_remote_updates()
        # send message
        self._send_channel_reestablish(chan)
        # wait until we receive their channel_reestablish
        fut = self.channel_reestablish_msg[chan_id]
        await fut
        we_must_resend_revoke_and_ack, their_next_local_ctn = fut.result()

        def replay_updates_and_commitsig():
            # Replay un-acked local updates (including commitment_signed) byte-for-byte.
            # If we have sent them a commitment signature that they "lost" (due to disconnect),
            # we need to make sure we replay the same local updates, as otherwise they could
            # end up with two (or more) signed valid commitment transactions at the same ctn.
            # Multiple valid ctxs at the same ctn is a major headache for pre-signing spending txns,
            # e.g. for watchtowers, hence we must ensure these ctxs coincide.
            # We replay the local updates even if they were not yet committed.
            unacked = chan.hm.get_unacked_local_updates()
            replayed_msgs = []
            for ctn, messages in unacked.items():
                if ctn < their_next_local_ctn:
                    # They claim to have received these messages and the corresponding
                    # commitment_signed, hence we must not replay them.
                    continue
                for raw_upd_msg in messages:
                    self.transport.send_bytes(raw_upd_msg)
                    replayed_msgs.append(raw_upd_msg)
            self.logger.info(f'channel_reestablish ({chan.get_id_for_log()}): replayed {len(replayed_msgs)} unacked messages. '
                             f'{[decode_msg(raw_upd_msg)[0] for raw_upd_msg in replayed_msgs]}')

        def resend_revoke_and_ack():
            last_secret, last_point = chan.get_secret_and_point(LOCAL, oldest_unrevoked_local_ctn - 1)
            next_secret, next_point = chan.get_secret_and_point(LOCAL, oldest_unrevoked_local_ctn + 1)
            self.send_message(
                "revoke_and_ack",
                channel_id=chan.channel_id,
                per_commitment_secret=last_secret,
                next_per_commitment_point=next_point)

        # We need to preserve relative order of last revack and commitsig.
        # note: it is not possible to recover and reestablish a channel if we are out-of-sync by
        # more than one ctns, i.e. we will only ever retransmit up to one commitment_signed message.
        # Hence, if we need to retransmit a revack, without loss of generality, we can either replay
        # it as the first message or as the last message.
        was_revoke_last = chan.hm.was_revoke_last()
        if we_must_resend_revoke_and_ack and not was_revoke_last:
            self.logger.info(f'channel_reestablish ({chan.get_id_for_log()}): replaying a revoke_and_ack first.')
            resend_revoke_and_ack()
        replay_updates_and_commitsig()
        if we_must_resend_revoke_and_ack and was_revoke_last:
            self.logger.info(f'channel_reestablish ({chan.get_id_for_log()}): replaying a revoke_and_ack last.')
            resend_revoke_and_ack()

        chan.peer_state = PeerState.GOOD
        self._chan_reest_finished[chan.channel_id].set()
        if chan.is_funded():
            chan_just_became_ready = (their_next_local_ctn == next_local_ctn == 1)
            if chan_just_became_ready or self.features.supports(LnFeatures.OPTION_SCID_ALIAS_OPT):
                self.send_channel_ready(chan)

        self.maybe_send_announcement_signatures(chan)
        self.maybe_update_fee(chan)  # if needed, update fee ASAP, to avoid force-closures from this
        # checks done
        util.trigger_callback('channel', self.lnworker.wallet, chan)
        # if we have sent a previous shutdown, it must be retransmitted (Bolt2)
        if chan.get_state() == ChannelState.SHUTDOWN:
            await self.taskgroup.spawn(self.send_shutdown(chan))

    def send_channel_ready(self, chan: Channel):
        assert chan.is_funded()
        if chan.sent_channel_ready:
            return
        channel_id = chan.channel_id
        per_commitment_secret_index = RevocationStore.START_INDEX - 1
        second_per_commitment_point = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.config[LOCAL].per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        channel_ready_tlvs = {}
        if self.features.supports(LnFeatures.OPTION_SCID_ALIAS_OPT):
            # LND requires that we send an alias if the option has been negotiated in INIT.
            # otherwise, the channel will not be marked as active.
            # This does not apply if the channel was previously marked active without an alias.
            channel_ready_tlvs['short_channel_id'] = {'alias': chan.get_local_scid_alias(create_new_if_needed=True)}
        # note: if 'channel_ready' was not yet received, we might send it multiple times
        self.send_message(
            "channel_ready",
            channel_id=channel_id,
            second_per_commitment_point=second_per_commitment_point,
            channel_ready_tlvs=channel_ready_tlvs)
        chan.sent_channel_ready = True
        self.maybe_mark_open(chan)

    def on_channel_ready(self, chan: Channel, payload):
        self.logger.info(f"on_channel_ready. channel: {chan.channel_id.hex()}")
        if chan.peer_state != PeerState.GOOD:  # should never happen
            raise Exception(f"received channel_ready in unexpected {chan.peer_state=!r}")
        if chan.is_closed():
            self.logger.warning(
                f"on_channel_ready. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        # save remote alias for use in invoices
        scid_alias = payload.get('channel_ready_tlvs', {}).get('short_channel_id', {}).get('alias')
        if scid_alias:
            chan.save_remote_scid_alias(scid_alias)
        if not chan.config[LOCAL].funding_locked_received:
            their_next_point = payload["second_per_commitment_point"]
            chan.config[REMOTE].next_per_commitment_point = their_next_point
            chan.config[LOCAL].funding_locked_received = True
            self.lnworker.save_channel(chan)
        self.maybe_mark_open(chan)

    def send_node_announcement(self, alias:str, color_hex:str):
        from .channel_db import NodeInfo
        timestamp = int(time.time())
        node_id = privkey_to_pubkey(self.privkey)
        features = self.features.for_node_announcement()
        flen = features.min_len()
        rgb_color = bytes.fromhex(color_hex)
        alias = bytes(alias, 'utf8')
        alias += bytes(32 - len(alias))
        if self.lnworker.config.LIGHTNING_LISTEN is not None:
            addr = self.lnworker.config.LIGHTNING_LISTEN
            try:
                hostname, port = addr.split(':')
                if port is None:  # use default port if not specified
                    port = 9735
                addresses = NodeInfo.to_addresses_field(hostname, int(port))
            except Exception:
                self.logger.exception(f"Invalid lightning_listen address: {addr}")
                return
        else:
            addresses = b''
        raw_msg = encode_msg(
            "node_announcement",
            flen=flen,
            features=features,
            timestamp=timestamp,
            rgb_color=rgb_color,
            node_id=node_id,
            alias=alias,
            addrlen=len(addresses),
            addresses=addresses)
        h = sha256d(raw_msg[64+2:])
        signature = ecc.ECPrivkey(self.privkey).ecdsa_sign(h, sigencode=ecdsa_sig64_from_r_and_s)
        message_type, payload = decode_msg(raw_msg)
        payload['signature'] = signature
        raw_msg = encode_msg(message_type, **payload)
        self.transport.send_bytes(raw_msg)

    def maybe_send_channel_announcement(self, chan: Channel):
        node_sigs = [chan.config[REMOTE].announcement_node_sig, chan.config[LOCAL].announcement_node_sig]
        bitcoin_sigs = [chan.config[REMOTE].announcement_bitcoin_sig, chan.config[LOCAL].announcement_bitcoin_sig]
        if not bitcoin_sigs[0] or not bitcoin_sigs[1]:
            return
        raw_msg, is_reverse = chan.construct_channel_announcement_without_sigs()
        if is_reverse:
            node_sigs.reverse()
            bitcoin_sigs.reverse()
        message_type, payload = decode_msg(raw_msg)
        payload['node_signature_1'] = node_sigs[0]
        payload['node_signature_2'] = node_sigs[1]
        payload['bitcoin_signature_1'] = bitcoin_sigs[0]
        payload['bitcoin_signature_2'] = bitcoin_sigs[1]
        raw_msg = encode_msg(message_type, **payload)
        self.transport.send_bytes(raw_msg)

    def maybe_mark_open(self, chan: Channel):
        if not chan.sent_channel_ready:
            return
        if not chan.config[LOCAL].funding_locked_received:
            return
        self.mark_open(chan)

    def mark_open(self, chan: Channel):
        assert chan.is_funded()
        # only allow state transition from "FUNDED" to "OPEN"
        old_state = chan.get_state()
        if old_state == ChannelState.OPEN:
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
        forwarding_enabled = self.network.config.EXPERIMENTAL_LN_FORWARD_PAYMENTS
        if forwarding_enabled and chan.short_channel_id:
            # send channel_update of outgoing edge to peer,
            # so that channel can be used to receive payments
            self.logger.info(f"sending channel update for outgoing edge ({chan.get_id_for_log()})")
            chan_upd = chan.get_outgoing_gossip_channel_update()
            self.transport.send_bytes(chan_upd)

    def maybe_send_announcement_signatures(self, chan: Channel, is_reply=False):
        if not chan.is_public():
            return
        if chan.sent_announcement_signatures:
            return
        if not is_reply and chan.config[REMOTE].announcement_node_sig:
            return
        h = chan.get_channel_announcement_hash()
        bitcoin_signature = ecc.ECPrivkey(chan.config[LOCAL].multisig_key.privkey).ecdsa_sign(h, sigencode=ecdsa_sig64_from_r_and_s)
        node_signature = ecc.ECPrivkey(self.privkey).ecdsa_sign(h, sigencode=ecdsa_sig64_from_r_and_s)
        self.send_message(
            "announcement_signatures",
            channel_id=chan.channel_id,
            short_channel_id=chan.short_channel_id,
            node_signature=node_signature,
            bitcoin_signature=bitcoin_signature
        )
        chan.config[LOCAL].announcement_node_sig = node_signature
        chan.config[LOCAL].announcement_bitcoin_sig = bitcoin_signature
        self.lnworker.save_channel(chan)
        chan.sent_announcement_signatures = True

    def on_update_fail_htlc(self, chan: Channel, payload):
        htlc_id = payload["id"]
        reason = payload["reason"]
        self.logger.info(f"on_update_fail_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_update_fail_htlc. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {htlc_id=}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        chan.receive_fail_htlc(htlc_id, error_bytes=reason)  # TODO handle exc and maybe fail channel (e.g. bad htlc_id)
        self.maybe_send_commitment(chan)

    def maybe_send_commitment(self, chan: Channel) -> bool:
        assert util.get_running_loop() == util.get_asyncio_loop(), f"this must be run on the asyncio thread!"
        if not chan.can_update_ctx(proposer=LOCAL):
            return False
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

    def send_htlc(
        self,
        *,
        chan: Channel,
        payment_hash: bytes,
        amount_msat: int,
        cltv_abs: int,
        onion: OnionPacket,
        session_key: Optional[bytes] = None,
    ) -> UpdateAddHtlc:
        assert chan.can_send_update_add_htlc(), f"cannot send updates: {chan.short_channel_id}"
        htlc = UpdateAddHtlc(amount_msat=amount_msat, payment_hash=payment_hash, cltv_abs=cltv_abs, timestamp=int(time.time()))
        htlc = chan.add_htlc(htlc)
        if session_key:
            chan.set_onion_key(htlc.htlc_id, session_key) # should it be the outer onion secret?
        self.logger.info(f"starting payment. htlc: {htlc}")
        self.send_message(
            "update_add_htlc",
            channel_id=chan.channel_id,
            id=htlc.htlc_id,
            cltv_expiry=htlc.cltv_abs,
            amount_msat=htlc.amount_msat,
            payment_hash=htlc.payment_hash,
            onion_routing_packet=onion.to_bytes())
        self.maybe_send_commitment(chan)
        return htlc

    def pay(self, *,
            route: 'LNPaymentRoute',
            chan: Channel,
            amount_msat: int,
            total_msat: int,
            payment_hash: bytes,
            min_final_cltv_delta: int,
            payment_secret: bytes,
            trampoline_onion: Optional[OnionPacket] = None,
        ) -> UpdateAddHtlc:

        assert amount_msat > 0, "amount_msat is not greater zero"
        assert len(route) > 0
        if not chan.can_send_update_add_htlc():
            raise PaymentFailure("Channel cannot send update_add_htlc")
        onion, amount_msat, cltv_abs, session_key = self.lnworker.create_onion_for_route(
            route=route,
            amount_msat=amount_msat,
            total_msat=total_msat,
            payment_hash=payment_hash,
            min_final_cltv_delta=min_final_cltv_delta,
            payment_secret=payment_secret,
            trampoline_onion=trampoline_onion
        )
        htlc = self.send_htlc(
            chan=chan,
            payment_hash=payment_hash,
            amount_msat=amount_msat,
            cltv_abs=cltv_abs,
            onion=onion,
            session_key=session_key,
        )
        return htlc

    def send_revoke_and_ack(self, chan: Channel) -> None:
        if not chan.can_update_ctx(proposer=LOCAL):
            return
        self.logger.info(f'send_revoke_and_ack. chan {chan.short_channel_id}. ctn: {chan.get_oldest_unrevoked_ctn(LOCAL)}')
        rev = chan.revoke_current_commitment()
        self.lnworker.save_channel(chan)
        self.send_message("revoke_and_ack",
            channel_id=chan.channel_id,
            per_commitment_secret=rev.per_commitment_secret,
            next_per_commitment_point=rev.next_per_commitment_point)
        self.maybe_send_commitment(chan)

    def on_commitment_signed(self, chan: Channel, payload) -> None:
        self.logger.info(f'on_commitment_signed. chan {chan.short_channel_id}. ctn: {chan.get_next_ctn(LOCAL)}.')
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_commitment_signed. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
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
        self.received_commitsig_event.set()
        self.received_commitsig_event.clear()

    def on_update_fulfill_htlc(self, chan: Channel, payload):
        preimage = payload["payment_preimage"]
        payment_hash = sha256(preimage)
        htlc_id = payload["id"]
        self.logger.info(f"on_update_fulfill_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}")
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_update_fulfill_htlc. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {htlc_id=}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        chan.receive_htlc_settle(preimage, htlc_id)  # TODO handle exc and maybe fail channel (e.g. bad htlc_id)
        self.lnworker.save_preimage(payment_hash, preimage)
        self.maybe_send_commitment(chan)

    def on_update_fail_malformed_htlc(self, chan: Channel, payload):
        htlc_id = payload["id"]
        failure_code = payload["failure_code"]
        self.logger.info(f"on_update_fail_malformed_htlc. chan {chan.get_id_for_log()}. "
                         f"htlc_id {htlc_id}. failure_code={failure_code}")
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_update_fail_malformed_htlc. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {htlc_id=}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        if failure_code & OnionFailureCodeMetaFlag.BADONION == 0:
            self.schedule_force_closing(chan.channel_id)
            raise RemoteMisbehaving(f"received update_fail_malformed_htlc with unexpected failure code: {failure_code}")
        reason = OnionRoutingFailure(code=failure_code, data=payload["sha256_of_onion"])
        chan.receive_fail_htlc(htlc_id, error_bytes=None, reason=reason)
        self.maybe_send_commitment(chan)

    def on_update_add_htlc(self, chan: Channel, payload):
        payment_hash = payload["payment_hash"]
        htlc_id = payload["id"]
        cltv_abs = payload["cltv_expiry"]
        amount_msat_htlc = payload["amount_msat"]
        onion_packet = payload["onion_routing_packet"]
        htlc = UpdateAddHtlc(
            amount_msat=amount_msat_htlc,
            payment_hash=payment_hash,
            cltv_abs=cltv_abs,
            timestamp=int(time.time()),
            htlc_id=htlc_id)
        self.logger.info(f"on_update_add_htlc. chan {chan.short_channel_id}. htlc={str(htlc)}")
        if chan.get_state() != ChannelState.OPEN:
            raise RemoteMisbehaving(f"received update_add_htlc while chan.get_state() != OPEN. state was {chan.get_state()!r}")
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_update_add_htlc. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {htlc_id=}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        if cltv_abs > bitcoin.NLOCKTIME_BLOCKHEIGHT_MAX:
            self.schedule_force_closing(chan.channel_id)
            raise RemoteMisbehaving(f"received update_add_htlc with {cltv_abs=} > BLOCKHEIGHT_MAX")
        # add htlc
        chan.receive_htlc(htlc, onion_packet)
        util.trigger_callback('htlc_added', chan, htlc, RECEIVED)

    @staticmethod
    def _check_accepted_final_htlc(
            *, chan: Channel,
            htlc: UpdateAddHtlc,
            processed_onion: ProcessedOnionPacket,
            is_trampoline_onion: bool = False,
            log_fail_reason: Callable[[str], None],
    ) -> tuple[bytes, int, int, OnionRoutingFailure]:
        """
        Perform checks that are invariant (results do not depend on height, network conditions, etc.)
        for htlcs of which we are the receiver (forwarding htlcs will have their checks in maybe_forward_htlc).
        May raise OnionRoutingFailure
        """
        assert processed_onion.are_we_final, processed_onion
        if (amt_to_forward := processed_onion.amt_to_forward) is None:
            log_fail_reason(f"'amt_to_forward' missing from onion")
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')
        if (cltv_abs_from_onion := processed_onion.outgoing_cltv_value) is None:
            log_fail_reason(f"'outgoing_cltv_value' missing from onion")
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')
        if cltv_abs_from_onion > htlc.cltv_abs:
            log_fail_reason(f"cltv_abs_from_onion != htlc.cltv_abs")
            raise OnionRoutingFailure(
                code=OnionFailureCode.FINAL_INCORRECT_CLTV_EXPIRY,
                data=htlc.cltv_abs.to_bytes(4, byteorder="big"))

        exc_incorrect_or_unknown_pd = OnionRoutingFailure(
            code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
            data=amt_to_forward.to_bytes(8, byteorder="big")) # height will be added later
        if (total_msat := processed_onion.total_msat) is None:
            log_fail_reason(f"'total_msat' missing from onion")
            raise exc_incorrect_or_unknown_pd

        if chan.jit_opening_fee:
            channel_opening_fee = chan.jit_opening_fee
            total_msat -= channel_opening_fee
            amt_to_forward -= channel_opening_fee
        else:
            channel_opening_fee = 0

        if not is_trampoline_onion:
            # for inner trampoline onions amt_to_forward can be larger than the htlc amount
            if amt_to_forward > htlc.amount_msat:
                log_fail_reason(f"{amt_to_forward=} > {htlc.amount_msat=}")
                raise OnionRoutingFailure(
                    code=OnionFailureCode.FINAL_INCORRECT_HTLC_AMOUNT,
                    data=htlc.amount_msat.to_bytes(8, byteorder="big"))

        if (payment_secret_from_onion := processed_onion.payment_secret) is None:
            log_fail_reason(f"'payment_secret' missing from onion")
            raise exc_incorrect_or_unknown_pd

        return payment_secret_from_onion, total_msat, channel_opening_fee, exc_incorrect_or_unknown_pd

    def _check_unfulfilled_htlc(
        self, *,
        chan: Channel,
        htlc: UpdateAddHtlc,
        processed_onion: ProcessedOnionPacket,
        outer_onion_payment_secret: bytes = None,  # used to group trampoline htlcs for forwarding
    ) -> str:
        """
        Does additional checks on the incoming htlc and return the payment key if the tests pass,
        otherwise raises OnionRoutingError which will get the htlc failed.
        """
        _log_fail_reason = self._log_htlc_fail_reason_cb(chan.channel_id, htlc, processed_onion.hop_data.payload)

        # Check that our blockchain tip is sufficiently recent so that we have an approx idea of the height.
        # We should not release the preimage for an HTLC that its sender could already time out as
        # then they might try to force-close and it becomes a race.
        chain = self.network.blockchain()
        local_height = chain.height()
        blocks_to_expiry = max(htlc.cltv_abs - local_height, 0)
        if chain.is_tip_stale():
            _log_fail_reason(f"our chain tip is stale: {local_height=}")
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')

        payment_hash = htlc.payment_hash
        if not processed_onion.are_we_final:
            if outer_onion_payment_secret:
                # this is a trampoline forwarding htlc, multiple incoming trampoline htlcs can be collected
                payment_key = (payment_hash + outer_onion_payment_secret).hex()
                return payment_key
            # this is a regular htlc to forward, it will get its own set of size 1 keyed by htlc_key
            # Additional checks required only for forwarding nodes will be done in maybe_forward_htlc().
            payment_key = serialize_htlc_key(chan.get_scid_or_local_alias(), htlc.htlc_id)
            return payment_key

        # parse parameters and perform checks that are invariant
        payment_secret_from_onion, total_msat, channel_opening_fee, exc_incorrect_or_unknown_pd = (
            self._check_accepted_final_htlc(
                chan=chan,
                htlc=htlc,
                processed_onion=processed_onion,
                is_trampoline_onion=bool(outer_onion_payment_secret),
                log_fail_reason=_log_fail_reason,
            ))
        # trampoline htlcs of which we are the final receiver will first get grouped by the outer
        # onions secret to allow grouping a multi-trampoline mpp in different sets. Once a trampoline
        # payment part is completed (sum(htlcs) >= (trampoline-)amt_to_forward), its htlcs get moved into
        # the htlc set representing the whole payment (payment key derived from trampoline/invoice secret).
        payment_key = (payment_hash + (outer_onion_payment_secret or payment_secret_from_onion)).hex()

        # for safety, still enforce MIN_FINAL_CLTV_DELTA here even if payment_hash is in dont_expire_htlcs
        if blocks_to_expiry < MIN_FINAL_CLTV_DELTA_ACCEPTED:
            # this check should be done here for new htlcs and ongoing on pending sets.
            # Here it is done so that invalid received htlcs will never get added to a set,
            # so the set still has a chance to succeed until mpp timeout.
            _log_fail_reason(f"htlc.cltv_abs is unreasonably close: {htlc.cltv_abs=}, {local_height=}")
            raise exc_incorrect_or_unknown_pd

        # extract trampoline
        if processed_onion.trampoline_onion_packet:
            trampoline_onion = self._process_incoming_onion_packet(
                processed_onion.trampoline_onion_packet,
                payment_hash=payment_hash,
                is_trampoline=True)

            # compare trampoline onion against outer onion according to:
            # https://github.com/lightning/bolts/blob/9938ab3d6160a3ba91f3b0e132858ab14bfe4f81/04-onion-routing.md?plain=1#L547-L553
            if trampoline_onion.are_we_final:
                try:
                    assert not processed_onion.outgoing_cltv_value < trampoline_onion.outgoing_cltv_value
                    is_mpp = processed_onion.total_msat > processed_onion.amt_to_forward
                    if is_mpp:
                        assert not processed_onion.total_msat < trampoline_onion.amt_to_forward
                    else:
                        assert not processed_onion.amt_to_forward < trampoline_onion.amt_to_forward
                except AssertionError:
                    _log_fail_reason(f'incorrect trampoline onion {processed_onion=}\n{trampoline_onion=}')
                    raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_PAYLOAD, data=b'\x00\x00\x00')

            return self._check_unfulfilled_htlc(
                chan=chan,
                htlc=htlc,
                processed_onion=trampoline_onion,
                outer_onion_payment_secret=payment_secret_from_onion,
            )

        info = self.lnworker.get_payment_info(payment_hash, direction=RECEIVED)
        if info is None:
            _log_fail_reason(f"no payment_info found for RHASH {payment_hash.hex()}")
            raise exc_incorrect_or_unknown_pd
        elif info.status == PR_PAID:
            _log_fail_reason(f"invoice already paid: {payment_hash.hex()=}")
            raise exc_incorrect_or_unknown_pd
        elif blocks_to_expiry < info.min_final_cltv_delta:
            _log_fail_reason(
                f"min final cltv delta lower than requested: "
                f"{payment_hash.hex()=} {htlc.cltv_abs=} {blocks_to_expiry=}"
            )
            raise exc_incorrect_or_unknown_pd
        elif htlc.timestamp > info.expiration_ts:  # the set will get failed too if now > exp_ts
            _log_fail_reason(f"not accepting htlc for expired invoice")
            raise exc_incorrect_or_unknown_pd
        elif not info.invoice_features.supports(LnFeatures.BASIC_MPP_OPT) and total_msat > htlc.amount_msat:
            # in _check_unfulfilled_htlc_set we check the count to prevent mpp through overpayment
            _log_fail_reason(f"got mpp but we requested no mpp in the invoice: {total_msat=} > {htlc.amount_msat=}")
            raise exc_incorrect_or_unknown_pd

        expected_payment_secret = self.lnworker.get_payment_secret(payment_hash)
        if not util.constant_time_compare(payment_secret_from_onion, expected_payment_secret):
            _log_fail_reason(f'incorrect payment secret: {payment_secret_from_onion.hex()=}')
            raise exc_incorrect_or_unknown_pd

        invoice_msat = info.amount_msat
        if channel_opening_fee:
            # deduct just-in-time channel fees from invoice amount
            invoice_msat -= channel_opening_fee

        if not (invoice_msat is None or invoice_msat <= total_msat <= 2 * invoice_msat):
            _log_fail_reason(f"{total_msat=} too different from {invoice_msat=}")
            raise exc_incorrect_or_unknown_pd

        return payment_key

    def _fulfill_htlc_set(self, payment_key: str, preimage: bytes):
        htlc_set = self.lnworker.received_mpp_htlcs[payment_key]
        assert len(htlc_set.htlcs) > 0, f"{htlc_set=}"
        assert htlc_set.resolution == RecvMPPResolution.SETTLING
        assert htlc_set.parent_set_key is None, f"Must not settle child {htlc_set=}"
        # get payment hash of any htlc in the set (they are all the same)
        payment_hash = htlc_set.get_payment_hash()
        assert payment_hash is not None, htlc_set
        assert payment_hash.hex() not in self.lnworker.dont_settle_htlcs
        self.lnworker.dont_expire_htlcs.pop(payment_hash.hex(), None)  # htlcs wont get expired anymore
        for mpp_htlc in list(htlc_set.htlcs):
            htlc_id = mpp_htlc.htlc.htlc_id
            chan = self.get_channel_by_id(mpp_htlc.channel_id)
            if chan is None:
                # this htlc belongs to another peer and has to be settled in their htlc_switch
                continue
            if not chan.can_update_ctx(proposer=LOCAL):
                continue
            self.logger.info(f"fulfill htlc: {chan.short_channel_id}. {htlc_id=}. {payment_hash.hex()=}")
            if chan.hm.was_htlc_preimage_released(htlc_id=htlc_id, htlc_proposer=REMOTE):
                # this check is intended to gracefully handle stale htlcs in the set, e.g. after a crash
                self.logger.debug(f"{mpp_htlc=} was already settled before, dropping it.")
                htlc_set.htlcs.remove(mpp_htlc)
                continue
            self._fulfill_htlc(chan, htlc_id, preimage)
            htlc_set.htlcs.remove(mpp_htlc)
            # reset just-in-time opening fee of channel
            chan.jit_opening_fee = None
        # save htlc_set to storage
        self.lnworker.received_mpp_htlcs[payment_key] = htlc_set

    def _fulfill_htlc(self, chan: Channel, htlc_id: int, preimage: bytes):
        assert chan.hm.is_htlc_irrevocably_added_yet(htlc_proposer=REMOTE, htlc_id=htlc_id)
        self.received_htlcs_pending_removal.add((chan, htlc_id))
        chan.settle_htlc(preimage, htlc_id)
        self.send_message(
            "update_fulfill_htlc",
            channel_id=chan.channel_id,
            id=htlc_id,
            payment_preimage=preimage)

    def _fail_htlc_set(
        self,
        payment_key: str,
        error_tuple: Tuple[Optional[bytes], Optional[OnionFailureCode | int], Optional[bytes]],
    ):
        htlc_set = self.lnworker.received_mpp_htlcs[payment_key]
        assert htlc_set.resolution in (RecvMPPResolution.FAILED, RecvMPPResolution.EXPIRED)

        raw_error, error_code, error_data = error_tuple
        local_height = self.network.blockchain().height()
        payment_hash = htlc_set.get_payment_hash()
        assert payment_hash is not None, "Empty htlc set?"
        for mpp_htlc in list(htlc_set.htlcs):
            chan = self.get_channel_by_id(mpp_htlc.channel_id)
            htlc_id = mpp_htlc.htlc.htlc_id
            if chan is None:
                # this htlc belongs to another peer and has to be settled in their htlc_switch
                continue
            if not chan.can_update_ctx(proposer=LOCAL):
                continue
            assert chan.hm.is_htlc_irrevocably_added_yet(htlc_proposer=REMOTE, htlc_id=htlc_id)
            if chan.hm.was_htlc_failed(htlc_id=htlc_id, htlc_proposer=REMOTE):
                # this check is intended to gracefully handle stale htlcs in the set, e.g. after a crash
                self.logger.debug(f"{mpp_htlc=} was already failed before, dropping it.")
                htlc_set.htlcs.remove(mpp_htlc)
                continue
            onion_packet = self._parse_onion_packet(mpp_htlc.unprocessed_onion)
            processed_onion_packet = self._process_incoming_onion_packet(
                onion_packet,
                payment_hash=payment_hash,
                is_trampoline=False,
            )
            if raw_error:
                error_bytes = obfuscate_onion_error(raw_error, onion_packet.public_key, self.privkey)
            else:
                assert isinstance(error_code, (OnionFailureCode, int))
                if error_code == OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
                    amount_to_forward = processed_onion_packet.amt_to_forward
                    # if this was a trampoline htlc we use the inner amount_to_forward as this is
                    # the value known by the sender
                    if processed_onion_packet.trampoline_onion_packet:
                        processed_trampoline_onion_packet = self._process_incoming_onion_packet(
                            processed_onion_packet.trampoline_onion_packet,
                            payment_hash=payment_hash,
                            is_trampoline=True,
                        )
                        amount_to_forward = processed_trampoline_onion_packet.amt_to_forward
                    error_data = amount_to_forward.to_bytes(8, byteorder="big")
                e = OnionRoutingFailure(code=error_code, data=error_data or b'')
                error_bytes = e.to_wire_msg(onion_packet, self.privkey, local_height)
            self.fail_htlc(
                chan=chan,
                htlc_id=htlc_id,
                error_bytes=error_bytes,
            )
            htlc_set.htlcs.remove(mpp_htlc)
        # save htlc_set to storage
        self.lnworker.received_mpp_htlcs[payment_key] = htlc_set

    def fail_htlc(self, *, chan: Channel, htlc_id: int, error_bytes: bytes):
        self.logger.info(f"fail_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}.")
        assert chan.can_update_ctx(proposer=LOCAL), f"cannot send updates: {chan.short_channel_id}"
        self.received_htlcs_pending_removal.add((chan, htlc_id))
        chan.fail_htlc(htlc_id)
        self.send_message(
            "update_fail_htlc",
            channel_id=chan.channel_id,
            id=htlc_id,
            len=len(error_bytes),
            reason=error_bytes)

    def fail_malformed_htlc(self, *, chan: Channel, htlc_id: int, reason: OnionParsingError):
        self.logger.info(f"fail_malformed_htlc. chan {chan.short_channel_id}. htlc_id {htlc_id}.")
        assert chan.can_update_ctx(proposer=LOCAL), f"cannot send updates: {chan.short_channel_id}"
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

    def on_revoke_and_ack(self, chan: Channel, payload) -> None:
        self.logger.info(f'on_revoke_and_ack. chan {chan.short_channel_id}. ctn: {chan.get_oldest_unrevoked_ctn(REMOTE)}')
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_revoke_and_ack. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        rev = RevokeAndAck(payload["per_commitment_secret"], payload["next_per_commitment_point"])
        chan.receive_revocation(rev)
        self.lnworker.save_channel(chan)
        self.maybe_send_commitment(chan)
        self._received_revack_event.set()
        self._received_revack_event.clear()

    @event_listener
    async def on_event_fee(self, *args):
        async def async_wrapper():
            for chan in self.channels.values():
                self.maybe_update_fee(chan)
        await self.taskgroup.spawn(async_wrapper)

    def on_update_fee(self, chan: Channel, payload):
        if not chan.can_update_ctx(proposer=REMOTE):
            self.logger.warning(
                f"on_update_fee. dropping message. illegal action. "
                f"chan={chan.get_id_for_log()}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            return
        feerate = payload["feerate_per_kw"]
        chan.update_fee(feerate, False)

    def maybe_update_fee(self, chan: Channel):
        """
        called when our fee estimates change
        """
        if not chan.can_update_ctx(proposer=LOCAL):
            return
        if chan.get_state() != ChannelState.OPEN:
            return
        current_feerate_per_kw: Optional[int] = self.lnworker.current_target_feerate_per_kw(
            has_anchors=chan.has_anchors()
        )
        if current_feerate_per_kw is None:
            return
        # add some buffer to anchor chan fees as we always act at the lower end and don't
        # want to get kicked out of the mempool immediately if it grows
        fee_buffer = current_feerate_per_kw * 0.5 if chan.has_anchors() else 0
        update_feerate_per_kw = int(current_feerate_per_kw + fee_buffer)
        def does_chan_fee_need_update(chan_feerate: Union[float, int]) -> Optional[bool]:
            if chan.has_anchors():
                # TODO: once package relay and electrum servers with submitpackage are more common,
                # TODO: we should reconsider this logic and move towards 0 fee ctx
                # update if we used up half of the buffer or the fee decreased a lot again
                fee_increased = current_feerate_per_kw + (fee_buffer / 2) > chan_feerate
                changed_significantly = abs((chan_feerate - update_feerate_per_kw) / chan_feerate) > 0.2
                return fee_increased or changed_significantly
            else:
                # We raise fees more aggressively than we lower them. Overpaying is not too bad,
                # but lowballing can be fatal if we can't even get into the mempool...
                high_fee = 2 * current_feerate_per_kw  # type: # Union[float, int]
                low_fee = self.lnworker.current_low_feerate_per_kw_srk_channel()  # type: Optional[Union[float, int]]
                if low_fee is None:
                    return None
                low_fee = max(low_fee, 0.75 * current_feerate_per_kw)
                # make sure low_feerate and target_feerate are not too close to each other:
                low_fee = min(low_fee, current_feerate_per_kw - FEERATE_PER_KW_MIN_RELAY_LIGHTNING)
                assert low_fee < high_fee, (low_fee, high_fee)
                return not (low_fee < chan_feerate < high_fee)
        if not chan.constraints.is_initiator:
            if constants.net is not constants.BitcoinRegtest:
                chan_feerate = chan.get_latest_feerate(LOCAL)
                ratio = chan_feerate / update_feerate_per_kw
                if ratio < 0.5:
                    # Note that we trust the Electrum server about fee rates
                    # Thus, automated force-closing might not be a good idea
                    # Maybe we should display something in the GUI instead
                    self.logger.warning(
                        f"({chan.get_id_for_log()}) feerate is {chan_feerate} sat/kw, "
                        f"current recommended feerate is {update_feerate_per_kw} sat/kw, consider force closing!")
            return
        # it is our responsibility to update the fee
        chan_fee = chan.get_next_feerate(REMOTE)
        if does_chan_fee_need_update(chan_fee):
            self.logger.info(f"({chan.get_id_for_log()}) onchain fees have changed considerably. updating fee.")
        elif chan.get_latest_ctn(REMOTE) == 0:
            # workaround eclair issue https://github.com/ACINQ/eclair/issues/1730 (fixed in 2022)
            self.logger.info(f"({chan.get_id_for_log()}) updating fee to bump remote ctn")
            if current_feerate_per_kw == chan_fee:
                update_feerate_per_kw += 1
        else:
            return
        self.logger.info(f"({chan.get_id_for_log()}) current pending feerate {chan_fee}. "
                         f"new feerate {update_feerate_per_kw}")
        assert update_feerate_per_kw >= FEERATE_PER_KW_MIN_RELAY_LIGHTNING, f"fee below minimum: {update_feerate_per_kw}"
        chan.update_fee(update_feerate_per_kw, True)
        self.send_message(
            "update_fee",
            channel_id=chan.channel_id,
            feerate_per_kw=update_feerate_per_kw)
        self.maybe_send_commitment(chan)

    @log_exceptions
    async def close_channel(self, chan_id: bytes):
        chan = self.get_channel_by_id(chan_id)
        assert chan
        self.shutdown_received[chan_id] = self.asyncio_loop.create_future()
        await self.send_shutdown(chan)
        payload = await self.shutdown_received[chan_id]
        try:
            txid = await self._shutdown(chan, payload, is_local=True)
            self.logger.info(f'({chan.get_id_for_log()}) Channel closed {txid}')
        except asyncio.TimeoutError:
            txid = chan.unconfirmed_closing_txid
            self.logger.warning(f'({chan.get_id_for_log()}) did not send closing_signed, {txid}')
            if txid is None:
                raise Exception('The remote peer did not send their final signature. The channel may not have been be closed')
        return txid

    @non_blocking_msg_handler
    async def on_shutdown(self, chan: Channel, payload):
        if chan.peer_state != PeerState.GOOD:  # should never happen
            raise Exception(f"received shutdown in unexpected {chan.peer_state=!r}")
        if not self.can_send_shutdown(chan, proposer=REMOTE):
            self.logger.warning(
                f"on_shutdown. illegal action. "
                f"chan={chan.get_id_for_log()}. {chan.get_state()=!r}. {chan.peer_state=!r}")
            self.send_error(chan.channel_id, message="cannot process 'shutdown' in current channel state.")
        their_scriptpubkey = payload['scriptpubkey']
        their_upfront_scriptpubkey = chan.config[REMOTE].upfront_shutdown_script
        # BOLT-02 check if they use the upfront shutdown script they advertised
        if self.is_upfront_shutdown_script() and their_upfront_scriptpubkey:
            if not (their_scriptpubkey == their_upfront_scriptpubkey):
                self.send_warning(
                    chan.channel_id,
                    "remote didn't use upfront shutdown script it committed to in channel opening",
                    close_connection=True)
        else:
            # BOLT-02 restrict the scriptpubkey to some templates:
            if self.is_shutdown_anysegwit() and match_script_against_template(their_scriptpubkey, transaction.SCRIPTPUBKEY_TEMPLATE_ANYSEGWIT):
                pass
            elif match_script_against_template(their_scriptpubkey, transaction.SCRIPTPUBKEY_TEMPLATE_WITNESS_V0):
                pass
            else:
                self.send_warning(
                    chan.channel_id,
                    f'scriptpubkey in received shutdown message does not conform to any template: {their_scriptpubkey.hex()}',
                    close_connection=True)

        chan_id = chan.channel_id
        if chan_id in self.shutdown_received:
            self.shutdown_received[chan_id].set_result(payload)
        else:
            await self.send_shutdown(chan)
            txid = await self._shutdown(chan, payload, is_local=False)
            self.logger.info(f'({chan.get_id_for_log()}) Channel closed by remote peer {txid}')

    def can_send_shutdown(self, chan: Channel, *, proposer: HTLCOwner) -> bool:
        if chan.get_state() >= ChannelState.CLOSED:
            return False
        if chan.get_state() >= ChannelState.OPENING:
            return True
        if proposer == LOCAL:
            if chan.constraints.is_initiator and chan.channel_id in self.funding_created_sent:
                return True
            if not chan.constraints.is_initiator and chan.channel_id in self.funding_signed_sent:
                return True
        else:  # proposer == REMOTE
            # (from BOLT-02)
            #   A receiving node:
            #       - if it hasn't received a funding_signed (if it is a funder) or a funding_created (if it is a fundee):
            #           - SHOULD send an error and fail the channel.
            # ^ that check is equivalent to `chan.get_state() < ChannelState.OPENING`, which is already checked.
            pass
        return False

    async def send_shutdown(self, chan: Channel):
        if not self.can_send_shutdown(chan, proposer=LOCAL):
            raise Exception(f"cannot send shutdown. chan={chan.get_id_for_log()}. {chan.get_state()=!r}")
        if chan.config[LOCAL].upfront_shutdown_script:
            scriptpubkey = chan.config[LOCAL].upfront_shutdown_script
        else:
            scriptpubkey = bitcoin.address_to_script(chan.get_sweep_address())
        assert scriptpubkey
        # wait until no more pending updates (bolt2)
        chan.set_can_send_ctx_updates(False)
        while chan.has_pending_changes(REMOTE):
            await asyncio.sleep(0.1)
        self.send_message('shutdown', channel_id=chan.channel_id, len=len(scriptpubkey), scriptpubkey=scriptpubkey)
        chan.set_state(ChannelState.SHUTDOWN)
        # can fulfill or fail htlcs. cannot add htlcs, because state != OPEN
        chan.set_can_send_ctx_updates(True)

    def get_shutdown_fee_range(self, chan, closing_tx, is_local):
        """ return the closing fee and fee range we initially try to enforce """
        config = self.network.config
        our_fee = None
        if config.TEST_SHUTDOWN_FEE:
            our_fee = config.TEST_SHUTDOWN_FEE
        else:
            fee_rate_per_kb = self.network.fee_estimates.eta_target_to_fee(FEE_LN_ETA_TARGET)
            if fee_rate_per_kb is None:  # fallback
                from .fee_policy import FeePolicy
                fee_rate_per_kb = FeePolicy(config.FEE_POLICY).fee_per_kb(self.network)
            if fee_rate_per_kb is not None:
                our_fee = fee_rate_per_kb * closing_tx.estimated_size() // 1000
            # TODO: anchors: remove this, as commitment fee rate can be below chain head fee rate?
            # BOLT2: The sending node MUST set fee less than or equal to the base fee of the final ctx
            max_fee = chan.get_latest_fee(LOCAL if is_local else REMOTE)
            if our_fee is None:  # fallback
                self.logger.warning(f"got no fee estimates for co-op close! falling back to chan.get_latest_fee")
                our_fee = max_fee
            our_fee = min(our_fee, max_fee)
        # config modern_fee_negotiation can be set in tests
        if config.TEST_SHUTDOWN_LEGACY:
            our_fee_range = None
        elif config.TEST_SHUTDOWN_FEE_RANGE:
            our_fee_range = config.TEST_SHUTDOWN_FEE_RANGE
        else:
            # we aim at a fee between next block inclusion and some lower value
            our_fee_range = {'min_fee_satoshis': our_fee // 2, 'max_fee_satoshis': our_fee * 2}
        self.logger.info(f"Our fee range: {our_fee_range} and fee: {our_fee}")
        return our_fee, our_fee_range

    @log_exceptions
    async def _shutdown(self, chan: Channel, payload, *, is_local: bool):
        # wait until no HTLCs remain in either commitment transaction
        while chan.has_unsettled_htlcs():
            self.logger.info(f'(chan: {chan.short_channel_id}) waiting for htlcs to settle...')
            await asyncio.sleep(1)
        # if no HTLCs remain, we must not send updates
        chan.set_can_send_ctx_updates(False)
        their_scriptpubkey = payload['scriptpubkey']
        if chan.config[LOCAL].upfront_shutdown_script:
            our_scriptpubkey = chan.config[LOCAL].upfront_shutdown_script
        else:
            our_scriptpubkey = bitcoin.address_to_script(chan.get_sweep_address())
        assert our_scriptpubkey
        # estimate fee of closing tx
        dummy_sig, dummy_tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=0)
        our_sig = None  # type: Optional[bytes]
        closing_tx = None  # type: Optional[PartialTransaction]
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

        def verify_signature(tx: 'PartialTransaction', sig) -> bool:
            their_pubkey = chan.config[REMOTE].multisig_key.pubkey
            pre_hash = tx.serialize_preimage(0)
            msg_hash = sha256d(pre_hash)
            return ECPubkey(their_pubkey).ecdsa_verify(sig, msg_hash)

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
            to_remote_set = closing_tx.get_output_idxs_from_scriptpubkey(their_scriptpubkey)
            if not drop_remote and to_remote_set:
                to_remote_idx = to_remote_set.pop()
                to_remote_amount = closing_tx.outputs()[to_remote_idx].value
                transaction.check_scriptpubkey_template_and_dust(their_scriptpubkey, to_remote_amount)
            return their_fee, their_fee_range, their_sig, drop_remote

        def choose_new_fee(our_fee, our_fee_range, their_fee, their_fee_range, their_previous_fee):
            assert our_fee != their_fee
            fee_range_sent = our_fee_range and (is_initiator or (their_previous_fee is not None))

            # The sending node, if it is not the funder:
            if our_fee_range and their_fee_range and not is_initiator and not self.network.config.TEST_SHUTDOWN_FEE_RANGE:
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
            signing_pubkey=chan.config[LOCAL].multisig_key.pubkey,
            sig=ecdsa_der_sig_from_ecdsa_sig64(our_sig) + Sighash.to_sigbytes(Sighash.ALL))
        closing_tx.add_signature_to_txin(
            txin_idx=0,
            signing_pubkey=chan.config[REMOTE].multisig_key.pubkey,
            sig=ecdsa_der_sig_from_ecdsa_sig64(their_sig) + Sighash.to_sigbytes(Sighash.ALL))
        # save local transaction and set state
        try:
            self.lnworker.wallet.adb.add_transaction(closing_tx)
        except UnrelatedTransactionException:
            pass  # this can happen if (~all the balance goes to REMOTE)
        chan.set_state(ChannelState.CLOSING)
        # broadcast
        await self.network.try_broadcasting(closing_tx, 'closing')
        return closing_tx.txid()

    async def htlc_switch(self):
        await self.initialized
        # don't context switch in a htlc switch iteration as htlc sets are shared between peers
        assert not inspect.iscoroutinefunction(self._run_htlc_switch_iteration)
        while True:
            await self.ping_if_required()
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
            try:
                self._run_htlc_switch_iteration()
            except Exception as e:
                # this is code with many asserts and dense logic so it seems useful to allow the user
                # report to exceptions that otherwise might go unnoticed for some time
                reported_exc = type(e)("redacted")  # text could contain onions, payment hashes etc.
                reported_exc.__traceback__ = e.__traceback__
                util.send_exception_to_crash_reporter(reported_exc)
                raise e

    @util.profiler(min_threshold=0.02)
    def _run_htlc_switch_iteration(self):
        self._maybe_cleanup_received_htlcs_pending_removal()
        # htlc processing happens in two steps:
        # 1. Step: Iterating through all channels and their pending htlcs, doing validation
        #    feasible for single htlcs (some checks only make sense on the whole mpp set) and
        #    then collecting these htlcs in a mpp set by payment key.
        #    HTLCs failing these checks will get failed directly and won't be added to any set.
        #    No htlcs will get settled in this step, settling only happens on complete mpp sets.
        #    If a new htlc belongs to a set which has already been failed, the htlc will be failed
        #    and not added to any set.
        #    Each htlc is only supposed to go through this first loop once when being received.
        for chan_id, chan in self.channels.items():
            if not chan.can_update_ctx(proposer=LOCAL):
                continue
            self.maybe_send_commitment(chan)
            unfulfilled = chan.unfulfilled_htlcs
            for htlc_id, onion_packet_hex in list(unfulfilled.items()):
                if not chan.hm.is_htlc_irrevocably_added_yet(htlc_proposer=REMOTE, htlc_id=htlc_id):
                    continue

                htlc = chan.hm.get_htlc_by_id(REMOTE, htlc_id)
                try:
                    onion_packet = self._parse_onion_packet(onion_packet_hex)
                except OnionParsingError as e:
                    self.fail_malformed_htlc(
                        chan=chan,
                        htlc_id=htlc.htlc_id,
                        reason=e,
                    )
                    del unfulfilled[htlc_id]
                    continue

                try:
                    processed_onion_packet = self._process_incoming_onion_packet(
                        onion_packet,
                        payment_hash=htlc.payment_hash,
                        is_trampoline=False,
                    )
                    payment_key: str = self._check_unfulfilled_htlc(
                        chan=chan,
                        htlc=htlc,
                        processed_onion=processed_onion_packet,
                    )
                    self.lnworker.update_or_create_mpp_with_received_htlc(
                        payment_key=payment_key,
                        channel_id=chan.channel_id,
                        htlc=htlc,
                        unprocessed_onion_packet=onion_packet_hex,  # outer onion if trampoline
                    )
                except OnionParsingError as e:  # could be raised when parsing the inner trampoline onion
                    self.fail_malformed_htlc(
                        chan=chan,
                        htlc_id=htlc.htlc_id,
                        reason=e,
                    )
                except Exception as e:
                    # Fail the htlc directly if it fails to pass these tests, it will not get added to a htlc set.
                    # https://github.com/lightning/bolts/blob/14272b1bd9361750cfdb3e5d35740889a6b510b5/04-onion-routing.md?plain=1#L388
                    reraise = False
                    if isinstance(e, OnionRoutingFailure):
                        orf = e
                    else:
                        orf = OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')
                        reraise = True  # propagate this out, as this might suggest a bug
                    error_bytes = orf.to_wire_msg(onion_packet, self.privkey, self.network.get_local_height())
                    self.fail_htlc(
                        chan=chan,
                        htlc_id=htlc.htlc_id,
                        error_bytes=error_bytes,
                    )
                    if reraise:
                        raise
                finally:
                    del unfulfilled[htlc_id]

        # 2. Step: Acting on sets of htlcs.
        #    Doing further checks that have to be done on sets of htlcs (e.g. total amount checks)
        #    and checks that have to be done continuously like checking for timeout.
        #    A set marked as failed once must never settle any htlcs associated to it.
        #    The sets are shared between all peers, so each peers htlc_switch acts on the same sets.
        for payment_key, htlc_set in list(self.lnworker.received_mpp_htlcs.items()):
            any_error, preimage, callback = self._check_unfulfilled_htlc_set(payment_key, htlc_set)
            assert bool(any_error) + bool(preimage) + bool(callback) <= 1, \
                        f"{any_error=}, {bool(preimage)=}, {callback=}"
            if any_error:
                error_tuple = self.lnworker.set_htlc_set_error(payment_key, any_error)
                self._fail_htlc_set(payment_key, error_tuple)
            if preimage:
                if self.lnworker.enable_htlc_settle:
                    self.lnworker.set_request_status(htlc_set.get_payment_hash(), PR_PAID)
                    self._fulfill_htlc_set(payment_key, preimage)
            if callback:
                task = asyncio.create_task(callback())
                task.add_done_callback(  # handle exceptions occurring in callback
                    lambda t: (util.send_exception_to_crash_reporter(t.exception()) if t.exception() else None)
                )

            if len(self.lnworker.received_mpp_htlcs[payment_key].htlcs) == 0:
                self.logger.debug(f"deleting resolved mpp set: {payment_key=}")
                del self.lnworker.received_mpp_htlcs[payment_key]
                self.lnworker.maybe_cleanup_forwarding(payment_key)

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

    def _log_htlc_fail_reason_cb(
        self,
        channel_id: bytes,
        htlc: UpdateAddHtlc,
        onion_payload: dict
    ) -> Callable[[str], None]:
        def _log_fail_reason(reason: str) -> None:
            scid = self.lnworker.get_channel_by_id(channel_id).short_channel_id
            self.logger.info(f"will FAIL HTLC: {str(scid)=}. {reason=}. {str(htlc)=}. {onion_payload=}")
        return _log_fail_reason

    def _log_htlc_set_fail_reason_cb(self, mpp_set: ReceivedMPPStatus) -> Callable[[str], None]:
        def log_fail_reason(reason: str):
            for mpp_htlc in mpp_set.htlcs:
                try:
                    processed_onion = self._process_incoming_onion_packet(
                        onion_packet=self._parse_onion_packet(mpp_htlc.unprocessed_onion),
                        payment_hash=mpp_htlc.htlc.payment_hash,
                        is_trampoline=False,
                    )
                    onion_payload = processed_onion.hop_data.payload
                except Exception:
                    onion_payload = {}

                self._log_htlc_fail_reason_cb(
                    mpp_htlc.channel_id,
                    mpp_htlc.htlc,
                    onion_payload,
                )(f"mpp set {id(mpp_set)} failed: {reason}")

        return log_fail_reason

    def _check_unfulfilled_htlc_set(
        self,
        payment_key: str,
        mpp_set: ReceivedMPPStatus
    ) -> Tuple[
        Optional[Union[OnionRoutingFailure, OnionFailureCode, bytes]],  # error types used to fail the set
        Optional[bytes],  # preimage to settle the set
        Optional[Callable[[], Coroutine[Any, Any, None]]],  # callback
    ]:
        """
        Returns what to do next with the given set of htlcs:
            * Fail whole set -> returns error code
            * Settle whole set -> Returns preimage
            * call callback (e.g. forwarding, hold invoice)
        May modify the mpp set in lnworker.received_mpp_htlcs (e.g. by setting its resolution to COMPLETE).
        """
        _log_fail_reason = self._log_htlc_set_fail_reason_cb(mpp_set)

        if (final_state := self._check_final_mpp_set_state(payment_key, mpp_set)) is not None:
            return final_state

        assert mpp_set.resolution in (RecvMPPResolution.WAITING, RecvMPPResolution.COMPLETE)
        chain = self.network.blockchain()
        local_height = chain.height()
        if chain.is_tip_stale():
            _log_fail_reason(f"our chain tip is stale: {local_height=}")
            return OnionFailureCode.TEMPORARY_NODE_FAILURE, None, None

        amount_msat: int = 0  # sum(amount_msat of each htlc)
        total_msat = None  # type: Optional[int]
        payment_hash = mpp_set.get_payment_hash()
        closest_cltv_abs = mpp_set.get_closest_cltv_abs()
        first_htlc_timestamp = mpp_set.get_first_htlc_timestamp()
        processed_onions = {}  # type: dict[ReceivedMPPHtlc, Tuple[ProcessedOnionPacket, Optional[ProcessedOnionPacket]]]
        for mpp_htlc in mpp_set.htlcs:
            processed_onion = self._process_incoming_onion_packet(
                onion_packet=self._parse_onion_packet(mpp_htlc.unprocessed_onion),
                payment_hash=payment_hash,
                is_trampoline=False,  # this is always the outer onion
            )
            processed_onions[mpp_htlc] = (processed_onion, None)
            inner_onion = None
            if processed_onion.trampoline_onion_packet:
                inner_onion = self._process_incoming_onion_packet(
                    onion_packet=processed_onion.trampoline_onion_packet,
                    payment_hash=payment_hash,
                    is_trampoline=True,
                )
                processed_onions[mpp_htlc] = (processed_onion, inner_onion)

            total_msat_outer_onion = processed_onion.total_msat
            total_msat_inner_onion = inner_onion.total_msat if inner_onion else None
            if total_msat is None:
                total_msat = total_msat_inner_onion or total_msat_outer_onion

            # check total_msat is equal for all htlcs of the set
            if total_msat != (total_msat_inner_onion or total_msat_outer_onion):
                _log_fail_reason(f"total_msat is not uniform: {total_msat=} != {processed_onion.total_msat=}")
                return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None

            amount_msat += mpp_htlc.htlc.amount_msat

        # If the set contains outer onions with different payment secrets, the set's payment_key is
        # derived from the trampoline/invoice/inner payment secret, so it is the second stage of a
        # multi-trampoline payment in which all the trampoline parts/htlcs got combined.
        # In this case the amt_to_forward cannot be compared as it may differ between the trampoline parts.
        # However, amt_to_forward should be similar for all onions of a single trampoline part and gets
        # compared in the first stage where the htlc set represents a single trampoline part.
        outer_onions = [onions[0] for onions in processed_onions.values()]
        can_have_different_amt_to_fwd = not all(o.payment_secret == outer_onions[0].payment_secret for o in outer_onions)
        trampoline_onions = iter(onions[1] for onions in processed_onions.values())
        if not lnonion.compare_trampoline_onions(trampoline_onions, exclude_amt_to_fwd=can_have_different_amt_to_fwd):
            _log_fail_reason(f"got inconsistent {trampoline_onions=}")
            return OnionFailureCode.INVALID_ONION_PAYLOAD, None, None

        if len(processed_onions) == 1:
            outer_onion, inner_onion = next(iter(processed_onions.values()))
            if not outer_onion.are_we_final:
                assert inner_onion is None, f"{outer_onion=}\n{inner_onion=}"
                if not self.lnworker.enable_htlc_forwarding:
                    return None, None, None
                # this is a single (non-trampoline) htlc set which needs to be forwarded.
                # set to settling state so it will not be failed or forwarded twice.
                self.lnworker.set_mpp_resolution(payment_key, RecvMPPResolution.SETTLING)
                fwd_cb = lambda: self.lnworker.maybe_forward_htlc_set(payment_key, processed_htlc_set=processed_onions)
                return None, None, fwd_cb

        assert payment_hash is not None and total_msat is not None
        # check for expiry over time and potentially fail the whole set if any
        # htlc's cltv becomes too close
        blocks_to_expiry = max(0, closest_cltv_abs - local_height)
        accepted_expiry_delta = self.lnworker.dont_expire_htlcs.get(payment_hash.hex(), MIN_FINAL_CLTV_DELTA_ACCEPTED)
        if accepted_expiry_delta is not None and blocks_to_expiry < accepted_expiry_delta:
            _log_fail_reason(f"htlc.cltv_abs is unreasonably close")
            return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None

        # check for mpp expiry (if incomplete and expired -> fail)
        if mpp_set.resolution == RecvMPPResolution.WAITING \
                or not self.lnworker.is_payment_bundle_complete(payment_key):
            # maybe this set is COMPLETE but the bundle is not yet completed, so the bundle can be considered WAITING
            if int(time.time()) - first_htlc_timestamp > self.lnworker.MPP_EXPIRY \
                    or self.lnworker.lnpeermgr.stopping_soon:
                _log_fail_reason(f"MPP TIMEOUT (> {self.lnworker.MPP_EXPIRY} sec)")
                return OnionFailureCode.MPP_TIMEOUT, None, None

        if mpp_set.resolution == RecvMPPResolution.WAITING:
            # calculate the sum of just in time channel opening fees, note jit only supports
            # single part payments for now, this is enforced by checking against the invoice features
            htlc_channels = [self.lnworker.get_channel_by_id(channel_id) for channel_id in set(h.channel_id for h in mpp_set.htlcs)]
            jit_opening_fees_msat = sum((c.jit_opening_fee or 0) for c in htlc_channels)

            # check if set is first stage multi-trampoline payment to us
            # first stage trampoline payment:
            # is a trampoline payment + we_are_final + payment key is derived from outer onion's payment secret
            # (so it is not the payment secret we requested in the invoice, but some secret set by a
            # trampoline forwarding node on the route).
            # if it is first stage, check if sum(htlcs) >= amount_to_forward of the trampoline_payload.
            # If this part is complete, move the htlcs to the overall mpp set of the payment (keyed by inner secret).
            # Once the second stage set (the set containing all htlcs of the separate trampoline parts)
            # is complete, the payment gets fulfilled.
            trampoline_payment_key = None
            any_trampoline_onion = next(iter(processed_onions.values()))[1]
            if any_trampoline_onion and any_trampoline_onion.are_we_final:
                trampoline_payment_secret = any_trampoline_onion.payment_secret
                assert trampoline_payment_secret == self.lnworker.get_payment_secret(payment_hash)
                trampoline_payment_key = (payment_hash + trampoline_payment_secret).hex()

            if trampoline_payment_key and trampoline_payment_key != payment_key:
                if jit_opening_fees_msat:
                    # for jit openings we only accept a single htlc
                    expected_amount_first_stage = any_trampoline_onion.total_msat - jit_opening_fees_msat
                else:
                    expected_amount_first_stage = any_trampoline_onion.amt_to_forward

                # first stage of trampoline payment, the first stage must never get set COMPLETE
                if amount_msat >= expected_amount_first_stage:
                    # setting the parent key will mark the htlcs to be moved to the parent set
                    self.logger.debug(f"trampoline part complete. {len(mpp_set.htlcs)=}, "
                                      f"{amount_msat=}. setting parent key: {trampoline_payment_key}")
                    self.lnworker.received_mpp_htlcs[payment_key] = mpp_set._replace(
                        parent_set_key=trampoline_payment_key,
                    )
            elif amount_msat >= (total_msat - jit_opening_fees_msat):  # regular mpp or 2nd stage trampoline
                # set mpp_set as completed as we have received the full total_msat
                mpp_set = self.lnworker.set_mpp_resolution(
                    payment_key=payment_key,
                    new_resolution=RecvMPPResolution.COMPLETE,
                )

        # check if this set is a trampoline forwarding and potentially return forwarding callback
        # note: all inner trampoline onions are equal (enforced above)
        _, any_inner_onion = next(iter(processed_onions.values()))
        if any_inner_onion and not any_inner_onion.are_we_final:
            # this is a trampoline forwarding
            can_forward = mpp_set.resolution == RecvMPPResolution.COMPLETE and self.lnworker.enable_htlc_forwarding
            if not can_forward:
                return None, None, None
            self.lnworker.set_mpp_resolution(payment_key, RecvMPPResolution.SETTLING)
            fwd_cb = lambda: self.lnworker.maybe_forward_htlc_set(payment_key, processed_htlc_set=processed_onions)
            return None, None, fwd_cb

        #  -- from here on it's assumed this set is a payment for us (not something to forward) --
        payment_info = self.lnworker.get_payment_info(payment_hash, direction=RECEIVED)
        if payment_info is None:
            _log_fail_reason(f"payment info has been deleted")
            return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None
        elif not payment_info.invoice_features.supports(LnFeatures.BASIC_MPP_OPT) and len(mpp_set.htlcs) > 1:
            # in _check_unfulfilled_htlc we already check amount == total_amount, however someone could
            # send us multiple htlcs that all pay the full amount, so we also check the htlc count
            _log_fail_reason(f"got mpp but we requested no mpp in the invoice: {len(mpp_set.htlcs)=}")
            return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None

        # check invoice expiry, fail set if the invoice has expired before it was completed
        if mpp_set.resolution == RecvMPPResolution.WAITING:
            if int(time.time()) > payment_info.expiration_ts:
                _log_fail_reason(f"invoice is expired {payment_info.expiration_ts=}")
                return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None
            return None, None, None

        preimage = self.lnworker.get_preimage(payment_hash)
        settling_blocked = preimage is not None and payment_hash.hex() in self.lnworker.dont_settle_htlcs
        waiting_for_preimage = preimage is None and payment_hash.hex() in self.lnworker.dont_expire_htlcs
        if settling_blocked or waiting_for_preimage:
            # used by hold invoice cli and JIT channels to prevent the htlcs from getting fulfilled automatically
            return None, None, None

        hold_invoice_callback = self.lnworker.hold_invoice_callbacks.get(payment_hash)
        if not preimage and not hold_invoice_callback:
            _log_fail_reason(f"cannot settle, no preimage or callback found for {payment_hash.hex()=}")
            return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None

        if not self.lnworker.is_payment_bundle_complete(payment_key):
            # don't allow settling before all sets of the bundle are COMPLETE
            return None, None, None
        else:
            # If this set is part of a bundle now all parts are COMPLETE so the bundle can be deleted
            # so the individual sets will get fulfilled.
            self.lnworker.delete_payment_bundle(payment_key=bytes.fromhex(payment_key))

        assert mpp_set.resolution == RecvMPPResolution.COMPLETE, "should return earlier if set is incomplete"
        if not preimage:
            assert hold_invoice_callback is not None, "should have been failed before"
            async def callback():
                try:
                    await hold_invoice_callback(payment_hash)
                except OnionRoutingFailure as e:  # todo: should this catch all exceptions?
                    _log_fail_reason(f"hold invoice callback raised {e}")
                    self.lnworker.set_mpp_resolution(payment_key, RecvMPPResolution.FAILED)
            # mpp set must not be failed unless the consumer calls unregister_hold_invoice and
            # callback must only be called once. This is enforced by setting the set to SETTLING.
            self.lnworker.set_mpp_resolution(payment_key, RecvMPPResolution.SETTLING)
            return None, None, callback

        # settle htlc set
        self.lnworker.set_mpp_resolution(payment_key, RecvMPPResolution.SETTLING)
        return None, preimage, None

    def _check_final_mpp_set_state(
        self,
        payment_key: str,
        mpp_set: ReceivedMPPStatus,
    ) -> Optional[Tuple[
            Optional[Union[OnionRoutingFailure, OnionFailureCode, bytes]],  # error types used to fail the set
            Optional[bytes],  # preimage to settle the set
            None,  # callback
        ]]:
        """
        handle sets that are already in a state eligible for fulfillment or failure and shouldn't
        go through another iteration of _check_unfulfilled_htlc_set.
        """
        if len(mpp_set.htlcs) == 0:
            # stale set, will get deleted on the next iteration
            return None, None, None

        if mpp_set.resolution == RecvMPPResolution.FAILED:
            error_bytes, failure_message = self.lnworker.get_forwarding_failure(payment_key)
            if error_bytes or failure_message:
                return error_bytes or failure_message, None, None
            return OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, None, None
        elif mpp_set.resolution == RecvMPPResolution.EXPIRED:
            return OnionFailureCode.MPP_TIMEOUT, None, None

        if mpp_set.parent_set_key:
            # this is a complete trampoline part of a multi trampoline payment. Move the htlcs to parent.
            parent = self.lnworker.received_mpp_htlcs.get(mpp_set.parent_set_key)
            if not parent:
                parent = ReceivedMPPStatus(
                    resolution=RecvMPPResolution.WAITING,
                    htlcs=set(),
                )
            parent.htlcs.update(mpp_set.htlcs)
            mpp_set.htlcs.clear()
            # save to storage
            self.lnworker.received_mpp_htlcs[mpp_set.parent_set_key] = parent
            self.lnworker.received_mpp_htlcs[payment_key] = mpp_set
            return None, None, None  # this set will get deleted as there are no htlcs in it anymore

        assert not mpp_set.parent_set_key
        if mpp_set.resolution == RecvMPPResolution.SETTLING:
            # this is an ongoing forwarding, or a set that has not yet been fully settled (and removed).
            # note the htlcs in SETTLING will not get failed automatically,
            # even if timeout comes close, so either a forwarding failure or preimage has to be set
            error_bytes, failure_message = self.lnworker.get_forwarding_failure(payment_key)
            if error_bytes or failure_message:
                # this was a forwarding set and it failed
                self.lnworker.set_mpp_resolution(payment_key, RecvMPPResolution.FAILED)
                return error_bytes or failure_message, None, None
            payment_hash = mpp_set.get_payment_hash()
            if payment_hash.hex() in self.lnworker.dont_settle_htlcs:
                return None, None, None
            preimage = self.lnworker.get_preimage(payment_hash)
            return None, preimage, None

        return None

    def _parse_onion_packet(self, onion_packet_hex: str) -> OnionPacket:
        """
        https://github.com/lightning/bolts/blob/14272b1bd9361750cfdb3e5d35740889a6b510b5/02-peer-protocol.md?plain=1#L2352
        """
        onion_packet_bytes = None
        try:
            onion_packet_bytes = bytes.fromhex(onion_packet_hex)
            onion_packet = OnionPacket.from_bytes(onion_packet_bytes)
        except Exception as parsing_exc:
            self.logger.warning(f"unable to parse onion: {str(parsing_exc)}")
            onion_parsing_error = OnionParsingError(
                data=sha256(onion_packet_bytes or b''),
            )
            raise onion_parsing_error
        return onion_packet

    def _process_incoming_onion_packet(
            self,
            onion_packet: OnionPacket, *,
            payment_hash: bytes,
            is_trampoline: bool = False) -> ProcessedOnionPacket:
        onion_hash = onion_packet.onion_hash
        cache_key = sha256(onion_hash + payment_hash + bytes([is_trampoline]))  # type: ignore
        if cached_onion := self._processed_onion_cache.get(cache_key):
            return cached_onion
        try:
            processed_onion = lnonion.process_onion_packet(
                onion_packet,
                our_onion_private_key=self.privkey,
                associated_data=payment_hash,
                is_trampoline=is_trampoline)
            self._processed_onion_cache[cache_key] = processed_onion
        except UnsupportedOnionPacketVersion:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_VERSION, data=onion_hash)
        except InvalidOnionPubkey:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_KEY, data=onion_hash)
        except InvalidOnionMac:
            raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_HMAC, data=onion_hash)
        except Exception as e:
            self.logger.warning(f"error processing onion packet: {e!r}")
            raise OnionParsingError(data=onion_hash)
        if self.network.config.TEST_FAIL_HTLCS_AS_MALFORMED:
            raise OnionParsingError(data=onion_hash)
        if self.network.config.TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE:
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')
        return processed_onion

    def on_onion_message(self, payload):
        if hasattr(self.lnworker, 'onion_message_manager'):  # only on LNWallet
            self.lnworker.onion_message_manager.on_onion_message(payload)
