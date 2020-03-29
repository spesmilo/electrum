# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2015-2018 The Lightning Network Developers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# API (method signatures and docstrings) partially copied from lnd
# 42de4400bff5105352d0552155f73589166d162b

import os
from collections import namedtuple, defaultdict
import binascii
import json
from enum import IntEnum
from typing import Optional, Dict, List, Tuple, NamedTuple, Set, Callable, Iterable, Sequence, TYPE_CHECKING, Iterator
import time
import threading

from aiorpcx import NetAddress
import attr

from . import ecc
from . import constants
from .util import bfh, bh2u
from .bitcoin import redeem_script_to_address
from .crypto import sha256, sha256d
from .transaction import Transaction, PartialTransaction
from .logging import Logger
from .lnonion import decode_onion_error, OnionFailureCode, OnionRoutingFailureMessage
from . import lnutil
from .lnutil import (Outpoint, LocalConfig, RemoteConfig, Keypair, OnlyPubkeyKeypair, ChannelConstraints,
                     get_per_commitment_secret_from_seed, secret_to_pubkey, derive_privkey, make_closing_tx,
                     sign_and_get_sig_string, RevocationStore, derive_blinded_pubkey, Direction, derive_pubkey,
                     make_htlc_tx_with_open_channel, make_commitment, make_received_htlc, make_offered_htlc,
                     HTLC_TIMEOUT_WEIGHT, HTLC_SUCCESS_WEIGHT, extract_ctn_from_tx_and_chan, UpdateAddHtlc,
                     funding_output_script, SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, make_commitment_outputs,
                     ScriptHtlc, PaymentFailure, calc_fees_for_commitment_tx, RemoteMisbehaving, make_htlc_output_witness_script,
                     ShortChannelID, map_htlcs_to_ctx_output_idxs, LNPeerAddr, BarePaymentAttemptLog,
                     LN_MAX_HTLC_VALUE_MSAT, fee_for_htlc_output, offered_htlc_trim_threshold_sat,
                     received_htlc_trim_threshold_sat)
from .lnsweep import create_sweeptxs_for_our_ctx, create_sweeptxs_for_their_ctx
from .lnsweep import create_sweeptx_for_their_revoked_htlc, SweepInfo
from .lnhtlc import HTLCManager
from .lnmsg import encode_msg, decode_msg

if TYPE_CHECKING:
    from .lnworker import LNWallet
    from .json_db import StoredDict
    from .lnrouter import RouteEdge


# lightning channel states
# Note: these states are persisted by name (for a given channel) in the wallet file,
#       so consider doing a wallet db upgrade when changing them.
class channel_states(IntEnum):
    PREOPENING      = 0 # Initial negotiation. Channel will not be reestablished
    OPENING         = 1 # Channel will be reestablished. (per BOLT2)
                        #  - Funding node: has received funding_signed (can broadcast the funding tx)
                        #  - Non-funding node: has sent the funding_signed message.
    FUNDED          = 2 # Funding tx was mined (requires min_depth and tx verification)
    OPEN            = 3 # both parties have sent funding_locked
    CLOSING         = 4 # shutdown has been sent, and closing tx is unconfirmed.
    FORCE_CLOSING   = 5 # we force-closed, and closing tx is unconfirmed. (otherwise we remain OPEN)
    CLOSED          = 6 # closing tx has been mined
    REDEEMED        = 7 # we can stop watching

class peer_states(IntEnum):
    DISCONNECTED   = 0
    REESTABLISHING = 1
    GOOD           = 2
    BAD            = 3

cs = channel_states
state_transitions = [
    (cs.PREOPENING, cs.OPENING),
    (cs.OPENING, cs.FUNDED),
    (cs.FUNDED, cs.OPEN),
    (cs.OPENING, cs.CLOSING),
    (cs.FUNDED, cs.CLOSING),
    (cs.OPEN, cs.CLOSING),
    (cs.OPENING, cs.FORCE_CLOSING),
    (cs.FUNDED, cs.FORCE_CLOSING),
    (cs.OPEN, cs.FORCE_CLOSING),
    (cs.CLOSING, cs.FORCE_CLOSING),
    (cs.OPENING, cs.CLOSED),
    (cs.FUNDED, cs.CLOSED),
    (cs.OPEN, cs.CLOSED),
    (cs.CLOSING, cs.CLOSING), # if we reestablish
    (cs.CLOSING, cs.CLOSED),
    (cs.FORCE_CLOSING, cs.FORCE_CLOSING), # allow multiple attempts
    (cs.FORCE_CLOSING, cs.CLOSED),
    (cs.FORCE_CLOSING, cs.REDEEMED),
    (cs.CLOSED, cs.REDEEMED),
    (cs.OPENING, cs.REDEEMED), # channel never funded (dropped from mempool)
    (cs.PREOPENING, cs.REDEEMED), # channel never funded
]
del cs  # delete as name is ambiguous without context


RevokeAndAck = namedtuple("RevokeAndAck", ["per_commitment_secret", "next_per_commitment_point"])


class RemoteCtnTooFarInFuture(Exception): pass


def htlcsum(htlcs):
    return sum([x.amount_msat for x in htlcs])


class Channel(Logger):
    # note: try to avoid naming ctns/ctxs/etc as "current" and "pending".
    #       they are ambiguous. Use "oldest_unrevoked" or "latest" or "next".
    #       TODO enforce this ^

    def diagnostic_name(self):
        if self.name:
            return str(self.name)
        try:
            return f"lnchannel_{bh2u(self.channel_id[-4:])}"
        except:
            return super().diagnostic_name()

    def __init__(self, state: 'StoredDict', *, sweep_address=None, name=None, lnworker=None, initial_feerate=None):
        self.name = name
        Logger.__init__(self)
        self.lnworker = lnworker  # type: Optional[LNWallet]
        self.sweep_address = sweep_address
        self.storage = state
        self.db_lock = self.storage.db.lock if self.storage.db else threading.RLock()
        self.config = {}  # type: Dict[HTLCOwner, lnutil.Config]
        self.config[LOCAL] = state["local_config"]
        self.config[REMOTE] = state["remote_config"]
        self.channel_id = bfh(state["channel_id"])
        self.constraints = state["constraints"]
        self.funding_outpoint = state["funding_outpoint"]
        self.node_id = bfh(state["node_id"])
        self.short_channel_id = ShortChannelID.normalize(state["short_channel_id"])
        self.onion_keys = state['onion_keys']
        self.data_loss_protect_remote_pcp = state['data_loss_protect_remote_pcp']
        self.hm = HTLCManager(log=state['log'], initial_feerate=initial_feerate)
        self._state = channel_states[state['state']]
        self.peer_state = peer_states.DISCONNECTED
        self.sweep_info = {}  # type: Dict[str, Dict[str, SweepInfo]]
        self._outgoing_channel_update = None  # type: Optional[bytes]
        self._chan_ann_without_sigs = None  # type: Optional[bytes]
        self.revocation_store = RevocationStore(state["revocation_store"])
        self._can_send_ctx_updates = True  # type: bool
        self._receive_fail_reasons = {}  # type: Dict[int, BarePaymentAttemptLog]
        self._ignore_max_htlc_value = False  # used in tests

    def get_id_for_log(self) -> str:
        scid = self.short_channel_id
        if scid:
            return str(scid)
        return self.channel_id.hex()

    def set_onion_key(self, key, value):
        self.onion_keys[key] = value

    def get_onion_key(self, key):
        return self.onion_keys.get(key)

    def set_data_loss_protect_remote_pcp(self, key, value):
        self.data_loss_protect_remote_pcp[key] = value

    def get_data_loss_protect_remote_pcp(self, key):
        return self.data_loss_protect_remote_pcp.get(key)

    def get_local_pubkey(self) -> bytes:
        if not self.lnworker:
            raise Exception('lnworker not set for channel!')
        return self.lnworker.node_keypair.pubkey

    def set_remote_update(self, raw: bytes) -> None:
        self.storage['remote_update'] = raw.hex()

    def get_remote_update(self) -> Optional[bytes]:
        return bfh(self.storage.get('remote_update')) if self.storage.get('remote_update') else None

    def add_or_update_peer_addr(self, peer: LNPeerAddr) -> None:
        if 'peer_network_addresses' not in self.storage:
            self.storage['peer_network_addresses'] = {}
        now = int(time.time())
        self.storage['peer_network_addresses'][peer.net_addr_str()] = now

    def get_peer_addresses(self) -> Iterator[LNPeerAddr]:
        # sort by timestamp: most recent first
        addrs = sorted(self.storage.get('peer_network_addresses', {}).items(),
                       key=lambda x: x[1], reverse=True)
        for net_addr_str, ts in addrs:
            net_addr = NetAddress.from_string(net_addr_str)
            yield LNPeerAddr(host=str(net_addr.host), port=net_addr.port, pubkey=self.node_id)

    def get_outgoing_gossip_channel_update(self) -> bytes:
        if self._outgoing_channel_update is not None:
            return self._outgoing_channel_update
        if not self.lnworker:
            raise Exception('lnworker not set for channel!')
        sorted_node_ids = list(sorted([self.node_id, self.get_local_pubkey()]))
        channel_flags = b'\x00' if sorted_node_ids[0] == self.get_local_pubkey() else b'\x01'
        now = int(time.time())
        htlc_maximum_msat = min(self.config[REMOTE].max_htlc_value_in_flight_msat, 1000 * self.constraints.capacity)

        chan_upd = encode_msg(
            "channel_update",
            short_channel_id=self.short_channel_id,
            channel_flags=channel_flags,
            message_flags=b'\x01',
            cltv_expiry_delta=lnutil.NBLOCK_OUR_CLTV_EXPIRY_DELTA.to_bytes(2, byteorder="big"),
            htlc_minimum_msat=self.config[REMOTE].htlc_minimum_msat.to_bytes(8, byteorder="big"),
            htlc_maximum_msat=htlc_maximum_msat.to_bytes(8, byteorder="big"),
            fee_base_msat=lnutil.OUR_FEE_BASE_MSAT.to_bytes(4, byteorder="big"),
            fee_proportional_millionths=lnutil.OUR_FEE_PROPORTIONAL_MILLIONTHS.to_bytes(4, byteorder="big"),
            chain_hash=constants.net.rev_genesis_bytes(),
            timestamp=now.to_bytes(4, byteorder="big"),
        )
        sighash = sha256d(chan_upd[2 + 64:])
        sig = ecc.ECPrivkey(self.lnworker.node_keypair.privkey).sign(sighash, ecc.sig_string_from_r_and_s)
        message_type, payload = decode_msg(chan_upd)
        payload['signature'] = sig
        chan_upd = encode_msg(message_type, **payload)

        self._outgoing_channel_update = chan_upd
        return chan_upd

    def construct_channel_announcement_without_sigs(self) -> bytes:
        if self._chan_ann_without_sigs is not None:
            return self._chan_ann_without_sigs
        if not self.lnworker:
            raise Exception('lnworker not set for channel!')

        bitcoin_keys = [self.config[REMOTE].multisig_key.pubkey,
                        self.config[LOCAL].multisig_key.pubkey]
        node_ids = [self.node_id, self.get_local_pubkey()]
        sorted_node_ids = list(sorted(node_ids))
        if sorted_node_ids != node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()

        chan_ann = encode_msg("channel_announcement",
            len=0,
            features=b'',
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=self.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )

        self._chan_ann_without_sigs = chan_ann
        return chan_ann

    def is_static_remotekey_enabled(self):
        return self.storage.get('static_remotekey_enabled')

    def set_short_channel_id(self, short_id):
        self.short_channel_id = short_id
        self.storage["short_channel_id"] = short_id

    def get_feerate(self, subject, ctn):
        return self.hm.get_feerate(subject, ctn)

    def get_oldest_unrevoked_feerate(self, subject):
        return self.hm.get_feerate_in_oldest_unrevoked_ctx(subject)

    def get_latest_feerate(self, subject):
        return self.hm.get_feerate_in_latest_ctx(subject)

    def get_next_feerate(self, subject):
        return self.hm.get_feerate_in_next_ctx(subject)

    def get_payments(self):
        out = []
        for subject in LOCAL, REMOTE:
            log = self.hm.log[subject]
            for htlc_id, htlc in log.get('adds', {}).items():
                if htlc_id in log.get('fails',{}):
                    status = 'failed'
                elif htlc_id in log.get('settles',{}):
                    status = 'settled'
                else:
                    status = 'inflight'
                direction = SENT if subject is LOCAL else RECEIVED
                rhash = bh2u(htlc.payment_hash)
                out.append((rhash, self.channel_id, htlc, direction, status))
        return out

    def get_settled_payments(self):
        out = {}
        for subject in LOCAL, REMOTE:
            log = self.hm.log[subject]
            for htlc_id, htlc in log.get('adds', {}).items():
                if htlc_id in log.get('settles',{}):
                    direction = SENT if subject is LOCAL else RECEIVED
                    rhash = bh2u(htlc.payment_hash)
                    out[rhash] = (self.channel_id, htlc, direction)
        return out

    def open_with_first_pcp(self, remote_pcp: bytes, remote_sig: bytes) -> None:
        with self.db_lock:
            self.config[REMOTE].current_per_commitment_point = remote_pcp
            self.config[REMOTE].next_per_commitment_point = None
            self.config[LOCAL].current_commitment_signature = remote_sig
            self.hm.channel_open_finished()
            self.peer_state = peer_states.GOOD

    def set_state(self, state):
        """ set on-chain state """
        old_state = self._state
        if (old_state, state) not in state_transitions:
            raise Exception(f"Transition not allowed: {old_state.name} -> {state.name}")
        self.logger.debug(f'Setting channel state: {old_state.name} -> {state.name}')
        self._state = state
        self.storage['state'] = self._state.name

        if self.lnworker:
            self.lnworker.save_channel(self)
            self.lnworker.network.trigger_callback('channel', self)

    def get_state(self):
        return self._state

    def get_state_for_GUI(self):
        # status displayed in the GUI
        cs = self.get_state()
        if self.is_closed():
            return cs.name
        ps = self.peer_state
        if ps != peer_states.GOOD:
            return ps.name
        return cs.name

    def is_open(self):
        return self.get_state() == channel_states.OPEN

    def is_closing(self):
        return self.get_state() in [channel_states.CLOSING, channel_states.FORCE_CLOSING]

    def is_closed(self):
        # the closing txid has been saved
        return self.get_state() >= channel_states.CLOSED

    def set_can_send_ctx_updates(self, b: bool) -> None:
        self._can_send_ctx_updates = b

    def can_send_ctx_updates(self) -> bool:
        """Whether we can send update_fee, update_*_htlc changes to the remote."""
        if not (self.is_open() or self.is_closing()):
            return False
        if self.peer_state != peer_states.GOOD:
            return False
        if not self._can_send_ctx_updates:
            return False
        return True

    def can_send_update_add_htlc(self) -> bool:
        return self.can_send_ctx_updates() and not self.is_closing()

    def save_funding_height(self, txid, height, timestamp):
        self.storage['funding_height'] = txid, height, timestamp

    def get_funding_height(self):
        return self.storage.get('funding_height')

    def delete_funding_height(self):
        self.storage.pop('funding_height', None)

    def save_closing_height(self, txid, height, timestamp):
        self.storage['closing_height'] = txid, height, timestamp

    def get_closing_height(self):
        return self.storage.get('closing_height')

    def delete_closing_height(self):
        self.storage.pop('closing_height', None)

    def is_redeemed(self):
        return self.get_state() == channel_states.REDEEMED

    def is_frozen_for_sending(self) -> bool:
        """Whether the user has marked this channel as frozen for sending.
        Frozen channels are not supposed to be used for new outgoing payments.
        (note that payment-forwarding ignores this option)
        """
        return self.storage.get('frozen_for_sending', False)

    def set_frozen_for_sending(self, b: bool) -> None:
        self.storage['frozen_for_sending'] = bool(b)
        if self.lnworker:
            self.lnworker.network.trigger_callback('channel', self)

    def is_frozen_for_receiving(self) -> bool:
        """Whether the user has marked this channel as frozen for receiving.
        Frozen channels are not supposed to be used for new incoming payments.
        (note that payment-forwarding ignores this option)
        """
        return self.storage.get('frozen_for_receiving', False)

    def set_frozen_for_receiving(self, b: bool) -> None:
        self.storage['frozen_for_receiving'] = bool(b)
        if self.lnworker:
            self.lnworker.network.trigger_callback('channel', self)

    def _assert_can_add_htlc(self, *, htlc_proposer: HTLCOwner, amount_msat: int) -> None:
        """Raises PaymentFailure if the htlc_proposer cannot add this new HTLC.
        (this is relevant both for forwarding and endpoint)
        """
        htlc_receiver = htlc_proposer.inverted()
        # note: all these tests are about the *receiver's* *next* commitment transaction,
        #       and the constraints are the ones imposed by their config
        ctn = self.get_next_ctn(htlc_receiver)
        chan_config = self.config[htlc_receiver]
        if self.is_closed():
            raise PaymentFailure('Channel closed')
        if self.get_state() != channel_states.OPEN:
            raise PaymentFailure('Channel not open', self.get_state())
        if htlc_proposer == LOCAL:
            if not self.can_send_ctx_updates():
                raise PaymentFailure('Channel cannot send ctx updates')
            if not self.can_send_update_add_htlc():
                raise PaymentFailure('Channel cannot add htlc')

        # If proposer is LOCAL we apply stricter checks as that is behaviour we can control.
        # This should lead to fewer disagreements (i.e. channels failing).
        strict = (htlc_proposer == LOCAL)

        # check htlc raw value
        if amount_msat <= 0:
            raise PaymentFailure("HTLC value must be positive")
        if amount_msat < chan_config.htlc_minimum_msat:
            raise PaymentFailure(f'HTLC value too small: {amount_msat} msat')
        if amount_msat > LN_MAX_HTLC_VALUE_MSAT and not self._ignore_max_htlc_value:
            raise PaymentFailure(f"HTLC value over protocol maximum: {amount_msat} > {LN_MAX_HTLC_VALUE_MSAT} msat")

        # check proposer can afford htlc
        max_can_send_msat = self.available_to_spend(htlc_proposer, strict=strict)
        if max_can_send_msat < amount_msat:
            raise PaymentFailure(f'Not enough balance. can send: {max_can_send_msat}, tried: {amount_msat}')

        # check "max_accepted_htlcs"
        # this is the loose check BOLT-02 specifies:
        if len(self.hm.htlcs_by_direction(htlc_receiver, direction=RECEIVED, ctn=ctn)) + 1 > chan_config.max_accepted_htlcs:
            raise PaymentFailure('Too many HTLCs already in channel')
        # however, c-lightning is a lot stricter, so extra checks:
        if strict:
            max_concurrent_htlcs = min(self.config[htlc_proposer].max_accepted_htlcs,
                                       self.config[htlc_receiver].max_accepted_htlcs)
            if len(self.hm.htlcs(htlc_receiver, ctn=ctn)) + 1 > max_concurrent_htlcs:
                raise PaymentFailure('Too many HTLCs already in channel')

        # check "max_htlc_value_in_flight_msat"
        current_htlc_sum = htlcsum(self.hm.htlcs_by_direction(htlc_receiver, direction=RECEIVED, ctn=ctn).values())
        if current_htlc_sum + amount_msat > chan_config.max_htlc_value_in_flight_msat:
            raise PaymentFailure(f'HTLC value sum (sum of pending htlcs: {current_htlc_sum/1000} sat '
                                 f'plus new htlc: {amount_msat/1000} sat) '
                                 f'would exceed max allowed: {chan_config.max_htlc_value_in_flight_msat/1000} sat')

    def can_pay(self, amount_msat: int, *, check_frozen=False) -> bool:
        """Returns whether we can add an HTLC of given value."""
        if check_frozen and self.is_frozen_for_sending():
            return False
        try:
            self._assert_can_add_htlc(htlc_proposer=LOCAL, amount_msat=amount_msat)
        except PaymentFailure:
            return False
        return True

    def can_receive(self, amount_msat: int, *, check_frozen=False) -> bool:
        """Returns whether the remote can add an HTLC of given value."""
        if check_frozen and self.is_frozen_for_receiving():
            return False
        try:
            self._assert_can_add_htlc(htlc_proposer=REMOTE, amount_msat=amount_msat)
        except PaymentFailure:
            return False
        return True

    def should_try_to_reestablish_peer(self) -> bool:
        return channel_states.PREOPENING < self._state < channel_states.FORCE_CLOSING and self.peer_state == peer_states.DISCONNECTED

    def get_funding_address(self):
        script = funding_output_script(self.config[LOCAL], self.config[REMOTE])
        return redeem_script_to_address('p2wsh', script)

    def add_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        """
        AddHTLC adds an HTLC to the state machine's local update log. This method
        should be called when preparing to send an outgoing HTLC.

        This docstring is from LND.
        """
        if isinstance(htlc, dict):  # legacy conversion  # FIXME remove
            htlc = UpdateAddHtlc(**htlc)
        assert isinstance(htlc, UpdateAddHtlc)
        self._assert_can_add_htlc(htlc_proposer=LOCAL, amount_msat=htlc.amount_msat)
        if htlc.htlc_id is None:
            htlc = attr.evolve(htlc, htlc_id=self.hm.get_next_htlc_id(LOCAL))
        with self.db_lock:
            self.hm.send_htlc(htlc)
        self.logger.info("add_htlc")
        return htlc

    def receive_htlc(self, htlc: UpdateAddHtlc, onion_packet:bytes = None) -> UpdateAddHtlc:
        """
        ReceiveHTLC adds an HTLC to the state machine's remote update log. This
        method should be called in response to receiving a new HTLC from the remote
        party.

        This docstring is from LND.
        """
        if isinstance(htlc, dict):  # legacy conversion  # FIXME remove
            htlc = UpdateAddHtlc(**htlc)
        assert isinstance(htlc, UpdateAddHtlc)
        try:
            self._assert_can_add_htlc(htlc_proposer=REMOTE, amount_msat=htlc.amount_msat)
        except PaymentFailure as e:
            raise RemoteMisbehaving(e) from e
        if htlc.htlc_id is None:  # used in unit tests
            htlc = attr.evolve(htlc, htlc_id=self.hm.get_next_htlc_id(REMOTE))
        with self.db_lock:
            self.hm.recv_htlc(htlc)
            local_ctn = self.get_latest_ctn(LOCAL)
            remote_ctn = self.get_latest_ctn(REMOTE)
            if onion_packet:
                self.hm.log['unfulfilled_htlcs'][htlc.htlc_id] = local_ctn, remote_ctn, onion_packet.hex(), False

        self.logger.info("receive_htlc")
        return htlc

    def sign_next_commitment(self):
        """
        SignNextCommitment signs a new commitment which includes any previous
        unsettled HTLCs, any new HTLCs, and any modifications to prior HTLCs
        committed in previous commitment updates.
        The first return parameter is the signature for the commitment transaction
        itself, while the second parameter is are all HTLC signatures concatenated.
        any). The HTLC signatures are sorted according to the BIP 69 order of the
        HTLC's on the commitment transaction.

        This docstring was adapted from LND.
        """
        next_remote_ctn = self.get_next_ctn(REMOTE)
        self.logger.info(f"sign_next_commitment {next_remote_ctn}")

        pending_remote_commitment = self.get_next_commitment(REMOTE)
        sig_64 = sign_and_get_sig_string(pending_remote_commitment, self.config[LOCAL], self.config[REMOTE])

        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(self.config[LOCAL].htlc_basepoint.privkey, 'big'),
            self.config[REMOTE].next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

        htlcsigs = []
        htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(chan=self,
                                                                  ctx=pending_remote_commitment,
                                                                  pcp=self.config[REMOTE].next_per_commitment_point,
                                                                  subject=REMOTE,
                                                                  ctn=next_remote_ctn)
        for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
            _script, htlc_tx = make_htlc_tx_with_open_channel(chan=self,
                                                              pcp=self.config[REMOTE].next_per_commitment_point,
                                                              subject=REMOTE,
                                                              htlc_direction=direction,
                                                              commit=pending_remote_commitment,
                                                              ctx_output_idx=ctx_output_idx,
                                                              htlc=htlc)
            sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
            htlc_sig = ecc.sig_string_from_der_sig(sig[:-1])
            htlcsigs.append((ctx_output_idx, htlc_sig))
        htlcsigs.sort()
        htlcsigs = [x[1] for x in htlcsigs]
        with self.db_lock:
            self.hm.send_ctx()
        return sig_64, htlcsigs

    def receive_new_commitment(self, sig, htlc_sigs):
        """
        ReceiveNewCommitment process a signature for a new commitment state sent by
        the remote party. This method should be called in response to the
        remote party initiating a new change, or when the remote party sends a
        signature fully accepting a new state we've initiated. If we are able to
        successfully validate the signature, then the generated commitment is added
        to our local commitment chain. Once we send a revocation for our prior
        state, then this newly added commitment becomes our current accepted channel
        state.

        This docstring is from LND.
        """
        # TODO in many failure cases below, we should "fail" the channel (force-close)
        next_local_ctn = self.get_next_ctn(LOCAL)
        self.logger.info(f"receive_new_commitment. ctn={next_local_ctn}, len(htlc_sigs)={len(htlc_sigs)}")

        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        pending_local_commitment = self.get_next_commitment(LOCAL)
        preimage_hex = pending_local_commitment.serialize_preimage(0)
        pre_hash = sha256d(bfh(preimage_hex))
        if not ecc.verify_signature(self.config[REMOTE].multisig_key.pubkey, sig, pre_hash):
            raise Exception(f'failed verifying signature of our updated commitment transaction: {bh2u(sig)} preimage is {preimage_hex}')

        htlc_sigs_string = b''.join(htlc_sigs)

        _secret, pcp = self.get_secret_and_point(subject=LOCAL, ctn=next_local_ctn)

        htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(chan=self,
                                                                  ctx=pending_local_commitment,
                                                                  pcp=pcp,
                                                                  subject=LOCAL,
                                                                  ctn=next_local_ctn)
        if len(htlc_to_ctx_output_idx_map) != len(htlc_sigs):
            raise Exception(f'htlc sigs failure. recv {len(htlc_sigs)} sigs, expected {len(htlc_to_ctx_output_idx_map)}')
        for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
            htlc_sig = htlc_sigs[htlc_relative_idx]
            self.verify_htlc(htlc=htlc,
                             htlc_sig=htlc_sig,
                             htlc_direction=direction,
                             pcp=pcp,
                             ctx=pending_local_commitment,
                             ctx_output_idx=ctx_output_idx)
        with self.db_lock:
            self.hm.recv_ctx()
            self.config[LOCAL].current_commitment_signature=sig
            self.config[LOCAL].current_htlc_signatures=htlc_sigs_string

    def verify_htlc(self, *, htlc: UpdateAddHtlc, htlc_sig: bytes, htlc_direction: Direction,
                    pcp: bytes, ctx: Transaction, ctx_output_idx: int) -> None:
        _script, htlc_tx = make_htlc_tx_with_open_channel(chan=self,
                                                          pcp=pcp,
                                                          subject=LOCAL,
                                                          htlc_direction=htlc_direction,
                                                          commit=ctx,
                                                          ctx_output_idx=ctx_output_idx,
                                                          htlc=htlc)
        pre_hash = sha256d(bfh(htlc_tx.serialize_preimage(0)))
        remote_htlc_pubkey = derive_pubkey(self.config[REMOTE].htlc_basepoint.pubkey, pcp)
        if not ecc.verify_signature(remote_htlc_pubkey, htlc_sig, pre_hash):
            raise Exception(f'failed verifying HTLC signatures: {htlc} {htlc_direction}')

    def get_remote_htlc_sig_for_htlc(self, *, htlc_relative_idx: int) -> bytes:
        data = self.config[LOCAL].current_htlc_signatures
        htlc_sigs = [data[i:i + 64] for i in range(0, len(data), 64)]
        htlc_sig = htlc_sigs[htlc_relative_idx]
        remote_htlc_sig = ecc.der_sig_from_sig_string(htlc_sig) + b'\x01'
        return remote_htlc_sig

    def revoke_current_commitment(self):
        self.logger.info("revoke_current_commitment")
        new_ctn = self.get_latest_ctn(LOCAL)
        new_ctx = self.get_latest_commitment(LOCAL)
        if not self.signature_fits(new_ctx):
            # this should never fail; as receive_new_commitment already did this test
            raise Exception("refusing to revoke as remote sig does not fit")
        with self.db_lock:
            self.hm.send_rev()
        if self.lnworker:
            received = self.hm.received_in_ctn(new_ctn)
            for htlc in received:
                self.lnworker.payment_received(self, htlc.payment_hash)
        last_secret, last_point = self.get_secret_and_point(LOCAL, new_ctn - 1)
        next_secret, next_point = self.get_secret_and_point(LOCAL, new_ctn + 1)
        return RevokeAndAck(last_secret, next_point)

    def receive_revocation(self, revocation: RevokeAndAck):
        self.logger.info("receive_revocation")
        new_ctn = self.get_latest_ctn(REMOTE)
        cur_point = self.config[REMOTE].current_per_commitment_point
        derived_point = ecc.ECPrivkey(revocation.per_commitment_secret).get_public_key_bytes(compressed=True)
        if cur_point != derived_point:
            raise Exception('revoked secret not for current point')
        with self.db_lock:
            self.revocation_store.add_next_entry(revocation.per_commitment_secret)
            ##### start applying fee/htlc changes
            self.hm.recv_rev()
            self.config[REMOTE].current_per_commitment_point=self.config[REMOTE].next_per_commitment_point
            self.config[REMOTE].next_per_commitment_point=revocation.next_per_commitment_point
        # lnworker callbacks
        if self.lnworker:
            sent = self.hm.sent_in_ctn(new_ctn)
            for htlc in sent:
                self.lnworker.payment_sent(self, htlc.payment_hash)
            failed = self.hm.failed_in_ctn(new_ctn)
            for htlc in failed:
                payment_attempt = self._receive_fail_reasons.get(htlc.htlc_id)
                self.lnworker.payment_failed(self, htlc.payment_hash, payment_attempt)

    def balance(self, whose: HTLCOwner, *, ctx_owner=HTLCOwner.LOCAL, ctn: int = None) -> int:
        """This balance (in msat) only considers HTLCs that have been settled by ctn.
        It disregards reserve, fees, and pending HTLCs (in both directions).
        """
        assert type(whose) is HTLCOwner
        initial = self.config[whose].initial_msat
        return self.hm.get_balance_msat(whose=whose,
                                        ctx_owner=ctx_owner,
                                        ctn=ctn,
                                        initial_balance_msat=initial)

    def balance_minus_outgoing_htlcs(self, whose: HTLCOwner, *, ctx_owner: HTLCOwner = HTLCOwner.LOCAL,
                                     ctn: int = None):
        """This balance (in msat), which includes the value of
        pending outgoing HTLCs, is used in the UI.
        """
        assert type(whose) is HTLCOwner
        if ctn is None:
            ctn = self.get_next_ctn(ctx_owner)
        committed_balance = self.balance(whose, ctx_owner=ctx_owner, ctn=ctn)
        direction = RECEIVED if whose != ctx_owner else SENT
        balance_in_htlcs = self.balance_tied_up_in_htlcs_by_direction(ctx_owner, ctn=ctn, direction=direction)
        return committed_balance - balance_in_htlcs

    def balance_tied_up_in_htlcs_by_direction(self, ctx_owner: HTLCOwner = LOCAL, *, ctn: int = None,
                                              direction: Direction):
        # in msat
        if ctn is None:
            ctn = self.get_next_ctn(ctx_owner)
        return htlcsum(self.hm.htlcs_by_direction(ctx_owner, direction, ctn).values())

    def available_to_spend(self, subject: HTLCOwner, *, strict: bool = True) -> int:
        """The usable balance of 'subject' in msat, after taking reserve and fees into
        consideration. Note that fees (and hence the result) fluctuate even without user interaction.
        """
        assert type(subject) is HTLCOwner
        sender = subject
        receiver = subject.inverted()
        ctx_owner = receiver
        # TODO but what about the other ctx? BOLT-02 only talks about checking the receiver's ctx,
        #      however the channel reserve is only meaningful if we also check the sender's ctx!
        #      in particular, note that dust limits can be different between the parties!
        #      but due to the racy nature of this, we cannot be sure exactly what the sender's
        #      next ctx will look like (e.g. what feerate it will use). hmmm :/
        ctn = self.get_next_ctn(ctx_owner)
        sender_balance_msat = self.balance_minus_outgoing_htlcs(whose=sender, ctx_owner=ctx_owner, ctn=ctn)
        receiver_balance_msat = self.balance_minus_outgoing_htlcs(whose=receiver, ctx_owner=ctx_owner, ctn=ctn)
        sender_reserve_msat = self.config[receiver].reserve_sat * 1000
        receiver_reserve_msat = self.config[sender].reserve_sat * 1000
        initiator = LOCAL if self.constraints.is_initiator else REMOTE
        # the initiator/funder pays on-chain fees
        num_htlcs_in_ctx = len(self.included_htlcs(ctx_owner, SENT, ctn=ctn) + self.included_htlcs(ctx_owner, RECEIVED, ctn=ctn))
        feerate = self.get_feerate(ctx_owner, ctn=ctn)
        ctx_fees_msat = calc_fees_for_commitment_tx(
            num_htlcs=num_htlcs_in_ctx,
            feerate=feerate,
            is_local_initiator=self.constraints.is_initiator,
            round_to_sat=False,
        )
        # note: if this supposed new HTLC is large enough to create an output, the initiator needs to pay for that too
        # note: if sender != initiator, both the sender and the receiver need to "afford" the payment
        htlc_fee_msat = fee_for_htlc_output(feerate=feerate)
        # TODO stuck channels. extra funder reserve? "fee spike buffer" (maybe only if "strict")
        #      see https://github.com/lightningnetwork/lightning-rfc/issues/728
        # note: in terms of on-chain outputs, as we are considering the htlc_receiver's ctx, this is a "received" HTLC
        htlc_trim_threshold_msat = received_htlc_trim_threshold_sat(dust_limit_sat=self.config[receiver].dust_limit_sat, feerate=feerate) * 1000
        if strict:
            # also consider the other ctx, where the trim threshold is different
            # note: the 'feerate' we use is not technically correct but we have no way
            #       of knowing the actual future feerate ahead of time (this is a protocol bug)
            htlc_trim_threshold_msat = min(htlc_trim_threshold_msat,
                                           offered_htlc_trim_threshold_sat(dust_limit_sat=self.config[sender].dust_limit_sat, feerate=feerate) * 1000)
        max_send_msat = sender_balance_msat - sender_reserve_msat - ctx_fees_msat[sender]
        if max_send_msat < htlc_trim_threshold_msat:
            # there will be no corresponding HTLC output
            return max_send_msat
        if sender == initiator:
            max_send_after_htlc_fee_msat = max_send_msat - htlc_fee_msat
            max_send_msat = max(htlc_trim_threshold_msat - 1, max_send_after_htlc_fee_msat)
            return max_send_msat
        else:
            # the receiver is the initiator, so they need to be able to pay tx fees
            if receiver_balance_msat - receiver_reserve_msat - ctx_fees_msat[receiver] - htlc_fee_msat < 0:
                max_send_msat = htlc_trim_threshold_msat - 1
            return max_send_msat

    def included_htlcs(self, subject: HTLCOwner, direction: Direction, ctn: int = None) -> Sequence[UpdateAddHtlc]:
        """
        return filter of non-dust htlcs for subjects commitment transaction, initiated by given party
        """
        assert type(subject) is HTLCOwner
        assert type(direction) is Direction
        if ctn is None:
            ctn = self.get_oldest_unrevoked_ctn(subject)
        feerate = self.get_feerate(subject, ctn)
        conf = self.config[subject]
        if direction == RECEIVED:
            threshold_sat = received_htlc_trim_threshold_sat(dust_limit_sat=conf.dust_limit_sat, feerate=feerate)
        else:
            threshold_sat = offered_htlc_trim_threshold_sat(dust_limit_sat=conf.dust_limit_sat, feerate=feerate)
        htlcs = self.hm.htlcs_by_direction(subject, direction, ctn=ctn).values()
        return list(filter(lambda htlc: htlc.amount_msat // 1000 >= threshold_sat, htlcs))

    def get_secret_and_point(self, subject: HTLCOwner, ctn: int) -> Tuple[Optional[bytes], bytes]:
        assert type(subject) is HTLCOwner
        assert ctn >= 0, ctn
        offset = ctn - self.get_oldest_unrevoked_ctn(subject)
        if subject == REMOTE:
            if offset > 1:
                raise RemoteCtnTooFarInFuture(f"offset: {offset}")
            conf = self.config[REMOTE]
            if offset == 1:
                secret = None
                point = conf.next_per_commitment_point
            elif offset == 0:
                secret = None
                point = conf.current_per_commitment_point
            else:
                secret = self.revocation_store.retrieve_secret(RevocationStore.START_INDEX - ctn)
                point = secret_to_pubkey(int.from_bytes(secret, 'big'))
        else:
            secret = get_per_commitment_secret_from_seed(self.config[LOCAL].per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
            point = secret_to_pubkey(int.from_bytes(secret, 'big'))
        return secret, point

    def get_secret_and_commitment(self, subject, ctn):
        secret, point = self.get_secret_and_point(subject, ctn)
        ctx = self.make_commitment(subject, point, ctn)
        return secret, ctx

    def get_commitment(self, subject, ctn) -> PartialTransaction:
        secret, ctx = self.get_secret_and_commitment(subject, ctn)
        return ctx

    def get_next_commitment(self, subject: HTLCOwner) -> PartialTransaction:
        ctn = self.get_next_ctn(subject)
        return self.get_commitment(subject, ctn)

    def get_latest_commitment(self, subject: HTLCOwner) -> PartialTransaction:
        ctn = self.get_latest_ctn(subject)
        return self.get_commitment(subject, ctn)

    def get_oldest_unrevoked_commitment(self, subject: HTLCOwner) -> PartialTransaction:
        ctn = self.get_oldest_unrevoked_ctn(subject)
        return self.get_commitment(subject, ctn)

    def create_sweeptxs(self, ctn: int) -> List[Transaction]:
        from .lnsweep import create_sweeptxs_for_watchtower
        secret, ctx = self.get_secret_and_commitment(REMOTE, ctn)
        return create_sweeptxs_for_watchtower(self, ctx, secret, self.sweep_address)

    def get_oldest_unrevoked_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_oldest_unrevoked(subject)

    def get_latest_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_latest(subject)

    def get_next_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_latest(subject) + 1

    def total_msat(self, direction):
        """Return the cumulative total msat amount received/sent so far."""
        assert type(direction) is Direction
        return htlcsum(self.hm.all_settled_htlcs_ever_by_direction(LOCAL, direction))

    def settle_htlc(self, preimage, htlc_id):
        """
        SettleHTLC attempts to settle an existing outstanding received HTLC.
        """
        self.logger.info("settle_htlc")
        assert self.can_send_ctx_updates(), f"cannot update channel. {self.get_state()!r} {self.peer_state!r}"
        log = self.hm.log[REMOTE]
        htlc = log['adds'][htlc_id]
        assert htlc.payment_hash == sha256(preimage)
        assert htlc_id not in log['settles']
        self.hm.send_settle(htlc_id)

    def get_payment_hash(self, htlc_id):
        log = self.hm.log[LOCAL]
        htlc = log['adds'][htlc_id]
        return htlc.payment_hash

    def decode_onion_error(self, reason: bytes, route: Sequence['RouteEdge'],
                           htlc_id: int) -> Tuple[OnionRoutingFailureMessage, int]:
        failure_msg, sender_idx = decode_onion_error(
            reason,
            [x.node_id for x in route],
            self.onion_keys[htlc_id])
        return failure_msg, sender_idx

    def receive_htlc_settle(self, preimage, htlc_id):
        self.logger.info("receive_htlc_settle")
        log = self.hm.log[LOCAL]
        htlc = log['adds'][htlc_id]
        assert htlc.payment_hash == sha256(preimage)
        assert htlc_id not in log['settles']
        with self.db_lock:
            self.hm.recv_settle(htlc_id)

    def fail_htlc(self, htlc_id):
        self.logger.info("fail_htlc")
        assert self.can_send_ctx_updates(), f"cannot update channel. {self.get_state()!r} {self.peer_state!r}"
        with self.db_lock:
            self.hm.send_fail(htlc_id)

    def receive_fail_htlc(self, htlc_id: int, *,
                          error_bytes: Optional[bytes],
                          reason: Optional[OnionRoutingFailureMessage] = None):
        self.logger.info("receive_fail_htlc")
        with self.db_lock:
            self.hm.recv_fail(htlc_id)
        self._receive_fail_reasons[htlc_id] = BarePaymentAttemptLog(success=False,
                                                                    preimage=None,
                                                                    error_bytes=error_bytes,
                                                                    error_reason=reason)

    def pending_local_fee(self):
        return self.constraints.capacity - sum(x.value for x in self.get_next_commitment(LOCAL).outputs())

    def get_latest_fee(self, subject):
        return self.constraints.capacity - sum(x.value for x in self.get_latest_commitment(subject).outputs())

    def update_fee(self, feerate: int, from_us: bool):
        # feerate uses sat/kw
        if self.constraints.is_initiator != from_us:
            raise Exception(f"Cannot update_fee: wrong initiator. us: {from_us}")
        # TODO check that funder can afford the new on-chain fees (+ channel reserve)
        #      (maybe check both ctxs, at least if from_us is True??)
        with self.db_lock:
            if from_us:
                assert self.can_send_ctx_updates(), f"cannot update channel. {self.get_state()!r} {self.peer_state!r}"
                self.hm.send_update_fee(feerate)
            else:
                self.hm.recv_update_fee(feerate)

    def make_commitment(self, subject, this_point, ctn) -> PartialTransaction:
        assert type(subject) is HTLCOwner
        feerate = self.get_feerate(subject, ctn)
        other = subject.inverted()
        local_msat = self.balance(subject, ctx_owner=subject, ctn=ctn)
        remote_msat = self.balance(other, ctx_owner=subject, ctn=ctn)
        received_htlcs = self.hm.htlcs_by_direction(subject, RECEIVED, ctn).values()
        sent_htlcs = self.hm.htlcs_by_direction(subject, SENT, ctn).values()
        remote_msat -= htlcsum(received_htlcs)
        local_msat -= htlcsum(sent_htlcs)
        assert remote_msat >= 0
        assert local_msat >= 0
        # same htlcs as before, but now without dust.
        received_htlcs = self.included_htlcs(subject, RECEIVED, ctn)
        sent_htlcs = self.included_htlcs(subject, SENT, ctn)

        this_config = self.config[subject]
        other_config = self.config[-subject]
        other_htlc_pubkey = derive_pubkey(other_config.htlc_basepoint.pubkey, this_point)
        this_htlc_pubkey = derive_pubkey(this_config.htlc_basepoint.pubkey, this_point)
        other_revocation_pubkey = derive_blinded_pubkey(other_config.revocation_basepoint.pubkey, this_point)
        htlcs = []  # type: List[ScriptHtlc]
        for is_received_htlc, htlc_list in zip((True, False), (received_htlcs, sent_htlcs)):
            for htlc in htlc_list:
                htlcs.append(ScriptHtlc(make_htlc_output_witness_script(
                    is_received_htlc=is_received_htlc,
                    remote_revocation_pubkey=other_revocation_pubkey,
                    remote_htlc_pubkey=other_htlc_pubkey,
                    local_htlc_pubkey=this_htlc_pubkey,
                    payment_hash=htlc.payment_hash,
                    cltv_expiry=htlc.cltv_expiry), htlc))
        # note: maybe flip initiator here for fee purposes, we want LOCAL and REMOTE
        #       in the resulting dict to correspond to the to_local and to_remote *outputs* of the ctx
        onchain_fees = calc_fees_for_commitment_tx(
            num_htlcs=len(htlcs),
            feerate=feerate,
            is_local_initiator=self.constraints.is_initiator == (subject == LOCAL),
        )

        # TODO: we need to also include the respective channel reserves here, but not at the
        #       beginning of the channel lifecycle when the reserve might not be met yet
        if remote_msat - onchain_fees[REMOTE] < 0:
            raise Exception(f"negative remote_msat in make_commitment: {remote_msat}")
        if local_msat - onchain_fees[LOCAL] < 0:
            raise Exception(f"negative local_msat in make_commitment: {local_msat}")

        if self.is_static_remotekey_enabled():
            payment_pubkey = other_config.payment_basepoint.pubkey
        else:
            payment_pubkey = derive_pubkey(other_config.payment_basepoint.pubkey, this_point)

        return make_commitment(
            ctn,
            this_config.multisig_key.pubkey,
            other_config.multisig_key.pubkey,
            payment_pubkey,
            self.config[LOCAL if     self.constraints.is_initiator else REMOTE].payment_basepoint.pubkey,
            self.config[LOCAL if not self.constraints.is_initiator else REMOTE].payment_basepoint.pubkey,
            other_revocation_pubkey,
            derive_pubkey(this_config.delayed_basepoint.pubkey, this_point),
            other_config.to_self_delay,
            self.funding_outpoint.txid,
            self.funding_outpoint.output_index,
            self.constraints.capacity,
            local_msat,
            remote_msat,
            this_config.dust_limit_sat,
            onchain_fees,
            htlcs=htlcs)

    def make_closing_tx(self, local_script: bytes, remote_script: bytes,
                        fee_sat: int, *, drop_remote = False) -> Tuple[bytes, PartialTransaction]:
        """ cooperative close """
        _, outputs = make_commitment_outputs(
                fees_per_participant={
                    LOCAL:  fee_sat * 1000 if     self.constraints.is_initiator else 0,
                    REMOTE: fee_sat * 1000 if not self.constraints.is_initiator else 0,
                },
                local_amount_msat=self.balance(LOCAL),
                remote_amount_msat=self.balance(REMOTE) if not drop_remote else 0,
                local_script=bh2u(local_script),
                remote_script=bh2u(remote_script),
                htlcs=[],
                dust_limit_sat=self.config[LOCAL].dust_limit_sat)

        closing_tx = make_closing_tx(self.config[LOCAL].multisig_key.pubkey,
                                     self.config[REMOTE].multisig_key.pubkey,
                                     funding_txid=self.funding_outpoint.txid,
                                     funding_pos=self.funding_outpoint.output_index,
                                     funding_sat=self.constraints.capacity,
                                     outputs=outputs)

        der_sig = bfh(closing_tx.sign_txin(0, self.config[LOCAL].multisig_key.privkey))
        sig = ecc.sig_string_from_der_sig(der_sig[:-1])
        return sig, closing_tx

    def signature_fits(self, tx: PartialTransaction):
        remote_sig = self.config[LOCAL].current_commitment_signature
        preimage_hex = tx.serialize_preimage(0)
        msg_hash = sha256d(bfh(preimage_hex))
        assert remote_sig
        res = ecc.verify_signature(self.config[REMOTE].multisig_key.pubkey, remote_sig, msg_hash)
        return res

    def force_close_tx(self):
        tx = self.get_latest_commitment(LOCAL)
        assert self.signature_fits(tx)
        tx.sign({bh2u(self.config[LOCAL].multisig_key.pubkey): (self.config[LOCAL].multisig_key.privkey, True)})
        remote_sig = self.config[LOCAL].current_commitment_signature
        remote_sig = ecc.der_sig_from_sig_string(remote_sig) + b"\x01"
        tx.add_signature_to_txin(txin_idx=0,
                                 signing_pubkey=self.config[REMOTE].multisig_key.pubkey.hex(),
                                 sig=remote_sig.hex())
        assert tx.is_complete()
        return tx

    def sweep_ctx(self, ctx: Transaction) -> Dict[str, SweepInfo]:
        txid = ctx.txid()
        if self.sweep_info.get(txid) is None:
            our_sweep_info = create_sweeptxs_for_our_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)
            their_sweep_info = create_sweeptxs_for_their_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)
            if our_sweep_info is not None:
                self.sweep_info[txid] = our_sweep_info
                self.logger.info(f'we force closed.')
            elif their_sweep_info is not None:
                self.sweep_info[txid] = their_sweep_info
                self.logger.info(f'they force closed.')
            else:
                self.sweep_info[txid] = {}
        return self.sweep_info[txid]

    def sweep_htlc(self, ctx:Transaction, htlc_tx: Transaction):
        # look at the output address, check if it matches
        return create_sweeptx_for_their_revoked_htlc(self, ctx, htlc_tx, self.sweep_address)

    def has_pending_changes(self, subject):
        next_htlcs = self.hm.get_htlcs_in_next_ctx(subject)
        latest_htlcs = self.hm.get_htlcs_in_latest_ctx(subject)
        return not (next_htlcs == latest_htlcs and self.get_next_feerate(subject) == self.get_latest_feerate(subject))
