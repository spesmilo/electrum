# Copyright (C) 2018 The Electrum developers
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
import enum
import os
from collections import namedtuple, defaultdict
import binascii
import json
from enum import IntEnum, Enum
from typing import (Optional, Dict, List, Tuple, NamedTuple, Set, Callable,
                    Iterable, Sequence, TYPE_CHECKING, Iterator, Union, Mapping)
import time
import threading
from abc import ABC, abstractmethod
import itertools

from aiorpcx import NetAddress
import attr

from . import ecc
from .ecc import ECPubkey
from . import constants, util
from .util import bfh, chunks, TxMinedInfo
from .invoices import PR_PAID
from .bitcoin import redeem_script_to_address
from .crypto import sha256, sha256d
from .transaction import Transaction, PartialTransaction, TxInput, Sighash
from .logging import Logger
from .lnonion import OnionFailureCode, OnionRoutingFailure
from . import lnutil
from .lnutil import (Outpoint, LocalConfig, RemoteConfig, Keypair, OnlyPubkeyKeypair, ChannelConstraints,
                     get_per_commitment_secret_from_seed, secret_to_pubkey, derive_privkey, make_closing_tx,
                     sign_and_get_sig_string, RevocationStore, derive_blinded_pubkey, Direction, derive_pubkey,
                     make_htlc_tx_with_open_channel, make_commitment, make_received_htlc, make_offered_htlc,
                     HTLC_TIMEOUT_WEIGHT, HTLC_SUCCESS_WEIGHT, extract_ctn_from_tx_and_chan, UpdateAddHtlc,
                     funding_output_script, SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, make_commitment_outputs,
                     ScriptHtlc, PaymentFailure, calc_fees_for_commitment_tx, RemoteMisbehaving, make_htlc_output_witness_script,
                     ShortChannelID, map_htlcs_to_ctx_output_idxs, LNPeerAddr,
                     fee_for_htlc_output, offered_htlc_trim_threshold_sat,
                     received_htlc_trim_threshold_sat, make_commitment_output_to_remote_address,
                     ChannelType, LNProtocolWarning)
from .lnsweep import create_sweeptxs_for_our_ctx, create_sweeptxs_for_their_ctx
from .lnsweep import create_sweeptx_for_their_revoked_htlc, SweepInfo
from .lnhtlc import HTLCManager
from .lnmsg import encode_msg, decode_msg
from .address_synchronizer import TX_HEIGHT_LOCAL
from .lnutil import CHANNEL_OPENING_TIMEOUT
from .lnutil import ChannelBackupStorage, ImportedChannelBackupStorage, OnchainChannelBackupStorage
from .lnutil import format_short_channel_id
from .simple_config import FEERATE_PER_KW_MIN_RELAY_LIGHTNING

if TYPE_CHECKING:
    from .lnworker import LNWallet
    from .json_db import StoredDict
    from .lnrouter import RouteEdge

# channel flags
CF_ANNOUNCE_CHANNEL = 0x01

# lightning channel states
# Note: these states are persisted by name (for a given channel) in the wallet file,
#       so consider doing a wallet db upgrade when changing them.
class ChannelState(IntEnum):
    PREOPENING      = 0  # Initial negotiation. Channel will not be reestablished
    OPENING         = 1  # Channel will be reestablished. (per BOLT2)
                         #  - Funding node: has received funding_signed (can broadcast the funding tx)
                         #  - Non-funding node: has sent the funding_signed message.
    FUNDED          = 2  # Funding tx was mined (requires min_depth and tx verification)
    OPEN            = 3  # both parties have sent funding_locked
    SHUTDOWN        = 4  # shutdown has been sent.
    CLOSING         = 5  # closing negotiation done. we have a fully signed tx.
    FORCE_CLOSING   = 6  # *we* force-closed, and closing tx is unconfirmed. Note that if the
                         # remote force-closes then we remain OPEN until it gets mined -
                         # the server could be lying to us with a fake tx.
    REQUESTED_FCLOSE = 7   # Chan is open, but we have tried to request the *remote* to force-close
    WE_ARE_TOXIC     = 8   # Chan is open, but we have lost state and the remote proved this.
                           # The remote must force-close, it is *not* safe for us to do so.
    CLOSED           = 9   # closing tx has been mined
    REDEEMED         = 10  # we can stop watching


class PeerState(IntEnum):
    DISCONNECTED   = 0
    REESTABLISHING = 1
    GOOD           = 2
    BAD            = 3


cs = ChannelState
state_transitions = [
    (cs.PREOPENING, cs.OPENING),
    (cs.OPENING, cs.FUNDED),
    (cs.FUNDED, cs.OPEN),
    (cs.OPENING, cs.SHUTDOWN),
    (cs.FUNDED, cs.SHUTDOWN),
    (cs.OPEN, cs.SHUTDOWN),
    (cs.SHUTDOWN, cs.SHUTDOWN),  # if we reestablish
    (cs.SHUTDOWN, cs.CLOSING),
    (cs.CLOSING, cs.CLOSING),
    # we can force close almost any time
    (cs.OPENING,  cs.FORCE_CLOSING),
    (cs.FUNDED,   cs.FORCE_CLOSING),
    (cs.OPEN,     cs.FORCE_CLOSING),
    (cs.SHUTDOWN, cs.FORCE_CLOSING),
    (cs.CLOSING,  cs.FORCE_CLOSING),
    (cs.REQUESTED_FCLOSE, cs.FORCE_CLOSING),
    # we can request a force-close almost any time
    (cs.OPENING,  cs.REQUESTED_FCLOSE),
    (cs.FUNDED,   cs.REQUESTED_FCLOSE),
    (cs.OPEN,     cs.REQUESTED_FCLOSE),
    (cs.SHUTDOWN, cs.REQUESTED_FCLOSE),
    (cs.CLOSING,  cs.REQUESTED_FCLOSE),
    (cs.REQUESTED_FCLOSE,  cs.REQUESTED_FCLOSE),
    # we can get force closed almost any time
    (cs.OPENING,  cs.CLOSED),
    (cs.FUNDED,   cs.CLOSED),
    (cs.OPEN,     cs.CLOSED),
    (cs.SHUTDOWN, cs.CLOSED),
    (cs.CLOSING,  cs.CLOSED),
    (cs.REQUESTED_FCLOSE, cs.CLOSED),
    (cs.WE_ARE_TOXIC,          cs.CLOSED),
    # during channel_reestablish, we might realise we have lost state
    (cs.OPENING,  cs.WE_ARE_TOXIC),
    (cs.FUNDED,   cs.WE_ARE_TOXIC),
    (cs.OPEN,     cs.WE_ARE_TOXIC),
    (cs.SHUTDOWN, cs.WE_ARE_TOXIC),
    (cs.REQUESTED_FCLOSE, cs.WE_ARE_TOXIC),
    (cs.WE_ARE_TOXIC, cs.WE_ARE_TOXIC),
    #
    (cs.FORCE_CLOSING, cs.FORCE_CLOSING),  # allow multiple attempts
    (cs.FORCE_CLOSING, cs.CLOSED),
    (cs.FORCE_CLOSING, cs.REDEEMED),
    (cs.CLOSED, cs.REDEEMED),
    (cs.OPENING, cs.REDEEMED),  # channel never funded (dropped from mempool)
    (cs.PREOPENING, cs.REDEEMED),  # channel never funded
]
del cs  # delete as name is ambiguous without context


class ChanCloseOption(Enum):
    COOP_CLOSE = enum.auto()
    LOCAL_FCLOSE = enum.auto()
    REQUEST_REMOTE_FCLOSE = enum.auto()


class RevokeAndAck(NamedTuple):
    per_commitment_secret: bytes
    next_per_commitment_point: bytes


class RemoteCtnTooFarInFuture(Exception): pass


def htlcsum(htlcs: Iterable[UpdateAddHtlc]):
    return sum([x.amount_msat for x in htlcs])

def now():
    return int(time.time())

class HTLCWithStatus(NamedTuple):
    channel_id: bytes
    htlc: UpdateAddHtlc
    direction: Direction
    status: str


class AbstractChannel(Logger, ABC):
    storage: Union['StoredDict', dict]
    config: Dict[HTLCOwner, Union[LocalConfig, RemoteConfig]]
    _sweep_info: Dict[str, Dict[str, 'SweepInfo']]
    lnworker: Optional['LNWallet']
    channel_id: bytes
    short_channel_id: Optional[ShortChannelID] = None
    funding_outpoint: Outpoint
    node_id: bytes  # note that it might not be the full 33 bytes; for OCB it is only the prefix
    _state: ChannelState
    sweep_address: str

    def set_short_channel_id(self, short_id: ShortChannelID) -> None:
        self.short_channel_id = short_id
        self.storage["short_channel_id"] = short_id

    def get_id_for_log(self) -> str:
        scid = self.short_channel_id
        if scid:
            return str(scid)
        return self.channel_id.hex()

    def short_id_for_GUI(self) -> str:
        return format_short_channel_id(self.short_channel_id)

    def diagnostic_name(self):
        return self.get_id_for_log()

    def set_state(self, state: ChannelState, *, force: bool = False) -> None:
        """Set on-chain state.
        `force` can be set while debugging from the console to allow illegal transitions.
        """
        old_state = self._state
        if not force and (old_state, state) not in state_transitions:
            raise Exception(f"Transition not allowed: {old_state.name} -> {state.name}")
        self.logger.debug(f'Setting channel state: {old_state.name} -> {state.name}')
        self._state = state
        self.storage['state'] = self._state.name
        if self.lnworker:
            self.lnworker.channel_state_changed(self)

    def get_state(self) -> ChannelState:
        return self._state

    def is_funded(self):
        return self.get_state() >= ChannelState.FUNDED

    def is_open(self):
        return self.get_state() == ChannelState.OPEN

    def is_closed(self):
        # the closing txid has been saved
        return self.get_state() >= ChannelState.CLOSING

    def is_redeemed(self):
        return self.get_state() == ChannelState.REDEEMED

    def need_to_subscribe(self) -> bool:
        """Whether lnwatcher/synchronizer need to be watching this channel."""
        if not self.is_redeemed():
            return True
        # Chan already deeply closed. Still, if some txs are missing, we should sub.
        # check we have funding tx
        # note: tx might not be directly related to the wallet, e.g. chan opened by remote
        if (funding_item := self.get_funding_height()) is None:
            return True
        if self.lnworker:
            funding_txid, funding_height, funding_timestamp = funding_item
            if self.lnworker.wallet.adb.get_transaction(funding_txid) is None:
                return True
        # check we have closing tx
        # note: tx might not be directly related to the wallet, e.g. local-fclose
        if (closing_item := self.get_closing_height()) is None:
            return True
        if self.lnworker:
            closing_txid, closing_height, closing_timestamp = closing_item
            if self.lnworker.wallet.adb.get_transaction(closing_txid) is None:
                return True
        return False

    @abstractmethod
    def get_close_options(self) -> Sequence[ChanCloseOption]:
        pass

    def save_funding_height(self, *, txid: str, height: int, timestamp: Optional[int]) -> None:
        self.storage['funding_height'] = txid, height, timestamp

    def get_funding_height(self):
        return self.storage.get('funding_height')

    def delete_funding_height(self):
        self.storage.pop('funding_height', None)

    def save_closing_height(self, *, txid: str, height: int, timestamp: Optional[int]) -> None:
        self.storage['closing_height'] = txid, height, timestamp

    def get_closing_height(self):
        return self.storage.get('closing_height')

    def delete_closing_height(self):
        self.storage.pop('closing_height', None)

    def create_sweeptxs_for_our_ctx(self, ctx):
        return create_sweeptxs_for_our_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)

    def create_sweeptxs_for_their_ctx(self, ctx):
        return create_sweeptxs_for_their_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)

    def is_backup(self):
        return False

    def get_local_scid_alias(self, *, create_new_if_needed: bool = False) -> Optional[bytes]:
        return None

    def get_remote_scid_alias(self) -> Optional[bytes]:
        return None

    def sweep_ctx(self, ctx: Transaction) -> Dict[str, SweepInfo]:
        txid = ctx.txid()
        if self._sweep_info.get(txid) is None:
            our_sweep_info = self.create_sweeptxs_for_our_ctx(ctx)
            their_sweep_info = self.create_sweeptxs_for_their_ctx(ctx)
            if our_sweep_info:
                self._sweep_info[txid] = our_sweep_info
                self.logger.info(f'we (local) force closed')
            elif their_sweep_info:
                self._sweep_info[txid] = their_sweep_info
                self.logger.info(f'they (remote) force closed.')
            else:
                self._sweep_info[txid] = {}
                self.logger.info(f'not sure who closed.')
        return self._sweep_info[txid]

    def maybe_sweep_revoked_htlc(self, ctx: Transaction, htlc_tx: Transaction) -> Optional[SweepInfo]:
        return None

    def extract_preimage_from_htlc_txin(self, txin: TxInput) -> None:
        return

    def update_onchain_state(self, *, funding_txid: str, funding_height: TxMinedInfo,
                             closing_txid: str, closing_height: TxMinedInfo, keep_watching: bool) -> None:
        # note: state transitions are irreversible, but
        # save_funding_height, save_closing_height are reversible
        if funding_height.height == TX_HEIGHT_LOCAL:
            self.update_unfunded_state()
        elif closing_height.height == TX_HEIGHT_LOCAL:
            self.update_funded_state(
                funding_txid=funding_txid,
                funding_height=funding_height)
        else:
            self.update_closed_state(
                funding_txid=funding_txid,
                funding_height=funding_height,
                closing_txid=closing_txid,
                closing_height=closing_height,
                keep_watching=keep_watching)

    def update_unfunded_state(self):
        self.delete_funding_height()
        self.delete_closing_height()
        if self.get_state() in [ChannelState.PREOPENING, ChannelState.OPENING, ChannelState.FORCE_CLOSING] and self.lnworker:
            if self.is_initiator():
                # set channel state to REDEEMED so that it can be removed manually
                # to protect ourselves against a server lying by omission,
                # we check that funding_inputs have been double spent and deeply mined
                inputs = self.storage.get('funding_inputs', [])
                if not inputs:
                    self.logger.info(f'channel funding inputs are not provided')
                    self.set_state(ChannelState.REDEEMED)
                for i in inputs:
                    spender_txid = self.lnworker.wallet.db.get_spent_outpoint(*i)
                    if spender_txid is None:
                        continue
                    if spender_txid != self.funding_outpoint.txid:
                        tx_mined_height = self.lnworker.wallet.adb.get_tx_height(spender_txid)
                        if tx_mined_height.conf > lnutil.REDEEM_AFTER_DOUBLE_SPENT_DELAY:
                            self.logger.info(f'channel is double spent {inputs}')
                            self.set_state(ChannelState.REDEEMED)
                            break
            else:
                if self.lnworker and (now() - self.storage.get('init_timestamp', 0) > CHANNEL_OPENING_TIMEOUT):
                    self.lnworker.remove_channel(self.channel_id)

    def update_funded_state(self, *, funding_txid: str, funding_height: TxMinedInfo) -> None:
        self.save_funding_height(txid=funding_txid, height=funding_height.height, timestamp=funding_height.timestamp)
        self.delete_closing_height()
        if funding_height.conf>0:
            self.set_short_channel_id(ShortChannelID.from_components(
                funding_height.height, funding_height.txpos, self.funding_outpoint.output_index))
        if self.get_state() == ChannelState.OPENING:
            if self.is_funding_tx_mined(funding_height):
                self.set_state(ChannelState.FUNDED)

    def update_closed_state(self, *, funding_txid: str, funding_height: TxMinedInfo,
                            closing_txid: str, closing_height: TxMinedInfo, keep_watching: bool) -> None:
        self.save_funding_height(txid=funding_txid, height=funding_height.height, timestamp=funding_height.timestamp)
        self.save_closing_height(txid=closing_txid, height=closing_height.height, timestamp=closing_height.timestamp)
        if funding_height.conf>0:
            self.set_short_channel_id(ShortChannelID.from_components(
                funding_height.height, funding_height.txpos, self.funding_outpoint.output_index))
        if self.get_state() < ChannelState.CLOSED:
            conf = closing_height.conf
            if conf > 0:
                self.set_state(ChannelState.CLOSED)
            else:
                # we must not trust the server with unconfirmed transactions,
                # because the state transition is irreversible. if the remote
                # force closed, we remain OPEN until the closing tx is confirmed
                self.unconfirmed_closing_txid = closing_txid
                if self.lnworker:
                    util.trigger_callback('channel', self.lnworker.wallet, self)

        if self.get_state() == ChannelState.CLOSED and not keep_watching:
            self.set_state(ChannelState.REDEEMED)
            if self.lnworker and self.is_backup():
                # auto-remove redeemed backups
                self.lnworker.remove_channel_backup(self.channel_id)


    @abstractmethod
    def is_initiator(self) -> bool:
        pass

    @abstractmethod
    def is_public(self) -> bool:
        pass

    @abstractmethod
    def is_funding_tx_mined(self, funding_height: TxMinedInfo) -> bool:
        pass

    @abstractmethod
    def get_funding_address(self) -> str:
        pass

    def get_state_for_GUI(self) -> str:
        cs = self.get_state()
        if cs <= ChannelState.OPEN and self.unconfirmed_closing_txid:
            return 'FORCE-CLOSING'
        return cs.name

    @abstractmethod
    def get_oldest_unrevoked_ctn(self, subject: HTLCOwner) -> int:
        pass

    @abstractmethod
    def included_htlcs(self, subject: HTLCOwner, direction: Direction, ctn: int = None) -> Sequence[UpdateAddHtlc]:
        pass

    @abstractmethod
    def funding_txn_minimum_depth(self) -> int:
        pass

    @abstractmethod
    def balance(self, whose: HTLCOwner, *, ctx_owner=HTLCOwner.LOCAL, ctn: int = None) -> int:
        """This balance (in msat) only considers HTLCs that have been settled by ctn.
        It disregards reserve, fees, and pending HTLCs (in both directions).
        """
        pass

    @abstractmethod
    def balance_minus_outgoing_htlcs(self, whose: HTLCOwner, *,
                                     ctx_owner: HTLCOwner = HTLCOwner.LOCAL,
                                     ctn: int = None) -> int:
        """This balance (in msat), which includes the value of
        pending outgoing HTLCs, is used in the UI.
        """
        pass

    @abstractmethod
    def is_frozen_for_sending(self) -> bool:
        """Whether the user has marked this channel as frozen for sending.
        Frozen channels are not supposed to be used for new outgoing payments.
        (note that payment-forwarding ignores this option)
        """
        pass

    @abstractmethod
    def is_frozen_for_receiving(self) -> bool:
        """Whether the user has marked this channel as frozen for receiving.
        Frozen channels are not supposed to be used for new incoming payments.
        (note that payment-forwarding ignores this option)
        """
        pass

    @abstractmethod
    def get_local_pubkey(self) -> bytes:
        """Returns our node ID."""
        pass

    @abstractmethod
    def get_capacity(self) -> Optional[int]:
        """Returns channel capacity in satoshis, or None if unknown."""
        pass

    @abstractmethod
    def can_be_deleted(self) -> bool:
        pass


class ChannelBackup(AbstractChannel):
    """
    current capabilities:
      - detect force close
      - request force close
      - sweep my ctx to_local
    future:
      - will need to sweep their ctx to_remote
    """

    def __init__(self, cb: ChannelBackupStorage, *, lnworker=None):
        self.name = None
        self.cb = cb
        self.is_imported = isinstance(self.cb, ImportedChannelBackupStorage)
        self._sweep_info = {}
        self.storage = {} # dummy storage
        self._state = ChannelState.OPENING
        self.node_id = cb.node_id if self.is_imported else cb.node_id_prefix
        self.channel_id = cb.channel_id()
        self.funding_outpoint = cb.funding_outpoint()
        self.lnworker = lnworker
        self.short_channel_id = None
        Logger.__init__(self)
        self.config = {}
        if self.is_imported:
            assert isinstance(cb, ImportedChannelBackupStorage)
            self.init_config(cb)
        self.unconfirmed_closing_txid = None # not a state, only for GUI

    def init_config(self, cb: ImportedChannelBackupStorage):
        local_payment_pubkey = cb.local_payment_pubkey
        if local_payment_pubkey is None:
            self.logger.warning(
                f"local_payment_pubkey missing from (old-type) channel backup. "
                f"You should export and re-import a newer backup.")
        self.config[LOCAL] = LocalConfig.from_seed(
            channel_seed=cb.channel_seed,
            to_self_delay=cb.local_delay,
            static_remotekey=local_payment_pubkey,
            # dummy values
            dust_limit_sat=None,
            max_htlc_value_in_flight_msat=None,
            max_accepted_htlcs=None,
            initial_msat=None,
            reserve_sat=None,
            funding_locked_received=False,
            current_commitment_signature=None,
            current_htlc_signatures=b'',
            htlc_minimum_msat=1,
            upfront_shutdown_script='',
            announcement_node_sig=b'',
            announcement_bitcoin_sig=b'',
        )
        self.config[REMOTE] = RemoteConfig(
            # payment_basepoint needed to deobfuscate ctn in our_ctx
            payment_basepoint=OnlyPubkeyKeypair(cb.remote_payment_pubkey),
            # revocation_basepoint is used to claim to_local in our ctx
            revocation_basepoint=OnlyPubkeyKeypair(cb.remote_revocation_pubkey),
            to_self_delay=cb.remote_delay,
            # dummy values
            multisig_key=OnlyPubkeyKeypair(None),
            htlc_basepoint=OnlyPubkeyKeypair(None),
            delayed_basepoint=OnlyPubkeyKeypair(None),
            dust_limit_sat=None,
            max_htlc_value_in_flight_msat=None,
            max_accepted_htlcs=None,
            initial_msat = None,
            reserve_sat = None,
            htlc_minimum_msat=None,
            next_per_commitment_point=None,
            current_per_commitment_point=None,
            upfront_shutdown_script='',
            announcement_node_sig=b'',
            announcement_bitcoin_sig=b'',
        )

    def can_be_deleted(self):
        return self.is_imported or self.is_redeemed()

    def get_capacity(self):
        lnwatcher = self.lnworker.lnwatcher
        if lnwatcher:
            # fixme: we should probably not call that method here
            return lnwatcher.adb.get_tx_delta(self.funding_outpoint.txid, self.cb.funding_address)
        return None

    def is_backup(self):
        return True

    def create_sweeptxs_for_their_ctx(self, ctx):
        return {}

    def create_sweeptxs_for_our_ctx(self, ctx):
        if self.is_imported:
            return create_sweeptxs_for_our_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)
        else:
            # backup from op_return
            return {}

    def get_funding_address(self):
        return self.cb.funding_address

    def is_initiator(self):
        return self.cb.is_initiator

    def is_public(self):
        return False

    def get_oldest_unrevoked_ctn(self, who):
        return -1

    def included_htlcs(self, subject, direction, ctn=None):
        return []

    def funding_txn_minimum_depth(self):
        return 1

    def is_funding_tx_mined(self, funding_height):
        return funding_height.conf > 1

    def balance_minus_outgoing_htlcs(self, whose: HTLCOwner, *, ctx_owner: HTLCOwner = HTLCOwner.LOCAL, ctn: int = None):
        return 0

    def balance(self, whose: HTLCOwner, *, ctx_owner=HTLCOwner.LOCAL, ctn: int = None) -> int:
        return 0

    def is_frozen_for_sending(self) -> bool:
        return False

    def is_frozen_for_receiving(self) -> bool:
        return False

    @property
    def sweep_address(self) -> str:
        return self.lnworker.wallet.get_new_sweep_address_for_channel()

    def get_local_pubkey(self) -> bytes:
        cb = self.cb
        assert isinstance(cb, ChannelBackupStorage)
        if isinstance(cb, ImportedChannelBackupStorage):
            return ecc.ECPrivkey(cb.privkey).get_public_key_bytes(compressed=True)
        if isinstance(cb, OnchainChannelBackupStorage):
            return self.lnworker.node_keypair.pubkey
        raise NotImplementedError(f"unexpected cb type: {type(cb)}")

    def get_close_options(self) -> Sequence[ChanCloseOption]:
        ret = []
        if self.get_state() == ChannelState.FUNDED:
            ret.append(ChanCloseOption.REQUEST_REMOTE_FCLOSE)
        return ret


class Channel(AbstractChannel):
    # note: try to avoid naming ctns/ctxs/etc as "current" and "pending".
    #       they are ambiguous. Use "oldest_unrevoked" or "latest" or "next".
    #       TODO enforce this ^

    # our forwarding parameters for forwarding HTLCs through this channel
    forwarding_cltv_delta = 144
    forwarding_fee_base_msat = 1000
    forwarding_fee_proportional_millionths = 1

    def __repr__(self):
        return "Channel(%s)"%self.get_id_for_log()

    def __init__(self, state: 'StoredDict', *, name=None, lnworker=None, initial_feerate=None, opening_fee=None):
        self.opening_fee = opening_fee
        self.name = name
        self.channel_id = bfh(state["channel_id"])
        self.short_channel_id = ShortChannelID.normalize(state["short_channel_id"])
        Logger.__init__(self)  # should be after short_channel_id is set
        self.lnworker = lnworker
        self.storage = state
        self.db_lock = self.storage.db.lock if self.storage.db else threading.RLock()
        self.config = {}
        self.config[LOCAL] = state["local_config"]
        self.config[REMOTE] = state["remote_config"]
        self.constraints = state["constraints"]  # type: ChannelConstraints
        self.funding_outpoint = state["funding_outpoint"]
        self.node_id = bfh(state["node_id"])
        self.onion_keys = state['onion_keys']  # type: Dict[int, bytes]
        self.data_loss_protect_remote_pcp = state['data_loss_protect_remote_pcp']
        self.hm = HTLCManager(log=state['log'], initial_feerate=initial_feerate)
        self.unfulfilled_htlcs = state["unfulfilled_htlcs"]  # type: Dict[int, Tuple[str, Optional[str]]]
        # ^ htlc_id -> onion_packet_hex, forwarding_key
        self._state = ChannelState[state['state']]
        self.peer_state = PeerState.DISCONNECTED
        self._sweep_info = {}
        self._outgoing_channel_update = None  # type: Optional[bytes]
        self.revocation_store = RevocationStore(state["revocation_store"])
        self._can_send_ctx_updates = True  # type: bool
        self._receive_fail_reasons = {}  # type: Dict[int, (bytes, OnionRoutingFailure)]
        self.should_request_force_close = False
        self.unconfirmed_closing_txid = None # not a state, only for GUI
        self.sent_channel_ready = False # no need to persist this, because channel_ready is re-sent in channel_reestablish
        self.sent_announcement_signatures = False
        self.htlc_settle_time = {}

    def get_local_scid_alias(self, *, create_new_if_needed: bool = False) -> Optional[bytes]:
        """Get scid_alias to be used for *outgoing* HTLCs.
        (called local as we choose the value)
        """
        if alias := self.storage.get('local_scid_alias'):
            return bytes.fromhex(alias)
        elif create_new_if_needed:
            # deterministic, same secrecy level as wallet master pubkey
            wallet_fingerprint = bytes(self.lnworker.wallet.get_fingerprint(), "utf8")
            alias = sha256(wallet_fingerprint + self.channel_id)[0:8]
            self.storage['local_scid_alias'] = alias.hex()
            return alias
        return None

    def save_remote_scid_alias(self, alias: bytes):
        self.storage['alias'] = alias.hex()

    def get_remote_scid_alias(self) -> Optional[bytes]:
        """Get scid_alias to be used for *incoming* HTLCs.
        (called remote as the remote chooses the value)
        """
        alias = self.storage.get('alias')
        return bytes.fromhex(alias) if alias else None

    def get_scid_or_local_alias(self):
        return self.short_channel_id or self.get_local_scid_alias()

    def has_onchain_backup(self):
        return self.storage.get('has_onchain_backup', False)

    def can_be_deleted(self):
        return self.is_redeemed()

    def get_capacity(self):
        return self.constraints.capacity

    def is_public(self):
        return bool(self.constraints.flags & CF_ANNOUNCE_CHANNEL)

    def is_initiator(self):
        return self.constraints.is_initiator

    def is_active(self):
        return self.get_state() == ChannelState.OPEN and self.peer_state == PeerState.GOOD

    def funding_txn_minimum_depth(self):
        return self.constraints.funding_txn_minimum_depth

    def diagnostic_name(self):
        if self.name:
            return str(self.name)
        return super().diagnostic_name()

    def set_onion_key(self, key: int, value: bytes):
        self.onion_keys[key] = value

    def pop_onion_key(self, key: int) -> bytes:
        return self.onion_keys.pop(key)

    def set_data_loss_protect_remote_pcp(self, key, value):
        self.data_loss_protect_remote_pcp[key] = value

    def get_data_loss_protect_remote_pcp(self, key):
        return self.data_loss_protect_remote_pcp.get(key)

    def get_local_pubkey(self) -> bytes:
        if not self.lnworker:
            raise Exception('lnworker not set for channel!')
        return self.lnworker.node_keypair.pubkey

    def set_remote_update(self, payload: dict) -> None:
        """Save the ChannelUpdate message for the incoming direction of this channel.
        This message contains info we need to populate private route hints when
        creating invoices.
        """
        assert payload['short_channel_id'] in [self.short_channel_id, self.get_local_scid_alias()]
        from .channel_db import ChannelDB
        ChannelDB.verify_channel_update(payload, start_node=self.node_id)
        raw = payload['raw']
        self.storage['remote_update'] = raw.hex()

    def get_remote_update(self) -> Optional[bytes]:
        return bfh(self.storage.get('remote_update')) if self.storage.get('remote_update') else None

    def add_or_update_peer_addr(self, peer: LNPeerAddr) -> None:
        if 'peer_network_addresses' not in self.storage:
            self.storage['peer_network_addresses'] = {}
        self.storage['peer_network_addresses'][peer.net_addr_str()] = now()

    def get_peer_addresses(self) -> Iterator[LNPeerAddr]:
        # sort by timestamp: most recent first
        addrs = sorted(self.storage.get('peer_network_addresses', {}).items(),
                       key=lambda x: x[1], reverse=True)
        for net_addr_str, ts in addrs:
            net_addr = NetAddress.from_string(net_addr_str)
            yield LNPeerAddr(host=str(net_addr.host), port=net_addr.port, pubkey=self.node_id)

    def get_outgoing_gossip_channel_update(self, *, scid: ShortChannelID = None) -> bytes:
        """
        scid: to be put into the channel_update message instead of the real scid, as this might be an scid alias
        """
        if self._outgoing_channel_update is not None and scid is None:
            return self._outgoing_channel_update
        if not self.lnworker:
            raise Exception('lnworker not set for channel!')
        if scid is None:
            scid = self.short_channel_id
        sorted_node_ids = list(sorted([self.node_id, self.get_local_pubkey()]))
        channel_flags = b'\x00' if sorted_node_ids[0] == self.get_local_pubkey() else b'\x01'
        htlc_maximum_msat = min(self.config[REMOTE].max_htlc_value_in_flight_msat, 1000 * self.constraints.capacity)

        chan_upd = encode_msg(
            "channel_update",
            short_channel_id=scid,
            channel_flags=channel_flags,
            message_flags=b'\x01',
            cltv_expiry_delta=self.forwarding_cltv_delta,
            htlc_minimum_msat=self.config[REMOTE].htlc_minimum_msat,
            htlc_maximum_msat=htlc_maximum_msat,
            fee_base_msat=self.forwarding_fee_base_msat,
            fee_proportional_millionths=self.forwarding_fee_proportional_millionths,
            chain_hash=constants.net.rev_genesis_bytes(),
            timestamp=now(),
        )
        sighash = sha256d(chan_upd[2 + 64:])
        sig = ecc.ECPrivkey(self.lnworker.node_keypair.privkey).ecdsa_sign(sighash, sigencode=ecc.ecdsa_sig64_from_r_and_s)
        message_type, payload = decode_msg(chan_upd)
        payload['signature'] = sig
        chan_upd = encode_msg(message_type, **payload)

        self._outgoing_channel_update = chan_upd
        return chan_upd

    def construct_channel_announcement_without_sigs(self) -> bytes:
        bitcoin_keys = [
            self.config[REMOTE].multisig_key.pubkey,
            self.config[LOCAL].multisig_key.pubkey]
        node_ids = [self.node_id, self.get_local_pubkey()]
        is_reverse = node_ids[0] > node_ids[1]
        if is_reverse:
            node_ids.reverse()
            bitcoin_keys.reverse()
        chan_ann = encode_msg(
            "channel_announcement",
            len=0,
            features=b'',
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=self.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1],
        )
        return chan_ann, is_reverse

    def get_channel_announcement_hash(self):
        chan_ann, _ = self.construct_channel_announcement_without_sigs()
        return sha256d(chan_ann[256+2:])

    def is_static_remotekey_enabled(self) -> bool:
        channel_type = ChannelType(self.storage.get('channel_type'))
        return bool(channel_type & ChannelType.OPTION_STATIC_REMOTEKEY)

    def is_zeroconf(self) -> bool:
        channel_type = ChannelType(self.storage.get('channel_type'))
        return bool(channel_type & ChannelType.OPTION_ZEROCONF)

    @property
    def sweep_address(self) -> str:
        # TODO: in case of unilateral close with pending HTLCs, this address will be reused
        addr = None
        assert self.is_static_remotekey_enabled()
        our_payment_pubkey = self.config[LOCAL].payment_basepoint.pubkey
        addr = make_commitment_output_to_remote_address(our_payment_pubkey)
        if self.lnworker:
            assert self.lnworker.wallet.is_mine(addr)
        return addr

    def get_wallet_addresses_channel_might_want_reserved(self) -> Sequence[str]:
        assert self.is_static_remotekey_enabled()
        our_payment_pubkey = self.config[LOCAL].payment_basepoint.pubkey
        to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey)
        return [to_remote_address]

    def get_feerate(self, subject: HTLCOwner, *, ctn: int) -> int:
        # returns feerate in sat/kw
        return self.hm.get_feerate(subject, ctn)

    def get_oldest_unrevoked_feerate(self, subject: HTLCOwner) -> int:
        return self.hm.get_feerate_in_oldest_unrevoked_ctx(subject)

    def get_latest_feerate(self, subject: HTLCOwner) -> int:
        return self.hm.get_feerate_in_latest_ctx(subject)

    def get_next_feerate(self, subject: HTLCOwner) -> int:
        return self.hm.get_feerate_in_next_ctx(subject)

    def get_payments(self, status=None) -> Mapping[bytes, List[HTLCWithStatus]]:
        out = defaultdict(list)
        for direction, htlc in self.hm.all_htlcs_ever():
            htlc_proposer = LOCAL if direction is SENT else REMOTE
            if self.hm.was_htlc_failed(htlc_id=htlc.htlc_id, htlc_proposer=htlc_proposer):
                _status = 'failed'
            elif self.hm.was_htlc_preimage_released(htlc_id=htlc.htlc_id, htlc_proposer=htlc_proposer):
                _status = 'settled'
            else:
                _status = 'inflight'
            if status and status != _status:
                continue
            htlc_with_status = HTLCWithStatus(
                channel_id=self.channel_id, htlc=htlc, direction=direction, status=_status)
            out[htlc.payment_hash].append(htlc_with_status)
        return out

    def open_with_first_pcp(self, remote_pcp: bytes, remote_sig: bytes) -> None:
        with self.db_lock:
            self.config[REMOTE].current_per_commitment_point = remote_pcp
            self.config[REMOTE].next_per_commitment_point = None
            self.config[LOCAL].current_commitment_signature = remote_sig
            self.hm.channel_open_finished()
            self.peer_state = PeerState.GOOD

    def get_state_for_GUI(self):
        cs_name = super().get_state_for_GUI()
        if self.is_closed() or self.unconfirmed_closing_txid:
            return cs_name
        ps = self.peer_state
        if ps != PeerState.GOOD:
            return ps.name
        return cs_name

    def set_can_send_ctx_updates(self, b: bool) -> None:
        self._can_send_ctx_updates = b

    def can_send_ctx_updates(self) -> bool:
        """Whether we can send update_fee, update_*_htlc changes to the remote."""
        if self.get_state() not in (ChannelState.OPEN, ChannelState.SHUTDOWN):
            return False
        if self.peer_state != PeerState.GOOD:
            return False
        if not self._can_send_ctx_updates:
            return False
        return True

    def can_send_update_add_htlc(self) -> bool:
        return self.can_send_ctx_updates() and self.is_open()

    def is_frozen_for_sending(self) -> bool:
        if self.lnworker and self.lnworker.uses_trampoline() and not self.lnworker.is_trampoline_peer(self.node_id):
            return True
        return self.storage.get('frozen_for_sending', False)

    def set_frozen_for_sending(self, b: bool) -> None:
        self.storage['frozen_for_sending'] = bool(b)
        util.trigger_callback('channel', self.lnworker.wallet, self)

    def is_frozen_for_receiving(self) -> bool:
        if self.lnworker and self.lnworker.uses_trampoline() and not self.lnworker.is_trampoline_peer(self.node_id):
            return True
        return self.storage.get('frozen_for_receiving', False)

    def set_frozen_for_receiving(self, b: bool) -> None:
        self.storage['frozen_for_receiving'] = bool(b)
        util.trigger_callback('channel', self.lnworker.wallet, self)

    def _assert_can_add_htlc(self, *, htlc_proposer: HTLCOwner, amount_msat: int,
                             ignore_min_htlc_value: bool = False) -> None:
        """Raises PaymentFailure if the htlc_proposer cannot add this new HTLC.
        (this is relevant both for forwarding and endpoint)
        """
        htlc_receiver = htlc_proposer.inverted()
        # note: all these tests are about the *receiver's* *next* commitment transaction,
        #       and the constraints are the ones imposed by their config
        ctn = self.get_next_ctn(htlc_receiver)
        chan_config = self.config[htlc_receiver]
        if self.get_state() != ChannelState.OPEN:
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
        if not ignore_min_htlc_value:
            if amount_msat <= 0:
                raise PaymentFailure("HTLC value must be positive")
            if amount_msat < chan_config.htlc_minimum_msat:
                raise PaymentFailure(f'HTLC value too small: {amount_msat} msat')

        # check proposer can afford htlc
        max_can_send_msat = self.available_to_spend(htlc_proposer, strict=strict)
        if max_can_send_msat < amount_msat:
            raise PaymentFailure(f'Not enough balance. can send: {max_can_send_msat}, tried: {amount_msat}')

        # check "max_accepted_htlcs"
        # this is the loose check BOLT-02 specifies:
        if len(self.hm.htlcs_by_direction(htlc_receiver, direction=RECEIVED, ctn=ctn)) + 1 > chan_config.max_accepted_htlcs:
            raise PaymentFailure('Too many HTLCs already in channel')
        # however, c-lightning is a lot stricter, so extra checks:
        # https://github.com/ElementsProject/lightning/blob/4dcd4ca1556b13b6964a10040ba1d5ef82de4788/channeld/full_channel.c#L581
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

    def can_receive(self, amount_msat: int, *, check_frozen=False,
                    ignore_min_htlc_value: bool = False) -> bool:
        """Returns whether the remote can add an HTLC of given value."""
        if check_frozen and self.is_frozen_for_receiving():
            return False
        try:
            self._assert_can_add_htlc(htlc_proposer=REMOTE,
                                      amount_msat=amount_msat,
                                      ignore_min_htlc_value=ignore_min_htlc_value)
        except PaymentFailure:
            return False
        return True

    def should_try_to_reestablish_peer(self) -> bool:
        if self.peer_state != PeerState.DISCONNECTED:
            return False
        if self.should_request_force_close:
            return True
        return ChannelState.PREOPENING < self._state < ChannelState.CLOSING

    def get_funding_address(self):
        script = funding_output_script(self.config[LOCAL], self.config[REMOTE])
        return redeem_script_to_address('p2wsh', script)

    def add_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        """Adds a new LOCAL HTLC to the channel.
        Action must be initiated by LOCAL.
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
        """Adds a new REMOTE HTLC to the channel.
        Action must be initiated by REMOTE.
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
            if onion_packet:
                self.unfulfilled_htlcs[htlc.htlc_id] = onion_packet.hex(), None

        self.logger.info("receive_htlc")
        return htlc

    def sign_next_commitment(self) -> Tuple[bytes, Sequence[bytes]]:
        """Returns signatures for our next remote commitment tx.
        Action must be initiated by LOCAL.
        Finally, the next remote ctx becomes the latest remote ctx.
        """
        # TODO: when more channel types are supported, this method should depend on channel type
        next_remote_ctn = self.get_next_ctn(REMOTE)
        self.logger.info(f"sign_next_commitment. ctn={next_remote_ctn}")

        pending_remote_commitment = self.get_next_commitment(REMOTE)
        sig_64 = sign_and_get_sig_string(pending_remote_commitment, self.config[LOCAL], self.config[REMOTE])
        self.logger.debug(f"sign_next_commitment. {pending_remote_commitment.serialize()=}. {sig_64.hex()=}")

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
                                                              ctn=next_remote_ctn,
                                                              htlc_direction=direction,
                                                              commit=pending_remote_commitment,
                                                              ctx_output_idx=ctx_output_idx,
                                                              htlc=htlc)
            sig = htlc_tx.sign_txin(0, their_remote_htlc_privkey)
            htlc_sig = ecc.ecdsa_sig64_from_der_sig(sig[:-1])
            htlcsigs.append((ctx_output_idx, htlc_sig))
        htlcsigs.sort()
        htlcsigs = [x[1] for x in htlcsigs]
        with self.db_lock:
            self.hm.send_ctx()
        return sig_64, htlcsigs

    def receive_new_commitment(self, sig: bytes, htlc_sigs: Sequence[bytes]) -> None:
        """Processes signatures for our next local commitment tx, sent by the REMOTE.
        Action must be initiated by REMOTE.
        If all checks pass, the next local ctx becomes the latest local ctx.
        """
        # TODO in many failure cases below, we should "fail" the channel (force-close)
        # TODO: when more channel types are supported, this method should depend on channel type
        next_local_ctn = self.get_next_ctn(LOCAL)
        self.logger.info(f"receive_new_commitment. ctn={next_local_ctn}, len(htlc_sigs)={len(htlc_sigs)}")

        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        pending_local_commitment = self.get_next_commitment(LOCAL)
        pre_hash = pending_local_commitment.serialize_preimage(0)
        msg_hash = sha256d(pre_hash)
        if not ECPubkey(self.config[REMOTE].multisig_key.pubkey).ecdsa_verify(sig, msg_hash):
            raise LNProtocolWarning(
                f'failed verifying signature for our updated commitment transaction. '
                f'sig={sig.hex()}. '
                f'msg_hash={msg_hash.hex()}. '
                f'pubkey={self.config[REMOTE].multisig_key.pubkey}. '
                f'ctx={pending_local_commitment.serialize()} '
            )

        htlc_sigs_string = b''.join(htlc_sigs)

        _secret, pcp = self.get_secret_and_point(subject=LOCAL, ctn=next_local_ctn)

        htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(chan=self,
                                                                  ctx=pending_local_commitment,
                                                                  pcp=pcp,
                                                                  subject=LOCAL,
                                                                  ctn=next_local_ctn)
        if len(htlc_to_ctx_output_idx_map) != len(htlc_sigs):
            raise LNProtocolWarning(f'htlc sigs failure. recv {len(htlc_sigs)} sigs, expected {len(htlc_to_ctx_output_idx_map)}')
        for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
            htlc_sig = htlc_sigs[htlc_relative_idx]
            self._verify_htlc_sig(htlc=htlc,
                                  htlc_sig=htlc_sig,
                                  htlc_direction=direction,
                                  pcp=pcp,
                                  ctx=pending_local_commitment,
                                  ctx_output_idx=ctx_output_idx,
                                  ctn=next_local_ctn)
        with self.db_lock:
            self.hm.recv_ctx()
            self.config[LOCAL].current_commitment_signature=sig
            self.config[LOCAL].current_htlc_signatures=htlc_sigs_string

    def _verify_htlc_sig(self, *, htlc: UpdateAddHtlc, htlc_sig: bytes, htlc_direction: Direction,
                         pcp: bytes, ctx: Transaction, ctx_output_idx: int, ctn: int) -> None:
        _script, htlc_tx = make_htlc_tx_with_open_channel(chan=self,
                                                          pcp=pcp,
                                                          subject=LOCAL,
                                                          ctn=ctn,
                                                          htlc_direction=htlc_direction,
                                                          commit=ctx,
                                                          ctx_output_idx=ctx_output_idx,
                                                          htlc=htlc)
        pre_hash = htlc_tx.serialize_preimage(0)
        msg_hash = sha256d(pre_hash)
        remote_htlc_pubkey = derive_pubkey(self.config[REMOTE].htlc_basepoint.pubkey, pcp)
        if not ECPubkey(remote_htlc_pubkey).ecdsa_verify(htlc_sig, msg_hash):
            raise LNProtocolWarning(
                f'failed verifying HTLC signatures: {htlc=}, {htlc_direction=}. '
                f'htlc_tx={htlc_tx.serialize()}. '
                f'htlc_sig={htlc_sig.hex()}. '
                f'remote_htlc_pubkey={remote_htlc_pubkey.hex()}. '
                f'msg_hash={msg_hash.hex()}. '
                f'ctx={ctx.serialize()}. '
                f'ctx_output_idx={ctx_output_idx}. '
                f'ctn={ctn}. '
            )

    def get_remote_htlc_sig_for_htlc(self, *, htlc_relative_idx: int) -> bytes:
        data = self.config[LOCAL].current_htlc_signatures
        htlc_sigs = list(chunks(data, 64))
        htlc_sig = htlc_sigs[htlc_relative_idx]
        remote_htlc_sig = ecc.ecdsa_der_sig_from_ecdsa_sig64(htlc_sig) + Sighash.to_sigbytes(Sighash.ALL)
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
        assert new_ctn == self.get_oldest_unrevoked_ctn(REMOTE)
        # lnworker callbacks
        if self.lnworker:
            sent = self.hm.sent_in_ctn(new_ctn)
            for htlc in sent:
                self.lnworker.htlc_fulfilled(self, htlc.payment_hash, htlc.htlc_id)
            failed = self.hm.failed_in_ctn(new_ctn)
            for htlc in failed:
                try:
                    error_bytes, failure_message = self._receive_fail_reasons.pop(htlc.htlc_id)
                except KeyError:
                    error_bytes, failure_message = None, None
                self.lnworker.htlc_failed(self, htlc.payment_hash, htlc.htlc_id, error_bytes, failure_message)

    def extract_preimage_from_htlc_txin(self, txin: TxInput) -> None:
        witness = txin.witness_elements()
        if len(witness) == 5:  # HTLC success tx
            preimage = witness[3]
        elif len(witness) == 3:  # spending offered HTLC directly from ctx
            preimage = witness[1]
        else:
            return
        payment_hash = sha256(preimage)
        for direction, htlc in itertools.chain(self.hm.get_htlcs_in_oldest_unrevoked_ctx(REMOTE),
                                               self.hm.get_htlcs_in_latest_ctx(REMOTE)):
            if htlc.payment_hash == payment_hash:
                is_sent = direction == RECEIVED
                break
        else:
            for direction, htlc in itertools.chain(self.hm.get_htlcs_in_oldest_unrevoked_ctx(LOCAL),
                                                   self.hm.get_htlcs_in_latest_ctx(LOCAL)):
                if htlc.payment_hash == payment_hash:
                    is_sent = direction == SENT
                    break
            else:
                return
        if self.lnworker.get_preimage(payment_hash) is None:
            self.logger.info(f'found preimage for {payment_hash.hex()} in witness of length {len(witness)}')
            self.lnworker.save_preimage(payment_hash, preimage)
        info = self.lnworker.get_payment_info(payment_hash)
        if info is not None and info.status != PR_PAID:
            if is_sent:
                self.lnworker.htlc_fulfilled(self, payment_hash, htlc.htlc_id)
            else:
                # FIXME
                #self.lnworker.htlc_received(self, payment_hash)
                pass

    def balance(self, whose: HTLCOwner, *, ctx_owner=HTLCOwner.LOCAL, ctn: int = None) -> int:
        assert type(whose) is HTLCOwner
        initial = self.config[whose].initial_msat
        return self.hm.get_balance_msat(whose=whose,
                                        ctx_owner=ctx_owner,
                                        ctn=ctn,
                                        initial_balance_msat=initial)

    def balance_minus_outgoing_htlcs(self, whose: HTLCOwner, *, ctx_owner: HTLCOwner = HTLCOwner.LOCAL,
                                     ctn: int = None) -> int:
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

    def has_unsettled_htlcs(self) -> bool:
        return len(self.hm.htlcs(LOCAL)) + len(self.hm.htlcs(REMOTE)) > 0

    def available_to_spend(self, subject: HTLCOwner, *, strict: bool = True) -> int:
        """The usable balance of 'subject' in msat, after taking reserve and fees into
        consideration. Note that fees (and hence the result) fluctuate even without user interaction.
        """
        assert type(subject) is HTLCOwner
        sender = subject
        receiver = subject.inverted()
        initiator = LOCAL if self.constraints.is_initiator else REMOTE  # the initiator/funder pays on-chain fees

        def consider_ctx(*, ctx_owner: HTLCOwner, is_htlc_dust: bool) -> int:
            ctn = self.get_next_ctn(ctx_owner)
            sender_balance_msat = self.balance_minus_outgoing_htlcs(whose=sender, ctx_owner=ctx_owner, ctn=ctn)
            receiver_balance_msat = self.balance_minus_outgoing_htlcs(whose=receiver, ctx_owner=ctx_owner, ctn=ctn)
            sender_reserve_msat = self.config[receiver].reserve_sat * 1000
            receiver_reserve_msat = self.config[sender].reserve_sat * 1000
            num_htlcs_in_ctx = len(self.included_htlcs(ctx_owner, SENT, ctn=ctn) + self.included_htlcs(ctx_owner, RECEIVED, ctn=ctn))
            feerate = self.get_feerate(ctx_owner, ctn=ctn)
            ctx_fees_msat = calc_fees_for_commitment_tx(
                num_htlcs=num_htlcs_in_ctx,
                feerate=feerate,
                is_local_initiator=self.constraints.is_initiator,
                round_to_sat=False,
            )
            htlc_fee_msat = fee_for_htlc_output(feerate=feerate)
            htlc_trim_func = received_htlc_trim_threshold_sat if ctx_owner == receiver else offered_htlc_trim_threshold_sat
            htlc_trim_threshold_msat = htlc_trim_func(dust_limit_sat=self.config[ctx_owner].dust_limit_sat, feerate=feerate) * 1000
            if sender == initiator == LOCAL:  # see https://github.com/lightningnetwork/lightning-rfc/pull/740
                fee_spike_buffer = calc_fees_for_commitment_tx(
                    num_htlcs=num_htlcs_in_ctx + int(not is_htlc_dust) + 1,
                    feerate=2 * feerate,
                    is_local_initiator=self.constraints.is_initiator,
                    round_to_sat=False,
                )[sender]
                max_send_msat = sender_balance_msat - sender_reserve_msat - fee_spike_buffer
            else:
                max_send_msat = sender_balance_msat - sender_reserve_msat - ctx_fees_msat[sender]
            if is_htlc_dust:
                return min(max_send_msat, htlc_trim_threshold_msat - 1)
            else:
                if sender == initiator:
                    return max_send_msat - htlc_fee_msat
                else:
                    # the receiver is the initiator, so they need to be able to pay tx fees
                    if receiver_balance_msat - receiver_reserve_msat - ctx_fees_msat[receiver] - htlc_fee_msat < 0:
                        return 0
                    return max_send_msat

        max_send_msat = min(
                            max(
                                consider_ctx(ctx_owner=receiver, is_htlc_dust=True),
                                consider_ctx(ctx_owner=receiver, is_htlc_dust=False),
                            ),
                            max(
                                consider_ctx(ctx_owner=sender, is_htlc_dust=True),
                                consider_ctx(ctx_owner=sender, is_htlc_dust=False),
                            ),
        )
        max_send_msat = max(max_send_msat, 0)
        return max_send_msat


    def included_htlcs(self, subject: HTLCOwner, direction: Direction, ctn: int = None, *,
                       feerate: int = None) -> Sequence[UpdateAddHtlc]:
        """Returns list of non-dust HTLCs for subject's commitment tx at ctn,
        filtered by direction (of HTLCs).
        """
        assert type(subject) is HTLCOwner
        assert type(direction) is Direction
        if ctn is None:
            ctn = self.get_oldest_unrevoked_ctn(subject)
        if feerate is None:
            feerate = self.get_feerate(subject, ctn=ctn)
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

    def get_secret_and_commitment(self, subject: HTLCOwner, *, ctn: int) -> Tuple[Optional[bytes], PartialTransaction]:
        secret, point = self.get_secret_and_point(subject, ctn)
        ctx = self.make_commitment(subject, point, ctn)
        return secret, ctx

    def get_commitment(self, subject: HTLCOwner, *, ctn: int) -> PartialTransaction:
        secret, ctx = self.get_secret_and_commitment(subject, ctn=ctn)
        return ctx

    def get_next_commitment(self, subject: HTLCOwner) -> PartialTransaction:
        ctn = self.get_next_ctn(subject)
        return self.get_commitment(subject, ctn=ctn)

    def get_latest_commitment(self, subject: HTLCOwner) -> PartialTransaction:
        ctn = self.get_latest_ctn(subject)
        return self.get_commitment(subject, ctn=ctn)

    def get_oldest_unrevoked_commitment(self, subject: HTLCOwner) -> PartialTransaction:
        ctn = self.get_oldest_unrevoked_ctn(subject)
        return self.get_commitment(subject, ctn=ctn)

    def create_sweeptxs(self, ctn: int) -> List[Transaction]:
        from .lnsweep import create_sweeptxs_for_watchtower
        secret, ctx = self.get_secret_and_commitment(REMOTE, ctn=ctn)
        return create_sweeptxs_for_watchtower(self, ctx, secret, self.sweep_address)

    def get_oldest_unrevoked_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_oldest_unrevoked(subject)

    def get_latest_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_latest(subject)

    def get_next_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_latest(subject) + 1

    def total_msat(self, direction: Direction) -> int:
        """Return the cumulative total msat amount received/sent so far."""
        assert type(direction) is Direction
        return htlcsum(self.hm.all_settled_htlcs_ever_by_direction(LOCAL, direction))

    def settle_htlc(self, preimage: bytes, htlc_id: int) -> None:
        """Settle/fulfill a pending received HTLC.
        Action must be initiated by LOCAL.
        """
        self.logger.info("settle_htlc")
        assert self.can_send_ctx_updates(), f"cannot update channel. {self.get_state()!r} {self.peer_state!r}"
        htlc = self.hm.get_htlc_by_id(REMOTE, htlc_id)
        if htlc.payment_hash != sha256(preimage):
            raise Exception("incorrect preimage for HTLC")
        assert htlc_id not in self.hm.log[REMOTE]['settles']
        self.hm.send_settle(htlc_id)
        self.htlc_settle_time[htlc_id] = now()

    def get_payment_hash(self, htlc_id: int) -> bytes:
        htlc = self.hm.get_htlc_by_id(LOCAL, htlc_id)
        return htlc.payment_hash

    def receive_htlc_settle(self, preimage: bytes, htlc_id: int) -> None:
        """Settle/fulfill a pending offered HTLC.
        Action must be initiated by REMOTE.
        """
        self.logger.info("receive_htlc_settle")
        htlc = self.hm.get_htlc_by_id(LOCAL, htlc_id)
        if htlc.payment_hash != sha256(preimage):
            raise RemoteMisbehaving("received incorrect preimage for HTLC")
        assert htlc_id not in self.hm.log[LOCAL]['settles']
        with self.db_lock:
            self.hm.recv_settle(htlc_id)

    def fail_htlc(self, htlc_id: int) -> None:
        """Fail a pending received HTLC.
        Action must be initiated by LOCAL.
        """
        self.logger.info("fail_htlc")
        assert self.can_send_ctx_updates(), f"cannot update channel. {self.get_state()!r} {self.peer_state!r}"
        with self.db_lock:
            self.hm.send_fail(htlc_id)

    def receive_fail_htlc(self, htlc_id: int, *,
                          error_bytes: Optional[bytes],
                          reason: Optional[OnionRoutingFailure] = None) -> None:
        """Fail a pending offered HTLC.
        Action must be initiated by REMOTE.
        """
        self.logger.info("receive_fail_htlc")
        with self.db_lock:
            self.hm.recv_fail(htlc_id)
        self._receive_fail_reasons[htlc_id] = (error_bytes, reason)

    def get_next_fee(self, subject: HTLCOwner) -> int:
        return self.constraints.capacity - sum(x.value for x in self.get_next_commitment(subject).outputs())

    def get_latest_fee(self, subject: HTLCOwner) -> int:
        return self.constraints.capacity - sum(x.value for x in self.get_latest_commitment(subject).outputs())

    def update_fee(self, feerate: int, from_us: bool) -> None:
        # feerate uses sat/kw
        if self.constraints.is_initiator != from_us:
            raise Exception(f"Cannot update_fee: wrong initiator. us: {from_us}")
        if feerate < FEERATE_PER_KW_MIN_RELAY_LIGHTNING:
            raise Exception(f"Cannot update_fee: feerate lower than min relay fee. {feerate} sat/kw. us: {from_us}")
        sender = LOCAL if from_us else REMOTE
        ctx_owner = -sender
        ctn = self.get_next_ctn(ctx_owner)
        sender_balance_msat = self.balance_minus_outgoing_htlcs(whose=sender, ctx_owner=ctx_owner, ctn=ctn)
        sender_reserve_msat = self.config[-sender].reserve_sat * 1000
        num_htlcs_in_ctx = len(self.included_htlcs(ctx_owner, SENT, ctn=ctn, feerate=feerate) +
                               self.included_htlcs(ctx_owner, RECEIVED, ctn=ctn, feerate=feerate))
        ctx_fees_msat = calc_fees_for_commitment_tx(
            num_htlcs=num_htlcs_in_ctx,
            feerate=feerate,
            is_local_initiator=self.constraints.is_initiator,
        )
        remainder = sender_balance_msat - sender_reserve_msat - ctx_fees_msat[sender]
        if remainder < 0:
            raise Exception(f"Cannot update_fee. {sender} tried to update fee but they cannot afford it. "
                            f"Their balance would go below reserve: {remainder} msat missing.")
        with self.db_lock:
            if from_us:
                assert self.can_send_ctx_updates(), f"cannot update channel. {self.get_state()!r} {self.peer_state!r}"
                self.hm.send_update_fee(feerate)
            else:
                self.hm.recv_update_fee(feerate)

    def make_commitment(self, subject: HTLCOwner, this_point: bytes, ctn: int) -> PartialTransaction:
        assert type(subject) is HTLCOwner
        feerate = self.get_feerate(subject, ctn=ctn)
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
                    cltv_abs=htlc.cltv_abs), htlc))
        # note: maybe flip initiator here for fee purposes, we want LOCAL and REMOTE
        #       in the resulting dict to correspond to the to_local and to_remote *outputs* of the ctx
        onchain_fees = calc_fees_for_commitment_tx(
            num_htlcs=len(htlcs),
            feerate=feerate,
            is_local_initiator=self.constraints.is_initiator == (subject == LOCAL),
        )
        assert self.is_static_remotekey_enabled()
        payment_pubkey = other_config.payment_basepoint.pubkey
        return make_commitment(
            ctn=ctn,
            local_funding_pubkey=this_config.multisig_key.pubkey,
            remote_funding_pubkey=other_config.multisig_key.pubkey,
            remote_payment_pubkey=payment_pubkey,
            funder_payment_basepoint=self.config[LOCAL if     self.constraints.is_initiator else REMOTE].payment_basepoint.pubkey,
            fundee_payment_basepoint=self.config[LOCAL if not self.constraints.is_initiator else REMOTE].payment_basepoint.pubkey,
            revocation_pubkey=other_revocation_pubkey,
            delayed_pubkey=derive_pubkey(this_config.delayed_basepoint.pubkey, this_point),
            to_self_delay=other_config.to_self_delay,
            funding_txid=self.funding_outpoint.txid,
            funding_pos=self.funding_outpoint.output_index,
            funding_sat=self.constraints.capacity,
            local_amount=local_msat,
            remote_amount=remote_msat,
            dust_limit_sat=this_config.dust_limit_sat,
            fees_per_participant=onchain_fees,
            htlcs=htlcs,
        )

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
                local_script=local_script,
                remote_script=remote_script,
                htlcs=[],
                dust_limit_sat=self.config[LOCAL].dust_limit_sat)

        closing_tx = make_closing_tx(self.config[LOCAL].multisig_key.pubkey,
                                     self.config[REMOTE].multisig_key.pubkey,
                                     funding_txid=self.funding_outpoint.txid,
                                     funding_pos=self.funding_outpoint.output_index,
                                     funding_sat=self.constraints.capacity,
                                     outputs=outputs)

        der_sig = closing_tx.sign_txin(0, self.config[LOCAL].multisig_key.privkey)
        sig = ecc.ecdsa_sig64_from_der_sig(der_sig[:-1])
        return sig, closing_tx

    def signature_fits(self, tx: PartialTransaction) -> bool:
        remote_sig = self.config[LOCAL].current_commitment_signature
        pre_hash = tx.serialize_preimage(0)
        msg_hash = sha256d(pre_hash)
        assert remote_sig
        res = ECPubkey(self.config[REMOTE].multisig_key.pubkey).ecdsa_verify(remote_sig, msg_hash)
        return res

    def force_close_tx(self) -> PartialTransaction:
        tx = self.get_latest_commitment(LOCAL)
        assert self.signature_fits(tx)
        tx.sign({self.config[LOCAL].multisig_key.pubkey: self.config[LOCAL].multisig_key.privkey})
        remote_sig = self.config[LOCAL].current_commitment_signature
        remote_sig = ecc.ecdsa_der_sig_from_ecdsa_sig64(remote_sig) + Sighash.to_sigbytes(Sighash.ALL)
        tx.add_signature_to_txin(txin_idx=0,
                                 signing_pubkey=self.config[REMOTE].multisig_key.pubkey,
                                 sig=remote_sig)
        assert tx.is_complete()
        return tx

    def get_close_options(self) -> Sequence[ChanCloseOption]:
        # This method is used both in the GUI, and in lnpeer.schedule_force_closing
        # in the latter case, the result does not depend on peer_state
        ret = []
        if not self.is_closed() and self.peer_state == PeerState.GOOD:
            # If there are unsettled HTLCs, although is possible to cooperatively close,
            # we choose not to expose that option in the GUI, because it is very likely
            # that HTLCs will take a long time to settle (submarine swap, or stuck payment),
            # and the close dialog would be taking a very long time to finish
            if not self.has_unsettled_htlcs():
                ret.append(ChanCloseOption.COOP_CLOSE)
                ret.append(ChanCloseOption.REQUEST_REMOTE_FCLOSE)
        if self.get_state() == ChannelState.WE_ARE_TOXIC:
            ret.append(ChanCloseOption.REQUEST_REMOTE_FCLOSE)
        if not self.is_closed() or self.get_state() == ChannelState.REQUESTED_FCLOSE:
            ret.append(ChanCloseOption.LOCAL_FCLOSE)
        assert not (self.get_state() == ChannelState.WE_ARE_TOXIC and ChanCloseOption.LOCAL_FCLOSE in ret), "local force-close unsafe if we are toxic"
        return ret

    def maybe_sweep_revoked_htlc(self, ctx: Transaction, htlc_tx: Transaction) -> Optional[SweepInfo]:
        # look at the output address, check if it matches
        return create_sweeptx_for_their_revoked_htlc(self, ctx, htlc_tx, self.sweep_address)

    def has_pending_changes(self, subject: HTLCOwner) -> bool:
        next_htlcs = self.hm.get_htlcs_in_next_ctx(subject)
        latest_htlcs = self.hm.get_htlcs_in_latest_ctx(subject)
        return not (next_htlcs == latest_htlcs and self.get_next_feerate(subject) == self.get_latest_feerate(subject))

    def should_be_closed_due_to_expiring_htlcs(self, local_height) -> bool:
        htlcs_we_could_reclaim = {}  # type: Dict[Tuple[Direction, int], UpdateAddHtlc]
        # If there is a received HTLC for which we already released the preimage
        # but the remote did not revoke yet, and the CLTV of this HTLC is dangerously close
        # to the present, then unilaterally close channel
        recv_htlc_deadline_delta = lnutil.NBLOCK_DEADLINE_DELTA_BEFORE_EXPIRY_FOR_RECEIVED_HTLCS
        for sub, dir, ctn in ((LOCAL, RECEIVED, self.get_latest_ctn(LOCAL)),
                              (REMOTE, SENT, self.get_oldest_unrevoked_ctn(REMOTE)),
                              (REMOTE, SENT, self.get_latest_ctn(REMOTE)),):
            for htlc_id, htlc in self.hm.htlcs_by_direction(subject=sub, direction=dir, ctn=ctn).items():
                if not self.hm.was_htlc_preimage_released(htlc_id=htlc_id, htlc_proposer=REMOTE):
                    continue
                if htlc.cltv_abs - recv_htlc_deadline_delta > local_height:
                    continue
                # Do not force-close if we just sent fulfill_htlc and have not received revack yet
                if htlc_id in self.htlc_settle_time and now() - self.htlc_settle_time[htlc_id] < 30:
                    continue
                htlcs_we_could_reclaim[(RECEIVED, htlc_id)] = htlc
        # If there is an offered HTLC which has already expired (+ some grace period after), we
        # will unilaterally close the channel and time out the HTLC
        offered_htlc_deadline_delta = lnutil.NBLOCK_DEADLINE_DELTA_AFTER_EXPIRY_FOR_OFFERED_HTLCS
        for sub, dir, ctn in ((LOCAL, SENT, self.get_latest_ctn(LOCAL)),
                              (REMOTE, RECEIVED, self.get_oldest_unrevoked_ctn(REMOTE)),
                              (REMOTE, RECEIVED, self.get_latest_ctn(REMOTE)),):
            for htlc_id, htlc in self.hm.htlcs_by_direction(subject=sub, direction=dir, ctn=ctn).items():
                if htlc.cltv_abs + offered_htlc_deadline_delta > local_height:
                    continue
                htlcs_we_could_reclaim[(SENT, htlc_id)] = htlc

        total_value_sat = sum([htlc.amount_msat // 1000 for htlc in htlcs_we_could_reclaim.values()])
        num_htlcs = len(htlcs_we_could_reclaim)
        min_value_worth_closing_channel_over_sat = max(num_htlcs * 10 * self.config[REMOTE].dust_limit_sat,
                                                       500_000)
        return total_value_sat > min_value_worth_closing_channel_over_sat

    def is_funding_tx_mined(self, funding_height):
        funding_txid = self.funding_outpoint.txid
        funding_idx = self.funding_outpoint.output_index
        conf = funding_height.conf
        if conf < self.funding_txn_minimum_depth():
            #self.logger.info(f"funding tx is still not at sufficient depth. actual depth: {conf}")
            return False
        assert conf > 0 or self.is_zeroconf()
        # check funding_tx amount and script
        funding_tx = self.lnworker.lnwatcher.adb.get_transaction(funding_txid)
        if not funding_tx:
            self.logger.info(f"no funding_tx {funding_txid}")
            return False
        outp = funding_tx.outputs()[funding_idx]
        redeem_script = funding_output_script(self.config[REMOTE], self.config[LOCAL])
        funding_address = redeem_script_to_address('p2wsh', redeem_script)
        funding_sat = self.constraints.capacity
        if not (outp.address == funding_address and outp.value == funding_sat):
            self.logger.info('funding outpoint mismatch')
            return False
        return True
