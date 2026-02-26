from copy import deepcopy
from typing import Sequence, Tuple, Dict, TYPE_CHECKING, Set

from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction, FeeUpdate
from .util import bfh, with_lock
from .logging import get_logger

_logger = get_logger(__name__)

if TYPE_CHECKING:
    from .json_db import StoredDict

INITIAL_HISTORY_HASH = bytes(32)

HTLC_PAGE_SIZE = 5 # number of htlcs returned by query_htlcs_history. not consensus critical.

LOG_TEMPLATE = {
    'adds': {},              # "side who offered htlc" -> htlc_id -> htlc
    'locked_in': {},         # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
    'settles': {},           # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
    'fails': {},             # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
    'fee_updates': {},       # "side who initiated fee update" -> index -> list of FeeUpdates
    'revack_pending': False,
    'next_htlc_id': 0,
    'ctn': -1,               # oldest unrevoked ctx of sub
    'checkpoints': {},       # proposer -> 'checkpoints' -> htlc_id -> (local_hash, remote_hash, amount)
}


class HTLCManager:

    def __init__(self, log: 'StoredDict', *, initiator=None, initial_feerate=None):

        if len(log) == 0:
            # note: "htlc_id" keys in dict are str! but due to json_db magic they can *almost* be treated as int...
            log[LOCAL] = deepcopy(LOG_TEMPLATE)
            log[REMOTE] = deepcopy(LOG_TEMPLATE)
            log[LOCAL]['unacked_updates'] = {}
            log[LOCAL]['was_revoke_last'] = False

        # maybe bootstrap fee_updates if initial_feerate was provided
        if initial_feerate is not None:
            assert type(initial_feerate) is int
            assert initiator in [LOCAL, REMOTE]
            log[initiator]['fee_updates'][0] = FeeUpdate(rate=initial_feerate, ctn_local=0, ctn_remote=0)
        self.log = log

        # We need a lock as many methods of HTLCManager are accessed by both the asyncio thread and the GUI.
        # lnchannel sometimes calls us with Channel.db_lock (== log.lock) already taken,
        # and we ourselves often take log.lock (via StoredDict.__getitem__).
        # Hence, to avoid deadlocks, we reuse this same lock.
        self.lock = log.lock
        self._init_maybe_active_htlc_ids()
        self._is_local_ctn_reached = self.is_local_ctn_reached()
        self._local_next_htlc_id = self.get_next_htlc_id(LOCAL)
        self._remote_next_htlc_id = self.get_next_htlc_id(REMOTE)

    @with_lock
    def get_checkpoint(self, proposer, owner, htlc_id) -> bytes:
        # note: get_htlc_history and get_checkpoint recursively call eachother
        from .peerbackup import hash_htlc_history
        checkpoints = self.log[proposer]['checkpoints']
        if htlc_id == -1:
            return INITIAL_HISTORY_HASH, 0, -1
        if htlc_id not in checkpoints:
            checkpoints[htlc_id] = {LOCAL: None, REMOTE: None}
        if checkpoints[htlc_id][owner] is None:
            prev_htlc_history, prev_hash, prev_msat = self.get_htlc_history(proposer, owner, htlc_id + 1)
            assert len(prev_htlc_history) == HTLC_PAGE_SIZE
            first_hash, delta_msat, max_ctn = hash_htlc_history(
                prev_htlc_history,
                proposer=proposer,
                owner=owner,
                ctn_latest=self.ctn_latest(owner),
                first_hash=prev_hash)
            self.save_checkpoint(proposer, owner, htlc_id, first_hash, prev_msat + delta_msat, max_ctn)

        _hash, _msat, max_ctn = checkpoints[htlc_id][owner]
        return bytes.fromhex(_hash), _msat, max_ctn

    def save_checkpoint(self, proposer, owner, htlc_id, _hash: bytes, delta_msat:int, max_ctn: int):
        if htlc_id == -1:
            return
        checkpoints = self.log[proposer]['checkpoints']
        checkpoints[htlc_id][owner] = (_hash.hex(), delta_msat, max_ctn)
        _logger.info(f'saved checkpoint {proposer.name} {htlc_id} {owner.name} {_hash.hex()}')

    def on_ctn_latest(self, owner):
        ctn_latest = self.ctn_latest(owner)
        for proposer in [LOCAL, REMOTE]:
            checkpoints = self.log[proposer]['checkpoints']
            for k in checkpoints.keys():
                v = checkpoints[k][owner]
                if v is not None:
                    _hash, value, max_ctn = v
                    if max_ctn >= ctn_latest:
                        checkpoints[k][owner] = None
                        _logger.info(f'invalidating checkpoint {proposer.name} {owner.name} {k} because of ctn')

    @with_lock
    def invalidate_checkpoints(self, proposer, owner, htlc_id, reason):
        checkpoints = self.log[proposer]['checkpoints']
        k = (htlc_id // HTLC_PAGE_SIZE) * HTLC_PAGE_SIZE - 1 + HTLC_PAGE_SIZE
        while k in checkpoints:
            v = checkpoints[k][owner]
            if v is not None:
                _hash, value, max_ctn = v
                checkpoints[k][owner] = None
                _logger.info(f'invalidating checkpoint {proposer.name} {owner.name} {k} because {reason} {htlc_id=} {_hash}')
            k += HTLC_PAGE_SIZE

    def update_htlc_history(self, proposer, htlc_log):
        target_log = self.log[proposer]
        for htlc_id, v in htlc_log.items():
            target_log['adds'][htlc_id] = UpdateAddHtlc(
                amount_msat = v.amount_msat,
                payment_hash = v.payment_hash,
                cltv_abs = v.cltv_abs,
                htlc_id = v.htlc_id,
                timestamp = v.timestamp)
            assert (v.local_ctn_in is not None or v.remote_ctn_in is not None), v
            target_log['locked_in'][htlc_id] = {LOCAL:v.local_ctn_in, REMOTE:v.remote_ctn_in}
            if v.local_ctn_out is not None or v.remote_ctn_out is not None:
                target_log['settles' if v.is_success else 'fails'][htlc_id] = {LOCAL:v.local_ctn_out, REMOTE:v.remote_ctn_out}
        self._init_maybe_active_htlc_ids()

    def is_local_ctn_reached(self):
        # detect whether local ctn is reached in log values
        # todo: add test for this. make more efficient
        # fixme: ctn might be reached fee updates, but we have changed what we send
        def max_over_dict(dd):
            result = max([-1] + [(d.get(LOCAL) if d.get(LOCAL) is not None else -1) for htlc_id, d in dd.items()])
            return result
        local_ctn = self.log[LOCAL]['ctn']
        max_local_ctn = max([
            max_over_dict(self.log[LOCAL]['locked_in']),
            max_over_dict(self.log[REMOTE]['locked_in']),
            max_over_dict(self.log[LOCAL]['settles']),
            max_over_dict(self.log[REMOTE]['settles']),
            max_over_dict(self.log[LOCAL]['fails']),
            max_over_dict(self.log[REMOTE]['fails']),
            max([-1] + [(d.ctn_local or -1) for htlc_id, d in self.log[LOCAL]['fee_updates'].items()]),
            max([-1] + [(d.ctn_local or -1) for htlc_id, d in self.log[REMOTE]['fee_updates'].items()]),
        ])
        if max_local_ctn == local_ctn:
            return True
        else:
            # this assert does not work anymore when htlc history is not available
            #assert max_local_ctn + 1 == local_ctn, f'max_local_ctn={max_local_ctn}, local_ctn={local_ctn}'
            return False

    @with_lock
    def ctn_latest(self, sub: HTLCOwner) -> int:
        """Return the ctn for the latest (newest that has a valid sig) ctx of sub"""
        return self.ctn_oldest_unrevoked(sub) + int(self.is_revack_pending(sub))

    def ctn_oldest_unrevoked(self, sub: HTLCOwner) -> int:
        """Return the ctn for the oldest unrevoked ctx of sub"""
        return self.log[sub]['ctn']

    def is_revack_pending(self, sub: HTLCOwner) -> bool:
        """Returns True iff sub was sent commitment_signed but they did not
        send revoke_and_ack yet (sub has multiple unrevoked ctxs)
        """
        return self.log[sub]['revack_pending']

    def _set_revack_pending(self, sub: HTLCOwner, pending: bool) -> None:
        self.log[sub]['revack_pending'] = pending

    def get_ctn(self, proposer, name, htlc_id, owner, cap:bool):
        ctn = self.log[proposer][name].get(htlc_id, {}).get(owner)
        if cap:
            if ctn is not None and ctn <= self.ctn_latest(owner):
                return ctn
            else:
                return None
        return ctn

    def get_ctn_if_lower_than_latest(self, proposer, name, htlc_id, owner):
        ctn = self.log[proposer][name].get(htlc_id, {}).get(owner)
        if ctn is not None and ctn <= self.ctn_latest(owner):
            return ctn
        else:
            return None

    def get_next_htlc_id(self, sub: HTLCOwner) -> int:
        return self.log[sub]['next_htlc_id']

    def get_missing_htlc_history_interval(self, proposer: HTLCOwner) -> int:
        locked_in = self.log[proposer]['locked_in']
        max_id = self.get_next_htlc_id(proposer) - 1
        if max_id == -1:
            return 0, -1
        for i in range(max_id, -1, -1):
            # skip active htlcs
            settle = self.log[proposer]['settles'].get(i) or self.log[proposer]['fails'].get(i)
            if settle is None:
                break
            if settle[LOCAL] is not None or settle[REMOTE] is None:
                continue
            break
        N = i
        #
        s = [k for k in locked_in.keys() if k <=N]
        # fixme: there may be gaps in the history. we need to detect that
        K = max(s) + 1 if s else 0
        return K, N

    ##### Actions on channel:

    @with_lock
    def channel_open_finished(self):
        self.log[LOCAL]['ctn'] = 0
        self.log[REMOTE]['ctn'] = 0
        self._set_revack_pending(LOCAL, False)
        self._set_revack_pending(REMOTE, False)

    @with_lock
    def send_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        htlc_id = htlc.htlc_id
        if htlc_id != self.get_next_htlc_id(LOCAL):
            raise Exception(f"unexpected local htlc_id. next should be "
                            f"{self.get_next_htlc_id(LOCAL)} but got {htlc_id}")
        self.log[LOCAL]['adds'][htlc_id] = htlc
        self.log[LOCAL]['locked_in'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest(REMOTE)+1}
        self.log[LOCAL]['next_htlc_id'] += 1
        self._maybe_active_htlc_ids[LOCAL].add(htlc_id)
        return htlc

    @with_lock
    def recv_htlc(self, htlc: UpdateAddHtlc) -> None:
        htlc_id = htlc.htlc_id
        if htlc_id != self.get_next_htlc_id(REMOTE):
            raise Exception(f"unexpected remote htlc_id. next should be "
                            f"{self.get_next_htlc_id(REMOTE)} but got {htlc_id}")
        self.log[REMOTE]['adds'][htlc_id] = htlc
        self.log[REMOTE]['locked_in'][htlc_id] = {LOCAL: self.ctn_latest(LOCAL)+1, REMOTE: None}
        self.log[REMOTE]['next_htlc_id'] += 1
        self._maybe_active_htlc_ids[REMOTE].add(htlc_id)

    @with_lock
    def send_settle(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(REMOTE) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=REMOTE, ctn=next_ctn, htlc_proposer=REMOTE, htlc_id=htlc_id):
            raise Exception(f"(local) cannot remove htlc that is not there...")
        self.log[REMOTE]['settles'][htlc_id] = {LOCAL: None, REMOTE: next_ctn}
        self.invalidate_checkpoints(REMOTE, REMOTE, htlc_id, 'send_settle')

    @with_lock
    def recv_settle(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(LOCAL) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=LOCAL, ctn=next_ctn, htlc_proposer=LOCAL, htlc_id=htlc_id):
            raise Exception(f"(remote) cannot remove htlc that is not there...")
        self.log[LOCAL]['settles'][htlc_id] = {LOCAL: next_ctn, REMOTE: None}
        self.invalidate_checkpoints(LOCAL, LOCAL, htlc_id, 'recv_settle')

    @with_lock
    def send_fail(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(REMOTE) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=REMOTE, ctn=next_ctn, htlc_proposer=REMOTE, htlc_id=htlc_id):
            raise Exception(f"(local) cannot remove htlc that is not there...")
        self.log[REMOTE]['fails'][htlc_id] = {LOCAL: None, REMOTE: next_ctn}
        self.invalidate_checkpoints(REMOTE, REMOTE, htlc_id, 'send_fail')

    @with_lock
    def recv_fail(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(LOCAL) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=LOCAL, ctn=next_ctn, htlc_proposer=LOCAL, htlc_id=htlc_id):
            raise Exception(f"(remote) cannot remove htlc that is not there...")
        self.log[LOCAL]['fails'][htlc_id] = {LOCAL: next_ctn, REMOTE: None}
        self.invalidate_checkpoints(LOCAL, LOCAL, htlc_id, 'recv_fail')

    @with_lock
    def send_update_fee(self, feerate: int) -> None:
        fee_update = FeeUpdate(rate=feerate,
                               ctn_local=None, ctn_remote=self.ctn_latest(REMOTE) + 1)
        self._new_feeupdate(fee_update, subject=LOCAL)

    @with_lock
    def recv_update_fee(self, feerate: int) -> None:
        fee_update = FeeUpdate(rate=feerate,
                               ctn_local=self.ctn_latest(LOCAL) + 1, ctn_remote=None)
        self._new_feeupdate(fee_update, subject=REMOTE)

    @with_lock
    def _new_feeupdate(self, fee_update: FeeUpdate, subject: HTLCOwner) -> None:
        # overwrite last fee update if not yet committed to by anyone; otherwise append
        d = self.log[subject]['fee_updates']
        #assert type(d) is StoredDict
        n = len(d)
        last_fee_update = d[n-1]
        if (last_fee_update.ctn_local is None or last_fee_update.ctn_local > self.ctn_latest(LOCAL)) \
                and (last_fee_update.ctn_remote is None or last_fee_update.ctn_remote > self.ctn_latest(REMOTE)):
            d[n-1] = fee_update
        else:
            d[n] = fee_update

    @with_lock
    def send_ctx(self) -> None:
        assert self.ctn_latest(REMOTE) == self.ctn_oldest_unrevoked(REMOTE), (self.ctn_latest(REMOTE), self.ctn_oldest_unrevoked(REMOTE))
        self._set_revack_pending(REMOTE, True)
        self.on_ctn_latest(REMOTE)
        self.log[LOCAL]['was_revoke_last'] = False
        self._local_next_htlc_id = self.get_next_htlc_id(LOCAL)

    @with_lock
    def recv_ctx(self) -> None:
        assert self.ctn_latest(LOCAL) == self.ctn_oldest_unrevoked(LOCAL), (self.ctn_latest(LOCAL), self.ctn_oldest_unrevoked(LOCAL))
        self._set_revack_pending(LOCAL, True)
        self.on_ctn_latest(LOCAL)
        self._remote_next_htlc_id = self.get_next_htlc_id(REMOTE)

    @with_lock
    def send_rev(self) -> None:
        self.log[LOCAL]['ctn'] += 1
        self._set_revack_pending(LOCAL, False)
        self.on_ctn_latest(LOCAL) # maybe not needed
        self.log[LOCAL]['was_revoke_last'] = True
        # htlcs
        for htlc_id in self._maybe_active_htlc_ids[REMOTE]:
            ctns = self.log[REMOTE]['locked_in'][htlc_id]
            if ctns[REMOTE] is None and ctns[LOCAL] <= self.ctn_latest(LOCAL):
                ctns[REMOTE] = self.ctn_latest(REMOTE) + 1
        for log_action in ('settles', 'fails'):
            for htlc_id in self._maybe_active_htlc_ids[LOCAL]:
                ctns = self.log[LOCAL][log_action].get(htlc_id, None)
                if ctns is None: continue
                if ctns[REMOTE] is None and ctns[LOCAL] <= self.ctn_latest(LOCAL):
                    ctns[REMOTE] = self.ctn_latest(REMOTE) + 1
                    self.invalidate_checkpoints(LOCAL, REMOTE, htlc_id, f'send_rev {ctns}')
        self._update_maybe_active_htlc_ids()
        # fee updates
        for k, fee_update in list(self.log[REMOTE]['fee_updates'].items()):
            if fee_update.ctn_remote is None and fee_update.ctn_local <= self.ctn_latest(LOCAL):
                fee_update.ctn_remote = self.ctn_latest(REMOTE) + 1

    @with_lock
    def recv_rev(self) -> None:
        next_local_ctn = self.ctn_latest(LOCAL) + int(self._is_local_ctn_reached)

        self.log[REMOTE]['ctn'] += 1
        self._set_revack_pending(REMOTE, False)
        self.on_ctn_latest(REMOTE) # maybe not needed
        # htlcs
        for htlc_id in self._maybe_active_htlc_ids[LOCAL]:
            ctns = self.log[LOCAL]['locked_in'][htlc_id]
            if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                ctns[LOCAL] = next_local_ctn
        for log_action in ('settles', 'fails'):
            for htlc_id in self._maybe_active_htlc_ids[REMOTE]:
                ctns = self.log[REMOTE][log_action].get(htlc_id, None)
                if ctns is None: continue
                if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                    ctns[LOCAL] = next_local_ctn
                self.invalidate_checkpoints(REMOTE, LOCAL, htlc_id, 'recv_rev')
        self._update_maybe_active_htlc_ids()
        # fee updates
        for k, fee_update in list(self.log[LOCAL]['fee_updates'].items()):
            if fee_update.ctn_local is None and fee_update.ctn_remote <= self.ctn_latest(REMOTE):
                fee_update.ctn_local = next_local_ctn

        # no need to keep local update raw msgs anymore, they have just been ACKed.
        self.log[LOCAL]['unacked_updates'].pop(self.log[REMOTE]['ctn'], None)
        # reset this
        self._is_local_ctn_reached = True

    def get_active_htlcs(self):
        active_htlcs = {LOCAL:{}, REMOTE:{}}
        for proposer in [LOCAL, REMOTE]:
            for htlc_id in self._maybe_active_htlc_ids[proposer]:
                htlc_update = self.get_htlc_update(proposer, htlc_id, cap=True)
                if htlc_update.local_ctn_in is None and htlc_update.remote_ctn_in is None:
                    continue
                # remove inactive htlcs
                if htlc_update.local_ctn_out is not None and htlc_update.remote_ctn_out is not None:
                    continue
                active_htlcs[proposer][htlc_id] = htlc_update
        return active_htlcs

    def get_htlc_history(self, proposer, owner, next_htlc_id: int):
        # returns history between target and checkpoint
        log = self.log[proposer]
        locked_in_keys = log['locked_in'].keys()
        first_known_id = min(locked_in_keys) if locked_in_keys else next_htlc_id
        last_htlc_id = next_htlc_id - 1 # last of the requested interval
        checkpoint = (last_htlc_id // HTLC_PAGE_SIZE) * HTLC_PAGE_SIZE
        start = max(checkpoint, first_known_id)
        first_hash, delta_msat, max_ctn = self.get_checkpoint(proposer, owner=owner, htlc_id=start - 1)
        htlc_log = {}
        for htlc_id in range(start, next_htlc_id):
            htlc_update = self.get_htlc_update(proposer, htlc_id, cap=False)
            htlc_log[htlc_id] = htlc_update
        assert 0 <= len(htlc_log) <= HTLC_PAGE_SIZE
        return htlc_log, first_hash, delta_msat

    def get_htlc_update(self, proposer, htlc_id, cap=False):
        from .peerbackup import HtlcUpdate
        add = self.log[proposer]['adds'][htlc_id]
        local_ctn_in = self.get_ctn(proposer, 'locked_in', htlc_id, LOCAL, cap)
        local_ctn_settle = self.get_ctn(proposer, 'settles', htlc_id, LOCAL, cap)
        local_ctn_fail = self.get_ctn(proposer, 'fails', htlc_id, LOCAL, cap)
        remote_ctn_in = self.get_ctn(proposer, 'locked_in', htlc_id, REMOTE, cap)
        remote_ctn_settle = self.get_ctn(proposer, 'settles', htlc_id, REMOTE, cap)
        remote_ctn_fail = self.get_ctn(proposer, 'fails', htlc_id, REMOTE, cap)
        is_success = local_ctn_settle is not None or remote_ctn_settle is not None
        if is_success:
            local_ctn_out = local_ctn_settle
            remote_ctn_out = remote_ctn_settle
        else:
            local_ctn_out = local_ctn_fail
            remote_ctn_out = remote_ctn_fail
        htlc_update = HtlcUpdate(
            amount_msat = add.amount_msat,
            payment_hash = add.payment_hash,
            cltv_abs = add.cltv_abs,
            timestamp = add.timestamp,
            htlc_id = add.htlc_id,
            is_success = is_success,
            local_ctn_in = local_ctn_in,
            local_ctn_out = local_ctn_out,
            remote_ctn_in = remote_ctn_in,
            remote_ctn_out = remote_ctn_out,
        )
        return htlc_update

    @with_lock
    def _update_maybe_active_htlc_ids(self) -> None:
        # - Loosely, we want a set that contains the htlcs that are
        #   not "removed and revoked from all ctxs of both parties". (self._maybe_active_htlc_ids)
        #   It is guaranteed that those htlcs are in the set, but older htlcs might be there too:
        #   there is a sanity margin of 1 ctn -- this relaxes the care needed re order of method calls.
        # - balance_delta is in sync with maybe_active_htlc_ids. When htlcs are removed from the latter,
        #   balance_delta is updated to reflect that htlc.
        sanity_margin = 1
        for htlc_proposer in (LOCAL, REMOTE):
            for log_action in ('settles', 'fails'):
                for htlc_id in list(self._maybe_active_htlc_ids[htlc_proposer]):
                    ctns = self.log[htlc_proposer][log_action].get(htlc_id, None)
                    if ctns is None: continue
                    if (ctns[LOCAL] is not None
                            and ctns[LOCAL] <= self.ctn_oldest_unrevoked(LOCAL) - sanity_margin
                            and ctns[REMOTE] is not None
                            and ctns[REMOTE] <= self.ctn_oldest_unrevoked(REMOTE) - sanity_margin):
                        self._maybe_active_htlc_ids[htlc_proposer].remove(htlc_id)
                        if log_action == 'settles':
                            htlc = self.log[htlc_proposer]['adds'][htlc_id]  # type: UpdateAddHtlc
                            self._balance_delta -= htlc.amount_msat * htlc_proposer

    @with_lock
    def _init_maybe_active_htlc_ids(self):
        # first idx is "side who offered htlc":
        self._maybe_active_htlc_ids = {LOCAL: set(), REMOTE: set()}  # type: Dict[HTLCOwner, Set[int]]
        # add all htlcs
        self._balance_delta = 0  # the balance delta of LOCAL since channel open
        for htlc_proposer in (LOCAL, REMOTE):
            for htlc_id in self.log[htlc_proposer]['adds']:
                self._maybe_active_htlc_ids[htlc_proposer].add(htlc_id)
        # remove old htlcs
        self._update_maybe_active_htlc_ids()

    @with_lock
    def discard_unsigned_remote_updates(self):
        """Discard updates sent by the remote, that the remote itself
        did not yet sign (i.e. there was no corresponding commitment_signed msg)
        """
        # htlcs added
        for htlc_id, ctns in list(self.log[REMOTE]['locked_in'].items()):
            if ctns[LOCAL] > self.ctn_latest(LOCAL):
                del self.log[REMOTE]['locked_in'][htlc_id]
                del self.log[REMOTE]['adds'][htlc_id]
                self._maybe_active_htlc_ids[REMOTE].discard(htlc_id)
        if self.log[REMOTE]['locked_in']:
            self.log[REMOTE]['next_htlc_id'] = max([int(x) for x in self.log[REMOTE]['locked_in'].keys()]) + 1
        else:
            # fixme: test this
            self.log[REMOTE]['next_htlc_id'] = self._remote_next_htlc_id
        # htlcs removed
        for log_action in ('settles', 'fails'):
            for htlc_id, ctns in list(self.log[LOCAL][log_action].items()):
                if ctns[LOCAL] > self.ctn_latest(LOCAL):
                    del self.log[LOCAL][log_action][htlc_id]
                    self.invalidate_checkpoints(LOCAL, LOCAL, htlc_id, 'discard')
                    self.invalidate_checkpoints(LOCAL, REMOTE, htlc_id, 'discard')
        # fee updates
        for k, fee_update in list(self.log[REMOTE]['fee_updates'].items()):
            if fee_update.ctn_local > self.ctn_latest(LOCAL):
                self.log[REMOTE]['fee_updates'].pop(k)

    @with_lock
    def store_local_update_raw_msg(self, raw_update_msg: bytes, *, is_commitment_signed: bool) -> None:
        """We need to be able to replay unacknowledged updates we sent to the remote
        in case of disconnections. Hence, raw update and commitment_signed messages
        are stored temporarily (until they are acked)."""
        # self.log[LOCAL]['unacked_updates'][ctn_idx] is a list of raw messages
        # containing some number of updates and then a single commitment_signed
        if is_commitment_signed:
            ctn_idx = self.ctn_latest(REMOTE)
        else:
            ctn_idx = self.ctn_latest(REMOTE) + 1
        l = self.log[LOCAL]['unacked_updates'].get(ctn_idx, [])
        l.append(raw_update_msg.hex())
        self.log[LOCAL]['unacked_updates'][ctn_idx] = l

    @with_lock
    def get_unacked_local_updates(self) -> Dict[int, Sequence[bytes]]:
        #return self.log[LOCAL]['unacked_updates']
        return {ctn: [bfh(msg) for msg in messages]
                for ctn, messages in self.log[LOCAL]['unacked_updates'].items()}

    @with_lock
    def was_revoke_last(self) -> bool:
        """Whether we sent a revoke_and_ack after the last commitment_signed we sent."""
        return self.log[LOCAL].get('was_revoke_last') or False

    ##### Queries re HTLCs:

    def get_htlc_by_id(self, htlc_proposer: HTLCOwner, htlc_id: int) -> UpdateAddHtlc:
        return self.log[htlc_proposer]['adds'][htlc_id]

    @with_lock
    def is_htlc_active_at_ctn(self, *, ctx_owner: HTLCOwner, ctn: int,
                              htlc_proposer: HTLCOwner, htlc_id: int) -> bool:
        htlc_id = int(htlc_id)
        if htlc_id >= self.get_next_htlc_id(htlc_proposer):
            return False
        settles = self.log[htlc_proposer]['settles']
        fails = self.log[htlc_proposer]['fails']
        ctns = self.log[htlc_proposer]['locked_in'][htlc_id]
        if ctns[ctx_owner] is not None and ctns[ctx_owner] <= ctn:
            not_settled = htlc_id not in settles or settles[htlc_id][ctx_owner] is None or settles[htlc_id][ctx_owner] > ctn
            not_failed = htlc_id not in fails or fails[htlc_id][ctx_owner] is None or fails[htlc_id][ctx_owner] > ctn
            if not_settled and not_failed:
                return True
        return False

    @with_lock
    def is_htlc_irrevocably_added_yet(
            self,
            *,
            ctx_owner: HTLCOwner = None,
            htlc_proposer: HTLCOwner,
            htlc_id: int,
    ) -> bool:
        """Returns whether `add_htlc` was irrevocably committed to `ctx_owner's` ctx.
        If `ctx_owner` is None, both parties' ctxs are checked.
        """
        in_local = self._is_htlc_irrevocably_added_yet(
            ctx_owner=LOCAL, htlc_proposer=htlc_proposer, htlc_id=htlc_id)
        in_remote = self._is_htlc_irrevocably_added_yet(
            ctx_owner=REMOTE, htlc_proposer=htlc_proposer, htlc_id=htlc_id)
        if ctx_owner is None:
            return in_local and in_remote
        elif ctx_owner == LOCAL:
            return in_local
        elif ctx_owner == REMOTE:
            return in_remote
        else:
            raise Exception(f"unexpected ctx_owner: {ctx_owner!r}")

    @with_lock
    def _is_htlc_irrevocably_added_yet(
            self,
            *,
            ctx_owner: HTLCOwner,
            htlc_proposer: HTLCOwner,
            htlc_id: int,
    ) -> bool:
        if htlc_id >= self.get_next_htlc_id(htlc_proposer):
            return False
        ctns = self.log[htlc_proposer]['locked_in'][htlc_id]
        if ctns[ctx_owner] is None:
            return False
        return ctns[ctx_owner] <= self.ctn_oldest_unrevoked(ctx_owner)

    @with_lock
    def is_htlc_irrevocably_removed_yet(
            self,
            *,
            ctx_owner: HTLCOwner = None,
            htlc_proposer: HTLCOwner,
            htlc_id: int,
    ) -> bool:
        """Returns whether the removal of an htlc was irrevocably committed to `ctx_owner's` ctx.
        The removal can either be a fulfill/settle or a fail; they are not distinguished.
        If `ctx_owner` is None, both parties' ctxs are checked.
        """
        in_local = self._is_htlc_irrevocably_removed_yet(
            ctx_owner=LOCAL, htlc_proposer=htlc_proposer, htlc_id=htlc_id)
        in_remote = self._is_htlc_irrevocably_removed_yet(
            ctx_owner=REMOTE, htlc_proposer=htlc_proposer, htlc_id=htlc_id)
        if ctx_owner is None:
            return in_local and in_remote
        elif ctx_owner == LOCAL:
            return in_local
        elif ctx_owner == REMOTE:
            return in_remote
        else:
            raise Exception(f"unexpected ctx_owner: {ctx_owner!r}")

    @with_lock
    def _is_htlc_irrevocably_removed_yet(
            self,
            *,
            ctx_owner: HTLCOwner,
            htlc_proposer: HTLCOwner,
            htlc_id: int,
    ) -> bool:
        if htlc_id >= self.get_next_htlc_id(htlc_proposer):
            return False
        if htlc_id in self.log[htlc_proposer]['settles']:
            ctn_of_settle = self.log[htlc_proposer]['settles'][htlc_id][ctx_owner]
        else:
            ctn_of_settle = None
        if htlc_id in self.log[htlc_proposer]['fails']:
            ctn_of_fail = self.log[htlc_proposer]['fails'][htlc_id][ctx_owner]
        else:
            ctn_of_fail = None
        ctn_of_rm = ctn_of_settle or ctn_of_fail or None
        if ctn_of_rm is None:
            return False
        return ctn_of_rm <= self.ctn_oldest_unrevoked(ctx_owner)

    @with_lock
    def htlcs_by_direction(self, subject: HTLCOwner, direction: Direction,
                           ctn: int = None) -> Dict[int, UpdateAddHtlc]:
        """Return the dict of received or sent (depending on direction) HTLCs
        in subject's ctx at ctn, keyed by htlc_id.

        direction is relative to subject!
        """
        assert type(subject) is HTLCOwner
        assert type(direction) is Direction
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(subject)
        d = {}
        # subject's ctx
        # party is the proposer of the HTLCs
        party = subject if direction == SENT else subject.inverted()
        if ctn >= self.ctn_oldest_unrevoked(subject):
            considered_htlc_ids = self._maybe_active_htlc_ids[party]
        else:  # ctn is too old; need to consider full log (slow...)
            considered_htlc_ids = self.log[party]['locked_in']
        for htlc_id in considered_htlc_ids:
            htlc_id = int(htlc_id)
            if self.is_htlc_active_at_ctn(ctx_owner=subject, ctn=ctn, htlc_proposer=party, htlc_id=htlc_id):
                d[htlc_id] = self.log[party]['adds'][htlc_id]
        return d

    @with_lock
    def htlcs(self, subject: HTLCOwner, ctn: int = None) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of HTLCs in subject's ctx at ctn."""
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(subject)
        l = []
        l += [(SENT, x) for x in self.htlcs_by_direction(subject, SENT, ctn).values()]
        l += [(RECEIVED, x) for x in self.htlcs_by_direction(subject, RECEIVED, ctn).values()]
        return l

    @with_lock
    def get_htlcs_in_oldest_unrevoked_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_oldest_unrevoked(subject)
        return self.htlcs(subject, ctn)

    @with_lock
    def get_htlcs_in_latest_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_latest(subject)
        return self.htlcs(subject, ctn)

    @with_lock
    def get_htlcs_in_next_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_latest(subject) + 1
        return self.htlcs(subject, ctn)

    def was_htlc_preimage_released(self, *, htlc_id: int, htlc_proposer: HTLCOwner) -> bool:
        settles = self.log[htlc_proposer]['settles']
        if htlc_id not in settles:
            return False
        return settles[htlc_id][htlc_proposer] is not None

    def was_htlc_failed(self, *, htlc_id: int, htlc_proposer: HTLCOwner) -> bool:
        """Returns whether an HTLC has been (or will be if we already know) failed."""
        fails = self.log[htlc_proposer]['fails']
        if htlc_id not in fails:
            return False
        return fails[htlc_id][htlc_proposer] is not None

    @with_lock
    def all_settled_htlcs_ever_by_direction(self, subject: HTLCOwner, direction: Direction,
                                            ctn: int = None) -> Sequence[UpdateAddHtlc]:
        """Return the list of all HTLCs that have been ever settled in subject's
        ctx up to ctn, filtered to only "direction".
        """
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(subject)
        # subject's ctx
        # party is the proposer of the HTLCs
        party = subject if direction == SENT else subject.inverted()
        d = []
        for htlc_id, ctns in self.log[party]['settles'].items():
            if ctns[subject] is not None and ctns[subject] <= ctn:
                d.append(self.log[party]['adds'][htlc_id])
        return d

    @with_lock
    def all_settled_htlcs_ever(self, subject: HTLCOwner, ctn: int = None) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of all HTLCs that have been ever settled in subject's
        ctx up to ctn.
        """
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(subject)
        sent = [(SENT, x) for x in self.all_settled_htlcs_ever_by_direction(subject, SENT, ctn)]
        received = [(RECEIVED, x) for x in self.all_settled_htlcs_ever_by_direction(subject, RECEIVED, ctn)]
        return sent + received

    @with_lock
    def all_htlcs_ever(self) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        sent = [(SENT, htlc) for htlc in self.log[LOCAL]['adds'].values()]
        received = [(RECEIVED, htlc) for htlc in self.log[REMOTE]['adds'].values()]
        return sent + received

    def get_initial_balance_offset(self, proposer, ctx_owner):
        locked_in = self.log[proposer]['locked_in']
        checkpoints = self.log[proposer]['checkpoints']
        min_locked_in = min(locked_in.keys()) if locked_in else -1
        min_checkpoint = min(checkpoints.keys()) if checkpoints else -1
        if min_checkpoint < min_locked_in:
            #_hash, delta_msat = self.get_checkpoint(proposer, ctx_owner, min_checkpoint)
            #return delta_msat
            return 0
        else:
            return 0

    @with_lock
    def get_balance_msat(self, whose: HTLCOwner, *, ctx_owner=HTLCOwner.LOCAL, ctn: int = None,
                         initial_balance_msat: int) -> int:
        """Returns the balance of 'whose' in 'ctx' at 'ctn'.
        Only HTLCs that have been settled by that ctn are counted.
        """
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(ctx_owner)
        balance = initial_balance_msat
        balance -= self.get_initial_balance_offset(whose, ctx_owner)
        balance += self.get_initial_balance_offset(-whose, ctx_owner)

        if ctn >= self.ctn_oldest_unrevoked(ctx_owner):
            balance += self._balance_delta * whose
            considered_sent_htlc_ids = self._maybe_active_htlc_ids[whose]
            considered_recv_htlc_ids = self._maybe_active_htlc_ids[-whose]
        else:  # ctn is too old; need to consider full log (slow...)
            considered_sent_htlc_ids = self.log[whose]['settles']
            considered_recv_htlc_ids = self.log[-whose]['settles']
        # sent htlcs
        for htlc_id in considered_sent_htlc_ids:
            ctns = self.log[whose]['settles'].get(htlc_id, None)
            if ctns is None:
                continue
            if ctns[ctx_owner] is not None and ctns[ctx_owner] <= ctn:
                htlc = self.log[whose]['adds'][htlc_id]
                balance -= htlc.amount_msat
        # recv htlcs
        for htlc_id in considered_recv_htlc_ids:
            ctns = self.log[-whose]['settles'].get(htlc_id, None)
            if ctns is None:
                continue
            if ctns[ctx_owner] is not None and ctns[ctx_owner] <= ctn:
                htlc = self.log[-whose]['adds'][htlc_id]
                balance += htlc.amount_msat
        return balance

    @with_lock
    def _get_htlcs_that_got_removed_exactly_at_ctn(
            self, ctn: int, *, ctx_owner: HTLCOwner, htlc_proposer: HTLCOwner, log_action: str,
    ) -> Sequence[UpdateAddHtlc]:
        if ctn >= self.ctn_oldest_unrevoked(ctx_owner):
            considered_htlc_ids = self._maybe_active_htlc_ids[htlc_proposer]
        else:  # ctn is too old; need to consider full log (slow...)
            considered_htlc_ids = self.log[htlc_proposer][log_action]
        htlcs = []
        for htlc_id in considered_htlc_ids:
            ctns = self.log[htlc_proposer][log_action].get(htlc_id, None)
            if ctns is None:
                continue
            if ctns[ctx_owner] == ctn:
                htlcs.append(self.log[htlc_proposer]['adds'][htlc_id])
        return htlcs

    def received_in_ctn(self, local_ctn: int) -> Sequence[UpdateAddHtlc]:
        """
        received htlcs that became fulfilled when we send a revocation.
        we check only local, because they are committed in the remote ctx first.
        """
        return self._get_htlcs_that_got_removed_exactly_at_ctn(local_ctn,
                                                               ctx_owner=LOCAL,
                                                               htlc_proposer=REMOTE,
                                                               log_action='settles')

    def sent_in_ctn(self, remote_ctn: int) -> Sequence[UpdateAddHtlc]:
        """
        sent htlcs that became fulfilled when we received a revocation
        we check only remote, because they are committed in the local ctx first.
        """
        return self._get_htlcs_that_got_removed_exactly_at_ctn(remote_ctn,
                                                               ctx_owner=REMOTE,
                                                               htlc_proposer=LOCAL,
                                                               log_action='settles')

    def failed_in_ctn(self, remote_ctn: int) -> Sequence[UpdateAddHtlc]:
        """
        sent htlcs that became failed when we received a revocation
        we check only remote, because they are committed in the local ctx first.
        """
        return self._get_htlcs_that_got_removed_exactly_at_ctn(remote_ctn,
                                                               ctx_owner=REMOTE,
                                                               htlc_proposer=LOCAL,
                                                               log_action='fails')

    ##### Queries re Fees:
    # note: feerates are in sat/kw everywhere in this file

    @with_lock
    def get_feerate(self, subject: HTLCOwner, ctn: int) -> int:
        """Return feerate (sat/kw) used in subject's commitment txn at ctn."""
        ctn = max(0, ctn)  # FIXME rm this
        # only one party can update fees; use length of logs to figure out which:
        assert not (len(self.log[LOCAL]['fee_updates']) > 0 and len(self.log[REMOTE]['fee_updates']) > 0)
        fee_log = self.log[LOCAL]['fee_updates']  # type: Sequence[FeeUpdate]
        if len(self.log[REMOTE]['fee_updates']) > 0:
            fee_log = self.log[REMOTE]['fee_updates']
        # binary search
        left = 0
        right = len(fee_log)
        while True:
            i = (left + right) // 2
            ctn_at_i = fee_log[i].ctn_local if subject == LOCAL else fee_log[i].ctn_remote
            if right - left <= 1:
                break
            if ctn_at_i is None:  # Nones can only be on the right end
                right = i
                continue
            if ctn_at_i <= ctn:  # among equals, we want the rightmost
                left = i
            else:
                right = i
        assert ctn_at_i <= ctn
        return fee_log[i].rate

    def get_feerate_in_oldest_unrevoked_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_oldest_unrevoked(subject))

    def get_feerate_in_latest_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_latest(subject))

    def get_feerate_in_next_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_latest(subject) + 1)
