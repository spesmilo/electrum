from copy import deepcopy
from typing import Optional, Sequence, Tuple, List, Dict, TYPE_CHECKING, Set

from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction, FeeUpdate
from .util import bh2u, bfh

if TYPE_CHECKING:
    from .json_db import StoredDict

class HTLCManager:

    def __init__(self, log:'StoredDict', *, initial_feerate=None):

        if len(log) == 0:
            initial = {
                'adds': {},              # "side who offered htlc" -> htlc_id -> htlc
                'locked_in': {},         # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                'settles': {},           # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                'fails': {},             # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                'fee_updates': {},       # "side who initiated fee update" -> action -> list of FeeUpdates
                'revack_pending': False,
                'next_htlc_id': 0,
                'ctn': -1,               # oldest unrevoked ctx of sub
            }
            # note: "htlc_id" keys in dict are str! but due to json_db magic they can *almost* be treated as int...
            log[LOCAL] = deepcopy(initial)
            log[REMOTE] = deepcopy(initial)
            log['unacked_local_updates2'] = {}

        if 'unfulfilled_htlcs' not in log:
            log['unfulfilled_htlcs'] = {}  # htlc_id -> onion_packet
        if 'fail_htlc_reasons' not in log:
            log['fail_htlc_reasons'] = {}  # htlc_id -> error_bytes, failure_message

        # maybe bootstrap fee_updates if initial_feerate was provided
        if initial_feerate is not None:
            assert type(initial_feerate) is int
            for sub in (LOCAL, REMOTE):
                if not log[sub]['fee_updates']:
                    log[sub]['fee_updates'][0] = FeeUpdate(rate=initial_feerate, ctn_local=0, ctn_remote=0)
        self.log = log
        self._init_maybe_active_htlc_ids()

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

    def get_next_htlc_id(self, sub: HTLCOwner) -> int:
        return self.log[sub]['next_htlc_id']

    ##### Actions on channel:

    def channel_open_finished(self):
        self.log[LOCAL]['ctn'] = 0
        self.log[REMOTE]['ctn'] = 0
        self._set_revack_pending(LOCAL, False)
        self._set_revack_pending(REMOTE, False)

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

    def recv_htlc(self, htlc: UpdateAddHtlc) -> None:
        htlc_id = htlc.htlc_id
        if htlc_id != self.get_next_htlc_id(REMOTE):
            raise Exception(f"unexpected remote htlc_id. next should be "
                            f"{self.get_next_htlc_id(REMOTE)} but got {htlc_id}")
        self.log[REMOTE]['adds'][htlc_id] = htlc
        self.log[REMOTE]['locked_in'][htlc_id] = {LOCAL: self.ctn_latest(LOCAL)+1, REMOTE: None}
        self.log[REMOTE]['next_htlc_id'] += 1
        self._maybe_active_htlc_ids[REMOTE].add(htlc_id)

    def send_settle(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(REMOTE) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=REMOTE, ctn=next_ctn, htlc_proposer=REMOTE, htlc_id=htlc_id):
            raise Exception(f"(local) cannot remove htlc that is not there...")
        self.log[REMOTE]['settles'][htlc_id] = {LOCAL: None, REMOTE: next_ctn}

    def recv_settle(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(LOCAL) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=LOCAL, ctn=next_ctn, htlc_proposer=LOCAL, htlc_id=htlc_id):
            raise Exception(f"(remote) cannot remove htlc that is not there...")
        self.log[LOCAL]['settles'][htlc_id] = {LOCAL: next_ctn, REMOTE: None}

    def send_fail(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(REMOTE) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=REMOTE, ctn=next_ctn, htlc_proposer=REMOTE, htlc_id=htlc_id):
            raise Exception(f"(local) cannot remove htlc that is not there...")
        self.log[REMOTE]['fails'][htlc_id] = {LOCAL: None, REMOTE: next_ctn}

    def recv_fail(self, htlc_id: int) -> None:
        next_ctn = self.ctn_latest(LOCAL) + 1
        if not self.is_htlc_active_at_ctn(ctx_owner=LOCAL, ctn=next_ctn, htlc_proposer=LOCAL, htlc_id=htlc_id):
            raise Exception(f"(remote) cannot remove htlc that is not there...")
        self.log[LOCAL]['fails'][htlc_id] = {LOCAL: next_ctn, REMOTE: None}

    def send_update_fee(self, feerate: int) -> None:
        fee_update = FeeUpdate(rate=feerate,
                               ctn_local=None, ctn_remote=self.ctn_latest(REMOTE) + 1)
        self._new_feeupdate(fee_update, subject=LOCAL)

    def recv_update_fee(self, feerate: int) -> None:
        fee_update = FeeUpdate(rate=feerate,
                               ctn_local=self.ctn_latest(LOCAL) + 1, ctn_remote=None)
        self._new_feeupdate(fee_update, subject=REMOTE)

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

    def send_ctx(self) -> None:
        assert self.ctn_latest(REMOTE) == self.ctn_oldest_unrevoked(REMOTE), (self.ctn_latest(REMOTE), self.ctn_oldest_unrevoked(REMOTE))
        self._set_revack_pending(REMOTE, True)

    def recv_ctx(self) -> None:
        assert self.ctn_latest(LOCAL) == self.ctn_oldest_unrevoked(LOCAL), (self.ctn_latest(LOCAL), self.ctn_oldest_unrevoked(LOCAL))
        self._set_revack_pending(LOCAL, True)

    def send_rev(self) -> None:
        self.log[LOCAL]['ctn'] += 1
        self._set_revack_pending(LOCAL, False)
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
        self._update_maybe_active_htlc_ids()
        # fee updates
        for k, fee_update in list(self.log[REMOTE]['fee_updates'].items()):
            if fee_update.ctn_remote is None and fee_update.ctn_local <= self.ctn_latest(LOCAL):
                fee_update.ctn_remote = self.ctn_latest(REMOTE) + 1

    def recv_rev(self) -> None:
        self.log[REMOTE]['ctn'] += 1
        self._set_revack_pending(REMOTE, False)
        # htlcs
        for htlc_id in self._maybe_active_htlc_ids[LOCAL]:
            ctns = self.log[LOCAL]['locked_in'][htlc_id]
            if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                ctns[LOCAL] = self.ctn_latest(LOCAL) + 1
        for log_action in ('settles', 'fails'):
            for htlc_id in self._maybe_active_htlc_ids[REMOTE]:
                ctns = self.log[REMOTE][log_action].get(htlc_id, None)
                if ctns is None: continue
                if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                    ctns[LOCAL] = self.ctn_latest(LOCAL) + 1
        self._update_maybe_active_htlc_ids()
        # fee updates
        for k, fee_update in list(self.log[LOCAL]['fee_updates'].items()):
            if fee_update.ctn_local is None and fee_update.ctn_remote <= self.ctn_latest(REMOTE):
                fee_update.ctn_local = self.ctn_latest(LOCAL) + 1

        # no need to keep local update raw msgs anymore, they have just been ACKed.
        self.log['unacked_local_updates2'].pop(self.log[REMOTE]['ctn'], None)

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
            self.log[REMOTE]['next_htlc_id'] = 0
        # htlcs removed
        for log_action in ('settles', 'fails'):
            for htlc_id, ctns in list(self.log[LOCAL][log_action].items()):
                if ctns[LOCAL] > self.ctn_latest(LOCAL):
                    del self.log[LOCAL][log_action][htlc_id]
        # fee updates
        for k, fee_update in list(self.log[REMOTE]['fee_updates'].items()):
            if fee_update.ctn_local > self.ctn_latest(LOCAL):
                self.log[REMOTE]['fee_updates'].pop(k)

    def store_local_update_raw_msg(self, raw_update_msg: bytes, *, is_commitment_signed: bool) -> None:
        """We need to be able to replay unacknowledged updates we sent to the remote
        in case of disconnections. Hence, raw update and commitment_signed messages
        are stored temporarily (until they are acked)."""
        # self.log['unacked_local_updates2'][ctn_idx] is a list of raw messages
        # containing some number of updates and then a single commitment_signed
        if is_commitment_signed:
            ctn_idx = self.ctn_latest(REMOTE)
        else:
            ctn_idx = self.ctn_latest(REMOTE) + 1
        l = self.log['unacked_local_updates2'].get(ctn_idx, [])
        l.append(raw_update_msg.hex())
        self.log['unacked_local_updates2'][ctn_idx] = l

    def get_unacked_local_updates(self) -> Dict[int, Sequence[bytes]]:
        #return self.log['unacked_local_updates2']
        return {int(ctn): [bfh(msg) for msg in messages]
                for ctn, messages in self.log['unacked_local_updates2'].items()}

    ##### Queries re HTLCs:

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

    def htlcs(self, subject: HTLCOwner, ctn: int = None) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of HTLCs in subject's ctx at ctn."""
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(subject)
        l = []
        l += [(SENT, x) for x in self.htlcs_by_direction(subject, SENT, ctn).values()]
        l += [(RECEIVED, x) for x in self.htlcs_by_direction(subject, RECEIVED, ctn).values()]
        return l

    def get_htlcs_in_oldest_unrevoked_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_oldest_unrevoked(subject)
        return self.htlcs(subject, ctn)

    def get_htlcs_in_latest_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_latest(subject)
        return self.htlcs(subject, ctn)

    def get_htlcs_in_next_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_latest(subject) + 1
        return self.htlcs(subject, ctn)

    def was_htlc_preimage_released(self, *, htlc_id: int, htlc_sender: HTLCOwner) -> bool:
        settles = self.log[htlc_sender]['settles']
        if htlc_id not in settles:
            return False
        return settles[htlc_id][htlc_sender] is not None

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

    def all_settled_htlcs_ever(self, subject: HTLCOwner, ctn: int = None) \
            -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of all HTLCs that have been ever settled in subject's
        ctx up to ctn.
        """
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(subject)
        sent = [(SENT, x) for x in self.all_settled_htlcs_ever_by_direction(subject, SENT, ctn)]
        received = [(RECEIVED, x) for x in self.all_settled_htlcs_ever_by_direction(subject, RECEIVED, ctn)]
        return sent + received

    def get_balance_msat(self, whose: HTLCOwner, *, ctx_owner=HTLCOwner.LOCAL, ctn: int = None,
                         initial_balance_msat: int) -> int:
        """Returns the balance of 'whose' in 'ctx' at 'ctn'.
        Only HTLCs that have been settled by that ctn are counted.
        """
        if ctn is None:
            ctn = self.ctn_oldest_unrevoked(ctx_owner)
        balance = initial_balance_msat
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
            if ctns is None: continue
            if ctns[ctx_owner] is not None and ctns[ctx_owner] <= ctn:
                htlc = self.log[whose]['adds'][htlc_id]
                balance -= htlc.amount_msat
        # recv htlcs
        for htlc_id in considered_recv_htlc_ids:
            ctns = self.log[-whose]['settles'].get(htlc_id, None)
            if ctns is None: continue
            if ctns[ctx_owner] is not None and ctns[ctx_owner] <= ctn:
                htlc = self.log[-whose]['adds'][htlc_id]
                balance += htlc.amount_msat
        return balance

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
            if ctns is None: continue
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

    def get_feerate(self, subject: HTLCOwner, ctn: int) -> int:
        """Return feerate used in subject's commitment txn at ctn."""
        ctn = max(0, ctn)  # FIXME rm this
        # only one party can update fees; use length of logs to figure out which:
        assert not (len(self.log[LOCAL]['fee_updates']) > 1 and len(self.log[REMOTE]['fee_updates']) > 1)
        fee_log = self.log[LOCAL]['fee_updates']  # type: Sequence[FeeUpdate]
        if len(self.log[REMOTE]['fee_updates']) > 1:
            fee_log = self.log[REMOTE]['fee_updates']
        # binary search
        left = 0
        right = len(fee_log)
        while True:
            i = (left + right) // 2
            ctn_at_i = fee_log[i].ctn_local if subject==LOCAL else fee_log[i].ctn_remote
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
