from copy import deepcopy
from typing import Optional, Sequence, Tuple, List

from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction, FeeUpdate
from .util import bh2u


class HTLCManager:

    def __init__(self, *, local_ctn=0, remote_ctn=0, log=None, initial_feerate=None):
        # self.ctn[sub] is the ctn for the oldest unrevoked ctx of sub
        self.ctn = {LOCAL:local_ctn, REMOTE: remote_ctn}
        if log is None:
            initial = {
                'adds': {},
                'locked_in': {},
                'settles': {},
                'fails': {},
                'fee_updates': [],
                'revack_pending': False,
            }
            log = {LOCAL: deepcopy(initial), REMOTE: deepcopy(initial)}
        else:
            assert type(log) is dict
            log = {(HTLCOwner(int(k)) if k in ("-1", "1") else k): v
                   for k, v in deepcopy(log).items()}
            for sub in (LOCAL, REMOTE):
                log[sub]['adds'] = {int(x): UpdateAddHtlc(*y) for x, y in log[sub]['adds'].items()}
                coerceHtlcOwner2IntMap = lambda ctns: {HTLCOwner(int(owner)): ctn for owner, ctn in ctns.items()}
                # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                log[sub]['locked_in'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['locked_in'].items()}
                log[sub]['settles'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['settles'].items()}
                log[sub]['fails'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['fails'].items()}
                # "side who initiated fee update" -> action -> list of FeeUpdates
                log[sub]['fee_updates'] = [FeeUpdate.from_dict(fee_upd) for fee_upd in log[sub]['fee_updates']]
        # maybe bootstrap fee_updates if initial_feerate was provided
        if initial_feerate is not None:
            assert type(initial_feerate) is int
            for sub in (LOCAL, REMOTE):
                if not log[sub]['fee_updates']:
                    log[sub]['fee_updates'].append(FeeUpdate(initial_feerate, ctns={LOCAL:0, REMOTE:0}))
        self.log = log

    def ctn_latest(self, sub: HTLCOwner) -> int:
        """Return the ctn for the latest (newest that has a valid sig) ctx of sub"""
        return self.ctn[sub] + int(self.is_revack_pending(sub))

    def is_revack_pending(self, sub: HTLCOwner) -> bool:
        """Returns True iff sub was sent commitment_signed but they did not
        send revoke_and_ack yet (sub has multiple unrevoked ctxs)
        """
        return self.log[sub]['revack_pending']

    def _set_revack_pending(self, sub: HTLCOwner, pending: bool) -> None:
        self.log[sub]['revack_pending'] = pending

    def to_save(self):
        log = deepcopy(self.log)
        for sub in (LOCAL, REMOTE):
            # adds
            d = {}
            for htlc_id, htlc in log[sub]['adds'].items():
                d[htlc_id] = (htlc[0], bh2u(htlc[1])) + htlc[2:]
            log[sub]['adds'] = d
            # fee_updates
            log[sub]['fee_updates'] = [FeeUpdate.to_dict(fee_upd) for fee_upd in log[sub]['fee_updates']]
        return log

    ##### Actions on channel:

    def channel_open_finished(self):
        self.ctn = {LOCAL: 0, REMOTE: 0}
        self._set_revack_pending(LOCAL, False)
        self._set_revack_pending(REMOTE, False)

    def send_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        htlc_id = htlc.htlc_id
        self.log[LOCAL]['adds'][htlc_id] = htlc
        self.log[LOCAL]['locked_in'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest(REMOTE)+1}
        return htlc

    def recv_htlc(self, htlc: UpdateAddHtlc) -> None:
        htlc_id = htlc.htlc_id
        self.log[REMOTE]['adds'][htlc_id] = htlc
        self.log[REMOTE]['locked_in'][htlc_id] = {LOCAL: self.ctn_latest(LOCAL)+1, REMOTE: None}

    def send_settle(self, htlc_id: int) -> None:
        self.log[REMOTE]['settles'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest(REMOTE) + 1}

    def recv_settle(self, htlc_id: int) -> None:
        self.log[LOCAL]['settles'][htlc_id] = {LOCAL: self.ctn_latest(LOCAL) + 1, REMOTE: None}

    def send_fail(self, htlc_id: int) -> None:
        self.log[REMOTE]['fails'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest(REMOTE) + 1}

    def recv_fail(self, htlc_id: int) -> None:
        self.log[LOCAL]['fails'][htlc_id] = {LOCAL: self.ctn_latest(LOCAL) + 1, REMOTE: None}

    def send_update_fee(self, feerate: int) -> None:
        fee_update = FeeUpdate(rate=feerate,
                               ctns={LOCAL: None, REMOTE: self.ctn_latest(REMOTE) + 1})
        self._new_feeupdate(fee_update, subject=LOCAL)

    def recv_update_fee(self, feerate: int) -> None:
        fee_update = FeeUpdate(rate=feerate,
                               ctns={LOCAL: self.ctn_latest(LOCAL) + 1, REMOTE: None})
        self._new_feeupdate(fee_update, subject=REMOTE)

    def _new_feeupdate(self, fee_update: FeeUpdate, subject: HTLCOwner) -> None:
        # overwrite last fee update if not yet committed to by anyone; otherwise append
        last_fee_update = self.log[subject]['fee_updates'][-1]
        if (last_fee_update.ctns[LOCAL] is None or last_fee_update.ctns[LOCAL] > self.ctn_latest(LOCAL)) \
                and (last_fee_update.ctns[REMOTE] is None or last_fee_update.ctns[REMOTE] > self.ctn_latest(REMOTE)):
            self.log[subject]['fee_updates'][-1] = fee_update
        else:
            self.log[subject]['fee_updates'].append(fee_update)

    def send_ctx(self) -> None:
        assert self.ctn_latest(REMOTE) == self.ctn[REMOTE], (self.ctn_latest(REMOTE), self.ctn[REMOTE])
        self._set_revack_pending(REMOTE, True)

    def recv_ctx(self) -> None:
        assert self.ctn_latest(LOCAL) == self.ctn[LOCAL], (self.ctn_latest(LOCAL), self.ctn[LOCAL])
        self._set_revack_pending(LOCAL, True)

    def send_rev(self) -> None:
        self.ctn[LOCAL] += 1
        self._set_revack_pending(LOCAL, False)
        # htlcs
        for ctns in self.log[REMOTE]['locked_in'].values():
            if ctns[REMOTE] is None and ctns[LOCAL] <= self.ctn_latest(LOCAL):
                ctns[REMOTE] = self.ctn_latest(REMOTE) + 1
        for log_action in ('settles', 'fails'):
            for ctns in self.log[LOCAL][log_action].values():
                if ctns[REMOTE] is None and ctns[LOCAL] <= self.ctn_latest(LOCAL):
                    ctns[REMOTE] = self.ctn_latest(REMOTE) + 1
        # fee updates
        for fee_update in self.log[REMOTE]['fee_updates']:
            if fee_update.ctns[REMOTE] is None and fee_update.ctns[LOCAL] <= self.ctn_latest(LOCAL):
                fee_update.ctns[REMOTE] = self.ctn_latest(REMOTE) + 1

    def recv_rev(self) -> None:
        self.ctn[REMOTE] += 1
        self._set_revack_pending(REMOTE, False)
        # htlcs
        for ctns in self.log[LOCAL]['locked_in'].values():
            if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                ctns[LOCAL] = self.ctn_latest(LOCAL) + 1
        for log_action in ('settles', 'fails'):
            for ctns in self.log[REMOTE][log_action].values():
                if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                    ctns[LOCAL] = self.ctn_latest(LOCAL) + 1
        # fee updates
        for fee_update in self.log[LOCAL]['fee_updates']:
            if fee_update.ctns[LOCAL] is None and fee_update.ctns[REMOTE] <= self.ctn_latest(REMOTE):
                fee_update.ctns[LOCAL] = self.ctn_latest(LOCAL) + 1

    ##### Queries re HTLCs:

    def htlcs_by_direction(self, subject: HTLCOwner, direction: Direction,
                           ctn: int = None) -> Sequence[UpdateAddHtlc]:
        """Return the list of received or sent (depending on direction) HTLCs
        in subject's ctx at ctn.

        direction is relative to subject!
        """
        assert type(subject) is HTLCOwner
        assert type(direction) is Direction
        if ctn is None:
            ctn = self.ctn[subject]
        l = []
        # subject's ctx
        # party is the proposer of the HTLCs
        party = subject if direction == SENT else subject.inverted()
        for htlc_id, ctns in self.log[party]['locked_in'].items():
            if ctns[subject] is not None and ctns[subject] <= ctn:
                settles = self.log[party]['settles']
                fails = self.log[party]['fails']
                not_settled = htlc_id not in settles or settles[htlc_id][subject] is None or settles[htlc_id][subject] > ctn
                not_failed = htlc_id not in fails or fails[htlc_id][subject] is None or fails[htlc_id][subject] > ctn
                if not_settled and not_failed:
                        l.append(self.log[party]['adds'][htlc_id])
        return l

    def htlcs(self, subject: HTLCOwner, ctn: int = None) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of HTLCs in subject's ctx at ctn."""
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn[subject]
        l = []
        l += [(SENT, x) for x in self.htlcs_by_direction(subject, SENT, ctn)]
        l += [(RECEIVED, x) for x in self.htlcs_by_direction(subject, RECEIVED, ctn)]
        return l

    def get_htlcs_in_oldest_unrevoked_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn[subject]
        return self.htlcs(subject, ctn)

    def get_htlcs_in_latest_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_latest(subject)
        return self.htlcs(subject, ctn)

    def get_htlcs_in_next_ctx(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        assert type(subject) is HTLCOwner
        ctn = self.ctn_latest(subject) + 1
        return self.htlcs(subject, ctn)

    def all_settled_htlcs_ever_by_direction(self, subject: HTLCOwner, direction: Direction,
                                            ctn: int = None) -> Sequence[UpdateAddHtlc]:
        """Return the list of all HTLCs that have been ever settled in subject's
        ctx up to ctn, filtered to only "direction".
        """
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.ctn[subject]
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
            ctn = self.ctn[subject]
        sent = [(SENT, x) for x in self.all_settled_htlcs_ever_by_direction(subject, SENT, ctn)]
        received = [(RECEIVED, x) for x in self.all_settled_htlcs_ever_by_direction(subject, RECEIVED, ctn)]
        return sent + received

    def received_in_ctn(self, ctn: int) -> Sequence[UpdateAddHtlc]:
        return [self.log[REMOTE]['adds'][htlc_id]
                for htlc_id, ctns in self.log[REMOTE]['settles'].items()
                if ctns[LOCAL] == ctn]

    def sent_in_ctn(self, ctn: int) -> Sequence[UpdateAddHtlc]:
        return [self.log[LOCAL]['adds'][htlc_id]
                for htlc_id, ctns in self.log[LOCAL]['settles'].items()
                if ctns[LOCAL] == ctn]

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
            ctn_at_i = fee_log[i].ctns[subject]
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
        return self.get_feerate(subject=subject, ctn=self.ctn[subject])

    def get_feerate_in_latest_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_latest(subject))

    def get_feerate_in_next_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_latest(subject) + 1)
