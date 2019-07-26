from copy import deepcopy
from typing import Optional, Sequence, Tuple, List

from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction, FeeUpdate
from .util import bh2u


class HTLCManager:

    def __init__(self, *, local_ctn=0, remote_ctn=0, log=None):
        # self.ctn[sub] is the ctn for the oldest unrevoked ctx of sub
        self.ctn = {LOCAL:local_ctn, REMOTE: remote_ctn}
        # ctx_pending[sub] is True iff sub has received commitment_signed but did not send revoke_and_ack (sub has multiple unrevoked ctxs)
        self.ctx_pending = {LOCAL:False, REMOTE: False} # FIXME does this need to be persisted?
        if log is None:
            initial = {'adds': {}, 'locked_in': {}, 'settles': {}, 'fails': {}}
            log = {LOCAL: deepcopy(initial), REMOTE: deepcopy(initial)}
        else:
            assert type(log) is dict
            log = {HTLCOwner(int(sub)): action for sub, action in deepcopy(log).items()}
            for sub in (LOCAL, REMOTE):
                log[sub]['adds'] = {int(x): UpdateAddHtlc(*y) for x, y in log[sub]['adds'].items()}
                coerceHtlcOwner2IntMap = lambda ctns: {HTLCOwner(int(owner)): ctn for owner, ctn in ctns.items()}
                # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                log[sub]['locked_in'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['locked_in'].items()}
                log[sub]['settles'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['settles'].items()}
                log[sub]['fails'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['fails'].items()}
        self.log = log

    def ctn_latest(self, sub: HTLCOwner) -> int:
        """Return the ctn for the latest (newest that has a valid sig) ctx of sub"""
        return self.ctn[sub] + int(self.ctx_pending[sub])

    def to_save(self):
        log = deepcopy(self.log)
        for sub in (LOCAL, REMOTE):
            # adds
            d = {}
            for htlc_id, htlc in log[sub]['adds'].items():
                d[htlc_id] = (htlc[0], bh2u(htlc[1])) + htlc[2:]
            log[sub]['adds'] = d
        return log

    def channel_open_finished(self):
        self.ctn = {LOCAL: 0, REMOTE: 0}
        self.ctx_pending = {LOCAL:False, REMOTE: False}

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

    def send_ctx(self) -> None:
        assert self.ctn_latest(REMOTE) == self.ctn[REMOTE], (self.ctn_latest(REMOTE), self.ctn[REMOTE])
        self.ctx_pending[REMOTE] = True

    def recv_ctx(self) -> None:
        assert self.ctn_latest(LOCAL) == self.ctn[LOCAL], (self.ctn_latest(LOCAL), self.ctn[LOCAL])
        self.ctx_pending[LOCAL] = True

    def send_rev(self) -> None:
        self.ctn[LOCAL] += 1
        self.ctx_pending[LOCAL] = False
        for ctns in self.log[REMOTE]['locked_in'].values():
            if ctns[REMOTE] is None and ctns[LOCAL] <= self.ctn_latest(LOCAL):
                ctns[REMOTE] = self.ctn_latest(REMOTE) + 1
        for log_action in ('settles', 'fails'):
            for ctns in self.log[LOCAL][log_action].values():
                if ctns[REMOTE] is None and ctns[LOCAL] <= self.ctn_latest(LOCAL):
                    ctns[REMOTE] = self.ctn_latest(REMOTE) + 1

    def recv_rev(self) -> None:
        self.ctn[REMOTE] += 1
        self.ctx_pending[REMOTE] = False
        for ctns in self.log[LOCAL]['locked_in'].values():
            if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                ctns[LOCAL] = self.ctn_latest(LOCAL) + 1
        for log_action in ('settles', 'fails'):
            for ctns in self.log[REMOTE][log_action].values():
                if ctns[LOCAL] is None and ctns[REMOTE] <= self.ctn_latest(REMOTE):
                    ctns[LOCAL] = self.ctn_latest(LOCAL) + 1

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
