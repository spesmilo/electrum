from copy import deepcopy
from typing import Optional, Sequence, Tuple

from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction
from .util import bh2u


class HTLCManager:

    def __init__(self, local_ctn=0, remote_ctn=0, log=None):
        # self.ctn[sub] is the ctn for the oldest unrevoked ctx of sub
        self.ctn = {LOCAL:local_ctn, REMOTE: remote_ctn}
        # self.ctn_latest[sub] is the ctn for the latest (newest that has a valid sig) ctx of sub
        self.ctn_latest = {LOCAL:local_ctn, REMOTE: remote_ctn}  # FIXME does this need to be persisted?
        # after sending commitment_signed but before receiving revoke_and_ack,
        # self.ctn_latest[REMOTE] == self.ctn[REMOTE] + 1
        # otherwise they are equal
        self.expect_sig = {SENT: False, RECEIVED: False}
        if log is None:
            initial = {'adds': {}, 'locked_in': {}, 'settles': {}, 'fails': {}}
            log = {LOCAL: deepcopy(initial), REMOTE: deepcopy(initial)}
        else:
            assert type(log) is dict
            log = {HTLCOwner(int(x)): y for x, y in deepcopy(log).items()}
            for sub in (LOCAL, REMOTE):
                log[sub]['adds'] = {int(x): UpdateAddHtlc(*y) for x, y in log[sub]['adds'].items()}
                coerceHtlcOwner2IntMap = lambda x: {HTLCOwner(int(y)): z for y, z in x.items()}
                # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                log[sub]['locked_in'] = {int(x): coerceHtlcOwner2IntMap(y) for x, y in log[sub]['locked_in'].items()}
                log[sub]['settles'] = {int(x): coerceHtlcOwner2IntMap(y) for x, y in log[sub]['settles'].items()}
                log[sub]['fails'] = {int(x): coerceHtlcOwner2IntMap(y) for x, y in log[sub]['fails'].items()}
        self.log = log

    def to_save(self):
        x = deepcopy(self.log)
        for sub in (LOCAL, REMOTE):
            d = {}
            for htlc_id, htlc in x[sub]['adds'].items():
                d[htlc_id] = (htlc[0], bh2u(htlc[1])) + htlc[2:]
            x[sub]['adds'] = d
        return x

    def channel_open_finished(self):
        self.ctn = {LOCAL: 0, REMOTE: 0}
        self.ctn_latest = {LOCAL: 0, REMOTE: 0}

    def send_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        htlc_id = htlc.htlc_id
        adds = self.log[LOCAL]['adds']
        assert type(adds) is not str
        adds[htlc_id] = htlc
        self.log[LOCAL]['locked_in'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest[REMOTE]+1}
        self.expect_sig[SENT] = True
        return htlc

    def recv_htlc(self, htlc: UpdateAddHtlc) -> None:
        htlc_id = htlc.htlc_id
        self.log[REMOTE]['adds'][htlc_id] = htlc
        l = self.log[REMOTE]['locked_in'][htlc_id] = {LOCAL: self.ctn_latest[LOCAL]+1, REMOTE: None}
        self.expect_sig[RECEIVED] = True

    def send_ctx(self) -> None:
        assert self.ctn_latest[REMOTE] == self.ctn[REMOTE], (self.ctn_latest[REMOTE], self.ctn[REMOTE])
        self.ctn_latest[REMOTE] = self.ctn[REMOTE] + 1
        for locked_in in self.log[REMOTE]['locked_in'].values():
            if locked_in[REMOTE] is None:
                locked_in[REMOTE] = self.ctn_latest[REMOTE]
        self.expect_sig[SENT] = False

    def recv_ctx(self) -> None:
        assert self.ctn_latest[LOCAL] == self.ctn[LOCAL], (self.ctn_latest[LOCAL], self.ctn[LOCAL])
        self.ctn_latest[LOCAL] = self.ctn[LOCAL] + 1
        for locked_in in self.log[LOCAL]['locked_in'].values():
            if locked_in[LOCAL] is None:
                locked_in[LOCAL] = self.ctn_latest[LOCAL]
        self.expect_sig[RECEIVED] = False

    def send_rev(self) -> None:
        self.ctn[LOCAL] += 1
        for log_action in ('settles', 'fails'):
            for htlc_id, ctns in self.log[LOCAL][log_action].items():
                if ctns[REMOTE] is None:
                    ctns[REMOTE] = self.ctn_latest[REMOTE] + 1

    def recv_rev(self) -> None:
        self.ctn[REMOTE] += 1
        for htlc_id, ctns in self.log[LOCAL]['locked_in'].items():
            if ctns[LOCAL] is None:
                #assert ctns[REMOTE] == self.ctn[REMOTE]  # FIXME I don't think this assert is correct
                ctns[LOCAL] = self.ctn_latest[LOCAL] + 1
        for log_action in ('settles', 'fails'):
            for htlc_id, ctns in self.log[REMOTE][log_action].items():
                if ctns[LOCAL] is None:
                    ctns[LOCAL] = self.ctn_latest[LOCAL] + 1

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
            htlc_height = ctns[subject]
            if htlc_height is None:
                expect_sig = self.expect_sig[RECEIVED if party != LOCAL else SENT]
                include = not expect_sig and ctns[-subject] <= ctn
            else:
                include = htlc_height <= ctn
            if include:
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

    def current_htlcs(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of HTLCs in subject's oldest unrevoked ctx."""
        assert type(subject) is HTLCOwner
        ctn = self.ctn[subject]
        return self.htlcs(subject, ctn)

    def pending_htlcs(self, subject: HTLCOwner) -> Sequence[Tuple[Direction, UpdateAddHtlc]]:
        """Return the list of HTLCs in subject's next ctx (one after oldest unrevoked)."""
        assert type(subject) is HTLCOwner
        ctn = self.ctn[subject] + 1
        return self.htlcs(subject, ctn)

    def send_settle(self, htlc_id: int) -> None:
        self.log[REMOTE]['settles'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest[REMOTE] + 1}

    def recv_settle(self, htlc_id: int) -> None:
        self.log[LOCAL]['settles'][htlc_id] = {LOCAL: self.ctn_latest[LOCAL] + 1, REMOTE: None}

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

    def send_fail(self, htlc_id: int) -> None:
        self.log[REMOTE]['fails'][htlc_id] = {LOCAL: None, REMOTE: self.ctn_latest[REMOTE] + 1}

    def recv_fail(self, htlc_id: int) -> None:
        self.log[LOCAL]['fails'][htlc_id] = {LOCAL: self.ctn_latest[LOCAL] + 1, REMOTE: None}
