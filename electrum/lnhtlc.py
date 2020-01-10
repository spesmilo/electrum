from copy import deepcopy
from typing import Optional, Sequence, Tuple, List, Dict

from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction, FeeUpdate
from .util import bh2u, bfh


class HTLCManager:

    def __init__(self, *, log=None, initial_feerate=None):
        if log is None:
            initial = {
                'adds': {},
                'locked_in': {},
                'settles': {},
                'fails': {},
                'fee_updates': [],
                'revack_pending': False,
                'next_htlc_id': 0,
                'ctn': -1,  # oldest unrevoked ctx of sub
            }
            log = {LOCAL: deepcopy(initial), REMOTE: deepcopy(initial)}
        else:
            assert type(log) is dict
            log = {(HTLCOwner(int(k)) if k in ("-1", "1") else k): v
                   for k, v in deepcopy(log).items()}
            for sub in (LOCAL, REMOTE):
                log[sub]['adds'] = {int(htlc_id): UpdateAddHtlc(*htlc) for htlc_id, htlc in log[sub]['adds'].items()}
                coerceHtlcOwner2IntMap = lambda ctns: {HTLCOwner(int(owner)): ctn for owner, ctn in ctns.items()}
                # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                log[sub]['locked_in'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['locked_in'].items()}
                log[sub]['settles'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['settles'].items()}
                log[sub]['fails'] = {int(htlc_id): coerceHtlcOwner2IntMap(ctns) for htlc_id, ctns in log[sub]['fails'].items()}
                # "side who initiated fee update" -> action -> list of FeeUpdates
                log[sub]['fee_updates'] = [FeeUpdate.from_dict(fee_upd) for fee_upd in log[sub]['fee_updates']]
        if 'unacked_local_updates2' not in log:
            log['unacked_local_updates2'] = {}
        log['unacked_local_updates2'] = {int(ctn): [bfh(msg) for msg in messages]
                                         for ctn, messages in log['unacked_local_updates2'].items()}
        # maybe bootstrap fee_updates if initial_feerate was provided
        if initial_feerate is not None:
            assert type(initial_feerate) is int
            for sub in (LOCAL, REMOTE):
                if not log[sub]['fee_updates']:
                    log[sub]['fee_updates'].append(FeeUpdate(initial_feerate, ctns={LOCAL:0, REMOTE:0}))
        self.log = log

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
        log['unacked_local_updates2'] = {ctn: [bh2u(msg) for msg in messages]
                                         for ctn, messages in log['unacked_local_updates2'].items()}
        return log

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
        return htlc

    def recv_htlc(self, htlc: UpdateAddHtlc) -> None:
        htlc_id = htlc.htlc_id
        if htlc_id != self.get_next_htlc_id(REMOTE):
            raise Exception(f"unexpected remote htlc_id. next should be "
                            f"{self.get_next_htlc_id(REMOTE)} but got {htlc_id}")
        self.log[REMOTE]['adds'][htlc_id] = htlc
        self.log[REMOTE]['locked_in'][htlc_id] = {LOCAL: self.ctn_latest(LOCAL)+1, REMOTE: None}
        self.log[REMOTE]['next_htlc_id'] += 1

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
        assert self.ctn_latest(REMOTE) == self.ctn_oldest_unrevoked(REMOTE), (self.ctn_latest(REMOTE), self.ctn_oldest_unrevoked(REMOTE))
        self._set_revack_pending(REMOTE, True)

    def recv_ctx(self) -> None:
        assert self.ctn_latest(LOCAL) == self.ctn_oldest_unrevoked(LOCAL), (self.ctn_latest(LOCAL), self.ctn_oldest_unrevoked(LOCAL))
        self._set_revack_pending(LOCAL, True)

    def send_rev(self) -> None:
        self.log[LOCAL]['ctn'] += 1
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
        self.log[REMOTE]['ctn'] += 1
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
        # no need to keep local update raw msgs anymore, they have just been ACKed.
        self.log['unacked_local_updates2'].pop(self.log[REMOTE]['ctn'], None)

    def discard_unsigned_remote_updates(self):
        """Discard updates sent by the remote, that the remote itself
        did not yet sign (i.e. there was no corresponding commitment_signed msg)
        """
        # htlcs added
        for htlc_id, ctns in list(self.log[REMOTE]['locked_in'].items()):
            if ctns[LOCAL] > self.ctn_latest(LOCAL):
                del self.log[REMOTE]['locked_in'][htlc_id]
                del self.log[REMOTE]['adds'][htlc_id]
        if self.log[REMOTE]['locked_in']:
            self.log[REMOTE]['next_htlc_id'] = max(self.log[REMOTE]['locked_in']) + 1
        else:
            self.log[REMOTE]['next_htlc_id'] = 0
        # htlcs removed
        for log_action in ('settles', 'fails'):
            for htlc_id, ctns in list(self.log[LOCAL][log_action].items()):
                if ctns[LOCAL] > self.ctn_latest(LOCAL):
                    del self.log[LOCAL][log_action][htlc_id]
        # fee updates
        for i, fee_update in enumerate(list(self.log[REMOTE]['fee_updates'])):
            if fee_update.ctns[LOCAL] > self.ctn_latest(LOCAL):
                del self.log[REMOTE]['fee_updates'][i]

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
        if ctn_idx not in self.log['unacked_local_updates2']:
            self.log['unacked_local_updates2'][ctn_idx] = []
        self.log['unacked_local_updates2'][ctn_idx].append(raw_update_msg)

    def get_unacked_local_updates(self) -> Dict[int, Sequence[bytes]]:
        return self.log['unacked_local_updates2']

    ##### Queries re HTLCs:

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
        settles = self.log[party]['settles']
        fails = self.log[party]['fails']
        for htlc_id, ctns in self.log[party]['locked_in'].items():
            if ctns[subject] is not None and ctns[subject] <= ctn:
                not_settled = htlc_id not in settles or settles[htlc_id][subject] is None or settles[htlc_id][subject] > ctn
                not_failed = htlc_id not in fails or fails[htlc_id][subject] is None or fails[htlc_id][subject] > ctn
                if not_settled and not_failed:
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
        return self.get_feerate(subject=subject, ctn=self.ctn_oldest_unrevoked(subject))

    def get_feerate_in_latest_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_latest(subject))

    def get_feerate_in_next_ctx(self, subject: HTLCOwner) -> int:
        return self.get_feerate(subject=subject, ctn=self.ctn_latest(subject) + 1)
