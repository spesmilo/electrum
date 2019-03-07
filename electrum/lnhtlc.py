from copy import deepcopy
from .lnutil import SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, UpdateAddHtlc, Direction
from .util import bh2u

class HTLCManager:
    def __init__(self, log=None):
        self.expect_sig = {SENT: False, RECEIVED: False}
        if log is None:
            initial = {'ctn': 0, 'adds': {}, 'locked_in': {}, 'settles': {}, 'fails': {}}
            log = {LOCAL: deepcopy(initial), REMOTE: deepcopy(initial)}
        else:
            assert type(log) is dict
            log = {HTLCOwner(int(x)): y for x, y in deepcopy(log).items()}
            # log[sub]['ctn'] is the ctn for the oldest unrevoked ctx of sub
            for sub in (LOCAL, REMOTE):
                log[sub]['adds'] = {int(x): UpdateAddHtlc(*y) for x, y in log[sub]['adds'].items()}
                coerceHtlcOwner2IntMap = lambda x: {HTLCOwner(int(y)): z for y, z in x.items()}

                # "side who offered htlc" -> action -> htlc_id -> whose ctx -> ctn
                log[sub]['locked_in'] = {int(x): coerceHtlcOwner2IntMap(y) for x, y in log[sub]['locked_in'].items()}
                log[sub]['settles'] = {int(x): coerceHtlcOwner2IntMap(y) for x, y in log[sub]['settles'].items()}
                # FIXME "fails" should be handled like "settles"
                log[sub]['fails'] = {int(x): y for x, y in log[sub]['fails'].items()}
        self.log = log

    def to_save(self):
        x = deepcopy(self.log)
        for sub in (LOCAL, REMOTE):
            d = {}
            for htlc_id, htlc in x[sub]['adds'].items():
                d[htlc_id] = (htlc[0], bh2u(htlc[1])) + htlc[2:]
            x[sub]['adds'] = d
        return x

    def send_htlc(self, htlc):
        htlc_id = htlc.htlc_id
        adds = self.log[LOCAL]['adds']
        assert type(adds) is not str
        adds[htlc_id] = htlc
        self.log[LOCAL]['locked_in'][htlc_id] = {LOCAL: None, REMOTE: self.log[REMOTE]['ctn']+1}
        self.expect_sig[SENT] = True
        return htlc

    def recv_htlc(self, htlc):
        htlc_id = htlc.htlc_id
        self.log[REMOTE]['adds'][htlc_id] = htlc
        l = self.log[REMOTE]['locked_in'][htlc_id] = {LOCAL: self.log[LOCAL]['ctn']+1, REMOTE: None}
        self.expect_sig[RECEIVED] = True

    def send_ctx(self):
        next_ctn = self.log[REMOTE]['ctn'] + 1
        for locked_in in self.log[REMOTE]['locked_in'].values():
            if locked_in[REMOTE] is None:
                locked_in[REMOTE] = next_ctn
        self.expect_sig[SENT] = False

    def recv_ctx(self):
        next_ctn = self.log[LOCAL]['ctn'] + 1
        for locked_in in self.log[LOCAL]['locked_in'].values():
            if locked_in[LOCAL] is None:
                locked_in[LOCAL] = next_ctn
        self.expect_sig[RECEIVED] = False

    def send_rev(self):
        self.log[LOCAL]['ctn'] += 1
        for htlc_id, ctns in self.log[LOCAL]['settles'].items():
            if ctns[REMOTE] is None:
                ctns[REMOTE] = self.log[REMOTE]['ctn'] + 1

    def recv_rev(self):
        self.log[REMOTE]['ctn'] += 1
        did_set_htlc_height = False
        for htlc_id, ctns in self.log[LOCAL]['locked_in'].items():
            if ctns[LOCAL] is None:
                did_set_htlc_height = True
                assert ctns[REMOTE] == self.log[REMOTE]['ctn']
                ctns[LOCAL] = self.log[LOCAL]['ctn'] + 1
        for htlc_id, ctns in self.log[REMOTE]['settles'].items():
            if ctns[LOCAL] is None:
                ctns[LOCAL] = self.log[LOCAL]['ctn'] + 1
        return did_set_htlc_height

    def htlcs_by_direction(self, subject, direction, ctn=None):
        """
        direction is relative to subject!
        """
        assert type(subject) is HTLCOwner
        assert type(direction) is Direction
        if ctn is None:
            ctn = self.log[subject]['ctn']
        l = []
        if direction == SENT and subject == LOCAL:
            party = LOCAL
        elif direction == RECEIVED and subject == REMOTE:
            party = LOCAL
        else:
            party = REMOTE
        for htlc_id, ctns in self.log[party]['locked_in'].items():
            htlc_height = ctns[subject]
            if htlc_height is None:
                expect_sig = self.expect_sig[RECEIVED if party != LOCAL else SENT]
                include = not expect_sig and ctns[-subject] <= ctn
            else:
                include = htlc_height <= ctn
            if include:
                settles = self.log[party]['settles']
                if htlc_id not in settles or settles[htlc_id][subject] is None or settles[htlc_id][subject] > ctn:
                    fails = self.log[party]['fails']
                    if htlc_id not in fails or fails[htlc_id] > ctn:
                        l.append(self.log[party]['adds'][htlc_id])
        return l

    def htlcs(self, subject, ctn=None):
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.log[subject]['ctn']
        l = []
        l += [(SENT, x) for x in self.htlcs_by_direction(subject, SENT, ctn)]
        l += [(RECEIVED, x) for x in self.htlcs_by_direction(subject, RECEIVED, ctn)]
        return l

    def current_htlcs(self, subject):
        assert type(subject) is HTLCOwner
        ctn = self.log[subject]['ctn']
        return self.htlcs(subject, ctn)

    def pending_htlcs(self, subject):
        assert type(subject) is HTLCOwner
        ctn = self.log[subject]['ctn'] + 1
        return self.htlcs(subject, ctn)

    def send_settle(self, htlc_id):
        self.log[REMOTE]['settles'][htlc_id] = {LOCAL: None, REMOTE: self.log[REMOTE]['ctn'] + 1}

    def recv_settle(self, htlc_id):
        self.log[LOCAL]['settles'][htlc_id] = {LOCAL: self.log[LOCAL]['ctn'] + 1, REMOTE: None}

    def settled_htlcs_by(self, subject, ctn=None):
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.log[subject]['ctn']
        d = []
        for htlc_id, ctns in self.log[subject]['settles'].items():
            if ctns[subject] <= ctn:
                d.append(self.log[subject]['adds'][htlc_id])
        return d

    def settled_htlcs(self, subject, ctn=None):
        assert type(subject) is HTLCOwner
        if ctn is None:
            ctn = self.log[subject]['ctn']
        sent = [(SENT, x) for x in self.settled_htlcs_by(subject, ctn)]
        other = subject.inverted()
        received = [(RECEIVED, x) for x in self.settled_htlcs_by(other, ctn)]
        return sent + received

    def received_in_ctn(self, ctn):
        return [self.log[REMOTE]['adds'][htlc_id]
                for htlc_id, ctns in self.log[REMOTE]['settles'].items()
                if ctns[LOCAL] == ctn]

    def sent_in_ctn(self, ctn):
        return [self.log[LOCAL]['adds'][htlc_id]
                for htlc_id, ctns in self.log[LOCAL]['settles'].items()
                if ctns[LOCAL] == ctn]

    def send_fail(self, htlc_id):
        self.log[REMOTE]['fails'][htlc_id] = self.log[REMOTE]['ctn'] + 1

    def recv_fail(self, htlc_id):
        self.log[LOCAL]['fails'][htlc_id] = self.log[LOCAL]['ctn'] + 1
