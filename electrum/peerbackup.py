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

import json
import io
import attr
from copy import deepcopy

from . import util
from .lnutil import LOCAL, REMOTE, HTLCOwner
from .lnutil import UpdateAddHtlc, ChannelType, RevocationStore
from .lnmsg import LNSerializer
from .lnutil import BIP32Node, generate_keypair, LnKeyFamily
from .lnhtlc import LOG_TEMPLATE
from .crypto import sha256



# Note: we must reconstruct everything from 2 owners
#
#  A          B       Alice=client, Bob=server
#
#   is_remote=True (bob receives CS)  [about updates sent by client]
#    ---Up-->
#    ---CS-->         bob: receive_peerbackup(their_remote)     alice: get_our_signed_peerbackup(remote)
#    <--Rev--         alice: recv_rev()   bob: send_rev(). occurs after sig.
#
#
#   is_remote=False (bob receives rev) [it is about updates proposed by server]
#    <--Up---
#    <--CS---
#    ---Rev->         bob: receive_new_peerbackup(their_local)  alice: get_our_signed_peerbackup(local)



# update_fee:
#
#    Alice does not need to remember the feerate that applies to Bob's ctx
#    she needs to remember for her local ctx
#
# Bolt2: An update_fee message is sent by the node which is paying the
# Bitcoin fee. Like any update, it's first committed to the receiver's
# commitment transaction and then (once acknowledged) committed to the
# sender's. Unlike an HTLC, update_fee is never closed but simply
# replaced.
#
#  A                    B
#    ---update_fee--->
#    ---CS----------->  # we send remote (current: old: pending: new)
                        # new_fee is in alice's remote
                        # (remote: new, local:old)  # fee_updates['1'] = {'0': (old, local_ctn, remote_ctn) '1': (new, None, remote_ctn+1)}
#    <--rev_ack-------     # new_fee in alice's local   # (remote: new, local:new)  # fee_updates['1'] = {'1': (new, local_ctn+1, remote_ctn+1)}}
#
#    <----CS----------
#    ----revack------>  # we send local (current: new, pending: none)
#
#    so, bob will merge: (current: old, pending: new)  + (current: new, pending: none)
#                       -> no way we can recreate half-states
#
#     well, if there are 2 values: local state should have the most recent, remote should have both
#     otherwise: only current
#
#

# if alice is initiator, the fee is pending in the remote half-state.
# when alice receives revack, the fee becomes current
#
# if bob is initiator, pending_fees apply to local state
#

# with pending:
#    fee_updates['-1'] = {'0': (old, local_ctn, remote_ctn) '1': (new, local_ctn+1, None)}
# without:
#    fee_updates['-1'] = {'1': (new, local_ctn, remote_ctn)}}


# pending_feerate will apply to next ctx: current_feerate := pending_feerate. (ctn_local is increased)
#
#    <--update_fee----
#    <--CS------------      # new_fee in alice's local    (remote:old, local:new)  # fee_updates['-1'] = {'0': (old, local_ctn, remote_ctn) '1': (new, local_ctn+1, None)}
#    ---rev_ack------>      # new_fee in alice's remote   (remote:new, local:new)  # fee_updates['-1'] = {'1': (new, local_ctn+1, remote_ctn+1)}}
#
#    current_feerate, pending_feerate


# next_htlc_id
#
#  A                   B
#    ----add-------->
#    ------CS-------> (consensus on local_next_htlc_id)
#    <----rev--------
#
#    <---add---------
#    <-----CS--------
#    ----rev--------> (consensus on remote_next_htlc at the time CS was sent. Bob needs to save it)
#
#



PEERBACKUP_VERSION = 0

HTLC_UPDATE_LENGTH = 89

PeerBackupWireSerializer = LNSerializer(name='peerbackup_wire')

MAX_CTN = pow(2,8*6) - 1

def ctn_to_bytes(x):
    if x is None:
        x = MAX_CTN
    return int.to_bytes(x, length=6, byteorder="big", signed=False)

def bytes_to_ctn(x):
    assert len(x) == 6
    ctn = int.from_bytes(x, byteorder="big", signed=False)
    if ctn == MAX_CTN:
        ctn = None
    return ctn


@attr.s
class HtlcUpdate:
    htlc_id = attr.ib(type=int)
    amount_msat = attr.ib(type=int)
    payment_hash = attr.ib(type=bytes)
    cltv_abs = attr.ib(type=int)
    timestamp = attr.ib(type=int)
    is_success = attr.ib(type=bool, default=False)
    local_ctn_in = attr.ib(type=int, default=None)
    local_ctn_out = attr.ib(type=int, default=None)
    remote_ctn_in = attr.ib(type=int, default=None)
    remote_ctn_out = attr.ib(type=int, default=None)

    def to_json(self):
        return repr(self)

    def flip(self):
        self.local_ctn_in, self.remote_ctn_in = self.remote_ctn_in, self.local_ctn_in
        self.local_ctn_out, self.remote_ctn_out = self.remote_ctn_out, self.local_ctn_out

    def update_local(self, v):
        self.local_ctn_in = v.local_ctn_in
        self.local_ctn_out = v.local_ctn_out

    def update_remote(self, v):
        self.remote_ctn_in = v.remote_ctn_in
        self.remote_ctn_out = v.remote_ctn_out

    def to_bytes(self, owner=None, blank_timestamps=False):
        local_ctn_in = None if owner == REMOTE else self.local_ctn_in
        local_ctn_out = None if owner == REMOTE else self.local_ctn_out
        remote_ctn_in = None if owner == LOCAL else self.remote_ctn_in
        remote_ctn_out = None if owner == LOCAL else self.remote_ctn_out
        is_success = self.is_success
        if owner == LOCAL and self.local_ctn_out is None:
            is_success = False
        if owner == REMOTE and self.remote_ctn_out is None:
            is_success = False
        if local_ctn_in is None and remote_ctn_in is None:
            return
        r = b''
        r += int.to_bytes(self.htlc_id, length=8, byteorder="big", signed=False)
        r += int.to_bytes(self.amount_msat, length=8, byteorder="big", signed=False)
        r += self.payment_hash
        r += int.to_bytes(self.cltv_abs, length=8, byteorder="big", signed=False)
        r += int.to_bytes(0 if blank_timestamps else self.timestamp, length=8, byteorder="big", signed=False)
        r += b'\x01' if is_success else b'\x00'
        r += ctn_to_bytes(local_ctn_in)
        r += ctn_to_bytes(local_ctn_out)
        r += ctn_to_bytes(remote_ctn_in)
        r += ctn_to_bytes(remote_ctn_out)
        assert len(r) == HTLC_UPDATE_LENGTH, len(r)
        return r

    @classmethod
    def from_bytes(cls, chunk:bytes):
        assert len(chunk) == HTLC_UPDATE_LENGTH, len(chunk)
        with io.BytesIO(bytes(chunk)) as s:
            htlc_update = HtlcUpdate(
                htlc_id = int.from_bytes(s.read(8), byteorder="big"),
                amount_msat = int.from_bytes(s.read(8), byteorder="big"),
                payment_hash = s.read(32),
                cltv_abs = int.from_bytes(s.read(8), byteorder="big"),
                timestamp = int.from_bytes(s.read(8), byteorder="big"),
                is_success = bool(s.read(1) == b'\x01'),
                local_ctn_in = bytes_to_ctn(s.read(6)),
                local_ctn_out = bytes_to_ctn(s.read(6)),
                remote_ctn_in = bytes_to_ctn(s.read(6)),
                remote_ctn_out = bytes_to_ctn(s.read(6)),
            )
        return htlc_update


@attr.s
class PeerBackup:

    channel_id = attr.ib(default=None, type=str)
    node_id = attr.ib(default=None, type=str)
    channel_type = attr.ib(default=None, type=str)
    constraints = attr.ib(default=None, type=str)
    funding_outpoint = attr.ib(default=None, type=str)
    local_config = attr.ib(default=None, type=str)
    remote_config = attr.ib(default=None, type=str)
    local_ctn = attr.ib(default=None, type=int)
    remote_ctn = attr.ib(default=None, type=int)
    local_next_htlc_id = attr.ib(default=None, type=int)
    remote_next_htlc_id = attr.ib(default=None, type=int)
    htlc_log = attr.ib(default=None, type=str)
    revocation_store = attr.ib(default=None, type=str)
    current_feerate = attr.ib(type=int, default=None)
    pending_feerate = attr.ib(type=int, default=None)

    @classmethod
    def from_channel(cls, chan, owner):
        # convert StoredDict to dict
        with chan.db_lock:
            state = json.loads(json.dumps(chan.storage, cls=util.MyEncoder))
        # remove private keys
        for key in ['delayed_basepoint', 'revocation_basepoint', 'multisig_key', 'htlc_basepoint']:
            state['local_config'][key].pop('privkey')
        # payment_basepoint: not always here, sure why.
        # see tests.regtest.TestLightningJIT.test_just_in_time
        state['local_config']['payment_basepoint'].pop('privkey', None)
        state['local_config'].pop('per_commitment_secret_seed')
        state['local_config'].pop('funding_locked_received')
        # encrypt seed in local_config
        channel_seed = bytes.fromhex(state['local_config'].pop('channel_seed'))
        encrypted_seed = chan.lnworker.encrypt_channel_seed(channel_seed)
        state['local_config']['encrypted_seed'] = encrypted_seed.hex()
        # convert log to a list of HtlcUpdate
        log = chan.hm.log
        htlc_log = {LOCAL:{}, REMOTE:{}}
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, add in log[proposer]['adds'].items():
                local_ctn_in = chan.hm.get_ctn_if_lower_than_latest(proposer, 'locked_in', htlc_id, LOCAL)
                local_ctn_settle = chan.hm.get_ctn_if_lower_than_latest(proposer, 'settles', htlc_id, LOCAL)
                local_ctn_fail = chan.hm.get_ctn_if_lower_than_latest(proposer, 'fails', htlc_id, LOCAL)
                remote_ctn_in = chan.hm.get_ctn_if_lower_than_latest(proposer, 'locked_in', htlc_id, REMOTE)
                remote_ctn_settle = chan.hm.get_ctn_if_lower_than_latest(proposer, 'settles', htlc_id, REMOTE)
                remote_ctn_fail = chan.hm.get_ctn_if_lower_than_latest(proposer, 'fails', htlc_id, REMOTE)
                if local_ctn_in is None and remote_ctn_in is None:
                    continue
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
                htlc_log[proposer][htlc_id] = htlc_update

        initiator = LOCAL if state['constraints']['is_initiator'] else REMOTE
        fee_updates = log[initiator]['fee_updates']

        last_key = max(fee_updates.keys())
        last_fee_update = fee_updates[last_key]
        last_feerate = last_fee_update.rate

        if last_key > 0:
            previous_fee_update = fee_updates[last_key - 1]
            previous_feerate = previous_fee_update.rate
        else:
            previous_feerate = None

        # convert fee log to (current_feerate, pending_feerate)
        if initiator == LOCAL:
            assert last_fee_update.ctn_remote is not None
            if last_fee_update.ctn_local is None:
                current_feerate = previous_feerate
                pending_feerate = last_feerate
            else:
                current_feerate = last_feerate
                pending_feerate = None
        else:
            assert last_fee_update.ctn_local is not None
            if last_fee_update.ctn_remote is None:
                current_feerate = previous_feerate
                pending_feerate = last_feerate
            else:
                current_feerate = last_feerate
                pending_feerate = None

        #fee_update_ctn = last_fee_update.ctn_local if owner == LOCAL else last_fee_update.ctn_remote
        #if fee_update_ctn is None:

        # proposed by remote -> part of LOCAL ctx
        remote_next_htlc_id = state['log']['-1']['next_htlc_id']
        # proposed by local -> part of REMOTE ctx
        local_next_htlc_id = chan.hm._local_next_htlc_id

        p = PeerBackup(
            channel_id = state['channel_id'],
            node_id = state['node_id'],
            channel_type = state['channel_type'],
            constraints = state['constraints'],
            funding_outpoint = state['funding_outpoint'],
            local_config = state['local_config'],
            remote_config = state['remote_config'],
            local_ctn = state['log']['1']['ctn'],
            remote_ctn = state['log']['-1']['ctn'],
            local_next_htlc_id = local_next_htlc_id,
            remote_next_htlc_id = remote_next_htlc_id,
            htlc_log = htlc_log,
            revocation_store = state['revocation_store'],
            current_feerate = current_feerate,
            pending_feerate = pending_feerate,
        )
        if owner == REMOTE:
            p.flip_values()
            p.node_id = chan.lnworker.node_keypair.pubkey.hex()
            p.revocation_store = json.loads(json.dumps(chan.storage['remote_revocation_store'], cls=util.MyEncoder))
        return p

    def as_dict(self, p):
        #self.local_config['encrypted_seed'] = ''
        return {
            'channel_id': p.channel_id,
            'node_id': p.node_id,
            'channel_type': p.channel_type,
            'constraints': p.constraints,
            'funding_outpoint': p.funding_outpoint,
            'local_config': p.local_config,
            'remote_config': p.remote_config,
            'local_ctn': p.local_ctn,
            'remote_ctn': p.remote_ctn,
            'htlc_log': p.htlc_log,
            'revocation_store': p.revocation_store,
            'current_feerate': p.current_feerate,
            'pending_feerate': p.pending_feerate,
        }

    @classmethod
    def convert_config_to_payload(self, config, ctn, next_htlc_id):
        a = {
            'htlc_basepoint': bytes.fromhex(config['htlc_basepoint']['pubkey']),
            'payment_basepoint': bytes.fromhex(config['payment_basepoint']['pubkey']),
            'revocation_basepoint': bytes.fromhex(config['revocation_basepoint']['pubkey']),
            'delayed_basepoint': bytes.fromhex(config['delayed_basepoint']['pubkey']),
            'multisig_key': bytes.fromhex(config['multisig_key']['pubkey']),
            'to_self_delay': config['to_self_delay'],
            'dust_limit_satoshis': config['dust_limit_sat'],
            'max_htlc_value_in_flight_msat': config['max_htlc_value_in_flight_msat'],
            'reserve_sat': config['reserve_sat'],
            'initial_msat': config['initial_msat'],
            'htlc_minimum_msat': config['htlc_minimum_msat'],
            'max_accepted_htlcs': config['max_accepted_htlcs'],
            'upfront_shutdown_script': bytes.fromhex(config['upfront_shutdown_script']),
        }
        b = {
            'ctn': ctn,
            'next_htlc_id': next_htlc_id,
            'current_per_commitment_point': bytes.fromhex(config['current_per_commitment_point']),
            'next_per_commitment_point': bytes.fromhex(config['next_per_commitment_point']),
            'current_commitment_signature': bytes.fromhex(config['current_commitment_signature']),
            'current_htlc_signatures': bytes.fromhex(config['current_htlc_signatures'] or ''),
        }
        return a, b

    @classmethod
    def convert_payload_to_config(self, config, ctx):
        ctn = ctx['ctn']
        next_htlc_id = ctx['next_htlc_id']
        config2 = {
            'htlc_basepoint': {'pubkey': config['htlc_basepoint'].hex()},
            'payment_basepoint': {'pubkey': config['payment_basepoint'].hex()},
            'revocation_basepoint': {'pubkey': config['revocation_basepoint'].hex()},
            'delayed_basepoint': {'pubkey':config['delayed_basepoint'].hex()},
            'multisig_key': {'pubkey':config['multisig_key'].hex()},
            'to_self_delay': config['to_self_delay'],
            'dust_limit_sat': config['dust_limit_satoshis'],
            'max_htlc_value_in_flight_msat': config['max_htlc_value_in_flight_msat'],
            'reserve_sat': config['reserve_sat'],
            'initial_msat': config['initial_msat'],
            'htlc_minimum_msat': config['htlc_minimum_msat'],
            'max_accepted_htlcs': config['max_accepted_htlcs'],
            'upfront_shutdown_script': config['upfront_shutdown_script'].hex(),
            'current_per_commitment_point': ctx['current_per_commitment_point'].hex(),
            'next_per_commitment_point': ctx['next_per_commitment_point'].hex(),
            'current_commitment_signature': ctx['current_commitment_signature'].hex(),
            'current_htlc_signatures': ctx['current_htlc_signatures'].hex(),
        }
        config2['announcement_node_sig'] = ''
        config2['announcement_bitcoin_sig'] = ''
        return config2, ctn, next_htlc_id

    @classmethod
    def from_bytes(cls, peerbackup_bytes: bytes) -> 'PeerBackup':
        payload = PeerBackupWireSerializer.read_tlv_stream(
            fd=io.BytesIO(peerbackup_bytes),
            tlv_stream_name="payload")
        version = payload['version']['version']
        assert version == PEERBACKUP_VERSION
        pending_feerate = payload['feerate']['pending']
        current_feerate = payload['feerate']['current']
        state = {
            'channel_id': payload['channel_id']['channel_id'].hex(),
            'channel_type': ChannelType.from_bytes(payload['channel_type']['type'], byteorder='big'),
            'node_id': payload['node_id']['node_id'].hex(),
            'constraints': payload['constraints'],
            'funding_outpoint': {
                'txid': payload['funding_outpoint']['txid'].hex(),
                'output_index': payload['funding_outpoint']['output_index'],
            },
            'current_feerate': current_feerate,
            'pending_feerate': pending_feerate if pending_feerate > 0 else None,
        }
        if 'revocation_store' in payload:
            buckets = {}
            buckets_bytes = payload['revocation_store']['buckets']
            while buckets_bytes:
                chunk = buckets_bytes[0:42]
                buckets_bytes = buckets_bytes[42:]
                with io.BytesIO(bytes(chunk)) as s:
                    key = int.from_bytes(s.read(2), byteorder="big")
                    _hash = s.read(32)
                    _index = int.from_bytes(s.read(8), byteorder="big")
                buckets[str(key)] = (_hash.hex(), _index)

            state['revocation_store'] = {
                'index': payload['revocation_store']['index'],
                'buckets': buckets,
            }
        if 'remote_config' in payload:
            config, ctn, next_htlc_id = cls.convert_payload_to_config(payload['remote_config'], payload['remote_ctx'])
            state['remote_config'] = config
            state['remote_ctn'] = ctn
            state['local_next_htlc_id'] = next_htlc_id
            state['remote_config']['encrypted_seed'] = None

        if 'local_config' in payload:
            config, ctn, next_htlc_id = cls.convert_payload_to_config(payload['local_config'], payload['local_ctx'])
            state['local_config'] = config
            state['local_ctn'] = ctn
            state['remote_next_htlc_id'] = next_htlc_id
            if 'encrypted_seed' in payload:
                state['local_config']['encrypted_seed'] = payload['encrypted_seed']['seed'].hex()


        def htlc_log_from_bytes(active_htlcs):
            log = {}
            while active_htlcs:
                chunk = active_htlcs[0:HTLC_UPDATE_LENGTH]
                active_htlcs = active_htlcs[HTLC_UPDATE_LENGTH:]
                htlc_update = HtlcUpdate.from_bytes(chunk)
                log[htlc_update.htlc_id] = htlc_update
            return log
        state['htlc_log'] = {
            LOCAL: htlc_log_from_bytes(payload['offered_htlcs']['active_htlcs']),
            REMOTE: htlc_log_from_bytes(payload['received_htlcs']['active_htlcs'])
        }
        return PeerBackup(**state)


    def _get_htlc_log(self, owner: HTLCOwner, proposer: HTLCOwner, blank_timestamps=False) -> bytes:
        local_msat = 0
        remote_msat = 0
        active_htlcs = b''

        for htlc_id, htlc_update in list(sorted(self.htlc_log[proposer].items())):
            _bytes = htlc_update.to_bytes(owner, blank_timestamps)
            if _bytes is None:
                continue
            local_ctn_in = None if owner == REMOTE else htlc_update.local_ctn_in
            local_ctn_out = None if owner == REMOTE else htlc_update.local_ctn_out
            remote_ctn_in = None if owner == LOCAL else htlc_update.remote_ctn_in
            remote_ctn_out = None if owner == LOCAL else htlc_update.remote_ctn_out

            if (remote_ctn_in is not None and remote_ctn_out is None)\
               or (local_ctn_in is not None and local_ctn_out is None):
                active_htlcs += _bytes

            if local_ctn_in is not None and local_ctn_out is not None:
                local_msat -= htlc_update.amount_msat * int(proposer)

            if remote_ctn_in is not None and remote_ctn_out is not None:
                remote_msat += htlc_update.amount_msat * int(proposer)

        return (
            local_msat,
            remote_msat,
            active_htlcs,
        )

    def to_bytes(self, owner=None, blank_timestamps=False) -> bytes:
        # for creation of state.

        local_offered_msat, remote_offered_msat,\
        active_offered_htlcs = self._get_htlc_log(owner, proposer=LOCAL, blank_timestamps=blank_timestamps)

        local_received_msat, remote_received_msat,\
        active_received_htlcs = self._get_htlc_log(owner, proposer=REMOTE, blank_timestamps=blank_timestamps)

        local_initial_msat = self.local_config['initial_msat'] + local_received_msat + local_offered_msat
        remote_initial_msat = self.remote_config['initial_msat'] + remote_received_msat + remote_offered_msat
        assert local_initial_msat >=0
        assert remote_initial_msat >=0

        # if we are initiator, the pending feerate applies to REMOTE
        # if we are not initiator, the pending feerate applies to LOCAL
        initiator = self.constraints['is_initiator']
        if (initiator and owner == LOCAL) or (not initiator and owner == REMOTE):
            if self.pending_feerate:
                current_feerate = self.pending_feerate
                pending_feerate = None
            else:
                current_feerate = self.current_feerate
                pending_feerate = None
        else:
            current_feerate = self.current_feerate
            pending_feerate = self.pending_feerate

        payload = {
            'version': {'version': PEERBACKUP_VERSION},
            'channel_id': {'channel_id': bytes.fromhex(self.channel_id)},
            'channel_type': {'type': ChannelType(self.channel_type).to_bytes_minimal()},
            'node_id': {'node_id': bytes.fromhex(self.node_id)},
            'offered_htlcs': {
                'active_htlcs': active_offered_htlcs,
            },
            'received_htlcs': {
                'active_htlcs': active_received_htlcs,
            },
            'constraints': self.constraints,
            'feerate': {'current': current_feerate, 'pending': (pending_feerate or 0)},
            'funding_outpoint': {
                'txid': bytes.fromhex(self.funding_outpoint['txid']),
                'output_index': self.funding_outpoint['output_index'],
            },
        }
        if owner != LOCAL:
            buckets_bytes = b''
            buckets = self.revocation_store['buckets']
            for k, v in sorted(buckets.items()):
                _hash, _index = v
                r = int.to_bytes(int(k), length=2, byteorder="big", signed=False)
                r += bytes.fromhex(_hash)
                r += int.to_bytes(_index, length=8, byteorder="big", signed=False)
                buckets_bytes += r
            payload['revocation_store'] = {
                'index': self.revocation_store['index'],
                'buckets': buckets_bytes,
            }
            a, b = self.convert_config_to_payload(self.remote_config, self.remote_ctn, self.local_next_htlc_id)
            payload['remote_config'] = a
            payload['remote_config']['initial_msat'] = remote_initial_msat
            payload['remote_ctx'] = b
        if owner != REMOTE:
            a, b = self.convert_config_to_payload(self.local_config, self.local_ctn, self.remote_next_htlc_id)
            payload['local_config'] = a
            payload['local_config']['initial_msat'] = local_initial_msat
            payload['local_ctx'] = b
            if 'encrypted_seed' in self.local_config:
                encrypted_seed = self.local_config['encrypted_seed']
                payload['encrypted_seed'] = {'seed': bytes.fromhex(encrypted_seed)}

        payload_fd = io.BytesIO()
        PeerBackupWireSerializer.write_tlv_stream(
            fd=payload_fd,
            tlv_stream_name="payload",
            **payload)
        payload_bytes = payload_fd.getvalue()
        return payload_bytes

    @classmethod
    def merge_peerbackup_bytes(cls, local_peerbackup_bytes, remote_peerbackup_bytes):
        local_peerbackup = PeerBackup.from_bytes(local_peerbackup_bytes)
        remote_peerbackup = PeerBackup.from_bytes(remote_peerbackup_bytes)
        #
        local_peerbackup.revocation_store = remote_peerbackup.revocation_store
        #
        local_peerbackup.remote_config = remote_peerbackup.remote_config
        remote_peerbackup.local_config = local_peerbackup.local_config
        #
        remote_peerbackup.local_ctn = local_peerbackup.local_ctn
        local_peerbackup.remote_ctn = remote_peerbackup.remote_ctn
        #
        remote_peerbackup.remote_next_htlc_id = local_peerbackup.remote_next_htlc_id
        local_peerbackup.local_next_htlc_id = remote_peerbackup.local_next_htlc_id
        # merge htlc logs
        local_htlc_log = local_peerbackup.htlc_log
        remote_htlc_log = remote_peerbackup.htlc_log
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, local_v in list(local_htlc_log[proposer].items()):
                remote_v = remote_htlc_log[proposer].get(htlc_id)
                if remote_v:
                    local_v.update_remote(remote_v)
                    local_htlc_log[proposer][htlc_id] = local_v
                else:
                    remote_htlc_log[proposer][htlc_id] = local_v
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, remote_v in list(remote_htlc_log[proposer].items()):
                local_v = local_htlc_log[proposer].get(htlc_id)
                if local_v:
                    remote_v.update_local(local_v)
                    remote_htlc_log[proposer][htlc_id] = remote_v
                else:
                    local_htlc_log[proposer][htlc_id] = remote_v
        assert local_htlc_log == remote_htlc_log

        if local_peerbackup.constraints['is_initiator']:
            # if alice is initiator, pending_fees are for the remote state
            assert local_peerbackup.pending_feerate is None
            if remote_peerbackup.pending_feerate:
                assert local_peerbackup.current_feerate == remote_peerbackup.pending_feerate
                local_peerbackup.current_feerate = remote_peerbackup.current_feerate
                local_peerbackup.pending_feerate = remote_peerbackup.pending_feerate
            else:
                assert local_peerbackup.current_feerate == remote_peerbackup.current_feerate
        else:
            # if bob is initiator, pending_fees are for the local state
            assert remote_peerbackup.pending_feerate is None
            if local_peerbackup.pending_feerate:
                assert local_peerbackup.current_feerate == remote_peerbackup.pending_feerate
                remote_peerbackup.current_feerate = local_peerbackup.current_feerate
                remote_peerbackup.pending_feerate = local_peerbackup.pending_feerate
            else:
                assert local_peerbackup.current_feerate == remote_peerbackup.current_feerate

        if local_peerbackup != remote_peerbackup:
            local_peerbackup.save_debug_file('local_peerbackup')
            remote_peerbackup.save_debug_file('remote_peerbackup')
            raise Exception('merge error')
        return local_peerbackup.to_bytes()

    def flip_values(self):

        def flip_dict_values(d: dict, key_a, key_b):
            a = d.pop(key_a)
            b = d.pop(key_b)
            d[key_a] = b
            d[key_b] = a

        self.local_ctn, self.remote_ctn = self.remote_ctn, self.local_ctn
        self.local_next_htlc_id, self.remote_next_htlc_id = self.remote_next_htlc_id, self.local_next_htlc_id
        self.local_config, self.remote_config = self.remote_config, self.local_config
        flip_dict_values(self.htlc_log, LOCAL, REMOTE)
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, v in self.htlc_log[proposer].items():
                v.flip()
        self.constraints['is_initiator'] = not self.constraints['is_initiator']

    def recreate_channel_state(self, lnworker) -> dict:
        """ returns a dict compatible with channel storage """
        b = self.to_bytes()
        p = self.from_bytes(b)
        state = self.as_dict(p) # fixme: rebuild from scratch
        state.pop('revocation_store')
        local_config = state['local_config']
        encrypted_seed = bytes.fromhex(local_config.pop('encrypted_seed'))
        channel_seed = lnworker.decrypt_channel_seed(encrypted_seed)
        local_config['channel_seed'] = channel_seed.hex()
        local_config['funding_locked_received'] = True
        node = BIP32Node.from_rootseed(channel_seed, xtype='standard')
        keypair_generator = lambda family: generate_keypair(node, family)
        local_config['per_commitment_secret_seed'] = keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey.hex()
        local_config['multisig_key']['privkey'] = keypair_generator(LnKeyFamily.MULTISIG).privkey.hex()
        assert local_config['multisig_key']['pubkey'] == keypair_generator(LnKeyFamily.MULTISIG).pubkey.hex()
        local_config['htlc_basepoint']['privkey'] = keypair_generator(LnKeyFamily.HTLC_BASE).privkey.hex()
        local_config['delayed_basepoint']['privkey'] = keypair_generator(LnKeyFamily.DELAY_BASE).privkey.hex()
        local_config['revocation_basepoint']['privkey'] = keypair_generator(LnKeyFamily.REVOCATION_BASE).privkey.hex()
        state['onion_keys'] = {}
        state['unfulfilled_htlcs'] = {}
        state['peer_network_addresses'] = {}
        # rebuild the log from local and remote
        log = {
            '1': deepcopy(LOG_TEMPLATE),
            '-1': deepcopy(LOG_TEMPLATE),
        }
        htlc_log = state.pop('htlc_log')
        for proposer in [LOCAL, REMOTE]:
            target_log = log[str(int(proposer))]
            for htlc_id, v in htlc_log[proposer].items():
                target_log['adds'][htlc_id] = (v.amount_msat, v.payment_hash, v.cltv_abs, v.htlc_id, v.timestamp)
                assert (v.local_ctn_in is not None or v.remote_ctn_in is not None), v
                target_log['locked_in'][htlc_id] = {'1':v.local_ctn_in, '-1':v.remote_ctn_in}
                if v.local_ctn_out is not None or v.remote_ctn_out is not None:
                    target_log['settles' if v.is_success else 'fails'][htlc_id] = {'1':v.local_ctn_out, '-1':v.remote_ctn_out}

        local_ctn = state.pop('local_ctn')
        remote_ctn = state.pop('remote_ctn')
        log['1']['ctn'] = local_ctn
        log['-1']['ctn'] = remote_ctn

        current_feerate = state.pop('current_feerate')
        pending_feerate = state.pop('pending_feerate')
        initiator = '1' if state['constraints']['is_initiator'] else '-1'
        fee_log = log[initiator]['fee_updates']
        # the following ctns depend on message ordering
        if pending_feerate and initiator=='1':
            fee_log['0'] = {'rate':current_feerate, 'ctn_local':local_ctn, 'ctn_remote':remote_ctn-1}
            fee_log['1'] = {'rate':pending_feerate, 'ctn_local':None, 'ctn_remote':remote_ctn}
        elif pending_feerate and initiator=='-1':
            fee_log['0'] = {'rate':current_feerate, 'ctn_local':local_ctn-1, 'ctn_remote':remote_ctn}
            fee_log['1'] = {'rate':pending_feerate, 'ctn_local':local_ctn, 'ctn_remote':None}
        else:
            fee_log['0'] = {'rate':current_feerate, 'ctn_local':local_ctn, 'ctn_remote':remote_ctn}

        lnworker.logger.info(f'{log}')
        state['log'] = log
        state['log']['1']['was_revoke_last'] = False
        state['log']['1']['unacked_updates'] = {}
        # restore next_htlc_id
        log = state['log']
        log['1']['next_htlc_id'] = self.local_next_htlc_id
        log['-1']['next_htlc_id'] = self.remote_next_htlc_id
        # set revack_pending
        log['1']['revack_pending'] = False
        log['-1']['revack_pending'] = True
        # assume OPEN
        state['state'] = 'OPEN'
        state['short_channel_id'] = None
        state['data_loss_protect_remote_pcp'] = {}
        state['revocation_store'] = self.revocation_store
        state['remote_revocation_store'] = self.get_their_revocation_store(local_config, local_ctn)

        lnworker.logger.info(f'recreating {state}')
        return state

    def get_their_revocation_store(self, local_config, ctn):
        seed = bytes.fromhex(local_config['per_commitment_secret_seed'])
        store = RevocationStore.from_seed_and_index(seed, ctn)
        return json.loads(json.dumps(store.storage, cls=util.MyEncoder))

    def save_debug_file(self, filename, peerbackup_bytes=None, sighash=b''):
        DEBUG = True
        if not DEBUG:
            return
        #if peerbackup_bytes:
        #    with open(filename, "wb") as f:
        #        f.write(peerbackup_bytes)
        #else:
        p = PeerBackup.from_bytes(peerbackup_bytes)
        with open(filename, "w") as f:
            d = self.as_dict(p)
            d['sighash'] = sighash.hex()
            f.write(json.dumps(d, cls=util.MyEncoder, sort_keys=True, indent=2))
