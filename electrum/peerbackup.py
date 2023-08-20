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
from .lnutil import UpdateAddHtlc, ChannelType, RevocationStore, derive_payment_basepoint
from .lnmsg import LNSerializer
from .lnutil import BIP32Node, generate_keypair, LnKeyFamily
from .lnhtlc import LOG_TEMPLATE
from .crypto import sha256
from .logging import get_logger

_logger = get_logger(__name__)



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



# about revack_pending:
#
#  B                   A
#    <-----add------>
#
#    ------CS-------> local revack_pending=True
#    <----rev-------- local revack_pending=False
#
#
#    <-----add------>
#
#    <-----CS-------- remote revack_pending=True
#    ----rev--------> remote revack_pending=False
#
#
# At the time when we create the peerbackup, revack pending is always
# true for a remote peerbackup and always false for a local peerbackup
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
class FeeUpdateX:
    feerate = attr.ib(type=int)
    local_ctn = attr.ib(type=int, default=None)
    remote_ctn = attr.ib(type=int, default=None)

    def flip(self):
        self.local_ctn, self.remote_ctn = self.remote_ctn, self.local_ctn

    def as_dict(self):
        return {'rate':self.feerate, 'ctn_local':self.local_ctn, 'ctn_remote':self.remote_ctn}

    def to_bytes(self, owner=None, blank_timestamps=False):
        local_ctn = None if owner == REMOTE else self.local_ctn
        remote_ctn = None if owner == LOCAL else self.remote_ctn
        if local_ctn is None and remote_ctn is None:
            return bytes(20)
        r = b''
        r += int.to_bytes(self.feerate, length=8, byteorder="big", signed=False)
        r += ctn_to_bytes(local_ctn)
        r += ctn_to_bytes(remote_ctn)
        return r

    @classmethod
    def from_bytes(cls, chunk:bytes):
        assert len(chunk) == 20
        if chunk == bytes(20):
            return None
        with io.BytesIO(bytes(chunk)) as s:
            fee_update = FeeUpdateX(
                feerate = int.from_bytes(s.read(8), byteorder="big"),
                local_ctn = bytes_to_ctn(s.read(6)),
                remote_ctn = bytes_to_ctn(s.read(6)),
            )
        return fee_update

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

def deserialize_htlcs(htlc_log_bytes):
    htlc_log = {}
    while htlc_log_bytes:
        chunk = htlc_log_bytes[0:HTLC_UPDATE_LENGTH]
        htlc_log_bytes = htlc_log_bytes[HTLC_UPDATE_LENGTH:]
        htlc_update = HtlcUpdate.from_bytes(chunk)
        htlc_log[htlc_update.htlc_id] = htlc_update
    return htlc_log


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
    active_htlcs = attr.ib(default=None, type=str)
    revocation_store = attr.ib(default=None, type=str)
    #
    local_offered_msat = attr.ib(default=None, type=bytes)
    local_received_msat = attr.ib(default=None, type=bytes)
    remote_offered_msat = attr.ib(default=None, type=bytes)
    remote_received_msat = attr.ib(default=None, type=bytes)
    current_fee_update = attr.ib(type=FeeUpdateX, default=None)
    pending_fee_update = attr.ib(type=FeeUpdateX, default=None)

    @classmethod
    def from_channel(cls, chan, owner):
        # convert StoredDict to dict
        with chan.db_lock:
            state = json.loads(json.dumps(chan.storage, cls=util.MyEncoder))
        # remove private keys
        for key in ['delayed_basepoint', 'revocation_basepoint', 'multisig_key', 'htlc_basepoint']:
            state['local_config'][key].pop('privkey')

        state['local_config']['payment_basepoint'].pop('privkey', None)
        state['local_config'].pop('per_commitment_secret_seed')
        state['local_config'].pop('funding_locked_received')
        # encrypt seed in local_config
        channel_seed = bytes.fromhex(state['local_config'].pop('channel_seed'))
        encrypted_seed = chan.lnworker.encrypt_channel_seed(channel_seed)
        state['local_config']['encrypted_seed'] = encrypted_seed.hex()
        # convert log to a list of HtlcUpdate
        log = chan.hm.log
        # active htlcs
        active_htlcs = chan.hm.get_active_htlcs()
        # fee updates
        initiator = LOCAL if state['constraints']['is_initiator'] else REMOTE
        fee_updates = log[initiator]['fee_updates']
        last_key = max(fee_updates.keys())
        last_fee_update = chan.hm.get_fee_update(initiator, last_key)
        if last_key > 0:
            previous_fee_update = chan.hm.get_fee_update(initiator, last_key - 1)
        else:
            previous_fee_update = None
        if last_fee_update is None:
            pending_fee_update = None
            current_fee_update = previous_fee_update
        elif previous_fee_update is None:
            pending_fee_update = None
            current_fee_update = last_fee_update
        else:
            pending_fee_update = last_fee_update
            current_fee_update = previous_fee_update
        _logger.info(f'{current_fee_update=}')
        _logger.info(f'{pending_fee_update=}')

        # proposed by remote -> part of LOCAL ctx
        remote_next_htlc_id = state['log']['-1']['next_htlc_id']
        # proposed by local -> part of REMOTE ctx
        local_next_htlc_id = chan.hm._local_next_htlc_id

        local_offered_msat = chan.hm.get_inactive_htlc_balance(proposer=LOCAL, owner=LOCAL)
        local_received_msat = chan.hm.get_inactive_htlc_balance(proposer=REMOTE, owner=LOCAL)
        remote_offered_msat = chan.hm.get_inactive_htlc_balance(proposer=LOCAL, owner=REMOTE)
        remote_received_msat = chan.hm.get_inactive_htlc_balance(proposer=REMOTE, owner=REMOTE)

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
            local_received_msat = local_received_msat,
            local_offered_msat = local_offered_msat,
            remote_received_msat= remote_received_msat,
            remote_offered_msat= remote_offered_msat,
            local_next_htlc_id = local_next_htlc_id,
            remote_next_htlc_id = remote_next_htlc_id,
            active_htlcs = active_htlcs,
            revocation_store = state['revocation_store'],
            current_fee_update = current_fee_update,
            pending_fee_update = pending_fee_update,
        )
        if owner == REMOTE:
            p.flip_values()
            p.node_id = chan.lnworker.node_keypair.pubkey.hex()
            p.revocation_store = json.loads(json.dumps(chan.storage['remote_revocation_store'], cls=util.MyEncoder))
        return p

    def as_dict(p):
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
            'active_htlcs': p.active_htlcs,
            'revocation_store': p.revocation_store,
            'local_offered_msat': p.local_offered_msat,
            'local_received_msat': p.local_received_msat,
            'remote_offered_msat': p.remote_offered_msat,
            'remote_received_msat': p.remote_received_msat,
            'current_fee_update': p.current_fee_update.as_dict(),
            'pending_fee_update': p.pending_fee_update.as_dict() if p.pending_fee_update else None,
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
        pending_fee_update = FeeUpdateX.from_bytes(payload['fee_updates']['pending'])
        current_fee_update = FeeUpdateX.from_bytes(payload['fee_updates']['current'])
        state = {
            'channel_id': payload['channel_id']['channel_id'].hex(),
            'channel_type': ChannelType.from_bytes(payload['channel_type']['type'], byteorder='big'),
            'node_id': payload['node_id']['node_id'].hex(),
            'constraints': payload['constraints'],
            'funding_outpoint': {
                'txid': payload['funding_outpoint']['txid'].hex(),
                'output_index': payload['funding_outpoint']['output_index'],
            },
            'current_fee_update': current_fee_update,
            'pending_fee_update': pending_fee_update,
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

        state['active_htlcs'] = {
            LOCAL: deserialize_htlcs(payload['offered_htlcs']['active_htlcs']),
            REMOTE: deserialize_htlcs(payload['received_htlcs']['active_htlcs'])
        }
        state['local_offered_msat'] = payload['offered_htlcs']['local_msat']
        state['remote_offered_msat'] = payload['offered_htlcs']['remote_msat']
        state['local_received_msat'] = payload['received_htlcs']['local_msat']
        state['remote_received_msat'] = payload['received_htlcs']['remote_msat']

        return PeerBackup(**state)

    def serialize_active_htlcs(self, owner, proposer, blank_timestamps):
        # for creation of state.
        active_htlcs = b''
        htlc_log = self.active_htlcs[proposer] # active htlcs
        for htlc_id, htlc_update in sorted(htlc_log.items()):
            _bytes = htlc_update.to_bytes(owner, blank_timestamps)
            if _bytes is None:
                continue
            local_ctn_in = None if owner == REMOTE else htlc_update.local_ctn_in
            local_ctn_out = None if owner == REMOTE else htlc_update.local_ctn_out
            remote_ctn_in = None if owner == LOCAL else htlc_update.remote_ctn_in
            remote_ctn_out = None if owner == LOCAL else htlc_update.remote_ctn_out

            if local_ctn_in is None and remote_ctn_in is None:
                continue
            if owner == LOCAL and local_ctn_in is not None and local_ctn_out is not None:
                continue

            if owner == REMOTE and remote_ctn_in is not None and remote_ctn_out is not None:
                continue

            active_htlcs += _bytes

        return active_htlcs

    def to_bytes(self, owner=None, blank_timestamps=False) -> bytes:
        active_offered_htlcs = self.serialize_active_htlcs(owner, proposer=LOCAL, blank_timestamps=blank_timestamps)
        active_received_htlcs = self.serialize_active_htlcs(owner, proposer=REMOTE, blank_timestamps=blank_timestamps)

        remote_offered_msat = 0 if owner == LOCAL else self.remote_offered_msat
        remote_received_msat = 0 if owner == LOCAL else self.remote_received_msat
        local_offered_msat = 0 if owner == REMOTE else self.local_offered_msat
        local_received_msat = 0 if owner == REMOTE else self.local_received_msat

        # if we are initiator, the pending feerate applies to REMOTE
        # if we are not initiator, the pending feerate applies to LOCAL
        current_fee_update_bytes = self.current_fee_update.to_bytes(owner)
        pending_fee_update_bytes = self.pending_fee_update.to_bytes(owner) if self.pending_fee_update else bytes(20)

        payload = {
            'version': {'version': PEERBACKUP_VERSION},
            'channel_id': {'channel_id': bytes.fromhex(self.channel_id)},
            'channel_type': {'type': ChannelType(self.channel_type).to_bytes_minimal()},
            'node_id': {'node_id': bytes.fromhex(self.node_id)},
            'offered_htlcs': {
                'local_msat': local_offered_msat,
                'remote_msat': remote_offered_msat,
                'active_htlcs': active_offered_htlcs,
            },
            'received_htlcs': {
                'local_msat': local_received_msat,
                'remote_msat': remote_received_msat,
                'active_htlcs': active_received_htlcs,
            },
            'constraints': self.constraints,
            'fee_updates': {'current': current_fee_update_bytes, 'pending': pending_fee_update_bytes},
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
            payload['remote_ctx'] = b
        if owner != REMOTE:
            a, b = self.convert_config_to_payload(self.local_config, self.local_ctn, self.remote_next_htlc_id)
            payload['local_config'] = a
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
    def merge_peerbackup_bytes(cls, config, local_peerbackup_bytes, remote_peerbackup_bytes):
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
        #
        remote_peerbackup.local_offered_msat = local_peerbackup.local_offered_msat
        remote_peerbackup.local_received_msat = local_peerbackup.local_received_msat
        local_peerbackup.remote_offered_msat = remote_peerbackup.remote_offered_msat
        local_peerbackup.remote_received_msat = remote_peerbackup.remote_received_msat
        # merge htlc logs
        local_htlc_log = local_peerbackup.active_htlcs
        remote_htlc_log = remote_peerbackup.active_htlcs
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

        local_peerbackup.current_fee_update.remote_ctn = remote_peerbackup.current_fee_update.remote_ctn
        remote_peerbackup.current_fee_update.local_ctn = local_peerbackup.current_fee_update.local_ctn
        if local_peerbackup.pending_fee_update:
            assert remote_peerbackup.pending_fee_update
            local_peerbackup.pending_fee_update.remote_ctn = remote_peerbackup.pending_fee_update.remote_ctn
            remote_peerbackup.pending_fee_update.local_ctn = local_peerbackup.pending_fee_update.local_ctn

        if local_peerbackup != remote_peerbackup:
            cls.save_debug_file(config, 'local_peerbackup', local_peerbackup_bytes)
            cls.save_debug_file(config, 'remote_peerbackup', remote_peerbackup_bytes)
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

        # flip owner and proposer:  a b  ->  d c
        #                           c d      b a

        self.local_received_msat, self.remote_offered_msat = self.remote_offered_msat, self.local_received_msat
        self.local_offered_msat, self.remote_received_msat = self.remote_received_msat, self.local_offered_msat

        self.current_fee_update.flip()
        if self.pending_fee_update:
            self.pending_fee_update.flip()

        flip_dict_values(self.active_htlcs, LOCAL, REMOTE)
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, v in self.active_htlcs[proposer].items():
                v.flip()
        self.constraints['is_initiator'] = not self.constraints['is_initiator']

    def recreate_channel_state(self, lnworker) -> dict:
        """ returns a dict compatible with channel storage """
        b = self.to_bytes()
        p = self.from_bytes(b)
        state = p.as_dict() # fixme: rebuild from scratch
        state.pop('revocation_store')
        local_config = state['local_config']
        remote_config = state['remote_config']
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
        # assumes anchor
        payment_basepoint = derive_payment_basepoint(
            static_payment_secret=lnworker.static_payment_key.privkey,
            funding_pubkey=bytes.fromhex(local_config['multisig_key']['pubkey'])
        )
        assert local_config['payment_basepoint']['pubkey'] == payment_basepoint.pubkey.hex()
        local_config['payment_basepoint']['privkey'] = payment_basepoint.privkey.hex()
        state['onion_keys'] = {}
        state['unfulfilled_htlcs'] = {}
        state['peer_network_addresses'] = {}
        # rebuild the log from local and remote
        log = {
            '1': deepcopy(LOG_TEMPLATE),
            '-1': deepcopy(LOG_TEMPLATE),
        }
        active_htlcs = state.pop('active_htlcs')
        for proposer in [LOCAL, REMOTE]:
            target_log = log[str(int(proposer))]
            for htlc_id, v in active_htlcs[proposer].items():
                target_log['adds'][str(htlc_id)] = (v.amount_msat, v.payment_hash.hex(), v.cltv_abs, v.htlc_id, v.timestamp)
                assert (v.local_ctn_in is not None or v.remote_ctn_in is not None), v
                target_log['locked_in'][str(htlc_id)] = {'1':v.local_ctn_in, '-1':v.remote_ctn_in}
                if v.local_ctn_out is not None or v.remote_ctn_out is not None:
                    target_log['settles' if v.is_success else 'fails'][str(htlc_id)] = {'1':v.local_ctn_out, '-1':v.remote_ctn_out}

        # set delta_msat
        log['1']['delta_msat'] = {'-1':self.remote_offered_msat, '1': self.local_offered_msat}
        log['-1']['delta_msat'] = {'-1':self.remote_received_msat, '1': self.local_received_msat}

        local_ctn = state.pop('local_ctn')
        remote_ctn = state.pop('remote_ctn')
        log['1']['ctn'] = local_ctn
        log['-1']['ctn'] = remote_ctn

        current_fee_update = state.pop('current_fee_update')
        pending_fee_update = state.pop('pending_fee_update')
        initiator = '1' if state['constraints']['is_initiator'] else '-1'
        fee_log = log[initiator]['fee_updates']
        fee_log['0'] = current_fee_update
        if pending_fee_update:
            fee_log['1'] = pending_fee_update

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

        lnworker.logger.info(f'recreated channel state')
        lnworker.logger.info(f'log[LOCAL]: {log["1"]}')
        lnworker.logger.info(f'log[REMOTE]: {log["-1"]}')
        return state

    def get_their_revocation_store(self, local_config, ctn):
        seed = bytes.fromhex(local_config['per_commitment_secret_seed'])
        store = RevocationStore.from_seed_and_index(seed, ctn)
        return json.loads(json.dumps(store.storage, cls=util.MyEncoder))

    @classmethod
    def save_debug_file(cls, config, filename, peerbackup_bytes, sighash=b''):
        if not config.DEBUG_PEERBACKUPS:
            return
        p = PeerBackup.from_bytes(peerbackup_bytes)
        with open(filename, "w") as f:
            d = p.as_dict()
            d['sighash'] = sighash.hex()
            f.write(json.dumps(d, cls=util.MyEncoder, sort_keys=True, indent=2))
