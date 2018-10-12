#!/usr/bin/env python3
"""
  Lightning network interface for Electrum
  Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8
"""

from collections import OrderedDict, defaultdict
import json
import asyncio
import os
import time
import hashlib
import hmac
from functools import partial
from typing import List

import cryptography.hazmat.primitives.ciphers.aead as AEAD
import aiorpcx

from . import bitcoin
from . import ecc
from .ecc import sig_string_from_r_and_s, get_r_and_s_from_sig_string
from .crypto import sha256
from . import constants
from .util import PrintError, bh2u, print_error, bfh, log_exceptions, list_enabled_bits, ignore_exceptions
from .transaction import Transaction, TxOutput
from .lnonion import new_onion_packet, OnionHopsDataSingle, OnionPerHop, decode_onion_error, OnionFailureCode
from .lnaddr import lndecode
from .lnchan import Channel, RevokeAndAck, htlcsum
from .lnutil import (Outpoint, LocalConfig, ChannelConfig,
                     RemoteConfig, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore,
                     funding_output_script, get_ecdh, get_per_commitment_secret_from_seed,
                     secret_to_pubkey, LNPeerAddr, PaymentFailure, LnLocalFeatures,
                     LOCAL, REMOTE, HTLCOwner, generate_keypair, LnKeyFamily,
                     get_ln_flag_pair_of_bit)
from .lnrouter import NotFoundChanAnnouncementForUpdate, RouteEdge


def channel_id_from_funding_tx(funding_txid, funding_index):
    funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
    i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
    return i.to_bytes(32, 'big'), funding_txid_bytes

class LightningError(Exception):
    pass

class LightningPeerConnectionClosed(LightningError):
    pass

message_types = {}

def handlesingle(x, ma):
    """
    Evaluate a term of the simple language used
    to specify lightning message field lengths.

    If `x` is an integer, it is returned as is,
    otherwise it is treated as a variable and
    looked up in `ma`.

    It the value in `ma` was no integer, it is
    assumed big-endian bytes and decoded.

    Returns int
    """
    try:
        x = int(x)
    except ValueError:
        x = ma[x]
    try:
        x = int(x)
    except ValueError:
        x = int.from_bytes(x, byteorder='big')
    return x

def calcexp(exp, ma):
    """
    Evaluate simple mathematical expression given
    in `exp` with variables assigned in the dict `ma`

    Returns int
    """
    exp = str(exp)
    if "*" in exp:
        assert "+" not in exp
        result = 1
        for term in exp.split("*"):
            result *= handlesingle(term, ma)
        return result
    return sum(handlesingle(x, ma) for x in exp.split("+"))

def make_handler(k, v):
    """
    Generate a message handler function (taking bytes)
    for message type `k` with specification `v`

    Check lib/lightning.json, `k` could be 'init',
    and `v` could be

      { type: 16, payload: { 'gflen': ..., ... }, ... }

    Returns function taking bytes
    """
    def handler(data):
        nonlocal k, v
        ma = {}
        pos = 0
        for fieldname in v["payload"]:
            poslenMap = v["payload"][fieldname]
            if "feature" in poslenMap and pos == len(data):
                continue
            #print(poslenMap["position"], ma)
            assert pos == calcexp(poslenMap["position"], ma)
            length = poslenMap["length"]
            length = calcexp(length, ma)
            ma[fieldname] = data[pos:pos+length]
            pos += length
        assert pos == len(data), (k, pos, len(data))
        return k, ma
    return handler

path = os.path.join(os.path.dirname(__file__), 'lightning.json')
with open(path) as f:
    structured = json.loads(f.read(), object_pairs_hook=OrderedDict)

for k in structured:
    v = structured[k]
    # these message types are skipped since their types collide
    # (for example with pong, which also uses type=19)
    # we don't need them yet
    if k in ["final_incorrect_cltv_expiry", "final_incorrect_htlc_amount"]:
        continue
    if len(v["payload"]) == 0:
        continue
    try:
        num = int(v["type"])
    except ValueError:
        #print("skipping", k)
        continue
    byts = num.to_bytes(2, 'big')
    assert byts not in message_types, (byts, message_types[byts].__name__, k)
    names = [x.__name__ for x in message_types.values()]
    assert k + "_handler" not in names, (k, names)
    message_types[byts] = make_handler(k, v)
    message_types[byts].__name__ = k + "_handler"

assert message_types[b"\x00\x10"].__name__ == "init_handler"

def decode_msg(data):
    """
    Decode Lightning message by reading the first
    two bytes to determine message type.

    Returns message type string and parsed message contents dict
    """
    typ = data[:2]
    k, parsed = message_types[typ](data[2:])
    return k, parsed

def gen_msg(msg_type, **kwargs):
    """
    Encode kwargs into a Lightning message (bytes)
    of the type given in the msg_type string
    """
    typ = structured[msg_type]
    data = int(typ["type"]).to_bytes(2, 'big')
    lengths = {}
    for k in typ["payload"]:
        poslenMap = typ["payload"][k]
        if "feature" in poslenMap: continue
        leng = calcexp(poslenMap["length"], lengths)
        try:
            clone = dict(lengths)
            clone.update(kwargs)
            leng = calcexp(poslenMap["length"], clone)
        except KeyError:
            pass
        try:
            param = kwargs[k]
        except KeyError:
            param = 0
        try:
            if not isinstance(param, bytes):
                assert isinstance(param, int), "field {} is neither bytes or int".format(k)
                param = param.to_bytes(leng, 'big')
        except ValueError:
            raise Exception("{} does not fit in {} bytes".format(k, leng))
        lengths[k] = len(param)
        if lengths[k] != leng:
            raise Exception("field {} is {} bytes long, should be {} bytes long".format(k, lengths[k], leng))
        data += param
    return data


class HandshakeState(object):
    prologue = b"lightning"
    protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256"
    handshake_version = b"\x00"

    def __init__(self, responder_pub):
        self.responder_pub = responder_pub
        self.h = sha256(self.protocol_name)
        self.ck = self.h
        self.update(self.prologue)
        self.update(self.responder_pub)

    def update(self, data):
        self.h = sha256(self.h + data)
        return self.h


class HandshakeFailed(Exception): pass


def get_nonce_bytes(n):
    """BOLT 8 requires the nonce to be 12 bytes, 4 bytes leading
    zeroes and 8 bytes little endian encoded 64 bit integer.
    """
    return b"\x00"*4 + n.to_bytes(8, 'little')

def aead_encrypt(k, nonce, associated_data, data):
    nonce_bytes = get_nonce_bytes(nonce)
    a = AEAD.ChaCha20Poly1305(k)
    return a.encrypt(nonce_bytes, data, associated_data)

def aead_decrypt(k, nonce, associated_data, data):
    nonce_bytes = get_nonce_bytes(nonce)
    a = AEAD.ChaCha20Poly1305(k)
    #raises InvalidTag exception if it's not valid
    return a.decrypt(nonce_bytes, data, associated_data)

def get_bolt8_hkdf(salt, ikm):
    """RFC5869 HKDF instantiated in the specific form
    used in Lightning BOLT 8:
    Extract and expand to 64 bytes using HMAC-SHA256,
    with info field set to a zero length string as per BOLT8
    Return as two 32 byte fields.
    """
    #Extract
    prk = hmac.new(salt, msg=ikm, digestmod=hashlib.sha256).digest()
    assert len(prk) == 32
    #Expand
    info = b""
    T0 = b""
    T1 = hmac.new(prk, T0 + info + b"\x01", digestmod=hashlib.sha256).digest()
    T2 = hmac.new(prk, T1 + info + b"\x02", digestmod=hashlib.sha256).digest()
    assert len(T1 + T2) == 64
    return T1, T2

def act1_initiator_message(hs, epriv, epub):
    hs.update(epub)
    ss = get_ecdh(epriv, hs.responder_pub)
    ck2, temp_k1 = get_bolt8_hkdf(hs.ck, ss)
    hs.ck = ck2
    c = aead_encrypt(temp_k1, 0, hs.h, b"")
    #for next step if we do it
    hs.update(c)
    msg = hs.handshake_version + epub + c
    assert len(msg) == 50
    return msg

def privkey_to_pubkey(priv: bytes) -> bytes:
    return ecc.ECPrivkey(priv[:32]).get_public_key_bytes()

def create_ephemeral_key() -> (bytes, bytes):
    privkey = ecc.ECPrivkey.generate_random_key()
    return privkey.get_secret_bytes(), privkey.get_public_key_bytes()


class Peer(PrintError):

    def __init__(self, lnworker, host, port, pubkey, request_initial_sync=False):
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self.peer_addr = LNPeerAddr(host, port, pubkey)
        self.lnworker = lnworker
        self.privkey = lnworker.node_keypair.privkey
        self.network = lnworker.network
        self.lnwatcher = lnworker.network.lnwatcher
        self.channel_db = lnworker.network.channel_db
        self.read_buffer = b''
        self.ping_time = 0
        self.initialized = asyncio.Future()
        self.channel_accepted = defaultdict(asyncio.Queue)
        self.channel_reestablished = defaultdict(asyncio.Future)
        self.funding_signed = defaultdict(asyncio.Queue)
        self.funding_created = defaultdict(asyncio.Queue)
        self.revoke_and_ack = defaultdict(asyncio.Queue)
        self.commitment_signed = defaultdict(asyncio.Queue)
        self.announcement_signatures = defaultdict(asyncio.Queue)
        self.closing_signed = defaultdict(asyncio.Queue)
        self.payment_preimages = defaultdict(asyncio.Queue)
        self.localfeatures = LnLocalFeatures(0)
        if request_initial_sync:
            self.localfeatures |= LnLocalFeatures.INITIAL_ROUTING_SYNC
        self.localfeatures |= LnLocalFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.invoices = lnworker.invoices
        self.attempted_route = {}

    @property
    def channels(self):
        return self.lnworker.channels_for_peer(self.pubkey)

    def diagnostic_name(self):
        return 'lnbase:' + str(self.host)

    def ping_if_required(self):
        if time.time() - self.ping_time > 120:
            self.send_message(gen_msg('ping', num_pong_bytes=4, byteslen=4))
            self.ping_time = time.time()

    def send_message(self, msg):
        message_type, payload = decode_msg(msg)
        self.print_error("Sending '%s'"%message_type.upper())
        l = len(msg).to_bytes(2, 'big')
        lc = aead_encrypt(self.sk, self.sn(), b'', l)
        c = aead_encrypt(self.sk, self.sn(), b'', msg)
        assert len(lc) == 18
        assert len(c) == len(msg) + 16
        self.writer.write(lc+c)

    async def read_message(self):
        rn_l, rk_l = self.rn()
        rn_m, rk_m = self.rn()
        while True:
            if len(self.read_buffer) >= 18:
                lc = self.read_buffer[:18]
                l = aead_decrypt(rk_l, rn_l, b'', lc)
                length = int.from_bytes(l, 'big')
                offset = 18 + length + 16
                if len(self.read_buffer) >= offset:
                    c = self.read_buffer[18:offset]
                    self.read_buffer = self.read_buffer[offset:]
                    msg = aead_decrypt(rk_m, rn_m, b'', c)
                    return msg
            try:
                s = await self.reader.read(2**10)
            except:
                s = None
            if not s:
                raise LightningPeerConnectionClosed()
            self.read_buffer += s

    async def handshake(self):
        hs = HandshakeState(self.pubkey)
        # Get a new ephemeral key
        epriv, epub = create_ephemeral_key()

        msg = act1_initiator_message(hs, epriv, epub)
        # act 1
        self.writer.write(msg)
        rspns = await self.reader.read(2**10)
        if len(rspns) != 50:
            raise HandshakeFailed("Lightning handshake act 1 response has bad length, are you sure this is the right pubkey? " + str(bh2u(self.pubkey)))
        hver, alice_epub, tag = rspns[0], rspns[1:34], rspns[34:]
        if bytes([hver]) != hs.handshake_version:
            raise HandshakeFailed("unexpected handshake version: {}".format(hver))
        # act 2
        hs.update(alice_epub)
        ss = get_ecdh(epriv, alice_epub)
        ck, temp_k2 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        p = aead_decrypt(temp_k2, 0, hs.h, tag)
        hs.update(tag)
        # act 3
        my_pubkey = privkey_to_pubkey(self.privkey)
        c = aead_encrypt(temp_k2, 1, hs.h, my_pubkey)
        hs.update(c)
        ss = get_ecdh(self.privkey[:32], alice_epub)
        ck, temp_k3 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        t = aead_encrypt(temp_k3, 0, hs.h, b'')
        self.sk, self.rk = get_bolt8_hkdf(hs.ck, b'')
        msg = hs.handshake_version + c + t
        self.writer.write(msg)
        # init counters
        self._sn = 0
        self._rn = 0
        self.r_ck = ck
        self.s_ck = ck

    def rn(self):
        o = self._rn, self.rk
        self._rn += 1
        if self._rn == 1000:
            self.r_ck, self.rk = get_bolt8_hkdf(self.r_ck, self.rk)
            self._rn = 0
        return o

    def sn(self):
        o = self._sn
        self._sn += 1
        if self._sn == 1000:
            self.s_ck, self.sk = get_bolt8_hkdf(self.s_ck, self.sk)
            self._sn = 0
        return o

    def process_message(self, message):
        message_type, payload = decode_msg(message)
        try:
            f = getattr(self, 'on_' + message_type)
        except AttributeError:
            self.print_error("Received '%s'" % message_type.upper(), payload)
            return
        # raw message is needed to check signature
        if message_type=='node_announcement':
            payload['raw'] = message
        execution_result = f(payload)
        if asyncio.iscoroutinefunction(f):
            asyncio.ensure_future(execution_result)

    def on_error(self, payload):
        self.print_error("error", payload["data"].decode("ascii"))
        chan_id = payload.get("channel_id")
        for d in [ self.channel_accepted, self.channel_reestablished, self.funding_signed,
                   self.funding_created, self.revoke_and_ack, self.commitment_signed,
                   self.announcement_signatures, self.closing_signed ]:
            if chan_id in d:
                self.channel_accepted[chan_id].put_nowait({'error':payload['data']})

    def on_ping(self, payload):
        l = int.from_bytes(payload['num_pong_bytes'], 'big')
        self.send_message(gen_msg('pong', byteslen=l))

    def on_pong(self, payload):
        pass

    def on_accept_channel(self, payload):
        temp_chan_id = payload["temporary_channel_id"]
        if temp_chan_id not in self.channel_accepted: raise Exception("Got unknown accept_channel")
        self.channel_accepted[temp_chan_id].put_nowait(payload)

    def on_funding_signed(self, payload):
        channel_id = payload['channel_id']
        if channel_id not in self.funding_signed: raise Exception("Got unknown funding_signed")
        self.funding_signed[channel_id].put_nowait(payload)

    def on_funding_created(self, payload):
        channel_id = payload['temporary_channel_id']
        if channel_id not in self.funding_created: raise Exception("Got unknown funding_created")
        self.funding_created[channel_id].put_nowait(payload)

    def on_node_announcement(self, payload):
        self.channel_db.on_node_announcement(payload)
        self.network.trigger_callback('ln_status')

    def on_init(self, payload):
        # if they required some even flag we don't have, they will close themselves
        # but if we require an even flag they don't have, we close
        our_flags = set(list_enabled_bits(self.localfeatures))
        their_flags = set(list_enabled_bits(int.from_bytes(payload['localfeatures'], byteorder="big")))
        for flag in our_flags:
            if flag not in their_flags and get_ln_flag_pair_of_bit(flag) not in their_flags:
                # they don't have this feature we wanted :(
                if flag % 2 == 0:  # even flags are compulsory
                    raise LightningPeerConnectionClosed("remote does not have even flag {}"
                                                        .format(str(LnLocalFeatures(1 << flag))))
                self.localfeatures ^= 1 << flag  # disable flag

    def on_channel_update(self, payload):
        try:
            self.channel_db.on_channel_update(payload)
        except NotFoundChanAnnouncementForUpdate:
            # If it's for a direct channel with this peer, save it in chan.
            # Note that this is prone to a race.. we might not have a short_channel_id
            # associated with the channel in some cases
            short_channel_id = payload['short_channel_id']
            self.print_error("not found channel announce for channel update in db", bh2u(short_channel_id))
            for chan in self.channels.values():
                if chan.short_channel_id_predicted == short_channel_id:
                    chan.pending_channel_update_message = payload
                    self.print_error("channel update is for our own private channel", bh2u(short_channel_id))
                    break

    def on_channel_announcement(self, payload):
        self.channel_db.on_channel_announcement(payload)

    def on_announcement_signatures(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels[payload['channel_id']]
        if chan.config[LOCAL].was_announced:
            h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        else:
            self.announcement_signatures[channel_id].put_nowait(payload)

    async def initialize(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self.handshake()
        # send init
        self.send_message(gen_msg("init", gflen=0, lflen=1, localfeatures=self.localfeatures))
        # read init
        msg = await self.read_message()
        self.process_message(msg)
        self.initialized.set_result(True)

    def handle_disconnect(func):
        async def wrapper_func(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except LightningPeerConnectionClosed as e:
                self.print_error("disconnecting gracefully. {}".format(e))
            finally:
                self.close_and_cleanup()
                self.lnworker.peers.pop(self.pubkey)
        return wrapper_func

    @ignore_exceptions  # do not kill main_taskgroup
    @log_exceptions
    @handle_disconnect
    async def main_loop(self):
        try:
            await asyncio.wait_for(self.initialize(), 10)
        except (OSError, asyncio.TimeoutError, HandshakeFailed) as e:
            self.print_error('disconnecting due to: {}'.format(repr(e)))
            return
        self.channel_db.add_recent_peer(self.peer_addr)
        # loop
        while True:
            self.ping_if_required()
            msg = await self.read_message()
            self.process_message(msg)

    def close_and_cleanup(self):
        try:
            self.writer.close()
        except:
            pass
        for chan in self.channels.values():
            chan.set_state('DISCONNECTED')
            self.network.trigger_callback('channel', chan)

    def make_local_config(self, funding_sat, push_msat, initiator: HTLCOwner):
        # key derivation
        channel_counter = self.lnworker.get_and_inc_counter_for_channel_keys()
        keypair_generator = lambda family: generate_keypair(self.lnworker.ln_keystore, family, channel_counter)
        if initiator == LOCAL:
            initial_msat = funding_sat * 1000 - push_msat
        else:
            initial_msat = push_msat
        local_config=ChannelConfig(
            payment_basepoint=keypair_generator(LnKeyFamily.PAYMENT_BASE),
            multisig_key=keypair_generator(LnKeyFamily.MULTISIG),
            htlc_basepoint=keypair_generator(LnKeyFamily.HTLC_BASE),
            delayed_basepoint=keypair_generator(LnKeyFamily.DELAY_BASE),
            revocation_basepoint=keypair_generator(LnKeyFamily.REVOCATION_BASE),
            to_self_delay=143,
            dust_limit_sat=546,
            max_htlc_value_in_flight_msat=0xffffffffffffffff,
            max_accepted_htlcs=5,
            initial_msat=initial_msat,
            ctn=-1,
            next_htlc_id=0,
            amount_msat=initial_msat,
        )
        per_commitment_secret_seed = keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey
        return local_config, per_commitment_secret_seed

    @log_exceptions
    async def channel_establishment_flow(self, password, funding_sat, push_msat, temp_channel_id):
        await self.initialized
        feerate = self.current_feerate_per_kw()
        local_config, per_commitment_secret_seed = self.make_local_config(funding_sat, push_msat, LOCAL)
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(per_commitment_secret_seed, RevocationStore.START_INDEX)
        per_commitment_point_first = secret_to_pubkey(int.from_bytes(per_commitment_secret_first, 'big'))
        msg = gen_msg(
            "open_channel",
            temporary_channel_id=temp_channel_id,
            chain_hash=constants.net.rev_genesis_bytes(),
            funding_satoshis=funding_sat,
            push_msat=push_msat,
            dust_limit_satoshis=local_config.dust_limit_sat,
            feerate_per_kw=feerate,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
            to_self_delay=local_config.to_self_delay,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_flags=0x00,  # not willing to announce channel
            channel_reserve_satoshis=546
        )
        self.send_message(msg)
        payload = await self.channel_accepted[temp_channel_id].get()
        if payload.get('error'):
            raise Exception(payload.get('error'))
        remote_per_commitment_point = payload['first_per_commitment_point']
        funding_txn_minimum_depth = int.from_bytes(payload['minimum_depth'], 'big')
        remote_dust_limit_sat = int.from_bytes(payload['dust_limit_satoshis'], byteorder='big')
        assert remote_dust_limit_sat < 600, remote_dust_limit_sat
        assert int.from_bytes(payload['htlc_minimum_msat'], 'big') < 600 * 1000
        remote_max = int.from_bytes(payload['max_htlc_value_in_flight_msat'], 'big')
        assert remote_max >= 198 * 1000 * 1000, remote_max
        their_revocation_store = RevocationStore()
        remote_config = RemoteConfig(
            payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
            multisig_key=OnlyPubkeyKeypair(payload["funding_pubkey"]),
            htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
            delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
            revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
            to_self_delay=int.from_bytes(payload['to_self_delay'], byteorder='big'),
            dust_limit_sat=remote_dust_limit_sat,
            max_htlc_value_in_flight_msat=remote_max,
            max_accepted_htlcs=int.from_bytes(payload["max_accepted_htlcs"], 'big'),
            initial_msat=push_msat,
            ctn = -1,
            amount_msat=push_msat,
            next_htlc_id = 0,

            next_per_commitment_point=remote_per_commitment_point,
            current_per_commitment_point=None,
            revocation_store=their_revocation_store,
        )
        # create funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = TxOutput(bitcoin.TYPE_ADDRESS, funding_address, funding_sat)
        funding_tx = self.lnworker.wallet.mktx([funding_output], password, self.lnworker.config, 1000)
        funding_txid = funding_tx.txid()
        funding_index = funding_tx.outputs().index(funding_output)
        # remote commitment transaction
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_index)
        chan = {
                "node_id": self.pubkey,
                "channel_id": channel_id,
                "short_channel_id": None,
                "funding_outpoint": Outpoint(funding_txid, funding_index),
                "remote_config": remote_config,
                "local_config": LocalConfig(
                    **local_config._asdict(),
                    per_commitment_secret_seed=per_commitment_secret_seed,
                    funding_locked_received = False,
                    was_announced = False,
                    current_commitment_signature = None,
                    current_htlc_signatures = None,
                ),
                "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=True, funding_txn_minimum_depth=funding_txn_minimum_depth, feerate=feerate),
                "remote_commitment_to_be_revoked": None,
        }
        m = Channel(chan)
        m.lnwatcher = self.lnwatcher
        m.sweep_address = self.lnworker.sweep_address
        sig_64, _ = m.sign_next_commitment()
        self.send_message(gen_msg("funding_created",
            temporary_channel_id=temp_channel_id,
            funding_txid=funding_txid_bytes,
            funding_output_index=funding_index,
            signature=sig_64))
        payload = await self.funding_signed[channel_id].get()
        self.print_error('received funding_signed')
        remote_sig = payload['signature']
        m.receive_new_commitment(remote_sig, [])
        # broadcast funding tx
        await self.network.broadcast_transaction(funding_tx)
        m.remote_commitment_to_be_revoked = m.pending_remote_commitment
        m.config[REMOTE] = m.config[REMOTE]._replace(ctn=0)
        m.config[LOCAL] = m.config[LOCAL]._replace(ctn=0, current_commitment_signature=remote_sig)
        m.set_state('OPENING')
        return m

    async def on_open_channel(self, payload):
        # payload['channel_flags']
        # payload['channel_reserve_satoshis']
        if payload['chain_hash'] != constants.net.rev_genesis_bytes():
            raise Exception('wrong chain_hash')
        funding_sat = int.from_bytes(payload['funding_satoshis'], 'big')
        push_msat = int.from_bytes(payload['push_msat'], 'big')
        feerate = int.from_bytes(payload['feerate_per_kw'], 'big')

        temp_chan_id = payload['temporary_channel_id']
        local_config, per_commitment_secret_seed = self.make_local_config(funding_sat * 1000, push_msat, REMOTE)

        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(per_commitment_secret_seed, RevocationStore.START_INDEX)
        per_commitment_point_first = secret_to_pubkey(int.from_bytes(per_commitment_secret_first, 'big'))

        min_depth = 3
        self.send_message(gen_msg('accept_channel',
            temporary_channel_id=temp_chan_id,
            dust_limit_satoshis=local_config.dust_limit_sat,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_reserve_satoshis=546,
            htlc_minimum_msat=1000,
            minimum_depth=min_depth,
            to_self_delay=local_config.to_self_delay,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
        ))
        funding_created = await self.funding_created[temp_chan_id].get()
        funding_idx = int.from_bytes(funding_created['funding_output_index'], 'big')
        funding_txid = bh2u(funding_created['funding_txid'][::-1])
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_idx)
        their_revocation_store = RevocationStore()
        remote_balance_sat = funding_sat * 1000 - push_msat
        chan = {
                "node_id": self.pubkey,
                "channel_id": channel_id,
                "short_channel_id": None,
                "funding_outpoint": Outpoint(funding_txid, funding_idx),
                "remote_config": RemoteConfig(
                    payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
                    multisig_key=OnlyPubkeyKeypair(payload['funding_pubkey']),
                    htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
                    delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
                    revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
                    to_self_delay=int.from_bytes(payload['to_self_delay'], 'big'),
                    dust_limit_sat=int.from_bytes(payload['dust_limit_satoshis'], 'big'),
                    max_htlc_value_in_flight_msat=int.from_bytes(payload['max_htlc_value_in_flight_msat'], 'big'),
                    max_accepted_htlcs=int.from_bytes(payload['max_accepted_htlcs'], 'big'),
                    initial_msat=remote_balance_sat,
                    ctn = -1,
                    amount_msat=remote_balance_sat,
                    next_htlc_id = 0,

                    next_per_commitment_point=payload['first_per_commitment_point'],
                    current_per_commitment_point=None,
                    revocation_store=their_revocation_store,
                ),
                "local_config": LocalConfig(
                    **local_config._asdict(),
                    per_commitment_secret_seed=per_commitment_secret_seed,
                    funding_locked_received = False,
                    was_announced = False,
                    current_commitment_signature = None,
                    current_htlc_signatures = None,
                ),
                "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=False, funding_txn_minimum_depth=min_depth, feerate=feerate),
                "remote_commitment_to_be_revoked": None,
        }
        m = Channel(chan)
        m.lnwatcher = self.lnwatcher
        m.sweep_address = self.lnworker.sweep_address
        remote_sig = funding_created['signature']
        m.receive_new_commitment(remote_sig, [])
        sig_64, _ = m.sign_next_commitment()
        self.send_message(gen_msg('funding_signed',
            channel_id=channel_id,
            signature=sig_64,
        ))
        m.set_state('OPENING')
        m.remote_commitment_to_be_revoked = m.pending_remote_commitment
        m.config[REMOTE] = m.config[REMOTE]._replace(ctn=0)
        m.config[LOCAL] = m.config[LOCAL]._replace(ctn=0, current_commitment_signature=remote_sig)
        self.lnworker.save_channel(m)
        self.lnwatcher.watch_channel(m.get_funding_address(), m.funding_outpoint.to_str())
        self.lnworker.on_channels_updated()
        while True:
            try:
                funding_tx = Transaction(await self.network.get_transaction(funding_txid))
            except aiorpcx.jsonrpc.RPCError as e:
                print("sleeping", str(e))
                await asyncio.sleep(1)
            else:
                break
        outp = funding_tx.outputs()[funding_idx]
        redeem_script = funding_output_script(m.config[REMOTE], m.config[LOCAL])
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        if outp != TxOutput(bitcoin.TYPE_ADDRESS, funding_address, funding_sat):
            m.set_state('DISCONNECTED')
            raise Exception('funding outpoint mismatch')

    @log_exceptions
    async def reestablish_channel(self, chan):
        await self.initialized
        chan_id = chan.channel_id
        if chan.get_state() != 'DISCONNECTED':
            self.print_error('reestablish_channel was called but channel {} already in state {}'
                             .format(chan_id, chan.get_state()))
            return
        chan.set_state('REESTABLISHING')
        self.network.trigger_callback('channel', chan)
        self.send_message(gen_msg("channel_reestablish",
            channel_id=chan_id,
            next_local_commitment_number=chan.config[LOCAL].ctn+1,
            next_remote_revocation_number=chan.config[REMOTE].ctn
        ))
        await self.channel_reestablished[chan_id]
        chan.set_state('OPENING')
        if chan.config[LOCAL].funding_locked_received and chan.short_channel_id:
            self.mark_open(chan)
        self.network.trigger_callback('channel', chan)

    def on_channel_reestablish(self, payload):
        chan_id = payload["channel_id"]
        self.print_error("Received channel_reestablish", bh2u(chan_id))
        chan = self.channels.get(chan_id)
        if not chan:
            print("Warning: received unknown channel_reestablish", bh2u(chan_id))
            return

        def try_to_get_remote_to_force_close_with_their_latest():
            self.print_error("trying to get remote to force close", bh2u(chan_id))
            self.send_message(gen_msg("channel_reestablish",
                                      channel_id=chan_id,
                                      next_local_commitment_number=0,
                                      next_remote_revocation_number=0
                                      ))

        channel_reestablish_msg = payload
        # compare remote ctns
        remote_ctn = int.from_bytes(channel_reestablish_msg["next_local_commitment_number"], 'big')
        if remote_ctn != chan.config[REMOTE].ctn + 1:
            self.print_error("expected remote ctn {}, got {}".format(chan.config[REMOTE].ctn + 1, remote_ctn))
            # TODO iff their ctn is lower than ours, we should force close instead
            try_to_get_remote_to_force_close_with_their_latest()
            return
        # compare local ctns
        local_ctn = int.from_bytes(channel_reestablish_msg["next_remote_revocation_number"], 'big')
        if local_ctn != chan.config[LOCAL].ctn:
            if remote_ctn == chan.config[LOCAL].ctn + 1:
                # A node:
                #    if next_remote_revocation_number is equal to the
                #    commitment number of the last revoke_and_ack
                #    the receiving node sent, AND the receiving node
                #    hasn't already received a closing_signed:
                #        MUST re-send the revoke_and_ack.
                self.config[LOCAL]=self.config[LOCAL]._replace(
                    ctn=remote_ctn,
                )
                self.revoke(chan)
                self.channel_reestablished[chan_id].set_result(True)
                return
            else:
                self.print_error("expected local ctn {}, got {}".format(chan.config[LOCAL].ctn, local_ctn))
                # TODO iff their ctn is lower than ours, we should force close instead
                try_to_get_remote_to_force_close_with_their_latest()
                return
        # compare per commitment points (needs data_protect option)
        their_pcp = channel_reestablish_msg.get("my_current_per_commitment_point", None)
        if their_pcp is not None:
            our_pcp = chan.config[REMOTE].current_per_commitment_point
            if our_pcp is None:
                our_pcp = chan.config[REMOTE].next_per_commitment_point
            if our_pcp != their_pcp:
                self.print_error("Remote PCP mismatch: {} {}".format(bh2u(our_pcp), bh2u(their_pcp)))
                # FIXME ...what now?
                try_to_get_remote_to_force_close_with_their_latest()
                return
        # checks done
        self.channel_reestablished[chan_id].set_result(True)

    def funding_locked(self, chan):
        channel_id = chan.channel_id
        per_commitment_secret_index = RevocationStore.START_INDEX - 1
        per_commitment_point_second = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.config[LOCAL].per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        # note: if funding_locked was not yet received, we might send it multiple times
        self.send_message(gen_msg("funding_locked", channel_id=channel_id, next_per_commitment_point=per_commitment_point_second))
        if chan.config[LOCAL].funding_locked_received:
            self.mark_open(chan)

    def on_funding_locked(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels.get(channel_id)
        if not chan:
            print(self.channels)
            raise Exception("Got unknown funding_locked", channel_id)
        if not chan.config[LOCAL].funding_locked_received:
            our_next_point = chan.config[REMOTE].next_per_commitment_point
            their_next_point = payload["next_per_commitment_point"]
            new_remote_state = chan.config[REMOTE]._replace(next_per_commitment_point=their_next_point, current_per_commitment_point=our_next_point)
            new_local_state = chan.config[LOCAL]._replace(funding_locked_received = True)
            chan.config[REMOTE]=new_remote_state
            chan.config[LOCAL]=new_local_state
            self.lnworker.save_channel(chan)
        if chan.short_channel_id:
            self.mark_open(chan)

    def on_network_update(self, chan, funding_tx_depth):
        """
        Only called when the channel is OPEN.

        Runs on the Network thread.
        """
        if not chan.config[LOCAL].was_announced and funding_tx_depth >= 6:
            # don't announce our channels
            # FIXME should this be a field in chan.local_state maybe?
            return
            chan.config[LOCAL]=chan.config[LOCAL]._replace(was_announced=True)
            coro = self.handle_announcements(chan)
            self.lnworker.save_channel(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    @log_exceptions
    async def handle_announcements(self, chan):
        h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        announcement_signatures_msg = await self.announcement_signatures[chan.channel_id].get()
        remote_node_sig = announcement_signatures_msg["node_signature"]
        remote_bitcoin_sig = announcement_signatures_msg["bitcoin_signature"]
        if not ecc.verify_signature(chan.config[REMOTE].multisig_key.pubkey, remote_bitcoin_sig, h):
            raise Exception("bitcoin_sig invalid in announcement_signatures")
        if not ecc.verify_signature(self.pubkey, remote_node_sig, h):
            raise Exception("node_sig invalid in announcement_signatures")

        node_sigs = [local_node_sig, remote_node_sig]
        bitcoin_sigs = [local_bitcoin_sig, remote_bitcoin_sig]
        node_ids = [privkey_to_pubkey(self.privkey), self.pubkey]
        bitcoin_keys = [chan.config[LOCAL].multisig_key.pubkey, chan.config[REMOTE].multisig_key.pubkey]

        if node_ids[0] > node_ids[1]:
            node_sigs.reverse()
            bitcoin_sigs.reverse()
            node_ids.reverse()
            bitcoin_keys.reverse()

        channel_announcement = gen_msg("channel_announcement",
            node_signatures_1=node_sigs[0],
            node_signatures_2=node_sigs[1],
            bitcoin_signature_1=bitcoin_sigs[0],
            bitcoin_signature_2=bitcoin_sigs[1],
            len=0,
            #features not set (defaults to zeros)
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=chan.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )

        self.send_message(channel_announcement)

        print("SENT CHANNEL ANNOUNCEMENT")

    def mark_open(self, chan):
        if chan.get_state() == "OPEN":
            return
        # NOTE: even closed channels will be temporarily marked "OPEN"
        assert chan.config[LOCAL].funding_locked_received
        chan.set_state("OPEN")
        self.network.trigger_callback('channel', chan)
        # add channel to database
        pubkey_ours = self.lnworker.node_keypair.pubkey
        pubkey_theirs = self.pubkey
        node_ids = [pubkey_theirs, pubkey_ours]
        bitcoin_keys = [chan.config[LOCAL].multisig_key.pubkey, chan.config[REMOTE].multisig_key.pubkey]
        sorted_node_ids = list(sorted(node_ids))
        if sorted_node_ids != node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()
        # note: we inject a channel announcement, and a channel update (for outgoing direction)
        # This is atm needed for
        # - finding routes
        # - the ChanAnn is needed so that we can anchor to it a future ChanUpd
        #   that the remote sends, even if the channel was not announced
        #   (from BOLT-07: "MAY create a channel_update to communicate the channel
        #    parameters to the final node, even though the channel has not yet been announced")
        self.channel_db.on_channel_announcement({"short_channel_id": chan.short_channel_id, "node_id_1": node_ids[0], "node_id_2": node_ids[1],
                                                 'chain_hash': constants.net.rev_genesis_bytes(), 'len': b'\x00\x00', 'features': b'',
                                                 'bitcoin_key_1': bitcoin_keys[0], 'bitcoin_key_2': bitcoin_keys[1]},
                                                trusted=True)
        # only inject outgoing direction:
        flags = b'\x00' if node_ids[0] == pubkey_ours else b'\x01'
        now = int(time.time()).to_bytes(4, byteorder="big")
        self.channel_db.on_channel_update({"short_channel_id": chan.short_channel_id, 'flags': flags, 'cltv_expiry_delta': b'\x90',
                                           'htlc_minimum_msat': b'\x03\xe8', 'fee_base_msat': b'\x03\xe8', 'fee_proportional_millionths': b'\x01',
                                           'chain_hash': constants.net.rev_genesis_bytes(), 'timestamp': now},
                                          trusted=True)
        # peer may have sent us a channel update for the incoming direction previously
        # note: if we were offline when the 3rd conf happened, lnd will never send us this channel_update
        # see https://github.com/lightningnetwork/lnd/issues/1347
        #self.send_message(gen_msg("query_short_channel_ids", chain_hash=constants.net.rev_genesis_bytes(),
        #                          len=9, encoded_short_ids=b'\x00'+chan.short_channel_id))
        if hasattr(chan, 'pending_channel_update_message'):
            self.on_channel_update(chan.pending_channel_update_message)

        self.print_error("CHANNEL OPENING COMPLETED")

    def send_announcement_signatures(self, chan):

        bitcoin_keys = [chan.config[LOCAL].multisig_key.pubkey,
                        chan.config[REMOTE].multisig_key.pubkey]

        node_ids = [privkey_to_pubkey(self.privkey),
                    self.pubkey]

        sorted_node_ids = list(sorted(node_ids))
        if sorted_node_ids != node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()

        chan_ann = gen_msg("channel_announcement",
            len=0,
            #features not set (defaults to zeros)
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=chan.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )
        to_hash = chan_ann[256+2:]
        h = bitcoin.Hash(to_hash)
        bitcoin_signature = ecc.ECPrivkey(chan.config[LOCAL].multisig_key.privkey).sign(h, sig_string_from_r_and_s, get_r_and_s_from_sig_string)
        node_signature = ecc.ECPrivkey(self.privkey).sign(h, sig_string_from_r_and_s, get_r_and_s_from_sig_string)
        self.send_message(gen_msg("announcement_signatures",
            channel_id=chan.channel_id,
            short_channel_id=chan.short_channel_id,
            node_signature=node_signature,
            bitcoin_signature=bitcoin_signature
        ))

        return h, node_signature, bitcoin_signature

    @log_exceptions
    async def on_update_fail_htlc(self, payload):
        channel_id = payload["channel_id"]
        htlc_id = int.from_bytes(payload["id"], "big")
        key = (channel_id, htlc_id)
        try:
            route = self.attempted_route[key]
        except KeyError:
            # the remote might try to fail an htlc after we restarted...
            # attempted_route is not persisted, so we will get here then
            self.print_error("UPDATE_FAIL_HTLC. cannot decode! attempted route is MISSING. {}".format(key))
        else:
            await self._handle_error_code_from_failed_htlc(payload["reason"], route, channel_id, htlc_id)
        # process update_fail_htlc on channel
        chan = self.channels[channel_id]
        chan.receive_fail_htlc(htlc_id)
        await self.receive_commitment(chan)
        self.revoke(chan)
        self.send_commitment(chan)  # htlc will be removed
        await self.receive_revoke(chan)
        self.lnworker.save_channel(chan)

    async def _handle_error_code_from_failed_htlc(self, error_reason, route, channel_id, htlc_id):
        chan = self.channels[channel_id]
        failure_msg, sender_idx = decode_onion_error(error_reason,
                                                     [x.node_id for x in route],
                                                     chan.onion_keys[htlc_id])
        code = OnionFailureCode(failure_msg.code)
        data = failure_msg.data
        self.print_error("UPDATE_FAIL_HTLC", repr(code), data)
        # handle some specific error codes
        failure_codes = {
            OnionFailureCode.TEMPORARY_CHANNEL_FAILURE: 2,
            OnionFailureCode.AMOUNT_BELOW_MINIMUM: 10,
            OnionFailureCode.FEE_INSUFFICIENT: 10,
            OnionFailureCode.INCORRECT_CLTV_EXPIRY: 6,
            OnionFailureCode.EXPIRY_TOO_SOON: 2,
            OnionFailureCode.CHANNEL_DISABLED: 4,
        }
        offset = failure_codes.get(code)
        if offset:
            channel_update = (258).to_bytes(length=2, byteorder="big") + data[offset:]
            message_type, payload = decode_msg(channel_update)
            self.on_channel_update(payload)
        else:
            # blacklist channel after reporter node
            # TODO this should depend on the error (even more granularity)
            # also, we need finer blacklisting (directed edges; nodes)
            try:
                short_chan_id = route[sender_idx + 1].short_channel_id
            except IndexError:
                self.print_error("payment destination reported error")
            else:
                self.network.path_finder.blacklist.add(short_chan_id)

    def send_commitment(self, chan):
        sig_64, htlc_sigs = chan.sign_next_commitment()
        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs)))
        return len(htlc_sigs)

    async def update_channel(self, chan, update):
        """ generic channel update flow """
        self.send_message(update)
        self.send_commitment(chan)
        await self.receive_revoke(chan)
        await self.receive_commitment(chan)
        self.revoke(chan)

    async def pay(self, route: List[RouteEdge], chan, amount_msat, payment_hash, min_final_cltv_expiry):
        assert chan.get_state() == "OPEN", chan.get_state()
        assert amount_msat > 0, "amount_msat is not greater zero"
        height = self.network.get_local_height()
        hops_data = []
        sum_of_deltas = sum(route_edge.cltv_expiry_delta for route_edge in route[1:])
        total_fee = 0
        final_cltv_expiry_without_deltas = (height + min_final_cltv_expiry)
        final_cltv_expiry_with_deltas = final_cltv_expiry_without_deltas + sum_of_deltas
        for idx, route_edge in enumerate(route[1:]):
            hops_data += [OnionHopsDataSingle(OnionPerHop(route_edge.short_channel_id, amount_msat.to_bytes(8, "big"), final_cltv_expiry_without_deltas.to_bytes(4, "big")))]
            total_fee += route_edge.fee_base_msat + ( amount_msat * route_edge.fee_proportional_millionths // 1000000 )
        associated_data = payment_hash
        secret_key = os.urandom(32)
        hops_data += [OnionHopsDataSingle(OnionPerHop(b"\x00"*8, amount_msat.to_bytes(8, "big"), (final_cltv_expiry_without_deltas).to_bytes(4, "big")))]
        onion = new_onion_packet([x.node_id for x in route], secret_key, hops_data, associated_data)
        amount_msat += total_fee
        # FIXME this below will probably break with multiple HTLCs
        msat_local = chan.balance(LOCAL) - amount_msat
        msat_remote = chan.balance(REMOTE) + amount_msat
        htlc = {'amount_msat':amount_msat, 'payment_hash':payment_hash, 'cltv_expiry':final_cltv_expiry_with_deltas}
        # FIXME if we raise here, this channel will not get blacklisted, and the payment can never succeed,
        # as we will just keep retrying this same path. using the current blacklisting is not a solution as
        # then no other payment can use this channel either.
        # we need finer blacklisting -- e.g. a blacklist for just this "payment session"?
        # or blacklist entries could store an msat value and also expire
        if len(chan.htlcs(LOCAL, only_pending=True)) + 1 > chan.config[REMOTE].max_accepted_htlcs:
            raise PaymentFailure('too many HTLCs already in channel')
        if htlcsum(chan.htlcs(LOCAL, only_pending=True)) + amount_msat > chan.config[REMOTE].max_htlc_value_in_flight_msat:
            raise PaymentFailure('HTLC value sum would exceed max allowed: {} msat'.format(chan.config[REMOTE].max_htlc_value_in_flight_msat))
        if msat_local < 0:
            # FIXME what about channel_reserve_satoshis? will the remote fail the channel if we go below? test.
            raise PaymentFailure('not enough local balance')
        htlc_id = chan.add_htlc(htlc)
        chan.onion_keys[htlc_id] = secret_key
        update = gen_msg("update_add_htlc", channel_id=chan.channel_id, id=htlc_id, cltv_expiry=final_cltv_expiry_with_deltas, amount_msat=amount_msat, payment_hash=payment_hash, onion_routing_packet=onion.to_bytes())
        self.attempted_route[(chan.channel_id, htlc_id)] = route
        await self.update_channel(chan, update)

    async def receive_revoke(self, m):
        revoke_and_ack_msg = await self.revoke_and_ack[m.channel_id].get()
        m.receive_revocation(RevokeAndAck(revoke_and_ack_msg["per_commitment_secret"], revoke_and_ack_msg["next_per_commitment_point"]))

    def revoke(self, m):
        rev, _ = m.revoke_current_commitment()
        self.lnworker.save_channel(m)
        self.send_message(gen_msg("revoke_and_ack",
            channel_id=m.channel_id,
            per_commitment_secret=rev.per_commitment_secret,
            next_per_commitment_point=rev.next_per_commitment_point))

    async def receive_commitment(self, m, commitment_signed_msg=None):
        if commitment_signed_msg is None:
            commitment_signed_msg = await self.commitment_signed[m.channel_id].get()
        data = commitment_signed_msg["htlc_signature"]
        htlc_sigs = [data[i:i+64] for i in range(0, len(data), 64)]
        m.receive_new_commitment(commitment_signed_msg["signature"], htlc_sigs)
        return len(htlc_sigs)

    @log_exceptions
    async def receive_commitment_revoke_ack(self, htlc, decoded, payment_preimage):
        chan = self.channels[htlc['channel_id']]
        channel_id = chan.channel_id
        expected_received_msat = int(decoded.amount * bitcoin.COIN * 1000)
        htlc_id = int.from_bytes(htlc["id"], 'big')
        assert htlc_id == chan.config[REMOTE].next_htlc_id, (htlc_id, chan.config[REMOTE].next_htlc_id)
        assert chan.get_state() == "OPEN"
        cltv_expiry = int.from_bytes(htlc["cltv_expiry"], 'big')
        # TODO verify sanity of their cltv expiry
        amount_msat = int.from_bytes(htlc["amount_msat"], 'big')
        assert amount_msat == expected_received_msat
        payment_hash = htlc["payment_hash"]
        htlc = {'amount_msat': amount_msat, 'payment_hash':payment_hash, 'cltv_expiry':cltv_expiry}
        chan.receive_htlc(htlc)
        assert (await self.receive_commitment(chan)) <= 1
        self.revoke(chan)
        self.send_commitment(chan)
        await self.receive_revoke(chan)
        chan.settle_htlc(payment_preimage, htlc_id)
        fulfillment = gen_msg("update_fulfill_htlc", channel_id=channel_id, id=htlc_id, payment_preimage=payment_preimage)
        await self.update_channel(chan, fulfillment)
        self.lnworker.save_channel(chan)

    def on_commitment_signed(self, payload):
        self.print_error("commitment_signed", payload)
        channel_id = payload['channel_id']
        chan = self.channels[channel_id]
        chan.config[LOCAL]=chan.config[LOCAL]._replace(
            current_commitment_signature=payload['signature'],
            current_htlc_signatures=payload['htlc_signature'])
        self.lnworker.save_channel(chan)
        self.commitment_signed[channel_id].put_nowait(payload)

    @log_exceptions
    async def on_update_fulfill_htlc(self, update_fulfill_htlc_msg):
        self.print_error("update_fulfill")
        chan = self.channels[update_fulfill_htlc_msg["channel_id"]]
        preimage = update_fulfill_htlc_msg["payment_preimage"]
        htlc_id = int.from_bytes(update_fulfill_htlc_msg["id"], "big")
        chan.receive_htlc_settle(preimage, htlc_id)
        await self.receive_commitment(chan)
        self.revoke(chan)
        self.send_commitment(chan) # htlc will be removed
        await self.receive_revoke(chan)
        self.lnworker.save_channel(chan)

        # used in lightning-integration
        self.payment_preimages[sha256(preimage)].put_nowait(preimage)

    def on_update_fail_malformed_htlc(self, payload):
        self.print_error("error", payload["data"].decode("ascii"))

    def on_update_add_htlc(self, payload):
        # no onion routing for the moment: we assume we are the end node
        self.print_error('on_update_add_htlc', payload)
        # check if this in our list of requests
        payment_hash = payload["payment_hash"]
        for k in self.invoices.keys():
            preimage = bfh(k)
            if sha256(preimage) == payment_hash:
                req = self.invoices[k]
                decoded = lndecode(req, expected_hrp=constants.net.SEGWIT_HRP)
                coro = self.receive_commitment_revoke_ack(payload, decoded, preimage)
                asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
                break
        else:
            assert False

    def on_revoke_and_ack(self, payload):
        print("got revoke_and_ack")
        channel_id = payload["channel_id"]
        self.revoke_and_ack[channel_id].put_nowait(payload)

    def on_update_fee(self, payload):
        channel_id = payload["channel_id"]
        self.channels[channel_id].receive_update_fee(int.from_bytes(payload["feerate_per_kw"], "big"))

    async def bitcoin_fee_update(self, chan):
        """
        called when our fee estimates change
        """
        if not chan.constraints.is_initiator:
            # TODO force close if initiator does not update_fee enough
            return
        feerate_per_kw = self.current_feerate_per_kw()
        chan_fee = chan.pending_feerate(REMOTE)
        self.print_error("current pending feerate", chan_fee)
        self.print_error("new feerate", feerate_per_kw)
        if feerate_per_kw < chan_fee / 2:
            self.print_error("FEES HAVE FALLEN")
        elif feerate_per_kw > chan_fee * 2:
            self.print_error("FEES HAVE RISEN")
        else:
            return
        chan.update_fee(feerate_per_kw)
        update = gen_msg("update_fee", channel_id=chan.channel_id, feerate_per_kw=feerate_per_kw)
        await self.update_channel(chan, update)

    def current_feerate_per_kw(self):
        if constants.net is constants.BitcoinRegtest:
            return 45000
        from .simple_config import FEE_LN_ETA_TARGET, FEERATE_FALLBACK_STATIC_FEE
        feerate_per_kvbyte = self.network.config.eta_target_to_fee(FEE_LN_ETA_TARGET)
        if feerate_per_kvbyte is None:
            feerate_per_kvbyte = FEERATE_FALLBACK_STATIC_FEE
        return max(253, feerate_per_kvbyte // 4)

    def on_closing_signed(self, payload):
        chan_id = payload["channel_id"]
        if chan_id not in self.closing_signed: raise Exception("Got unknown closing_signed")
        self.closing_signed[chan_id].put_nowait(payload)

    @log_exceptions
    async def on_shutdown(self, payload):
        # length of scripts allowed in BOLT-02
        if int.from_bytes(payload['len'], 'big') not in (3+20+2, 2+20+1, 2+20, 2+32):
            raise Exception('scriptpubkey length in received shutdown message invalid: ' + str(payload['len']))
        chan = self.channels[payload['channel_id']]
        scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        self.send_message(gen_msg('shutdown', channel_id=chan.channel_id, len=len(scriptpubkey), scriptpubkey=scriptpubkey))
        signature, fee = chan.make_closing_tx(scriptpubkey, payload['scriptpubkey'])
        self.send_message(gen_msg('closing_signed', channel_id=chan.channel_id, fee_satoshis=fee, signature=signature))
        while chan.get_state() != 'CLOSED':
            try:
                closing_signed = await asyncio.wait_for(self.closing_signed[chan.channel_id].get(), 1)
            except asyncio.TimeoutError:
                pass
            else:
                fee = int.from_bytes(closing_signed['fee_satoshis'], 'big')
                signature, _ = chan.make_closing_tx(scriptpubkey, payload['scriptpubkey'], fee_sat=fee)
                self.send_message(gen_msg('closing_signed', channel_id=chan.channel_id, fee_satoshis=fee, signature=signature))
        self.print_error('REMOTE PEER CLOSED CHANNEL')
