#!/usr/bin/env python3
"""
  Lightning network interface for Electrum
  Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8
"""

from ecdsa.util import sigdecode_der, sigencode_string_canonize, sigdecode_string
from ecdsa.curves import SECP256k1
import queue
import traceback
import json
from collections import OrderedDict, defaultdict
import asyncio
from concurrent.futures import FIRST_COMPLETED
import os
import time
import binascii
import hashlib
import hmac
from typing import Sequence, Union, Tuple
from collections import namedtuple, defaultdict
import cryptography.hazmat.primitives.ciphers.aead as AEAD
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703

from .ecc import ser_to_point, point_to_ser, string_to_number
from .bitcoin import (deserialize_privkey, rev_hex, int_to_hex,
                      push_script, script_num_to_hex,
                      add_number_to_script, var_int, COIN)
from . import bitcoin
from . import ecc
from . import crypto
from .crypto import sha256
from . import constants
from . import transaction
from .util import PrintError, bh2u, print_error, bfh, profiler, xor_bytes
from .transaction import opcodes, Transaction
from .lnrouter import new_onion_packet, OnionHopsDataSingle, OnionPerHop, decode_onion_error
from .lightning_payencode.lnaddr import lndecode
from .lnhtlc import UpdateAddHtlc, HTLCStateMachine, RevokeAndAck, SettleHtlc

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

def get_ecdh(priv: bytes, pub: bytes) -> bytes:
    pt = ecc.ECPubkey(pub) * string_to_number(priv)
    return sha256(pt.get_public_key_bytes())

def act1_initiator_message(hs, my_privkey):
    #Get a new ephemeral key
    epriv, epub = create_ephemeral_key(my_privkey)
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

def privkey_to_pubkey(priv):
    return ecc.ECPrivkey(priv[:32]).get_public_key_bytes()

def create_ephemeral_key(privkey):
    pub = privkey_to_pubkey(privkey)
    return (privkey[:32], pub)

Keypair = namedtuple("Keypair", ["pubkey", "privkey"])
Outpoint = namedtuple("Outpoint", ["txid", "output_index"])
ChannelConfig = namedtuple("ChannelConfig", [
    "payment_basepoint", "multisig_key", "htlc_basepoint", "delayed_basepoint", "revocation_basepoint",
    "to_self_delay", "dust_limit_sat", "max_htlc_value_in_flight_msat", "max_accepted_htlcs"])
OnlyPubkeyKeypair = namedtuple("OnlyPubkeyKeypair", ["pubkey"])
RemoteState = namedtuple("RemoteState", ["ctn", "next_per_commitment_point", "amount_msat", "revocation_store", "current_per_commitment_point", "next_htlc_id"])
LocalState = namedtuple("LocalState", ["ctn", "per_commitment_secret_seed", "amount_msat", "next_htlc_id", "funding_locked_received", "was_announced", "current_commitment_signature"])
ChannelConstraints = namedtuple("ChannelConstraints", ["feerate", "capacity", "is_initiator", "funding_txn_minimum_depth"])
OpenChannel = namedtuple("OpenChannel", ["channel_id", "short_channel_id", "funding_outpoint", "local_config", "remote_config", "remote_state", "local_state", "constraints", "node_id"])


def aiosafe(f):
    async def f2(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except:
            # if the loop isn't stopped
            # run_forever in network.py would not return,
            # the asyncioThread would not die,
            # and we would block on shutdown
            asyncio.get_event_loop().stop()
            traceback.print_exc()
    return f2

def get_obscured_ctn(ctn, local, remote):
    mask = int.from_bytes(sha256(local + remote)[-6:], 'big')
    return ctn ^ mask

def secret_to_pubkey(secret):
    assert type(secret) is int
    return point_to_ser(SECP256k1.generator * secret)

def derive_pubkey(basepoint, per_commitment_point):
    p = ecc.ECPubkey(basepoint) + ecc.generator() * ecc.string_to_number(sha256(per_commitment_point + basepoint))
    return p.get_public_key_bytes()

def derive_privkey(secret, per_commitment_point):
    assert type(secret) is int
    basepoint = point_to_ser(SECP256k1.generator * secret)
    basepoint = secret + ecc.string_to_number(sha256(per_commitment_point + basepoint))
    basepoint %= SECP256k1.order
    return basepoint

def derive_blinded_pubkey(basepoint, per_commitment_point):
    k1 = ecc.ECPubkey(basepoint) * ecc.string_to_number(sha256(basepoint + per_commitment_point))
    k2 = ecc.ECPubkey(per_commitment_point) * ecc.string_to_number(sha256(per_commitment_point + basepoint))
    return (k1 + k2).get_public_key_bytes()

def shachain_derive(element, toIndex):
    return ShachainElement(get_per_commitment_secret_from_seed(element.secret, toIndex, count_trailing_zeros(element.index)), toIndex)


def get_per_commitment_secret_from_seed(seed: bytes, i: int, bits: int = 48) -> bytes:
    """Generate per commitment secret."""
    per_commitment_secret = bytearray(seed)
    for bitindex in range(bits - 1, -1, -1):
        mask = 1 << bitindex
        if i & mask:
            per_commitment_secret[bitindex // 8] ^= 1 << (bitindex % 8)
            per_commitment_secret = bytearray(sha256(per_commitment_secret))
    bajts = bytes(per_commitment_secret)
    return bajts


def overall_weight(num_htlc):
    return 500 + 172 * num_htlc + 224

def make_htlc_tx_output(amount_msat, local_feerate, revocationpubkey, local_delayedpubkey, success, to_self_delay):
    assert type(amount_msat) is int
    assert type(local_feerate) is int
    assert type(revocationpubkey) is bytes
    assert type(local_delayedpubkey) is bytes
    script = bytes([opcodes.OP_IF]) \
        + bfh(push_script(bh2u(revocationpubkey))) \
        + bytes([opcodes.OP_ELSE]) \
        + bitcoin.add_number_to_script(to_self_delay) \
        + bytes([opcodes.OP_CSV, opcodes.OP_DROP]) \
        + bfh(push_script(bh2u(local_delayedpubkey))) \
        + bytes([opcodes.OP_ENDIF, opcodes.OP_CHECKSIG])

    p2wsh = bitcoin.redeem_script_to_address('p2wsh', bh2u(script))
    weight = HTLC_SUCCESS_WEIGHT if success else HTLC_TIMEOUT_WEIGHT
    fee = local_feerate * weight
    final_amount_sat = (amount_msat - fee) // 1000
    assert final_amount_sat > 0, final_amount_sat
    output = (bitcoin.TYPE_ADDRESS, p2wsh, final_amount_sat)
    return output

def make_htlc_tx_witness(remotehtlcsig, localhtlcsig, payment_preimage, witness_script):
    assert type(remotehtlcsig) is bytes
    assert type(localhtlcsig) is bytes
    assert type(payment_preimage) is bytes
    assert type(witness_script) is bytes
    return bfh(transaction.construct_witness([0, remotehtlcsig, localhtlcsig, payment_preimage, witness_script]))

def make_htlc_tx_inputs(htlc_output_txid, htlc_output_index, revocationpubkey, local_delayedpubkey, amount_msat, witness_script):
    assert type(htlc_output_txid) is str
    assert type(htlc_output_index) is int
    assert type(revocationpubkey) is bytes
    assert type(local_delayedpubkey) is bytes
    assert type(amount_msat) is int
    assert type(witness_script) is str
    c_inputs = [{
        'scriptSig': '',
        'type': 'p2wsh',
        'signatures': [],
        'num_sig': 0,
        'prevout_n': htlc_output_index,
        'prevout_hash': htlc_output_txid,
        'value': amount_msat // 1000,
        'coinbase': False,
        'sequence': 0x0,
        'preimage_script': witness_script,
    }]
    return c_inputs

def make_htlc_tx(cltv_timeout, inputs, output):
    assert type(cltv_timeout) is int
    c_outputs = [output]
    tx = Transaction.from_io(inputs, c_outputs, locktime=cltv_timeout, version=2)
    tx.BIP_LI01_sort()
    return tx

def make_offered_htlc(revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, payment_hash):
    assert type(revocation_pubkey) is bytes
    assert type(remote_htlcpubkey) is bytes
    assert type(local_htlcpubkey) is bytes
    assert type(payment_hash) is bytes
    return bytes([opcodes.OP_DUP, opcodes.OP_HASH160]) + bfh(push_script(bh2u(bitcoin.hash_160(revocation_pubkey))))\
        + bytes([opcodes.OP_EQUAL, opcodes.OP_IF, opcodes.OP_CHECKSIG, opcodes.OP_ELSE]) \
        + bfh(push_script(bh2u(remote_htlcpubkey)))\
        + bytes([opcodes.OP_SWAP, opcodes.OP_SIZE]) + bitcoin.add_number_to_script(32) + bytes([opcodes.OP_EQUAL, opcodes.OP_NOTIF, opcodes.OP_DROP])\
        + bitcoin.add_number_to_script(2) + bytes([opcodes.OP_SWAP]) + bfh(push_script(bh2u(local_htlcpubkey))) + bitcoin.add_number_to_script(2)\
        + bytes([opcodes.OP_CHECKMULTISIG, opcodes.OP_ELSE, opcodes.OP_HASH160])\
        + bfh(push_script(bh2u(crypto.ripemd(payment_hash)))) + bytes([opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG, opcodes.OP_ENDIF, opcodes.OP_ENDIF])

def make_received_htlc(revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, payment_hash, cltv_expiry):
    for i in [revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, payment_hash]:
        assert type(i) is bytes
    assert type(cltv_expiry) is int

    return bytes([opcodes.OP_DUP, opcodes.OP_HASH160]) \
        + bfh(push_script(bh2u(bitcoin.hash_160(revocation_pubkey)))) \
        + bytes([opcodes.OP_EQUAL, opcodes.OP_IF, opcodes.OP_CHECKSIG, opcodes.OP_ELSE]) \
        + bfh(push_script(bh2u(remote_htlcpubkey))) \
        + bytes([opcodes.OP_SWAP, opcodes.OP_SIZE]) \
        + bitcoin.add_number_to_script(32) \
        + bytes([opcodes.OP_EQUAL, opcodes.OP_IF, opcodes.OP_HASH160]) \
        + bfh(push_script(bh2u(crypto.ripemd(payment_hash)))) \
        + bytes([opcodes.OP_EQUALVERIFY]) \
        + bitcoin.add_number_to_script(2) \
        + bytes([opcodes.OP_SWAP]) \
        + bfh(push_script(bh2u(local_htlcpubkey))) \
        + bitcoin.add_number_to_script(2) \
        + bytes([opcodes.OP_CHECKMULTISIG, opcodes.OP_ELSE, opcodes.OP_DROP]) \
        + bitcoin.add_number_to_script(cltv_expiry) \
        + bytes([opcodes.OP_CLTV, opcodes.OP_DROP, opcodes.OP_CHECKSIG, opcodes.OP_ENDIF, opcodes.OP_ENDIF])

def make_htlc_tx_with_open_channel(chan, pcp, for_us, we_receive, amount_msat, cltv_expiry, payment_hash, commit, original_htlc_output_index):
    conf = chan.local_config if for_us else chan.remote_config
    other_conf = chan.local_config if not for_us else chan.remote_config

    revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    delayedpubkey = derive_pubkey(conf.delayed_basepoint.pubkey, pcp)
    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    other_htlc_pubkey = derive_pubkey(other_conf.htlc_basepoint.pubkey, pcp)
    htlc_pubkey = derive_pubkey(conf.htlc_basepoint.pubkey, pcp)
    # HTLC-success for the HTLC spending from a received HTLC output
    # if we do not receive, and the commitment tx is not for us, they receive, so it is also an HTLC-success
    is_htlc_success = for_us == we_receive
    htlc_tx_output = make_htlc_tx_output(
        amount_msat = amount_msat,
        local_feerate = chan.constraints.feerate,
        revocationpubkey=revocation_pubkey,
        local_delayedpubkey=delayedpubkey,
        success = is_htlc_success,
        to_self_delay = other_conf.to_self_delay)
    if is_htlc_success:
        preimage_script = make_received_htlc(other_revocation_pubkey, other_htlc_pubkey, htlc_pubkey, payment_hash, cltv_expiry)
    else:
        preimage_script = make_offered_htlc(other_revocation_pubkey, other_htlc_pubkey, htlc_pubkey, payment_hash)
    htlc_tx_inputs = make_htlc_tx_inputs(
        commit.txid(), commit.htlc_output_indices[original_htlc_output_index],
        revocationpubkey=revocation_pubkey,
        local_delayedpubkey=delayedpubkey,
        amount_msat=amount_msat,
        witness_script=bh2u(preimage_script))
    if is_htlc_success:
        cltv_expiry = 0
    htlc_tx = make_htlc_tx(cltv_expiry, inputs=htlc_tx_inputs, output=htlc_tx_output)
    return htlc_tx

def make_commitment_using_open_channel(chan, ctn, for_us, pcp, local_msat, remote_msat, htlcs=[], trimmed=0):
    conf = chan.local_config if for_us else chan.remote_config
    other_conf = chan.local_config if not for_us else chan.remote_config
    payment_pubkey = derive_pubkey(other_conf.payment_basepoint.pubkey, pcp)
    remote_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    return make_commitment(
        ctn,
        conf.multisig_key.pubkey,
        other_conf.multisig_key.pubkey,
        payment_pubkey,
        chan.local_config.payment_basepoint.pubkey,
        chan.remote_config.payment_basepoint.pubkey,
        remote_revocation_pubkey,
        derive_pubkey(conf.delayed_basepoint.pubkey, pcp),
        other_conf.to_self_delay,
        *chan.funding_outpoint,
        chan.constraints.capacity,
        local_msat,
        remote_msat,
        chan.local_config.dust_limit_sat,
        chan.constraints.feerate,
        for_us,
        chan.constraints.is_initiator,
        htlcs=htlcs,
        trimmed=trimmed)

def make_commitment(ctn, local_funding_pubkey, remote_funding_pubkey,
                    remote_payment_pubkey, payment_basepoint,
                    remote_payment_basepoint, revocation_pubkey,
                    delayed_pubkey, to_self_delay, funding_txid,
                    funding_pos, funding_sat, local_amount, remote_amount,
                    dust_limit_sat, local_feerate, for_us, we_are_initiator,
                    htlcs, trimmed=0):

    pubkeys = sorted([bh2u(local_funding_pubkey), bh2u(remote_funding_pubkey)])
    payments = [payment_basepoint, remote_payment_basepoint]
    if not we_are_initiator:
        payments.reverse()
    obs = get_obscured_ctn(ctn, *payments)
    locktime = (0x20 << 24) + (obs & 0xffffff)
    sequence = (0x80 << 24) + (obs >> 24)
    print_error('locktime', locktime, hex(locktime))
    # commitment tx input
    c_inputs = [{
        'type': 'p2wsh',
        'x_pubkeys': pubkeys,
        'signatures': [None, None],
        'num_sig': 2,
        'prevout_n': funding_pos,
        'prevout_hash': funding_txid,
        'value': funding_sat,
        'coinbase': False,
        'sequence': sequence
    }]
    # commitment tx outputs
    local_script = bytes([opcodes.OP_IF]) + bfh(push_script(bh2u(revocation_pubkey))) + bytes([opcodes.OP_ELSE]) + add_number_to_script(to_self_delay) \
                   + bytes([opcodes.OP_CSV, opcodes.OP_DROP]) + bfh(push_script(bh2u(delayed_pubkey))) + bytes([opcodes.OP_ENDIF, opcodes.OP_CHECKSIG])
    local_address = bitcoin.redeem_script_to_address('p2wsh', bh2u(local_script))
    remote_address = bitcoin.pubkey_to_address('p2wpkh', bh2u(remote_payment_pubkey))
    # TODO trim htlc outputs here while also considering 2nd stage htlc transactions
    fee = local_feerate * overall_weight(len(htlcs))
    fee -= trimmed * 1000
    assert type(fee) is int
    we_pay_fee = for_us == we_are_initiator
    to_local_amt = local_amount - (fee if we_pay_fee else 0)
    assert type(to_local_amt) is int
    to_local = (bitcoin.TYPE_ADDRESS, local_address, to_local_amt // 1000)
    to_remote_amt = remote_amount - (fee if not we_pay_fee else 0)
    assert type(to_remote_amt) is int
    to_remote = (bitcoin.TYPE_ADDRESS, remote_address, to_remote_amt // 1000)
    c_outputs = [to_local, to_remote]
    for script, msat_amount in htlcs:
        c_outputs += [(bitcoin.TYPE_ADDRESS, bitcoin.redeem_script_to_address('p2wsh', bh2u(script)), msat_amount // 1000)]

    # trim outputs
    c_outputs_filtered = list(filter(lambda x:x[2]>= dust_limit_sat, c_outputs))
    assert sum(x[2] for x in c_outputs) <= funding_sat

    # create commitment tx
    tx = Transaction.from_io(c_inputs, c_outputs_filtered, locktime=locktime, version=2)
    tx.BIP_LI01_sort()

    tx.htlc_output_indices = {}
    for idx, output in enumerate(c_outputs):
        if output in tx.outputs():
            # minus the first two outputs (to_local, to_remote)
            tx.htlc_output_indices[idx - 2] = tx.outputs().index(output)

    return tx


def calc_short_channel_id(block_height: int, tx_pos_in_block: int, output_index: int) -> bytes:
    bh = block_height.to_bytes(3, byteorder='big')
    tpos = tx_pos_in_block.to_bytes(3, byteorder='big')
    oi = output_index.to_bytes(2, byteorder='big')
    return bh + tpos + oi


def sign_and_get_sig_string(tx, local_config, remote_config):
    pubkeys = sorted([bh2u(local_config.multisig_key.pubkey), bh2u(remote_config.multisig_key.pubkey)])
    tx.sign({bh2u(local_config.multisig_key.pubkey): (local_config.multisig_key.privkey, True)})
    sig_index = pubkeys.index(bh2u(local_config.multisig_key.pubkey))
    sig = bytes.fromhex(tx.inputs()[0]["signatures"][sig_index])
    r, s = sigdecode_der(sig[:-1], SECP256k1.generator.order())
    sig_64 = sigencode_string_canonize(r, s, SECP256k1.generator.order())
    return sig_64

def is_synced(network):
    local_height, server_height = network.get_status_value("updated")
    synced = server_height != 0 and network.is_up_to_date() and local_height >= server_height
    return synced

def funding_output_script(local_config, remote_config):
    pubkeys = sorted([bh2u(local_config.multisig_key.pubkey), bh2u(remote_config.multisig_key.pubkey)])
    return transaction.multisig_script(pubkeys, 2)

class Peer(PrintError):

    def __init__(self, lnworker, host, port, pubkey, request_initial_sync=False):
        self.channel_update_event = asyncio.Event()
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self.lnworker = lnworker
        self.privkey = lnworker.privkey
        self.network = lnworker.network
        self.channel_db = lnworker.network.channel_db
        self.channel_state = lnworker.channel_state
        self.read_buffer = b''
        self.ping_time = 0
        self.initialized = asyncio.Future()
        self.channel_accepted = defaultdict(asyncio.Queue)
        self.channel_reestablished = defaultdict(asyncio.Future)
        self.funding_signed = defaultdict(asyncio.Queue)
        self.revoke_and_ack = defaultdict(asyncio.Queue)
        self.update_fulfill_htlc = defaultdict(asyncio.Queue)
        self.commitment_signed = defaultdict(asyncio.Queue)
        self.announcement_signatures = defaultdict(asyncio.Queue)
        self.update_fail_htlc = defaultdict(asyncio.Queue)
        self.localfeatures = (0x08 if request_initial_sync else 0)
        self.channels = lnworker.channels
        self.invoices = lnworker.invoices
        self.attempted_route = {}

    def diagnostic_name(self):
        return self.host

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
            s = await self.reader.read(2**10)
            if not s:
                raise LightningPeerConnectionClosed()
            self.read_buffer += s

    async def handshake(self):
        hs = HandshakeState(self.pubkey)
        msg = act1_initiator_message(hs, self.privkey)
        # act 1
        self.writer.write(msg)
        rspns = await self.reader.read(2**10)
        assert len(rspns) == 50, "Lightning handshake act 1 response has bad length, are you sure this is the right pubkey? " + str(bh2u(self.pubkey))
        hver, alice_epub, tag = rspns[0], rspns[1:34], rspns[34:]
        assert bytes([hver]) == hs.handshake_version
        # act 2
        hs.update(alice_epub)
        myepriv, myepub = create_ephemeral_key(self.privkey)
        ss = get_ecdh(myepriv, alice_epub)
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
        #self.print_error("Received '%s'" % message_type.upper())
        try:
            f = getattr(self, 'on_' + message_type)
        except AttributeError:
            self.print_error("Received '%s'" % message_type.upper(), payload)
            return
        # raw message is needed to check signature
        if message_type=='node_announcement':
            payload['raw'] = message
        f(payload)

    def on_error(self, payload):
        self.print_error("error", payload)

    def on_ping(self, payload):
        l = int.from_bytes(payload['num_pong_bytes'], 'big')
        self.send_message(gen_msg('pong', byteslen=l))

    def on_accept_channel(self, payload):
        temp_chan_id = payload["temporary_channel_id"]
        if temp_chan_id not in self.channel_accepted: raise Exception("Got unknown accept_channel")
        self.channel_accepted[temp_chan_id].put_nowait(payload)

    def on_funding_signed(self, payload):
        channel_id = payload['channel_id']
        if channel_id not in self.funding_signed: raise Exception("Got unknown funding_signed")
        self.funding_signed[channel_id].put_nowait(payload)

    def on_node_announcement(self, payload):
        pubkey = payload['node_id']
        signature = payload['signature']
        h = bitcoin.Hash(payload['raw'][66:])
        if not ecc.verify_signature(pubkey, signature, h):
            return False
        self.s = payload['addresses']
        def read(n):
            data, self.s = self.s[0:n], self.s[n:]
            return data
        addresses = []
        while self.s:
            atype = ord(read(1))
            if atype == 0:
                pass
            elif atype == 1:
                ipv4_addr = '.'.join(map(lambda x: '%d' % x, read(4)))
                port = int.from_bytes(read(2), 'big')
                x = ipv4_addr, port, binascii.hexlify(pubkey)
                addresses.append((ipv4_addr, port))
            elif atype == 2:
                ipv6_addr = b':'.join([binascii.hexlify(read(2)) for i in range(4)])
                port = int.from_bytes(read(2), 'big')
                addresses.append((ipv6_addr, port))
            else:
                pass
            continue
        alias = payload['alias'].rstrip(b'\x00')
        self.network.lightning_nodes[pubkey] = {
            'alias': alias,
            'addresses': addresses
        }
        self.print_error('node announcement', binascii.hexlify(pubkey), alias, addresses)

    def on_init(self, payload):
        pass

    def on_channel_update(self, payload):
        self.channel_db.on_channel_update(payload)
        self.channel_update_event.set()

    def on_channel_announcement(self, payload):
        self.channel_db.on_channel_announcement(payload)
        self.channel_update_event.set()

    def on_announcement_signatures(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels[payload['channel_id']]
        if chan.local_state.was_announced:
            h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        else:
            self.announcement_signatures[channel_id].put_nowait(payload)

    @aiosafe
    async def main_loop(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self.handshake()
        # send init
        self.send_message(gen_msg("init", gflen=0, lflen=1, localfeatures=self.localfeatures))
        # read init
        msg = await self.read_message()
        self.process_message(msg)
        self.initialized.set_result(True)
        # loop
        while True:
            self.ping_if_required()
            msg = await self.read_message()
            self.process_message(msg)
        # close socket
        self.print_error('closing lnbase')
        self.writer.close()

    @aiosafe
    async def channel_establishment_flow(self, wallet, config, password, funding_sat, push_msat, temp_channel_id):
        await self.initialized
        # see lnd/keychain/derivation.go
        keyfamilymultisig = 0
        keyfamilyrevocationbase = 1
        keyfamilyhtlcbase = 2
        keyfamilypaymentbase = 3
        keyfamilydelaybase = 4
        keyfamilyrevocationroot = 5
        keyfamilynodekey = 6 # TODO currently unused
        # amounts
        local_feerate = 20000
        # key derivation
        keypair_generator = lambda family, i: Keypair(*wallet.keystore.get_keypair([family, i], password))
        local_config=ChannelConfig(
            payment_basepoint=keypair_generator(keyfamilypaymentbase, 0),
            multisig_key=keypair_generator(keyfamilymultisig, 0),
            htlc_basepoint=keypair_generator(keyfamilyhtlcbase, 0),
            delayed_basepoint=keypair_generator(keyfamilydelaybase, 0),
            revocation_basepoint=keypair_generator(keyfamilyrevocationbase, 0),
            to_self_delay=143,
            dust_limit_sat=10,
            max_htlc_value_in_flight_msat=0xffffffffffffffff,
            max_accepted_htlcs=5
        )
        # TODO derive this?
        per_commitment_secret_seed = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100.to_bytes(32, 'big')
        per_commitment_secret_index = 2**48 - 1
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(per_commitment_secret_seed, per_commitment_secret_index)
        per_commitment_point_first = secret_to_pubkey(int.from_bytes(per_commitment_secret_first, 'big'))
        msg = gen_msg(
            "open_channel",
            temporary_channel_id=temp_channel_id,
            chain_hash=bytes.fromhex(rev_hex(constants.net.GENESIS)),
            funding_satoshis=funding_sat,
            push_msat=push_msat,
            dust_limit_satoshis=local_config.dust_limit_sat,
            feerate_per_kw=local_feerate,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
            to_self_delay=local_config.to_self_delay,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_flags=0x01, # publicly announcing channel
            channel_reserve_satoshis=10
        )
        self.send_message(msg)
        payload = await self.channel_accepted[temp_channel_id].get()
        remote_per_commitment_point = payload['first_per_commitment_point']
        remote_config=ChannelConfig(
            payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
            multisig_key=OnlyPubkeyKeypair(payload["funding_pubkey"]),
            htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
            delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
            revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
            to_self_delay=int.from_bytes(payload['to_self_delay'], byteorder='big'),
            dust_limit_sat=int.from_bytes(payload['dust_limit_satoshis'], byteorder='big'),
            max_htlc_value_in_flight_msat=int.from_bytes(payload['max_htlc_value_in_flight_msat'], 'big'),
            max_accepted_htlcs=int.from_bytes(payload["max_accepted_htlcs"], 'big')
        )
        funding_txn_minimum_depth = int.from_bytes(payload['minimum_depth'], 'big')
        print('remote dust limit', remote_config.dust_limit_sat)
        assert remote_config.dust_limit_sat < 600
        assert int.from_bytes(payload['htlc_minimum_msat'], 'big') < 600 * 1000
        assert remote_config.max_htlc_value_in_flight_msat >= 198 * 1000 * 1000, remote_config.max_htlc_value_in_flight_msat
        self.print_error('remote delay', remote_config.to_self_delay)
        self.print_error('funding_txn_minimum_depth', funding_txn_minimum_depth)
        # create funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        print("REDEEM SCRIPT", redeem_script)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = (bitcoin.TYPE_ADDRESS, funding_address, funding_sat)
        funding_tx = wallet.mktx([funding_output], password, config, 1000)
        funding_txid = funding_tx.txid()
        funding_index = funding_tx.outputs().index(funding_output)
        # compute amounts
        local_amount = funding_sat*1000 - push_msat
        remote_amount = push_msat
        # remote commitment transaction
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_index)
        their_revocation_store = RevocationStore()
        chan = OpenChannel(
                node_id=self.pubkey,
                channel_id=channel_id,
                short_channel_id=None,
                funding_outpoint=Outpoint(funding_txid, funding_index),
                local_config=local_config,
                remote_config=remote_config,
                remote_state=RemoteState(
                    ctn = -1,
                    next_per_commitment_point=remote_per_commitment_point,
                    current_per_commitment_point=None,
                    amount_msat=remote_amount,
                    revocation_store=their_revocation_store,
                    next_htlc_id = 0
                ),
                local_state=LocalState(
                    ctn = -1,
                    per_commitment_secret_seed=per_commitment_secret_seed,
                    amount_msat=local_amount,
                    next_htlc_id = 0,
                    funding_locked_received = False,
                    was_announced = False,
                    current_commitment_signature = None
                ),
                constraints=ChannelConstraints(capacity=funding_sat, feerate=local_feerate, is_initiator=True, funding_txn_minimum_depth=funding_txn_minimum_depth)
        )
        m = HTLCStateMachine(chan)
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
        success, _txid = self.network.broadcast_transaction(funding_tx)
        assert success, success
        m.state = chan._replace(remote_state=chan.remote_state._replace(ctn=0),local_state=chan.local_state._replace(ctn=0, current_commitment_signature=remote_sig))
        return m

    @aiosafe
    async def reestablish_channel(self, chan):
        await self.initialized
        chan_id = chan.channel_id
        self.channel_state[chan_id] = 'REESTABLISHING'
        self.network.trigger_callback('channel', chan)
        self.send_message(gen_msg("channel_reestablish",
            channel_id=chan_id,
            next_local_commitment_number=chan.local_state.ctn+1,
            next_remote_revocation_number=chan.remote_state.ctn
        ))
        await self.channel_reestablished[chan_id]
        self.channel_state[chan_id] = 'OPENING'
        if chan.local_state.funding_locked_received and chan.state.short_channel_id:
            self.mark_open(chan)
        self.network.trigger_callback('channel', chan)

    def on_channel_reestablish(self, payload):
        chan_id = payload["channel_id"]
        self.print_error("Received channel_reestablish", bh2u(chan_id))
        chan = self.channels.get(chan_id)
        if not chan:
            print("Warning: received unknown channel_reestablish", bh2u(chan_id))
            return
        channel_reestablish_msg = payload
        remote_ctn = int.from_bytes(channel_reestablish_msg["next_local_commitment_number"], 'big')
        if remote_ctn != chan.remote_state.ctn + 1:
            raise Exception("expected remote ctn {}, got {}".format(chan.remote_state.ctn + 1, remote_ctn))
        local_ctn = int.from_bytes(channel_reestablish_msg["next_remote_revocation_number"], 'big')
        if local_ctn != chan.local_state.ctn:
            raise Exception("expected local ctn {}, got {}".format(chan.local_state.ctn, local_ctn))
        their = channel_reestablish_msg["my_current_per_commitment_point"]
        our = chan.remote_state.current_per_commitment_point
        if our is None:
            our = chan.remote_state.next_per_commitment_point
        if our != their:
            raise Exception("Remote PCP mismatch: {} {}".format(bh2u(our), bh2u(their)))
        self.channel_reestablished[chan_id].set_result(True)

    def funding_locked(self, chan):
        channel_id = chan.channel_id
        per_commitment_secret_index = 2**48 - 2
        per_commitment_point_second = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        self.send_message(gen_msg("funding_locked", channel_id=channel_id, next_per_commitment_point=per_commitment_point_second))
        if chan.local_state.funding_locked_received:
            self.mark_open(chan)

    def on_funding_locked(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels.get(channel_id)
        if not chan:
            raise Exception("Got unknown funding_locked", channel_id)
        if not chan.local_state.funding_locked_received:
            our_next_point = chan.remote_state.next_per_commitment_point
            their_next_point = payload["next_per_commitment_point"]
            new_remote_state = chan.remote_state._replace(next_per_commitment_point=their_next_point, current_per_commitment_point=our_next_point)
            new_local_state = chan.local_state._replace(funding_locked_received = True)
            chan.state = chan.state._replace(remote_state=new_remote_state, local_state=new_local_state)
            self.lnworker.save_channel(chan)
        if chan.state.short_channel_id:
            self.mark_open(chan)

    def on_network_update(self, chan, funding_tx_depth):
        """
        Only called when the channel is OPEN.

        Runs on the Network thread.
        """
        if not chan.local_state.was_announced and funding_tx_depth >= 6:
            chan.state = chan.state._replace(local_state=chan.local_state._replace(was_announced=True))
            coro = self.handle_announcements(chan)
            self.lnworker.save_channel(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    @aiosafe
    async def handle_announcements(self, chan):
        h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        announcement_signatures_msg = await self.announcement_signatures[chan.channel_id].get()
        remote_node_sig = announcement_signatures_msg["node_signature"]
        remote_bitcoin_sig = announcement_signatures_msg["bitcoin_signature"]
        if not ecc.verify_signature(chan.remote_config.multisig_key.pubkey, remote_bitcoin_sig, h):
            raise Exception("bitcoin_sig invalid in announcement_signatures")
        if not ecc.verify_signature(self.pubkey, remote_node_sig, h):
            raise Exception("node_sig invalid in announcement_signatures")

        node_sigs = [local_node_sig, remote_node_sig]
        bitcoin_sigs = [local_bitcoin_sig, remote_bitcoin_sig]
        node_ids = [privkey_to_pubkey(self.privkey), self.pubkey]
        bitcoin_keys = [chan.local_config.multisig_key.pubkey, chan.remote_config.multisig_key.pubkey]

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
            chain_hash=bytes.fromhex(rev_hex(constants.net.GENESIS)),
            short_channel_id=chan.state.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )

        self.send_message(channel_announcement)

        print("SENT CHANNEL ANNOUNCEMENT")

    def mark_open(self, chan):
        if self.channel_state[chan.channel_id] == "OPEN":
            return
        assert chan.local_state.funding_locked_received
        self.channel_state[chan.channel_id] = "OPEN"
        self.network.trigger_callback('channel', chan.state)
        # add channel to database
        sorted_keys = list(sorted([self.pubkey, self.lnworker.pubkey]))
        self.channel_db.on_channel_announcement({"short_channel_id": chan.state.short_channel_id, "node_id_1": sorted_keys[0], "node_id_2": sorted_keys[1]})
        self.channel_db.on_channel_update({"short_channel_id": chan.state.short_channel_id, 'flags': b'\x01', 'cltv_expiry_delta': b'\x90', 'htlc_minimum_msat': b'\x03\xe8', 'fee_base_msat': b'\x03\xe8', 'fee_proportional_millionths': b'\x01'})
        self.channel_db.on_channel_update({"short_channel_id": chan.state.short_channel_id, 'flags': b'\x00', 'cltv_expiry_delta': b'\x90', 'htlc_minimum_msat': b'\x03\xe8', 'fee_base_msat': b'\x03\xe8', 'fee_proportional_millionths': b'\x01'})

        self.print_error("CHANNEL OPENING COMPLETED")

    def send_announcement_signatures(self, chan):

        bitcoin_keys = [chan.local_config.multisig_key.pubkey,
                        chan.remote_config.multisig_key.pubkey]

        node_ids = [privkey_to_pubkey(self.privkey),
                    self.pubkey]

        sorted_node_ids = list(sorted(node_ids))
        if sorted_node_ids != node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()

        chan_ann = gen_msg("channel_announcement",
            len=0,
            #features not set (defaults to zeros)
            chain_hash=bytes.fromhex(rev_hex(constants.net.GENESIS)),
            short_channel_id=chan.state.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )
        to_hash = chan_ann[256+2:]
        h = bitcoin.Hash(to_hash)
        bitcoin_signature = ecc.ECPrivkey(chan.local_config.multisig_key.privkey).sign(h, sigencode_string_canonize, sigdecode_string)
        node_signature = ecc.ECPrivkey(self.privkey).sign(h, sigencode_string_canonize, sigdecode_string)
        self.send_message(gen_msg("announcement_signatures",
            channel_id=chan.channel_id,
            short_channel_id=chan.state.short_channel_id,
            node_signature=node_signature,
            bitcoin_signature=bitcoin_signature
        ))

        return h, node_signature, bitcoin_signature

    def on_update_fail_htlc(self, payload):
        channel_id = payload["channel_id"]
        htlc_id = int.from_bytes(payload["id"], "big")
        key = (channel_id, htlc_id)
        route = self.attempted_route[key]
        failure_msg, sender_idx = decode_onion_error(payload["reason"], [x.node_id for x in route], self.secret_key)
        code = failure_msg.code
        data = failure_msg.data
        codes = []
        if code & 0x8000:
            codes += ["BADONION"]
        if code & 0x4000:
            codes += ["PERM"]
        if code & 0x2000:
            codes += ["NODE"]
        if code & 0x1000:
            codes += ["UPDATE"]
        print("UPDATE_FAIL_HTLC", codes, code, data)
        try:
            short_chan_id = route[sender_idx + 1].short_channel_id
        except IndexError:
            print("payment destination reported error")

        self.network.path_finder.blacklist.add(short_chan_id)
        self.update_fail_htlc[payload["channel_id"]].put_nowait("HTLC failure with code {} (categories {})".format(code, codes))

    @aiosafe
    async def pay(self, path, chan, amount_msat, payment_hash, pubkey_in_invoice, min_final_cltv_expiry):
        assert self.channel_state[chan.channel_id] == "OPEN"
        assert amount_msat > 0, "amount_msat is not greater zero"
        height = self.network.get_local_height()
        route = self.network.path_finder.create_route_from_path(path, self.lnworker.pubkey)
        hops_data = []
        sum_of_deltas = sum(route_edge.channel_policy.cltv_expiry_delta for route_edge in route[1:])
        total_fee = 0
        final_cltv_expiry_without_deltas = (height + min_final_cltv_expiry)
        final_cltv_expiry_with_deltas = final_cltv_expiry_without_deltas + sum_of_deltas
        for idx, route_edge in enumerate(route[1:]):
            hops_data += [OnionHopsDataSingle(OnionPerHop(route_edge.short_channel_id, amount_msat.to_bytes(8, "big"), final_cltv_expiry_without_deltas.to_bytes(4, "big")))]
            total_fee += route_edge.channel_policy.fee_base_msat + ( amount_msat * route_edge.channel_policy.fee_proportional_millionths // 1000000 )
        associated_data = payment_hash
        self.secret_key = os.urandom(32)
        hops_data += [OnionHopsDataSingle(OnionPerHop(b"\x00"*8, amount_msat.to_bytes(8, "big"), (final_cltv_expiry_without_deltas).to_bytes(4, "big")))]
        onion = new_onion_packet([x.node_id for x in route], self.secret_key, hops_data, associated_data)
        msat_local = chan.local_state.amount_msat - (amount_msat + total_fee)
        msat_remote = chan.remote_state.amount_msat + (amount_msat + total_fee)
        htlc = UpdateAddHtlc(amount_msat, payment_hash, final_cltv_expiry_with_deltas, total_fee)
        amount_msat += total_fee

        self.send_message(gen_msg("update_add_htlc", channel_id=chan.channel_id, id=chan.local_state.next_htlc_id, cltv_expiry=final_cltv_expiry_with_deltas, amount_msat=amount_msat, payment_hash=payment_hash, onion_routing_packet=onion.to_bytes()))

        chan.add_htlc(htlc)
        self.attempted_route[(chan.channel_id, htlc.htlc_id)] = route

        sig_64, htlc_sigs = chan.sign_next_commitment()
        htlc_sig = htlc_sigs[0]

        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=1, htlc_signature=htlc_sig))

        await self.receive_revoke(chan)

        self.revoke(chan)

        fulfill_coro = asyncio.ensure_future(self.update_fulfill_htlc[chan.channel_id].get())
        failure_coro = asyncio.ensure_future(self.update_fail_htlc[chan.channel_id].get())

        done, pending = await asyncio.wait([fulfill_coro, failure_coro], return_when=FIRST_COMPLETED)
        if failure_coro.done():
            sig_64, htlc_sigs = chan.sign_next_commitment()
            self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=1, htlc_signature=htlc_sigs[0]))
            while (await self.commitment_signed[chan.channel_id].get())["htlc_signature"] != b"":
                self.revoke(chan)
            await self.receive_revoke(chan)
            chan.fail_htlc(htlc)
            sig_64, htlc_sigs = chan.sign_next_commitment()
            self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=0))
            await self.receive_revoke(chan)
            fulfill_coro.cancel()
            self.lnworker.save_channel(chan)
            return failure_coro.result()
        if fulfill_coro.done():
            failure_coro.cancel()
            update_fulfill_htlc_msg = fulfill_coro.result()

        chan.receive_htlc_settle(update_fulfill_htlc_msg["payment_preimage"], int.from_bytes(update_fulfill_htlc_msg["id"], "big"))

        while (await self.commitment_signed[chan.channel_id].get())["htlc_signature"] != b"":
            self.revoke(chan)
        # TODO process above commitment transactions

        bare_ctx = make_commitment_using_open_channel(chan.state, chan.remote_state.ctn + 1, False, chan.remote_state.next_per_commitment_point,
            msat_remote, msat_local)

        sig_64 = sign_and_get_sig_string(bare_ctx, chan.local_config, chan.remote_config)
        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=0))

        await self.receive_revoke(chan)

        self.lnworker.save_channel(chan)

    async def receive_revoke(self, m):
        revoke_and_ack_msg = await self.revoke_and_ack[m.channel_id].get()
        m.receive_revocation(RevokeAndAck(revoke_and_ack_msg["per_commitment_secret"], revoke_and_ack_msg["next_per_commitment_point"]))

    def revoke(self, m):
        rev, _ = m.revoke_current_commitment()
        self.send_message(gen_msg("revoke_and_ack",
            channel_id=m.channel_id,
            per_commitment_secret=rev.per_commitment_secret,
            next_per_commitment_point=rev.next_per_commitment_point))

    async def receive_commitment(self, m):
        commitment_signed_msg = await self.commitment_signed[m.channel_id].get()
        data = commitment_signed_msg["htlc_signature"]
        htlc_sigs = [data[i:i+64] for i in range(0, len(data), 64)]
        m.receive_new_commitment(commitment_signed_msg["signature"], htlc_sigs)
        return len(htlc_sigs)

    @aiosafe
    async def receive_commitment_revoke_ack(self, htlc, decoded, payment_preimage):
        chan = self.channels[htlc['channel_id']]
        channel_id = chan.channel_id
        expected_received_msat = int(decoded.amount * COIN * 1000)
        htlc_id = int.from_bytes(htlc["id"], 'big')
        assert htlc_id == chan.remote_state.next_htlc_id, (htlc_id, chan.remote_state.next_htlc_id)

        assert self.channel_state[channel_id] == "OPEN"

        cltv_expiry = int.from_bytes(htlc["cltv_expiry"], 'big')
        # TODO verify sanity of their cltv expiry
        amount_msat = int.from_bytes(htlc["amount_msat"], 'big')
        assert amount_msat == expected_received_msat
        payment_hash = htlc["payment_hash"]

        htlc = UpdateAddHtlc(amount_msat, payment_hash, cltv_expiry, 0)

        chan.receive_htlc(htlc)

        assert (await self.receive_commitment(chan)) == 1

        self.revoke(chan)

        sig_64, htlc_sigs = chan.sign_next_commitment()
        htlc_sig = htlc_sigs[0]
        self.send_message(gen_msg("commitment_signed", channel_id=channel_id, signature=sig_64, num_htlcs=1, htlc_signature=htlc_sig))

        await self.receive_revoke(chan)

        m.settle_htlc(payment_preimage, htlc_id)
        self.send_message(gen_msg("update_fulfill_htlc", channel_id=channel_id, id=htlc_id, payment_preimage=payment_preimage))

        # remote commitment transaction without htlcs
        bare_ctx = make_commitment_using_open_channel(m.state, m.state.remote_state.ctn + 1, False, m.state.remote_state.next_per_commitment_point,
            m.state.remote_state.amount_msat - expected_received_msat, m.state.local_state.amount_msat + expected_received_msat)
        sig_64 = sign_and_get_sig_string(bare_ctx, m.state.local_config, m.state.remote_config)
        self.send_message(gen_msg("commitment_signed", channel_id=channel_id, signature=sig_64, num_htlcs=0))

        await self.receive_revoke(chan)

        assert (await self.receive_commitment(chan)) == 0

        self.revoke(chan)

        self.lnworker.save_channel(chan)

    def on_commitment_signed(self, payload):
        self.print_error("commitment_signed", payload)
        channel_id = payload['channel_id']
        chan = self.channels[channel_id]
        chan.state = chan.state._replace(local_state=chan.local_state._replace(current_commitment_signature=payload['signature']))
        self.lnworker.save_channel(chan)
        self.commitment_signed[channel_id].put_nowait(payload)

    def on_update_fulfill_htlc(self, payload):
        channel_id = payload["channel_id"]
        self.update_fulfill_htlc[channel_id].put_nowait(payload)

    def on_update_fail_malformed_htlc(self, payload):
        self.on_error(payload)

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
        self.channels[channel_id].update_fee(int.from_bytes(payload["feerate_per_kw"], "big"))


def count_trailing_zeros(index):
    """ BOLT-03 (where_to_put_secret) """
    try:
        return list(reversed(bin(index)[2:])).index("1")
    except ValueError:
        return 48

ShachainElement = namedtuple("ShachainElement", ["secret", "index"])
ShachainElement.__str__ = lambda self: "ShachainElement(" + bh2u(self.secret) + "," + str(self.index) + ")"

class RevocationStore:
    """ taken from lnd """
    def __init__(self):
        self.buckets = [None] * 48
        self.index = 2**48 - 1
    def add_next_entry(self, hsh):
        new_element = ShachainElement(index=self.index, secret=hsh)
        bucket = count_trailing_zeros(self.index)
        for i in range(0, bucket):
            this_bucket = self.buckets[i]
            e = shachain_derive(new_element, this_bucket.index)

            if e != this_bucket:
                raise Exception("hash is not derivable: {} {} {}".format(bh2u(e.secret), bh2u(this_bucket.secret), this_bucket.index))
        self.buckets[bucket] = new_element
        self.index -= 1
    def serialize(self):
        return {"index": self.index, "buckets": [[bh2u(k.secret), k.index] if k is not None else None for k in self.buckets]}
    @staticmethod
    def from_json_obj(decoded_json_obj):
        store = RevocationStore()
        decode = lambda to_decode: ShachainElement(bfh(to_decode[0]), int(to_decode[1]))
        store.buckets = [k if k is None else decode(k) for k in decoded_json_obj["buckets"]]
        store.index = decoded_json_obj["index"]
        return store
    def __eq__(self, o):
        return type(o) is RevocationStore and self.serialize() == o.serialize()
    def __hash__(self):
        return hash(json.dumps(self.serialize(), sort_keys=True))
