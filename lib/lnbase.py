#!/usr/bin/env python3
"""
  Lightning network interface for Electrum
  Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8
"""

from ecdsa.util import sigdecode_der, sigencode_string_canonize
from ecdsa import VerifyingKey
from ecdsa.curves import SECP256k1
import queue
import traceback
import json
from collections import OrderedDict, defaultdict
import asyncio
import sys
import os
import time
import binascii
import hashlib
import hmac
from typing import Sequence, Union, Tuple
import cryptography.hazmat.primitives.ciphers.aead as AEAD
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

from .bitcoin import (public_key_from_private_key, ser_to_point, point_to_ser,
                      string_to_number, deserialize_privkey, EC_KEY, rev_hex, int_to_hex,
                      push_script, script_num_to_hex,
                      add_number_to_script, var_int)
from . import bitcoin
from . import constants
from . import transaction
from .util import PrintError, bh2u, print_error, bfh, profiler, xor_bytes
from .transaction import opcodes, Transaction

from collections import namedtuple, defaultdict

# hardcoded nodes
node_list = [
    ('ecdsa.net', '9735', '038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff'),
]


class LightningError(Exception):
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

def H256(data):
    return hashlib.sha256(data).digest()

class HandshakeState(object):
    prologue = b"lightning"
    protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256"
    handshake_version = b"\x00"
    def __init__(self, responder_pub):
        self.responder_pub = responder_pub
        self.h = H256(self.protocol_name)
        self.ck = self.h
        self.update(self.prologue)
        self.update(self.responder_pub)

    def update(self, data):
        self.h = H256(self.h + data)
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
    s = string_to_number(priv)
    pk = ser_to_point(pub)
    pt = point_to_ser(pk * s)
    return H256(pt)

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
    pub = public_key_from_private_key(priv[:32], True)
    return bytes.fromhex(pub)

def create_ephemeral_key(privkey):
    pub = privkey_to_pubkey(privkey)
    return (privkey[:32], pub)

Keypair = namedtuple("Keypair", ["pubkey", "privkey"])
Outpoint = namedtuple("Outpoint", ["txid", "output_index"])
ChannelConfig = namedtuple("ChannelConfig", [
    "payment_basepoint", "multisig_key", "htlc_basepoint", "delayed_basepoint", "revocation_basepoint",
    "to_self_delay", "dust_limit_sat", "max_htlc_value_in_flight_msat", "max_accepted_htlcs"])
OnlyPubkeyKeypair = namedtuple("OnlyPubkeyKeypair", ["pubkey"])
RemoteState = namedtuple("RemoteState", ["ctn", "next_per_commitment_point", "amount_sat", "revocation_store", "last_per_commitment_point", "next_htlc_id"])
LocalState = namedtuple("LocalState", ["ctn", "per_commitment_secret_seed", "amount_sat", "next_htlc_id"])
ChannelConstraints = namedtuple("ChannelConstraints", ["feerate", "capacity", "is_initiator", "funding_txn_minimum_depth"])
OpenChannel = namedtuple("OpenChannel", ["channel_id", "short_channel_id", "funding_outpoint", "local_config", "remote_config", "remote_state", "local_state", "constraints"])


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
    mask = int.from_bytes(H256(local + remote)[-6:], 'big')
    return ctn ^ mask

def secret_to_pubkey(secret):
    assert type(secret) is int
    return point_to_ser(SECP256k1.generator * secret)

def derive_pubkey(basepoint, per_commitment_point):
    p = ser_to_point(basepoint) + SECP256k1.generator * bitcoin.string_to_number(bitcoin.sha256(per_commitment_point + basepoint))
    return point_to_ser(p)

def derive_privkey(secret, per_commitment_point):
    assert type(secret) is int
    basepoint = point_to_ser(SECP256k1.generator * secret)
    basepoint = secret + bitcoin.string_to_number(bitcoin.sha256(per_commitment_point + basepoint))
    basepoint %= SECP256k1.order
    return basepoint

def derive_blinded_pubkey(basepoint, per_commitment_point):
    k1 = ser_to_point(basepoint) * bitcoin.string_to_number(bitcoin.sha256(basepoint + per_commitment_point))
    k2 = ser_to_point(per_commitment_point) * bitcoin.string_to_number(bitcoin.sha256(per_commitment_point + basepoint))
    return point_to_ser(k1 + k2)

def shachain_derive(element, toIndex):
    return ShachainElement(get_per_commitment_secret_from_seed(element.secret, toIndex, count_trailing_zeros(element.index)), toIndex)


def get_per_commitment_secret_from_seed(seed: bytes, i: int, bits: int = 48) -> bytes:
    """Generate per commitment secret."""
    per_commitment_secret = bytearray(seed)
    for bitindex in range(bits - 1, -1, -1):
        mask = 1 << bitindex
        if i & mask:
            per_commitment_secret[bitindex // 8] ^= 1 << (bitindex % 8)
            per_commitment_secret = bytearray(bitcoin.sha256(per_commitment_secret))
    bajts = bytes(per_commitment_secret)
    return bajts


def overall_weight(num_htlc):
    return 500 + 172 * num_htlc + 224

HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703

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
        + bfh(push_script(bh2u(bitcoin.ripemd(payment_hash)))) + bytes([opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG, opcodes.OP_ENDIF, opcodes.OP_ENDIF])

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
        + bfh(push_script(bh2u(bitcoin.ripemd(payment_hash)))) \
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

def make_commitment_using_open_channel(chan, ctn, for_us, pcp, local_sat, remote_sat, htlcs=[]):
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
        local_sat,
        remote_sat,
        chan.local_config.dust_limit_sat,
        chan.constraints.feerate,
        for_us, htlcs=htlcs)

def make_commitment(ctn, local_funding_pubkey, remote_funding_pubkey, remote_payment_pubkey,
                    payment_basepoint, remote_payment_basepoint,
                    revocation_pubkey, delayed_pubkey, to_self_delay,
                    funding_txid, funding_pos, funding_sat,
                    local_amount, remote_amount,
                    dust_limit_sat, local_feerate, for_us, htlcs):

    pubkeys = sorted([bh2u(local_funding_pubkey), bh2u(remote_funding_pubkey)])
    obs = get_obscured_ctn(ctn, payment_basepoint, remote_payment_basepoint)
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
    fee = local_feerate * overall_weight(len(htlcs)) // 1000 # TODO incorrect if anything is trimmed
    assert type(fee) is int
    to_local_amt = local_amount - (fee if for_us else 0)
    assert type(to_local_amt) is int
    to_local = (bitcoin.TYPE_ADDRESS, local_address, to_local_amt)
    to_remote_amt = remote_amount - (fee if not for_us else 0)
    assert type(to_remote_amt) is int
    to_remote = (bitcoin.TYPE_ADDRESS, remote_address, to_remote_amt)
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

class Peer(PrintError):
    def __init__(self, host, port, pubkey, privkey, request_initial_sync=False, network=None):
        self.host = host
        self.port = port
        self.privkey = privkey
        self.pubkey = pubkey
        self.network = network
        self.read_buffer = b''
        self.ping_time = 0
        self.futures = ["channel_accepted",
            "funding_signed",
            "local_funding_locked",
            "remote_funding_locked",
            "revoke_and_ack",
            "channel_reestablish",
            "update_fulfill_htlc",
            "commitment_signed"]
        self.channel_accepted = defaultdict(asyncio.Future)
        self.funding_signed = defaultdict(asyncio.Future)
        self.local_funding_locked = defaultdict(asyncio.Future)
        self.remote_funding_locked = defaultdict(asyncio.Future)
        self.revoke_and_ack = defaultdict(asyncio.Future)
        self.channel_reestablish = defaultdict(asyncio.Future)
        self.update_fulfill_htlc = defaultdict(asyncio.Future)
        self.commitment_signed = defaultdict(asyncio.Future)
        self.initialized = asyncio.Future()
        self.localfeatures = (0x08 if request_initial_sync else 0)
        # view of the network
        self.nodes = {} # received node announcements
        self.channel_db = ChannelDB()
        self.path_finder = LNPathFinder(self.channel_db)
        self.unfulfilled_htlcs = []

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
            s = await self.reader.read(2**10)
            if not s:
                raise Exception('connection closed')
            self.read_buffer += s
            if len(self.read_buffer) < 18:
                continue
            lc = self.read_buffer[:18]
            l = aead_decrypt(rk_l, rn_l, b'', lc)
            length = int.from_bytes(l, 'big')
            offset = 18 + length + 16
            if len(self.read_buffer) < offset:
                continue
            c = self.read_buffer[18:offset]
            self.read_buffer = self.read_buffer[offset:]
            msg = aead_decrypt(rk_m, rn_m, b'', c)
            return msg

    async def handshake(self):
        hs = HandshakeState(self.pubkey)
        msg = act1_initiator_message(hs, self.privkey)
        # act 1
        self.writer.write(msg)
        rspns = await self.reader.read(2**10)
        assert len(rspns) == 50
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
        for i in self.futures:
            if payload["channel_id"] in getattr(self, i):
                getattr(self, i)[payload["channel_id"]].set_exception(LightningError(payload["data"]))
                return
        self.print_error("no future found to resolve", payload)

    def on_ping(self, payload):
        l = int.from_bytes(payload['num_pong_bytes'], 'big')
        self.send_message(gen_msg('pong', byteslen=l))

    def on_channel_reestablish(self, payload):
        chan_id = int.from_bytes(payload["channel_id"], 'big')
        if chan_id not in self.channel_reestablish: raise Exception("Got unknown channel_reestablish")
        self.channel_reestablish[chan_id].set_result(payload)

    def on_accept_channel(self, payload):
        temp_chan_id = payload["temporary_channel_id"]
        if temp_chan_id not in self.channel_accepted: raise Exception("Got unknown accept_channel")
        self.channel_accepted[temp_chan_id].set_result(payload)

    def on_funding_signed(self, payload):
        channel_id = int.from_bytes(payload['channel_id'], 'big')
        if channel_id not in self.funding_signed: raise Exception("Got unknown funding_signed")
        self.funding_signed[channel_id].set_result(payload)

    def on_funding_locked(self, payload):
        channel_id = int.from_bytes(payload['channel_id'], 'big')
        if channel_id not in self.funding_signed: print("Got unknown funding_locked", payload)
        self.remote_funding_locked[channel_id].set_result(payload)

    def on_node_announcement(self, payload):
        pubkey = payload['node_id']
        signature = payload['signature']
        h = bitcoin.Hash(payload['raw'][66:])
        if not bitcoin.verify_signature(pubkey, signature, h):
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
        self.nodes[pubkey] = {
            'alias': alias,
            'addresses': addresses
        }
        self.print_error('node announcement', binascii.hexlify(pubkey), alias, addresses)

    def on_init(self, payload):
        pass

    def on_channel_update(self, payload):
        self.channel_db.on_channel_update(payload)

    def on_channel_announcement(self, payload):
        self.channel_db.on_channel_announcement(payload)

    #def open_channel(self, funding_sat, push_msat):
    #    self.send_message(gen_msg('open_channel', funding_sat=funding_sat, push_msat=push_msat))

    @aiosafe
    async def main_loop(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self.handshake()
        # send init
        self.send_message(gen_msg("init", gflen=0, lflen=1, localfeatures=self.localfeatures))
        # read init
        msg = await self.read_message()
        self.process_message(msg)
        # initialized
        self.initialized.set_result(msg)
        # loop
        while True:
            self.ping_if_required()
            msg = await self.read_message()
            self.process_message(msg)
        # close socket
        self.print_error('closing lnbase')
        self.writer.close()

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
            max_htlc_value_in_flight_msat=500000 * 1000,
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
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat
        )
        self.send_message(msg)
        try:
            payload = await self.channel_accepted[temp_channel_id]
        finally:
            del self.channel_accepted[temp_channel_id]
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
        assert remote_config.max_htlc_value_in_flight_msat >= 500 * 1000 * 1000, remote_config.max_htlc_value_in_flight_msat
        self.print_error('remote delay', remote_config.to_self_delay)
        self.print_error('funding_txn_minimum_depth', funding_txn_minimum_depth)
        # create funding tx
        pubkeys = sorted([bh2u(local_config.multisig_key.pubkey), bh2u(remote_config.multisig_key.pubkey)])
        redeem_script = transaction.multisig_script(pubkeys, 2)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = (bitcoin.TYPE_ADDRESS, funding_address, funding_sat)
        funding_tx = wallet.mktx([funding_output], None, config, 1000)
        funding_txid = funding_tx.txid()
        funding_index = funding_tx.outputs().index(funding_output)
        # derive keys
        local_payment_pubkey = derive_pubkey(local_config.payment_basepoint.pubkey, remote_per_commitment_point)
        #local_payment_privkey = derive_privkey(base_secret, remote_per_commitment_point)
        remote_payment_pubkey = derive_pubkey(remote_config.payment_basepoint.pubkey, per_commitment_point_first)
        revocation_pubkey = derive_blinded_pubkey(local_config.revocation_basepoint.pubkey, remote_per_commitment_point)
        remote_revocation_pubkey = derive_blinded_pubkey(remote_config.revocation_basepoint.pubkey, per_commitment_point_first)
        local_delayedpubkey = derive_pubkey(local_config.delayed_basepoint.pubkey, per_commitment_point_first)
        remote_delayedpubkey = derive_pubkey(remote_config.delayed_basepoint.pubkey, remote_per_commitment_point)
        # compute amounts
        htlcs = []
        to_local_msat = funding_sat*1000 - push_msat
        to_remote_msat = push_msat
        local_amount = to_local_msat // 1000
        remote_amount = to_remote_msat // 1000
        # remote commitment transaction
        remote_ctx = make_commitment(
            0,
            remote_config.multisig_key.pubkey, local_config.multisig_key.pubkey, local_payment_pubkey,
            local_config.payment_basepoint.pubkey, remote_config.payment_basepoint.pubkey,
            revocation_pubkey, remote_delayedpubkey, local_config.to_self_delay,
            funding_txid, funding_index, funding_sat,
            remote_amount, local_amount, remote_config.dust_limit_sat, local_feerate, False, htlcs=[])
        sig_64 = sign_and_get_sig_string(remote_ctx, local_config, remote_config)
        funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
        channel_id = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
        self.send_message(gen_msg("funding_created",
            temporary_channel_id=temp_channel_id,
            funding_txid=funding_txid_bytes,
            funding_output_index=funding_index,
            signature=sig_64))
        try:
            payload = await self.funding_signed[channel_id]
        finally:
            del self.funding_signed[channel_id]
        self.print_error('received funding_signed')
        remote_sig = payload['signature']
        # verify remote signature
        local_ctx = make_commitment(
            0,
            local_config.multisig_key.pubkey, remote_config.multisig_key.pubkey, remote_payment_pubkey,
            local_config.payment_basepoint.pubkey, remote_config.payment_basepoint.pubkey,
            remote_revocation_pubkey, local_delayedpubkey, remote_config.to_self_delay,
            funding_txid, funding_index, funding_sat,
            local_amount, remote_amount, local_config.dust_limit_sat, local_feerate, True, htlcs=[])
        pre_hash = bitcoin.Hash(bfh(local_ctx.serialize_preimage(0)))
        if not bitcoin.verify_signature(remote_config.multisig_key.pubkey, remote_sig, pre_hash):
            raise Exception('verifying remote signature failed.')
        # broadcast funding tx
        success, _txid = self.network.broadcast(funding_tx)
        assert success, success
        their_revocation_store = RevocationStore()
        chan = OpenChannel(
                channel_id=channel_id,
                short_channel_id=None,
                funding_outpoint=Outpoint(funding_txid, funding_index),
                local_config=local_config,
                remote_config=remote_config,
                remote_state=RemoteState(
                    ctn = 0,
                    next_per_commitment_point=None,
                    last_per_commitment_point=remote_per_commitment_point,
                    amount_sat=remote_amount,
                    revocation_store=their_revocation_store,
                    next_htlc_id = 0
                ),
                local_state=LocalState(
                    ctn = 0,
                    per_commitment_secret_seed=per_commitment_secret_seed,
                    amount_sat=local_amount,
                    next_htlc_id = 0
                ),
                constraints=ChannelConstraints(capacity=funding_sat, feerate=local_feerate, is_initiator=True, funding_txn_minimum_depth=funding_txn_minimum_depth)
        )
        return chan

    async def reestablish_channel(self, chan):

        await self.initialized
        channel_reestablish_msg = await self.channel_reestablish[chan.channel_id]
        print(channel_reestablish_msg)
        # {
        #   'channel_id': b'\xfa\xce\x0b\x8cjZ6\x03\xd2\x99k\x12\x86\xc7\xed\xe5\xec\x80\x85F\xf2\x1bzn\xa1\xd30I\xf9_V\xfa',
        #   'next_local_commitment_number': b'\x00\x00\x00\x00\x00\x00\x00\x01',
        #   'next_remote_revocation_number': b'\x00\x00\x00\x00\x00\x00\x00\x00',
        #   'your_last_per_commitment_secret': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        #   'my_current_per_commitment_point': b'\x03\x18\xb9\x1b\x99\xd4\xc3\xf1\x92\x0f\xfe\xe4c\x9e\xae\xa4\xf1\xdeX\xcf4\xa9[\xd1\tAh\x80\x88\x01b*['
        # }
        remote_ctn = int.from_bytes(channel_reestablish_msg["next_local_commitment_number"], 'big')
        if remote_ctn != chan.remote_state.ctn + 1:
            raise Exception("expected remote ctn {}, got {}".format(chan.remote_state.ctn + 1, remote_ctn))

        local_ctn = int.from_bytes(channel_reestablish_msg["next_remote_revocation_number"], 'big')
        if local_ctn != chan.local_state.ctn:
            raise Exception("expected local ctn {}, got {}".format(chan.local_state.ctn, local_ctn))

        if channel_reestablish_msg["my_current_per_commitment_point"] != chan.remote_state.last_per_commitment_point:
            raise Exception("Remote PCP mismatch")
        self.send_message(gen_msg("channel_reestablish",
            channel_id=chan.channel_id,
            next_local_commitment_number=chan.local_state.ctn+1,
            next_remote_revocation_number=chan.remote_state.ctn
        ))
        return chan


    async def wait_for_funding_locked(self, chan, wallet):
        channel_id = chan.channel_id

        def on_network_update(event, *args):
            conf = wallet.get_tx_height(chan.funding_outpoint.txid)[1]
            if conf >= chan.constraints.funding_txn_minimum_depth:
                async def set_local_funding_locked_result():
                    try:
                        self.local_funding_locked[channel_id].set_result(short_channel_id)
                    except (asyncio.InvalidStateError, KeyError) as e:
                        # FIXME race condition if updates come in quickly, set_result might be called multiple times
                        # or self.local_funding_locked[channel_id] might be deleted already
                        self.print_error('local_funding_locked.set_result error for channel {}: {}'.format(channel_id, e))
                block_height, tx_pos = wallet.get_txpos(chan.funding_outpoint.txid)
                if tx_pos == -1:
                    self.print_error('funding tx is not yet SPV verified.. but there are '
                                     'already enough confirmations (currently {})'.format(conf))
                    return
                short_channel_id = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index)
                asyncio.run_coroutine_threadsafe(set_local_funding_locked_result(), asyncio.get_event_loop())
                self.network.unregister_callback(on_network_update)

        # wait until we see confirmations
        self.network.register_callback(on_network_update, ['updated', 'verified']) # thread safe

        on_network_update('updated') # shortcut (don't block) if funding tx locked and verified

        try:
            short_channel_id = await self.local_funding_locked[channel_id]
        finally:
            del self.local_funding_locked[channel_id]

        per_commitment_secret_index = 2**48 - 2
        per_commitment_point_second = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        self.send_message(gen_msg("funding_locked", channel_id=channel_id, next_per_commitment_point=per_commitment_point_second))
        # wait until we receive funding_locked
        try:
            remote_funding_locked_msg = await self.remote_funding_locked[channel_id]
        finally:
            del self.remote_funding_locked[channel_id]
        self.print_error('Done waiting for remote_funding_locked', remote_funding_locked_msg)

        return chan._replace(short_channel_id=short_channel_id, remote_state=chan.remote_state._replace(next_per_commitment_point=remote_funding_locked_msg["next_per_commitment_point"]))

    async def pay(self, wallet, chan, sat, payment_hash, pubkey_in_invoice):
        def derive_and_incr():
            nonlocal chan
            last_small_num = chan.local_state.ctn
            next_small_num = last_small_num + 2
            this_small_num = last_small_num + 1
            last_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-last_small_num-1)
            this_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-this_small_num-1)
            this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))
            next_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-next_small_num-1)
            next_point = secret_to_pubkey(int.from_bytes(next_secret, 'big'))
            chan = chan._replace(
                local_state=chan.local_state._replace(
                    ctn=chan.local_state.ctn + 1
                )
            )
            return last_secret, this_point, next_point
        their_revstore = chan.remote_state.revocation_store
        sat = int(sat)
        await asyncio.sleep(1)
        while not is_synced(wallet.network):
            await asyncio.sleep(1)
            print("sleeping more")
        cltv_expiry = wallet.get_local_height() + chan.remote_config.to_self_delay
        assert sat > 0, "sat is not positive"
        amount_msat = sat * 1000

        assert type(self.pubkey) is bytes
        hops_data = [OnionHopsDataSingle(OnionPerHop(chan.short_channel_id, amount_msat.to_bytes(8, "big"), cltv_expiry.to_bytes(4, "big")))]
        associated_data = payment_hash
        onion = new_onion_packet([self.pubkey], os.urandom(32), hops_data, associated_data)

        self.send_message(gen_msg("update_add_htlc", channel_id=chan.channel_id, id=chan.local_state.next_htlc_id, cltv_expiry=cltv_expiry, amount_msat=amount_msat, payment_hash=payment_hash, onion_routing_packet=onion.to_bytes()))

        their_local_htlc_pubkey = derive_pubkey(chan.remote_config.htlc_basepoint.pubkey, chan.remote_state.next_per_commitment_point)
        their_remote_htlc_pubkey = derive_pubkey(chan.local_config.htlc_basepoint.pubkey, chan.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(chan.local_config.htlc_basepoint.privkey, 'big'),
            chan.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')
        # TODO check payment_hash
        revocation_pubkey = derive_blinded_pubkey(chan.local_config.revocation_basepoint.pubkey, chan.remote_state.next_per_commitment_point)
        htlcs_in_remote = [(make_received_htlc(revocation_pubkey, their_remote_htlc_pubkey, their_local_htlc_pubkey, payment_hash, cltv_expiry), amount_msat)]
        new_local = chan.local_state.amount_sat - sat
        remote_ctx = make_commitment_using_open_channel(chan, chan.remote_state.ctn + 1, False, chan.remote_state.next_per_commitment_point,
            chan.remote_state.amount_sat, new_local, htlcs_in_remote)
        sig_64 = sign_and_get_sig_string(remote_ctx, chan.local_config, chan.remote_config)

        htlc_tx = make_htlc_tx_with_open_channel(chan, chan.remote_state.next_per_commitment_point, False, False, amount_msat, cltv_expiry, payment_hash, remote_ctx, 0)
        # htlc_sig signs the HTLC transaction that spends from THEIR commitment transaction's offered_htlc output
        sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
        r, s = sigdecode_der(sig[:-1], SECP256k1.generator.order())
        htlc_sig = sigencode_string_canonize(r, s, SECP256k1.generator.order())

        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=1, htlc_signature=htlc_sig))

        try:
            revoke_and_ack_msg = await self.revoke_and_ack[chan.channel_id]
        finally:
            del self.revoke_and_ack[chan.channel_id]
        # TODO check revoke_and_ack results

        last_secret, _, next_point = derive_and_incr()
        their_revstore.add_next_entry(last_secret)
        self.send_message(gen_msg("revoke_and_ack",
            channel_id=chan.channel_id,
            per_commitment_secret=last_secret,
            next_per_commitment_point=next_point))

        try:
            update_fulfill_htlc_msg = await self.update_fulfill_htlc[chan.channel_id]
        finally:
            del self.update_fulfill_htlc[chan.channel_id]

        # TODO use other fields too
        next_per_commitment_point = revoke_and_ack_msg["next_per_commitment_point"]

        try:
            commitment_signed_msg = await self.commitment_signed[chan.channel_id]
        finally:
            del self.commitment_signed[chan.channel_id]

        # TODO check commitment_signed results

        last_secret, _, next_point = derive_and_incr()
        their_revstore.add_next_entry(last_secret)
        self.send_message(gen_msg("revoke_and_ack",
            channel_id=chan.channel_id,
            per_commitment_secret=last_secret,
            next_per_commitment_point=next_point))

        bare_ctx = make_commitment_using_open_channel(chan, chan.remote_state.ctn + 2, False, next_per_commitment_point,
            chan.remote_state.amount_sat + sat, chan.local_state.amount_sat - sat)

        sig_64 = sign_and_get_sig_string(bare_ctx, chan.local_config, chan.remote_config)

        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=0))
        try:
            revoke_and_ack_msg = await self.revoke_and_ack[chan.channel_id]
        finally:
            del self.revoke_and_ack[chan.channel_id]
        # TODO check revoke_and_ack results

        return chan._replace(
            local_state=chan.local_state._replace(
                amount_sat=chan.local_state.amount_sat - sat,
                next_htlc_id=chan.local_state.next_htlc_id + 1
            ),
            remote_state=chan.remote_state._replace(
                ctn=chan.remote_state.ctn + 2,
                revocation_store=their_revstore,
                last_per_commitment_point=next_per_commitment_point,
                next_per_commitment_point=revoke_and_ack_msg["next_per_commitment_point"],
                amount_sat=chan.remote_state.amount_sat + sat
            )
        )

    async def receive_commitment_revoke_ack(self, chan, expected_received_sat, payment_preimage):
        def derive_and_incr():
            nonlocal chan
            last_small_num = chan.local_state.ctn
            next_small_num = last_small_num + 2
            this_small_num = last_small_num + 1
            last_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-last_small_num-1)
            this_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-this_small_num-1)
            this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))
            next_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-next_small_num-1)
            next_point = secret_to_pubkey(int.from_bytes(next_secret, 'big'))
            chan = chan._replace(
                local_state=chan.local_state._replace(
                    ctn=chan.local_state.ctn + 1
                )
            )
            return last_secret, this_point, next_point

        their_revstore = chan.remote_state.revocation_store

        channel_id = chan.channel_id
        try:
            commitment_signed_msg = await self.commitment_signed[channel_id]
        finally:
            del self.commitment_signed[channel_id]

        assert len(self.unfulfilled_htlcs) == 1
        htlc = self.unfulfilled_htlcs.pop()
        htlc_id = int.from_bytes(htlc["id"], 'big')
        assert htlc_id == chan.remote_state.next_htlc_id, (htlc_id, chan.remote_state.next_htlc_id)
        cltv_expiry = int.from_bytes(htlc["cltv_expiry"], 'big')
        # TODO verify sanity of their cltv expiry
        amount_msat = int.from_bytes(htlc["amount_msat"], 'big')
        assert amount_msat // 1000 == expected_received_sat
        payment_hash = htlc["payment_hash"]

        last_secret, this_point, next_point = derive_and_incr()

        remote_htlc_pubkey = derive_pubkey(chan.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(chan.local_config.htlc_basepoint.pubkey, this_point)

        remote_revocation_pubkey = derive_blinded_pubkey(chan.remote_config.revocation_basepoint.pubkey, this_point)

        htlcs_in_local = [
            (
                make_received_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, payment_hash, cltv_expiry),
                amount_msat
            )
        ]

        new_commitment = make_commitment_using_open_channel(chan, chan.local_state.ctn, True, this_point,
            chan.local_state.amount_sat,
            chan.remote_state.amount_sat - expected_received_sat,
            htlcs_in_local)

        preimage_hex = new_commitment.serialize_preimage(0)
        pre_hash = bitcoin.Hash(bfh(preimage_hex))
        if not bitcoin.verify_signature(chan.remote_config.multisig_key.pubkey, commitment_signed_msg["signature"], pre_hash):
            raise Exception('failed verifying signature of our updated commitment transaction')

        htlc_sigs_len = len(commitment_signed_msg["htlc_signature"])
        if htlc_sigs_len != 64:
            raise Exception("unexpected number of htlc signatures: " + str(htlc_sigs_len))

        htlc_tx = make_htlc_tx_with_open_channel(chan, this_point, True, True, amount_msat, cltv_expiry, payment_hash, new_commitment, 0)
        pre_hash = bitcoin.Hash(bfh(htlc_tx.serialize_preimage(0)))
        remote_htlc_pubkey = derive_pubkey(chan.remote_config.htlc_basepoint.pubkey, this_point)
        if not bitcoin.verify_signature(remote_htlc_pubkey, commitment_signed_msg["htlc_signature"], pre_hash):
            raise Exception("failed verifying signature an HTLC tx spending from one of our commit tx'es HTLC outputs")

        their_revstore.add_next_entry(last_secret)

        self.send_message(gen_msg("revoke_and_ack",
            channel_id=channel_id,
            per_commitment_secret=last_secret,
            next_per_commitment_point=next_point))

        their_local_htlc_pubkey = derive_pubkey(chan.remote_config.htlc_basepoint.pubkey, chan.remote_state.next_per_commitment_point)
        their_remote_htlc_pubkey = derive_pubkey(chan.local_config.htlc_basepoint.pubkey, chan.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(chan.local_config.htlc_basepoint.privkey, 'big'),
            chan.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')
        # TODO check payment_hash
        revocation_pubkey = derive_blinded_pubkey(chan.local_config.revocation_basepoint.pubkey, chan.remote_state.next_per_commitment_point)
        htlcs_in_remote = [(make_offered_htlc(revocation_pubkey, their_remote_htlc_pubkey, their_local_htlc_pubkey, payment_hash), amount_msat)]
        remote_ctx = make_commitment_using_open_channel(chan, chan.remote_state.ctn + 1, False, chan.remote_state.next_per_commitment_point,
            chan.remote_state.amount_sat - expected_received_sat, chan.local_state.amount_sat, htlcs_in_remote)
        sig_64 = sign_and_get_sig_string(remote_ctx, chan.local_config, chan.remote_config)

        htlc_tx = make_htlc_tx_with_open_channel(chan, chan.remote_state.next_per_commitment_point, False, True, amount_msat, cltv_expiry, payment_hash, remote_ctx, 0)

        # htlc_sig signs the HTLC transaction that spends from THEIR commitment transaction's offered_htlc output
        sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
        r, s = sigdecode_der(sig[:-1], SECP256k1.generator.order())
        htlc_sig = sigencode_string_canonize(r, s, SECP256k1.generator.order())

        self.send_message(gen_msg("commitment_signed", channel_id=channel_id, signature=sig_64, num_htlcs=1, htlc_signature=htlc_sig))

        try:
            revoke_and_ack_msg = await self.revoke_and_ack[channel_id]
        finally:
            del self.revoke_and_ack[channel_id]

        # TODO check revoke_and_ack_msg contents

        self.send_message(gen_msg("update_fulfill_htlc", channel_id=channel_id, id=htlc_id, payment_preimage=payment_preimage))

        remote_next_commitment_point = revoke_and_ack_msg["next_per_commitment_point"]

        # remote commitment transaction without htlcs
        bare_ctx = make_commitment_using_open_channel(chan, chan.remote_state.ctn + 2, False, remote_next_commitment_point,
            chan.remote_state.amount_sat - expected_received_sat, chan.local_state.amount_sat + expected_received_sat)

        sig_64 = sign_and_get_sig_string(bare_ctx, chan.local_config, chan.remote_config)

        self.send_message(gen_msg("commitment_signed", channel_id=channel_id, signature=sig_64, num_htlcs=0))
        try:
            revoke_and_ack_msg = await self.revoke_and_ack[channel_id]
        finally:
            del self.revoke_and_ack[channel_id]

        # TODO check revoke_and_ack results

        try:
            commitment_signed_msg = await self.commitment_signed[channel_id]
        finally:
            del self.commitment_signed[channel_id]

        # TODO check commitment_signed results

        last_secret, _, next_point = derive_and_incr()

        their_revstore.add_next_entry(last_secret)

        self.send_message(gen_msg("revoke_and_ack",
            channel_id=channel_id,
            per_commitment_secret=last_secret,
            next_per_commitment_point=next_point))

        return chan._replace(
            local_state=chan.local_state._replace(
                amount_sat=chan.local_state.amount_sat + expected_received_sat
            ),
            remote_state=chan.remote_state._replace(
                ctn=chan.remote_state.ctn + 2,
                revocation_store=their_revstore,
                last_per_commitment_point=remote_next_commitment_point,
                next_per_commitment_point=revoke_and_ack_msg["next_per_commitment_point"],
                amount_sat=chan.remote_state.amount_sat - expected_received_sat,
                next_htlc_id=htlc_id + 1
            )
        )

    def on_commitment_signed(self, payload):
        self.print_error("commitment_signed", payload)
        channel_id = int.from_bytes(payload['channel_id'], 'big')
        self.commitment_signed[channel_id].set_result(payload)

    def on_update_fulfill_htlc(self, payload):
        channel_id = int.from_bytes(payload["channel_id"], 'big')
        self.update_fulfill_htlc[channel_id].set_result(payload)

    def on_update_fail_malformed_htlc(self, payload):
        self.on_error(payload)

    def on_update_add_htlc(self, payload):
        # no onion routing for the moment: we assume we are the end node
        self.print_error('on_update_add_htlc', payload)
        assert self.unfulfilled_htlcs == []
        self.unfulfilled_htlcs.append(payload)

    def on_revoke_and_ack(self, payload):
        channel_id = int.from_bytes(payload["channel_id"], 'big')
        self.revoke_and_ack[channel_id].set_result(payload)


# replacement for lightningCall
class LNWorker:

    def __init__(self, wallet, network):
        self.privkey = H256(b"0123456789")
        self.wallet = wallet
        self.network = network
        self.config = network.config
        self.peers = {}
        self.channels = {}
        peer_list = network.config.get('lightning_peers', node_list)
        for host, port, pubkey in peer_list:
            self.add_peer(host, port, pubkey)

    def add_peer(self, host, port, pubkey):
        peer = Peer(host, int(port), binascii.unhexlify(pubkey), self.privkey)
        self.network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), asyncio.get_event_loop()))
        self.peers[pubkey] = peer

    def open_channel(self, pubkey, amount, push_msat, password):
        keystore = self.wallet.keystore
        peer = self.peers.get(pubkey)
        coro = peer.channel_establishment_flow(self.wallet, self.config, password, amount, push_msat, temp_channel_id=os.urandom(32))
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)


class ChannelInfo(PrintError):

    def __init__(self, channel_announcement_payload):
        self.channel_id = channel_announcement_payload['short_channel_id']
        self.node_id_1 = channel_announcement_payload['node_id_1']
        self.node_id_2 = channel_announcement_payload['node_id_2']

        self.capacity_sat = None
        self.policy_node1 = None
        self.policy_node2 = None

    def set_capacity(self, capacity):
        # TODO call this after looking up UTXO for funding txn on chain
        self.capacity_sat = capacity

    def on_channel_update(self, msg_payload):
        assert self.channel_id == msg_payload['short_channel_id']
        flags = int.from_bytes(msg_payload['flags'], 'big')
        direction = bool(flags & 1)
        if direction == 0:
            self.policy_node1 = ChannelInfoDirectedPolicy(msg_payload)
        else:
            self.policy_node2 = ChannelInfoDirectedPolicy(msg_payload)
        self.print_error('channel update', binascii.hexlify(self.channel_id), flags)

    def get_policy_for_node(self, node_id):
        if node_id == self.node_id_1:
            return self.policy_node1
        elif node_id == self.node_id_2:
            return self.policy_node2
        else:
            raise Exception('node_id {} not in channel {}'.format(node_id, self.channel_id))


class ChannelInfoDirectedPolicy:

    def __init__(self, channel_update_payload):
        self.cltv_expiry_delta           = channel_update_payload['cltv_expiry_delta']
        self.htlc_minimum_msat           = channel_update_payload['htlc_minimum_msat']
        self.fee_base_msat               = channel_update_payload['fee_base_msat']
        self.fee_proportional_millionths = channel_update_payload['fee_proportional_millionths']


class ChannelDB(PrintError):

    def __init__(self):
        self._id_to_channel_info = {}
        self._channels_for_node = defaultdict(set)  # node -> set(short_channel_id)

    def get_channel_info(self, channel_id):
        return self._id_to_channel_info.get(channel_id, None)

    def get_channels_for_node(self, node_id):
        """Returns the set of channels that have node_id as one of the endpoints."""
        return self._channels_for_node[node_id]

    def on_channel_announcement(self, msg_payload):
        short_channel_id = msg_payload['short_channel_id']
        self.print_error('channel announcement', binascii.hexlify(short_channel_id))
        channel_info = ChannelInfo(msg_payload)
        self._id_to_channel_info[short_channel_id] = channel_info
        self._channels_for_node[channel_info.node_id_1].add(short_channel_id)
        self._channels_for_node[channel_info.node_id_2].add(short_channel_id)

    def on_channel_update(self, msg_payload):
        short_channel_id = msg_payload['short_channel_id']
        try:
            channel_info = self._id_to_channel_info[short_channel_id]
        except KeyError:
            pass  # ignore channel update
        else:
            channel_info.on_channel_update(msg_payload)

    def remove_channel(self, short_channel_id):
        try:
            channel_info = self._id_to_channel_info[short_channel_id]
        except KeyError:
            self.print_error('cannot find channel {}'.format(short_channel_id))
            return
        self._id_to_channel_info.pop(short_channel_id, None)
        for node in (channel_info.node_id_1, channel_info.node_id_2):
            try:
                self._channels_for_node[node].remove(short_channel_id)
            except KeyError:
                pass


class RouteEdge:

    def __init__(self, node_id: bytes, short_channel_id: bytes,
                 channel_policy: ChannelInfoDirectedPolicy):
        self.node_id = node_id
        self.short_channel_id = short_channel_id
        self.channel_policy = channel_policy


class LNPathFinder(PrintError):

    def __init__(self, channel_db):
        self.channel_db = channel_db

    def _edge_cost(self, short_channel_id: bytes, start_node: bytes, payment_amt_msat: int) -> float:
        """Heuristic cost of going through a channel.
        direction: 0 or 1. --- 0 means node_id_1 -> node_id_2
        """
        channel_info = self.channel_db.get_channel_info(short_channel_id)
        if channel_info is None:
            return float('inf')

        channel_policy = channel_info.get_policy_for_node(start_node)
        cltv_expiry_delta           = channel_policy.cltv_expiry_delta
        htlc_minimum_msat           = channel_policy.htlc_minimum_msat
        fee_base_msat               = channel_policy.fee_base_msat
        fee_proportional_millionths = channel_policy.fee_proportional_millionths
        if payment_amt_msat is not None:
            if payment_amt_msat < htlc_minimum_msat:
                return float('inf')  # payment amount too little
            if channel_info.capacity_sat is not None and \
                    payment_amt_msat // 1000 > channel_info.capacity_sat:
                return float('inf')  # payment amount too large
        amt = payment_amt_msat or 50000 * 1000  # guess for typical payment amount
        fee_msat = fee_base_msat + amt * fee_proportional_millionths / 1000000
        # TODO revise
        # paying 10 more satoshis ~ waiting one more block
        fee_cost = fee_msat / 1000 / 10
        cltv_cost = cltv_expiry_delta
        return cltv_cost + fee_cost + 1

    @profiler
    def find_path_for_payment(self, from_node_id: bytes, to_node_id: bytes,
                              amount_msat: int=None) -> Sequence[Tuple[bytes, bytes]]:
        """Return a path between from_node_id and to_node_id.

        Returns a list of (node_id, short_channel_id) representing a path.
        To get from node ret[n][0] to ret[n+1][0], use channel ret[n+1][1];
        i.e. an element reads as, "to get to node_id, travel through short_channel_id"
        """
        # TODO find multiple paths??

        # run Dijkstra
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[from_node_id] = 0
        prev_node = {}
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, from_node_id))

        while nodes_to_explore.qsize() > 0:
            dist_to_cur_node, cur_node = nodes_to_explore.get()
            if cur_node == to_node_id:
                break
            if dist_to_cur_node != distance_from_start[cur_node]:
                # queue.PriorityQueue does not implement decrease_priority,
                # so instead of decreasing priorities, we add items again into the queue.
                # so there are duplicates in the queue, that we discard now:
                continue
            for edge_channel_id in self.channel_db.get_channels_for_node(cur_node):
                channel_info = self.channel_db.get_channel_info(edge_channel_id)
                node1, node2 = channel_info.node_id_1, channel_info.node_id_2
                neighbour = node2 if node1 == cur_node else node1
                alt_dist_to_neighbour = distance_from_start[cur_node] \
                                        + self._edge_cost(edge_channel_id, cur_node, amount_msat)
                if alt_dist_to_neighbour < distance_from_start[neighbour]:
                    distance_from_start[neighbour] = alt_dist_to_neighbour
                    prev_node[neighbour] = cur_node, edge_channel_id
                    nodes_to_explore.put((alt_dist_to_neighbour, neighbour))
        else:
            return None  # no path found

        # backtrack from end to start
        cur_node = to_node_id
        path = []
        while cur_node != from_node_id:
            prev_node_id, edge_taken = prev_node[cur_node]
            path += [(cur_node, edge_taken)]
            cur_node = prev_node_id
        path.reverse()
        return path

    def create_route_from_path(self, path) -> Sequence[RouteEdge]:
        if path is None:
            raise Exception('cannot create route from None path')
        route = []
        for node_id, short_channel_id in path:
            channel_info = self.channel_db.get_channel_info(short_channel_id)
            if channel_info is None:
                raise Exception('cannot find channel info for short_channel_id: {}'.format(bh2u(short_channel_id)))
            channel_policy = channel_info.get_policy_for_node(node_id)
            if channel_policy is None:
                raise Exception('cannot find channel policy for short_channel_id: {}'.format(bh2u(short_channel_id)))
            route.append(RouteEdge(node_id, short_channel_id, channel_policy))
        return route


# bolt 04, "onion"  ----->

NUM_MAX_HOPS_IN_PATH = 20
HOPS_DATA_SIZE = 1300      # also sometimes called routingInfoSize in bolt-04
PER_HOP_FULL_SIZE = 65     # HOPS_DATA_SIZE / 20
NUM_STREAM_BYTES = HOPS_DATA_SIZE + PER_HOP_FULL_SIZE
PER_HOP_HMAC_SIZE = 32


class UnsupportedOnionPacketVersion(Exception): pass
class InvalidOnionMac(Exception): pass


class OnionPerHop:

    def __init__(self, short_channel_id: bytes, amt_to_forward: bytes, outgoing_cltv_value: bytes):
        self.short_channel_id = short_channel_id
        self.amt_to_forward = amt_to_forward
        self.outgoing_cltv_value = outgoing_cltv_value

    def to_bytes(self) -> bytes:
        ret = self.short_channel_id
        ret += self.amt_to_forward
        ret += self.outgoing_cltv_value
        ret += bytes(12)  # padding
        if len(ret) != 32:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != 32:
            raise Exception('unexpected length {}'.format(len(b)))
        return OnionPerHop(
            short_channel_id=b[:8],
            amt_to_forward=b[8:16],
            outgoing_cltv_value=b[16:20]
        )


class OnionHopsDataSingle:  # called HopData in lnd

    def __init__(self, per_hop: OnionPerHop = None):
        self.realm = 0
        self.per_hop = per_hop
        self.hmac = None

    def to_bytes(self) -> bytes:
        ret = bytes([self.realm])
        ret += self.per_hop.to_bytes()
        ret += self.hmac if self.hmac is not None else bytes(PER_HOP_HMAC_SIZE)
        if len(ret) != PER_HOP_FULL_SIZE:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != PER_HOP_FULL_SIZE:
            raise Exception('unexpected length {}'.format(len(b)))
        ret = OnionHopsDataSingle()
        ret.realm = b[0]
        if ret.realm != 0:
            raise Exception('only realm 0 is supported')
        ret.per_hop = OnionPerHop.from_bytes(b[1:33])
        ret.hmac = b[33:]
        return ret


class OnionPacket:

    def __init__(self, public_key: bytes, hops_data: bytes, hmac: bytes):
        self.version = 0
        self.public_key = public_key
        self.hops_data = hops_data  # also called RoutingInfo in bolt-04
        self.hmac = hmac

    def to_bytes(self) -> bytes:
        ret = bytes([self.version])
        ret += self.public_key
        ret += self.hops_data
        ret += self.hmac
        if len(ret) != 1366:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != 1366:
            raise Exception('unexpected length {}'.format(len(b)))
        version = b[0]
        if version != 0:
            raise UnsupportedOnionPacketVersion('version {} is not supported'.format(version))
        return OnionPacket(
            public_key=b[1:34],
            hops_data=b[34:1334],
            hmac=b[1334:]
        )


def get_bolt04_onion_key(key_type: bytes, secret: bytes) -> bytes:
    if key_type not in (b'rho', b'mu', b'um', b'ammag'):
        raise Exception('invalid key_type {}'.format(key_type))
    key = hmac.new(key_type, msg=secret, digestmod=hashlib.sha256).digest()
    return key


def get_shared_secrets_along_route(payment_path_pubkeys: Sequence[bytes],
                                   session_key: bytes) -> Sequence[bytes]:
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = num_hops * [b'']
    ephemeral_key = session_key
    # compute shared key for each hop
    for i in range(0, num_hops):
        hop_shared_secrets[i] = get_ecdh(ephemeral_key, payment_path_pubkeys[i])
        ephemeral_pubkey = bfh(EC_KEY(ephemeral_key).get_public_key())
        blinding_factor = H256(ephemeral_pubkey + hop_shared_secrets[i])
        blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
        ephemeral_key_int = int.from_bytes(ephemeral_key, byteorder="big")
        ephemeral_key_int = ephemeral_key_int * blinding_factor_int % SECP256k1.order
        ephemeral_key = ephemeral_key_int.to_bytes(32, byteorder="big")
    return hop_shared_secrets


def new_onion_packet(payment_path_pubkeys: Sequence[bytes], session_key: bytes,
                     hops_data: Sequence[OnionHopsDataSingle], associated_data: bytes) -> OnionPacket:
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = get_shared_secrets_along_route(payment_path_pubkeys, session_key)

    filler = generate_filler(b'rho', num_hops, PER_HOP_FULL_SIZE, hop_shared_secrets)
    mix_header = bytes(HOPS_DATA_SIZE)
    next_hmac = bytes(PER_HOP_HMAC_SIZE)

    # compute routing info and MAC for each hop
    for i in range(num_hops-1, -1, -1):
        rho_key = get_bolt04_onion_key(b'rho', hop_shared_secrets[i])
        mu_key = get_bolt04_onion_key(b'mu', hop_shared_secrets[i])
        hops_data[i].hmac = next_hmac
        stream_bytes = generate_cipher_stream(rho_key, NUM_STREAM_BYTES)
        mix_header = mix_header[:-PER_HOP_FULL_SIZE]
        mix_header = hops_data[i].to_bytes() + mix_header
        mix_header = xor_bytes(mix_header, stream_bytes)
        if i == num_hops - 1 and len(filler) != 0:
            mix_header = mix_header[:-len(filler)] + filler
        packet = mix_header + associated_data
        next_hmac = hmac.new(mu_key, msg=packet, digestmod=hashlib.sha256).digest()

    return OnionPacket(
        public_key=bfh(EC_KEY(session_key).get_public_key()),
        hops_data=mix_header,
        hmac=next_hmac)


def generate_filler(key_type: bytes, num_hops: int, hop_size: int,
                    shared_secrets: Sequence[bytes]) -> bytes:
    filler_size = (NUM_MAX_HOPS_IN_PATH + 1) * hop_size
    filler = bytearray(filler_size)

    for i in range(0, num_hops-1):  # -1, as last hop does not obfuscate
        filler = filler[hop_size:]
        filler += bytearray(hop_size)
        stream_key = get_bolt04_onion_key(key_type, shared_secrets[i])
        stream_bytes = generate_cipher_stream(stream_key, filler_size)
        filler = xor_bytes(filler, stream_bytes)

    return filler[(NUM_MAX_HOPS_IN_PATH-num_hops+2)*hop_size:]


def generate_cipher_stream(stream_key: bytes, num_bytes: int) -> bytes:
    algo = algorithms.ChaCha20(stream_key, nonce=bytes(16))
    cipher = Cipher(algo, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(bytes(num_bytes))


ProcessedOnionPacket = namedtuple("ProcessedOnionPacket", ["are_we_final", "hop_data", "next_packet"])


# TODO replay protection
def process_onion_packet(onion_packet: OnionPacket, associated_data: bytes,
                         our_onion_private_key: bytes) -> ProcessedOnionPacket:
    shared_secret = get_ecdh(our_onion_private_key, onion_packet.public_key)

    # check message integrity
    mu_key = get_bolt04_onion_key(b'mu', shared_secret)
    calculated_mac = hmac.new(mu_key, msg=onion_packet.hops_data+associated_data,
                              digestmod=hashlib.sha256).digest()
    if onion_packet.hmac != calculated_mac:
        raise InvalidOnionMac()

    # peel an onion layer off
    rho_key = get_bolt04_onion_key(b'rho', shared_secret)
    stream_bytes = generate_cipher_stream(rho_key, NUM_STREAM_BYTES)
    padded_header = onion_packet.hops_data + bytes(PER_HOP_FULL_SIZE)
    next_hops_data = xor_bytes(padded_header, stream_bytes)

    # calc next ephemeral key
    blinding_factor = H256(onion_packet.public_key + shared_secret)
    blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
    next_public_key_int = ser_to_point(onion_packet.public_key) * blinding_factor_int
    next_public_key = point_to_ser(next_public_key_int)

    hop_data = OnionHopsDataSingle.from_bytes(next_hops_data[:PER_HOP_FULL_SIZE])
    next_onion_packet = OnionPacket(
        public_key=next_public_key,
        hops_data=next_hops_data[PER_HOP_FULL_SIZE:],
        hmac=hop_data.hmac
    )
    if hop_data.hmac == bytes(PER_HOP_HMAC_SIZE):
        # we are the destination / exit node
        are_we_final = True
    else:
        # we are an intermediate node; forwarding
        are_we_final = False
    return ProcessedOnionPacket(are_we_final, hop_data, next_onion_packet)


class FailedToDecodeOnionError(Exception): pass


class OnionRoutingFailureMessage:

    def __init__(self, code: int, data: bytes):
        self.code = code
        self.data = data


def _decode_onion_error(error_packet: bytes, payment_path_pubkeys: Sequence[bytes],
                        session_key: bytes) -> (bytes, int):
    """Returns the decoded error bytes, and the index of the sender of the error."""
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = get_shared_secrets_along_route(payment_path_pubkeys, session_key)
    for i in range(num_hops):
        ammag_key = get_bolt04_onion_key(b'ammag', hop_shared_secrets[i])
        um_key = get_bolt04_onion_key(b'um', hop_shared_secrets[i])
        stream_bytes = generate_cipher_stream(ammag_key, len(error_packet))
        error_packet = xor_bytes(error_packet, stream_bytes)
        hmac_computed = hmac.new(um_key, msg=error_packet[32:], digestmod=hashlib.sha256).digest()
        hmac_found = error_packet[:32]
        if hmac_computed == hmac_found:
            return error_packet, i
    raise FailedToDecodeOnionError()


def decode_onion_error(error_packet: bytes, payment_path_pubkeys: Sequence[bytes],
                       session_key: bytes) -> (OnionRoutingFailureMessage, int):
    """Returns the failure message, and the index of the sender of the error."""
    decrypted_error, sender_index = _decode_onion_error(error_packet, payment_path_pubkeys, session_key)
    failure_msg = get_failure_msg_from_onion_error(decrypted_error)
    return failure_msg, sender_index


def get_failure_msg_from_onion_error(decrypted_error_packet: bytes) -> OnionRoutingFailureMessage:
    # get failure_msg bytes from error packet
    failure_len = int.from_bytes(decrypted_error_packet[32:34], byteorder='big')
    failure_msg = decrypted_error_packet[34:34+failure_len]
    # create failure message object
    failure_code = int.from_bytes(failure_msg[:2], byteorder='big')
    failure_data = failure_msg[2:]
    return OnionRoutingFailureMessage(failure_code, failure_data)


# <----- bolt 04, "onion"


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
        return self.buckets == o.buckets and self.index == o.index
