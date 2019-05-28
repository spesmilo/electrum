# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from enum import IntFlag, IntEnum
import json
from collections import namedtuple
from typing import NamedTuple, List, Tuple, Mapping, Optional, TYPE_CHECKING, Union
import re

from .util import bfh, bh2u, inv_dict
from .crypto import sha256
from .transaction import Transaction
from .ecc import CURVE_ORDER, sig_string_from_der_sig, ECPubkey, string_to_number
from . import ecc, bitcoin, crypto, transaction
from .transaction import opcodes, TxOutput, Transaction
from .bitcoin import push_script, redeem_script_to_address, TYPE_ADDRESS
from . import segwit_addr
from .i18n import _
from .lnaddr import lndecode
from .keystore import BIP32_KeyStore

if TYPE_CHECKING:
    from .lnchannel import Channel


HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703

Keypair = namedtuple("Keypair", ["pubkey", "privkey"])
OnlyPubkeyKeypair = namedtuple("OnlyPubkeyKeypair", ["pubkey"])


# NamedTuples cannot subclass NamedTuples :'(   https://github.com/python/typing/issues/427
class LocalConfig(NamedTuple):
    # shared channel config fields (DUPLICATED code!!)
    ctn: int
    next_htlc_id: int
    payment_basepoint: 'Keypair'
    multisig_key: 'Keypair'
    htlc_basepoint: 'Keypair'
    delayed_basepoint: 'Keypair'
    revocation_basepoint: 'Keypair'
    to_self_delay: int
    dust_limit_sat: int
    max_htlc_value_in_flight_msat: int
    max_accepted_htlcs: int
    initial_msat: int
    reserve_sat: int
    # specific to "LOCAL" config
    per_commitment_secret_seed: bytes
    funding_locked_received: bool
    was_announced: bool
    current_commitment_signature: Optional[bytes]
    current_htlc_signatures: List[bytes]
    got_sig_for_next: bool


class RemoteConfig(NamedTuple):
    # shared channel config fields (DUPLICATED code!!)
    ctn: int
    next_htlc_id: int
    payment_basepoint: 'Keypair'
    multisig_key: 'Keypair'
    htlc_basepoint: 'Keypair'
    delayed_basepoint: 'Keypair'
    revocation_basepoint: 'Keypair'
    to_self_delay: int
    dust_limit_sat: int
    max_htlc_value_in_flight_msat: int
    max_accepted_htlcs: int
    initial_msat: int
    reserve_sat: int
    htlc_minimum_msat: int
    # specific to "REMOTE" config
    next_per_commitment_point: bytes
    revocation_store: 'RevocationStore'
    current_per_commitment_point: Optional[bytes]


ChannelConstraints = namedtuple("ChannelConstraints", ["capacity", "is_initiator", "funding_txn_minimum_depth", "feerate"])

ScriptHtlc = namedtuple('ScriptHtlc', ['redeem_script', 'htlc'])

class Outpoint(NamedTuple("Outpoint", [('txid', str), ('output_index', int)])):
    def to_str(self):
        return "{}:{}".format(self.txid, self.output_index)


class LightningError(Exception): pass
class LightningPeerConnectionClosed(LightningError): pass
class UnableToDeriveSecret(LightningError): pass
class HandshakeFailed(LightningError): pass
class PaymentFailure(LightningError): pass
class ConnStringFormatError(LightningError): pass
class UnknownPaymentHash(LightningError): pass
class RemoteMisbehaving(LightningError): pass

class NotFoundChanAnnouncementForUpdate(Exception): pass


# TODO make configurable?
DEFAULT_TO_SELF_DELAY = 144
MIN_FINAL_CLTV_EXPIRY_ACCEPTED = 144
MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE = MIN_FINAL_CLTV_EXPIRY_ACCEPTED + 1


# When we open a channel, the remote peer has to support at least this
# value of mSATs in HTLCs accumulated on the channel, or we refuse opening.
# Number is based on observed testnet limit https://github.com/spesmilo/electrum/issues/5032
MINIMUM_MAX_HTLC_VALUE_IN_FLIGHT_ACCEPTED = 19_800 * 1000

MAXIMUM_HTLC_MINIMUM_MSAT_ACCEPTED = 1000

MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED = 2016

class RevocationStore:
    """ Taken from LND, see license in lnchannel.py. """

    START_INDEX = 2 ** 48 - 1

    def __init__(self):
        self.buckets = [None] * 49
        self.index = self.START_INDEX

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

    def retrieve_secret(self, index: int) -> bytes:
        for bucket in self.buckets:
            if bucket is None:
                raise UnableToDeriveSecret()
            try:
                element = shachain_derive(bucket, index)
            except UnableToDeriveSecret:
                continue
            return element.secret
        raise UnableToDeriveSecret()

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


def count_trailing_zeros(index):
    """ BOLT-03 (where_to_put_secret) """
    try:
        return list(reversed(bin(index)[2:])).index("1")
    except ValueError:
        return 48

def shachain_derive(element, to_index):
    def get_prefix(index, pos):
        mask = (1 << 64) - 1 - ((1 << pos) - 1)
        return index & mask
    from_index = element.index
    zeros = count_trailing_zeros(from_index)
    if from_index != get_prefix(to_index, zeros):
        raise UnableToDeriveSecret("prefixes are different; index not derivable")
    return ShachainElement(
        get_per_commitment_secret_from_seed(element.secret, to_index, zeros),
        to_index)

ShachainElement = namedtuple("ShachainElement", ["secret", "index"])
ShachainElement.__str__ = lambda self: "ShachainElement(" + bh2u(self.secret) + "," + str(self.index) + ")"

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

def secret_to_pubkey(secret: int) -> bytes:
    assert type(secret) is int
    return ecc.ECPrivkey.from_secret_scalar(secret).get_public_key_bytes(compressed=True)

def privkey_to_pubkey(priv: bytes) -> bytes:
    return ecc.ECPrivkey(priv[:32]).get_public_key_bytes()

def derive_pubkey(basepoint: bytes, per_commitment_point: bytes) -> bytes:
    p = ecc.ECPubkey(basepoint) + ecc.generator() * ecc.string_to_number(sha256(per_commitment_point + basepoint))
    return p.get_public_key_bytes()

def derive_privkey(secret: int, per_commitment_point: bytes) -> int:
    assert type(secret) is int
    basepoint_bytes = secret_to_pubkey(secret)
    basepoint = secret + ecc.string_to_number(sha256(per_commitment_point + basepoint_bytes))
    basepoint %= CURVE_ORDER
    return basepoint

def derive_blinded_pubkey(basepoint: bytes, per_commitment_point: bytes) -> bytes:
    k1 = ecc.ECPubkey(basepoint) * ecc.string_to_number(sha256(basepoint + per_commitment_point))
    k2 = ecc.ECPubkey(per_commitment_point) * ecc.string_to_number(sha256(per_commitment_point + basepoint))
    return (k1 + k2).get_public_key_bytes()

def derive_blinded_privkey(basepoint_secret: bytes, per_commitment_secret: bytes) -> bytes:
    basepoint = ecc.ECPrivkey(basepoint_secret).get_public_key_bytes(compressed=True)
    per_commitment_point = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    k1 = ecc.string_to_number(basepoint_secret) * ecc.string_to_number(sha256(basepoint + per_commitment_point))
    k2 = ecc.string_to_number(per_commitment_secret) * ecc.string_to_number(sha256(per_commitment_point + basepoint))
    sum = (k1 + k2) % ecc.CURVE_ORDER
    return ecc.number_to_string(sum, CURVE_ORDER)


def make_htlc_tx_output(amount_msat, local_feerate, revocationpubkey, local_delayedpubkey, success, to_self_delay):
    assert type(amount_msat) is int
    assert type(local_feerate) is int
    assert type(revocationpubkey) is bytes
    assert type(local_delayedpubkey) is bytes
    script = bytes([opcodes.OP_IF]) \
        + bfh(push_script(bh2u(revocationpubkey))) \
        + bytes([opcodes.OP_ELSE]) \
        + bitcoin.add_number_to_script(to_self_delay) \
        + bytes([opcodes.OP_CHECKSEQUENCEVERIFY, opcodes.OP_DROP]) \
        + bfh(push_script(bh2u(local_delayedpubkey))) \
        + bytes([opcodes.OP_ENDIF, opcodes.OP_CHECKSIG])

    p2wsh = bitcoin.redeem_script_to_address('p2wsh', bh2u(script))
    weight = HTLC_SUCCESS_WEIGHT if success else HTLC_TIMEOUT_WEIGHT
    fee = local_feerate * weight
    fee = fee // 1000 * 1000
    final_amount_sat = (amount_msat - fee) // 1000
    assert final_amount_sat > 0, final_amount_sat
    output = TxOutput(bitcoin.TYPE_ADDRESS, p2wsh, final_amount_sat)
    return script, output

def make_htlc_tx_witness(remotehtlcsig: bytes, localhtlcsig: bytes,
                         payment_preimage: bytes, witness_script: bytes) -> bytes:
    assert type(remotehtlcsig) is bytes
    assert type(localhtlcsig) is bytes
    assert type(payment_preimage) is bytes
    assert type(witness_script) is bytes
    return bfh(transaction.construct_witness([0, remotehtlcsig, localhtlcsig, payment_preimage, witness_script]))

def make_htlc_tx_inputs(htlc_output_txid: str, htlc_output_index: int,
                        amount_msat: int, witness_script: str) -> List[dict]:
    assert type(htlc_output_txid) is str
    assert type(htlc_output_index) is int
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

def make_htlc_tx(cltv_timeout, inputs, output, name, cltv_expiry):
    assert type(cltv_timeout) is int
    c_outputs = [output]
    tx = Transaction.from_io(inputs, c_outputs, locktime=cltv_timeout, version=2, name=name, cltv_expiry=cltv_expiry)
    return tx

def make_offered_htlc(revocation_pubkey: bytes, remote_htlcpubkey: bytes,
                      local_htlcpubkey: bytes, payment_hash: bytes) -> bytes:
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

def make_received_htlc(revocation_pubkey: bytes, remote_htlcpubkey: bytes,
                       local_htlcpubkey: bytes, payment_hash: bytes, cltv_expiry: int) -> bytes:
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
        + bytes([opcodes.OP_CHECKLOCKTIMEVERIFY, opcodes.OP_DROP, opcodes.OP_CHECKSIG, opcodes.OP_ENDIF, opcodes.OP_ENDIF])

def make_htlc_output_witness_script(is_received_htlc: bool, remote_revocation_pubkey: bytes, remote_htlc_pubkey: bytes,
                                    local_htlc_pubkey: bytes, payment_hash: bytes, cltv_expiry: Optional[int]) -> bytes:
    if is_received_htlc:
        return make_received_htlc(revocation_pubkey=remote_revocation_pubkey,
                                  remote_htlcpubkey=remote_htlc_pubkey,
                                  local_htlcpubkey=local_htlc_pubkey,
                                  payment_hash=payment_hash,
                                  cltv_expiry=cltv_expiry)
    else:
        return make_offered_htlc(revocation_pubkey=remote_revocation_pubkey,
                                 remote_htlcpubkey=remote_htlc_pubkey,
                                 local_htlcpubkey=local_htlc_pubkey,
                                 payment_hash=payment_hash)


def get_ordered_channel_configs(chan: 'Channel', for_us: bool) -> Tuple[Union[LocalConfig, RemoteConfig],
                                                                        Union[LocalConfig, RemoteConfig]]:
    conf =       chan.config[LOCAL] if     for_us else chan.config[REMOTE]
    other_conf = chan.config[LOCAL] if not for_us else chan.config[REMOTE]
    return conf, other_conf


def make_htlc_tx_with_open_channel(chan: 'Channel', pcp: bytes, for_us: bool,
                                   we_receive: bool, commit: Transaction,
                                   htlc: 'UpdateAddHtlc', name: str = None, cltv_expiry: int = 0) -> Tuple[bytes, Transaction]:
    amount_msat, cltv_expiry, payment_hash = htlc.amount_msat, htlc.cltv_expiry, htlc.payment_hash
    conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=for_us)

    delayedpubkey = derive_pubkey(conf.delayed_basepoint.pubkey, pcp)
    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    other_htlc_pubkey = derive_pubkey(other_conf.htlc_basepoint.pubkey, pcp)
    htlc_pubkey = derive_pubkey(conf.htlc_basepoint.pubkey, pcp)
    # HTLC-success for the HTLC spending from a received HTLC output
    # if we do not receive, and the commitment tx is not for us, they receive, so it is also an HTLC-success
    is_htlc_success = for_us == we_receive
    script, htlc_tx_output = make_htlc_tx_output(
        amount_msat = amount_msat,
        local_feerate = chan.pending_feerate(LOCAL if for_us else REMOTE),
        revocationpubkey=other_revocation_pubkey,
        local_delayedpubkey=delayedpubkey,
        success = is_htlc_success,
        to_self_delay = other_conf.to_self_delay)
    preimage_script = make_htlc_output_witness_script(is_received_htlc=is_htlc_success,
                                                      remote_revocation_pubkey=other_revocation_pubkey,
                                                      remote_htlc_pubkey=other_htlc_pubkey,
                                                      local_htlc_pubkey=htlc_pubkey,
                                                      payment_hash=payment_hash,
                                                      cltv_expiry=cltv_expiry)
    htlc_address = redeem_script_to_address('p2wsh', bh2u(preimage_script))
    # FIXME handle htlc_address collision
    # also: https://github.com/lightningnetwork/lightning-rfc/issues/448
    prevout_idx = commit.get_output_idx_from_address(htlc_address)
    assert prevout_idx is not None, (htlc_address, commit.outputs(), extract_ctn_from_tx_and_chan(commit, chan))
    htlc_tx_inputs = make_htlc_tx_inputs(
        commit.txid(), prevout_idx,
        amount_msat=amount_msat,
        witness_script=bh2u(preimage_script))
    if is_htlc_success:
        cltv_expiry = 0
    htlc_tx = make_htlc_tx(cltv_expiry, inputs=htlc_tx_inputs, output=htlc_tx_output,
        name=name, cltv_expiry=cltv_expiry)
    return script, htlc_tx

def make_funding_input(local_funding_pubkey: bytes, remote_funding_pubkey: bytes,
        funding_pos: int, funding_txid: bytes, funding_sat: int):
    pubkeys = sorted([bh2u(local_funding_pubkey), bh2u(remote_funding_pubkey)])
    # commitment tx input
    c_input = {
        'type': 'p2wsh',
        'x_pubkeys': pubkeys,
        'signatures': [None, None],
        'num_sig': 2,
        'prevout_n': funding_pos,
        'prevout_hash': funding_txid,
        'value': funding_sat,
        'coinbase': False,
    }
    return c_input

class HTLCOwner(IntFlag):
    LOCAL = 1
    REMOTE = -LOCAL

    def inverted(self):
        return HTLCOwner(-self)

class Direction(IntFlag):
    SENT = -1
    RECEIVED = 1

SENT = Direction.SENT
RECEIVED = Direction.RECEIVED

LOCAL = HTLCOwner.LOCAL
REMOTE = HTLCOwner.REMOTE

def make_commitment_outputs(fees_per_participant: Mapping[HTLCOwner, int], local_amount: int, remote_amount: int,
        local_tupl, remote_tupl, htlcs: List[ScriptHtlc], dust_limit_sat: int) -> Tuple[List[TxOutput], List[TxOutput]]:
    to_local_amt = local_amount - fees_per_participant[LOCAL]
    to_local = TxOutput(*local_tupl, to_local_amt // 1000)
    to_remote_amt = remote_amount - fees_per_participant[REMOTE]
    to_remote = TxOutput(*remote_tupl, to_remote_amt // 1000)
    non_htlc_outputs = [to_local, to_remote]
    htlc_outputs = []
    for script, htlc in htlcs:
        htlc_outputs.append(TxOutput(bitcoin.TYPE_ADDRESS,
                               bitcoin.redeem_script_to_address('p2wsh', bh2u(script)),
                               htlc.amount_msat // 1000))

    # trim outputs
    c_outputs_filtered = list(filter(lambda x: x.value >= dust_limit_sat, non_htlc_outputs + htlc_outputs))
    return htlc_outputs, c_outputs_filtered

def calc_onchain_fees(num_htlcs, feerate, we_pay_fee):
    overall_weight = 500 + 172 * num_htlcs + 224
    fee = feerate * overall_weight
    fee = fee // 1000 * 1000
    return {LOCAL: fee if we_pay_fee else 0, REMOTE: fee if not we_pay_fee else 0}

def make_commitment(ctn, local_funding_pubkey, remote_funding_pubkey,
                    remote_payment_pubkey, funder_payment_basepoint,
                    fundee_payment_basepoint, revocation_pubkey,
                    delayed_pubkey, to_self_delay, funding_txid,
                    funding_pos, funding_sat, local_amount, remote_amount,
                    dust_limit_sat, fees_per_participant,
                    htlcs: List[ScriptHtlc]) -> Transaction:
    c_input = make_funding_input(local_funding_pubkey, remote_funding_pubkey,
                                 funding_pos, funding_txid, funding_sat)
    obs = get_obscured_ctn(ctn, funder_payment_basepoint, fundee_payment_basepoint)
    locktime = (0x20 << 24) + (obs & 0xffffff)
    sequence = (0x80 << 24) + (obs >> 24)
    c_input['sequence'] = sequence

    c_inputs = [c_input]

    # commitment tx outputs
    local_address = make_commitment_output_to_local_address(revocation_pubkey, to_self_delay, delayed_pubkey)
    remote_address = make_commitment_output_to_remote_address(remote_payment_pubkey)
    # TODO trim htlc outputs here while also considering 2nd stage htlc transactions

    htlc_outputs, c_outputs_filtered = make_commitment_outputs(fees_per_participant, local_amount, remote_amount,
        (bitcoin.TYPE_ADDRESS, local_address), (bitcoin.TYPE_ADDRESS, remote_address), htlcs, dust_limit_sat)

    assert sum(x.value for x in c_outputs_filtered) <= funding_sat, (c_outputs_filtered, funding_sat)

    # create commitment tx
    tx = Transaction.from_io(c_inputs, c_outputs_filtered, locktime=locktime, version=2)
    return tx

def make_commitment_output_to_local_witness_script(
        revocation_pubkey: bytes, to_self_delay: int, delayed_pubkey: bytes) -> bytes:
    local_script = bytes([opcodes.OP_IF]) + bfh(push_script(bh2u(revocation_pubkey))) + bytes([opcodes.OP_ELSE]) + bitcoin.add_number_to_script(to_self_delay) \
                   + bytes([opcodes.OP_CHECKSEQUENCEVERIFY, opcodes.OP_DROP]) + bfh(push_script(bh2u(delayed_pubkey))) + bytes([opcodes.OP_ENDIF, opcodes.OP_CHECKSIG])
    return local_script

def make_commitment_output_to_local_address(
        revocation_pubkey: bytes, to_self_delay: int, delayed_pubkey: bytes) -> str:
    local_script = make_commitment_output_to_local_witness_script(revocation_pubkey, to_self_delay, delayed_pubkey)
    return bitcoin.redeem_script_to_address('p2wsh', bh2u(local_script))

def make_commitment_output_to_remote_address(remote_payment_pubkey: bytes) -> str:
    return bitcoin.pubkey_to_address('p2wpkh', bh2u(remote_payment_pubkey))

def sign_and_get_sig_string(tx, local_config, remote_config):
    pubkeys = sorted([bh2u(local_config.multisig_key.pubkey), bh2u(remote_config.multisig_key.pubkey)])
    tx.sign({bh2u(local_config.multisig_key.pubkey): (local_config.multisig_key.privkey, True)})
    sig_index = pubkeys.index(bh2u(local_config.multisig_key.pubkey))
    sig = bytes.fromhex(tx.inputs()[0]["signatures"][sig_index])
    sig_64 = sig_string_from_der_sig(sig[:-1])
    return sig_64

def funding_output_script(local_config, remote_config) -> str:
    return funding_output_script_from_keys(local_config.multisig_key.pubkey, remote_config.multisig_key.pubkey)

def funding_output_script_from_keys(pubkey1: bytes, pubkey2: bytes) -> str:
    pubkeys = sorted([bh2u(pubkey1), bh2u(pubkey2)])
    return transaction.multisig_script(pubkeys, 2)

def calc_short_channel_id(block_height: int, tx_pos_in_block: int, output_index: int) -> bytes:
    bh = block_height.to_bytes(3, byteorder='big')
    tpos = tx_pos_in_block.to_bytes(3, byteorder='big')
    oi = output_index.to_bytes(2, byteorder='big')
    return bh + tpos + oi

def invert_short_channel_id(short_channel_id: bytes) -> (int, int, int):
    bh = int.from_bytes(short_channel_id[:3], byteorder='big')
    tpos = int.from_bytes(short_channel_id[3:6], byteorder='big')
    oi = int.from_bytes(short_channel_id[6:8], byteorder='big')
    return bh, tpos, oi

def get_obscured_ctn(ctn: int, funder: bytes, fundee: bytes) -> int:
    mask = int.from_bytes(sha256(funder + fundee)[-6:], 'big')
    return ctn ^ mask

def extract_ctn_from_tx(tx, txin_index: int, funder_payment_basepoint: bytes,
                        fundee_payment_basepoint: bytes) -> int:
    tx.deserialize()
    locktime = tx.locktime
    sequence = tx.inputs()[txin_index]['sequence']
    obs = ((sequence & 0xffffff) << 24) + (locktime & 0xffffff)
    return get_obscured_ctn(obs, funder_payment_basepoint, fundee_payment_basepoint)

def extract_ctn_from_tx_and_chan(tx: Transaction, chan: 'Channel') -> int:
    funder_conf = chan.config[LOCAL] if     chan.constraints.is_initiator else chan.config[REMOTE]
    fundee_conf = chan.config[LOCAL] if not chan.constraints.is_initiator else chan.config[REMOTE]
    return extract_ctn_from_tx(tx, txin_index=0,
                               funder_payment_basepoint=funder_conf.payment_basepoint.pubkey,
                               fundee_payment_basepoint=fundee_conf.payment_basepoint.pubkey)

def get_ecdh(priv: bytes, pub: bytes) -> bytes:
    pt = ECPubkey(pub) * string_to_number(priv)
    return sha256(pt.get_public_key_bytes())


class LnLocalFeatures(IntFlag):
    OPTION_DATA_LOSS_PROTECT_REQ = 1 << 0
    OPTION_DATA_LOSS_PROTECT_OPT = 1 << 1
    INITIAL_ROUTING_SYNC = 1 << 3
    OPTION_UPFRONT_SHUTDOWN_SCRIPT_REQ = 1 << 4
    OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT = 1 << 5
    GOSSIP_QUERIES_REQ = 1 << 6
    GOSSIP_QUERIES_OPT = 1 << 7

# note that these are powers of two, not the bits themselves
LN_LOCAL_FEATURES_KNOWN_SET = set(LnLocalFeatures)


def get_ln_flag_pair_of_bit(flag_bit: int):
    """Ln Feature flags are assigned in pairs, one even, one odd. See BOLT-09.
    Return the other flag from the pair.
    e.g. 6 -> 7
    e.g. 7 -> 6
    """
    if flag_bit % 2 == 0:
        return flag_bit + 1
    else:
        return flag_bit - 1


class LnGlobalFeatures(IntFlag):
    pass

# note that these are powers of two, not the bits themselves
LN_GLOBAL_FEATURES_KNOWN_SET = set(LnGlobalFeatures)


class LNPeerAddr(NamedTuple):
    host: str
    port: int
    pubkey: bytes

    def __str__(self):
        return '{}@{}:{}'.format(bh2u(self.pubkey), self.host, self.port)


def get_compressed_pubkey_from_bech32(bech32_pubkey: str) -> bytes:
    hrp, data_5bits = segwit_addr.bech32_decode(bech32_pubkey)
    if hrp != 'ln':
        raise Exception('unexpected hrp: {}'.format(hrp))
    data_8bits = segwit_addr.convertbits(data_5bits, 5, 8, False)
    # pad with zeroes
    COMPRESSED_PUBKEY_LENGTH = 33
    data_8bits = data_8bits + ((COMPRESSED_PUBKEY_LENGTH - len(data_8bits)) * [0])
    return bytes(data_8bits)


def make_closing_tx(local_funding_pubkey: bytes, remote_funding_pubkey: bytes,
        funding_txid: bytes, funding_pos: int, funding_sat: int, outputs: List[TxOutput]):
    c_input = make_funding_input(local_funding_pubkey, remote_funding_pubkey,
        funding_pos, funding_txid, funding_sat)
    c_input['sequence'] = 0xFFFF_FFFF
    tx = Transaction.from_io([c_input], outputs, locktime=0, version=2)
    return tx


def split_host_port(host_port: str) -> Tuple[str, str]: # port returned as string
    ipv6  = re.compile(r'\[(?P<host>[:0-9]+)\](?P<port>:\d+)?$')
    other = re.compile(r'(?P<host>[^:]+)(?P<port>:\d+)?$')
    m = ipv6.match(host_port)
    if not m:
        m = other.match(host_port)
    if not m:
        raise ConnStringFormatError(_('Connection strings must be in <node_pubkey>@<host>:<port> format'))
    host = m.group('host')
    if m.group('port'):
        port = m.group('port')[1:]
    else:
        port = '9735'
    try:
        int(port)
    except ValueError:
        raise ConnStringFormatError(_('Port number must be decimal'))
    return host, port

def extract_nodeid(connect_contents: str) -> Tuple[bytes, str]:
    rest = None
    try:
        # connection string?
        nodeid_hex, rest = connect_contents.split("@", 1)
    except ValueError:
        try:
            # invoice?
            invoice = lndecode(connect_contents)
            nodeid_bytes = invoice.pubkey.serialize()
            nodeid_hex = bh2u(nodeid_bytes)
        except:
            # node id as hex?
            nodeid_hex = connect_contents
    if rest == '':
        raise ConnStringFormatError(_('At least a hostname must be supplied after the at symbol.'))
    try:
        node_id = bfh(nodeid_hex)
        assert len(node_id) == 33, len(node_id)
    except:
        raise ConnStringFormatError(_('Invalid node ID, must be 33 bytes and hexadecimal'))
    return node_id, rest


# key derivation
# see lnd/keychain/derivation.go
class LnKeyFamily(IntEnum):
    MULTISIG = 0
    REVOCATION_BASE = 1
    HTLC_BASE = 2
    PAYMENT_BASE = 3
    DELAY_BASE = 4
    REVOCATION_ROOT = 5
    NODE_KEY = 6


def generate_keypair(ln_keystore: BIP32_KeyStore, key_family: LnKeyFamily, index: int) -> Keypair:
    return Keypair(*ln_keystore.get_keypair([key_family, 0, index], None))


NUM_MAX_HOPS_IN_PAYMENT_PATH = 20
NUM_MAX_EDGES_IN_PAYMENT_PATH = NUM_MAX_HOPS_IN_PAYMENT_PATH + 1

def format_short_channel_id(short_channel_id: Optional[bytes]):
    if not short_channel_id:
        return _('Not yet available')
    return str(int.from_bytes(short_channel_id[:3], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[3:6], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[6:], 'big'))


class UpdateAddHtlc(namedtuple('UpdateAddHtlc', ['amount_msat', 'payment_hash', 'cltv_expiry', 'htlc_id', 'timestamp'])):
    # note: typing.NamedTuple cannot be used because we are overriding __new__

    __slots__ = ()
    def __new__(cls, *args, **kwargs):
        # if you pass a hex-string as payment_hash, it is decoded to bytes.
        # Bytes can't be saved to disk, so we save hex-strings.
        if len(args) > 0:
            args = list(args)
            if type(args[1]) is str:
                args[1] = bfh(args[1])
            return super().__new__(cls, *args)
        if type(kwargs['payment_hash']) is str:
            kwargs['payment_hash'] = bfh(kwargs['payment_hash'])
        if len(args) < 4 and 'htlc_id' not in kwargs:
            kwargs['htlc_id'] = None
        return super().__new__(cls, **kwargs)

