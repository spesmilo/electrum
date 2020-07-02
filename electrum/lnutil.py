# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from enum import IntFlag, IntEnum
import enum
import json
from collections import namedtuple, defaultdict
from typing import NamedTuple, List, Tuple, Mapping, Optional, TYPE_CHECKING, Union, Dict, Set, Sequence
import re

import attr
from aiorpcx import NetAddress

from .util import bfh, bh2u, inv_dict, UserFacingException
from .util import list_enabled_bits
from .crypto import sha256
from .transaction import (Transaction, PartialTransaction, PartialTxInput, TxOutpoint,
                          PartialTxOutput, opcodes, TxOutput)
from .ecc import CURVE_ORDER, sig_string_from_der_sig, ECPubkey, string_to_number
from . import ecc, bitcoin, crypto, transaction
from .bitcoin import push_script, redeem_script_to_address, address_to_script
from . import segwit_addr
from .i18n import _
from .lnaddr import lndecode
from .bip32 import BIP32Node, BIP32_PRIME
from .transaction import BCDataStream

if TYPE_CHECKING:
    from .lnchannel import Channel, AbstractChannel
    from .lnrouter import LNPaymentRoute
    from .lnonion import OnionRoutingFailureMessage


# defined in BOLT-03:
HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703
COMMITMENT_TX_WEIGHT = 724
HTLC_OUTPUT_WEIGHT = 172

LN_MAX_FUNDING_SAT = pow(2, 24) - 1
LN_MAX_HTLC_VALUE_MSAT = pow(2, 32) - 1

# dummy address for fee estimation of funding tx
def ln_dummy_address():
    return redeem_script_to_address('p2wsh', '')

from .json_db import StoredObject


def channel_id_from_funding_tx(funding_txid: str, funding_index: int) -> Tuple[bytes, bytes]:
    funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
    i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
    return i.to_bytes(32, 'big'), funding_txid_bytes

hex_to_bytes = lambda v: v if isinstance(v, bytes) else bytes.fromhex(v) if v is not None else None
json_to_keypair = lambda v: v if isinstance(v, OnlyPubkeyKeypair) else Keypair(**v) if len(v)==2 else OnlyPubkeyKeypair(**v)


@attr.s
class OnlyPubkeyKeypair(StoredObject):
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes)

@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes)

@attr.s
class Config(StoredObject):
    # shared channel config fields
    payment_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
    multisig_key = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
    htlc_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
    delayed_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
    revocation_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
    to_self_delay = attr.ib(type=int)  # applies to OTHER ctx
    dust_limit_sat = attr.ib(type=int)  # applies to SAME ctx
    max_htlc_value_in_flight_msat = attr.ib(type=int)  # max val of INCOMING htlcs
    max_accepted_htlcs = attr.ib(type=int)  # max num of INCOMING htlcs
    initial_msat = attr.ib(type=int)
    reserve_sat = attr.ib(type=int)  # applies to OTHER ctx
    htlc_minimum_msat = attr.ib(type=int)  # smallest value for INCOMING htlc

    def validate_params(self, *, funding_sat: int) -> None:
        conf_name = type(self).__name__
        for key in (
                self.payment_basepoint,
                self.multisig_key,
                self.htlc_basepoint,
                self.delayed_basepoint,
                self.revocation_basepoint
        ):
            if not (len(key.pubkey) == 33 and ecc.ECPubkey.is_pubkey_bytes(key.pubkey)):
                raise Exception(f"{conf_name}. invalid pubkey in channel config")
        if self.reserve_sat < self.dust_limit_sat:
            raise Exception(f"{conf_name}. MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis")
        # technically this could be using the lower DUST_LIMIT_DEFAULT_SAT_SEGWIT
        # but other implementations are checking against this value too; also let's be conservative
        if self.dust_limit_sat < bitcoin.DUST_LIMIT_DEFAULT_SAT_LEGACY:
            raise Exception(f"{conf_name}. dust limit too low: {self.dust_limit_sat} sat")
        if self.reserve_sat > funding_sat // 100:
            raise Exception(f"{conf_name}. reserve too high: {self.reserve_sat}, funding_sat: {funding_sat}")
        if self.htlc_minimum_msat > 1_000:
            raise Exception(f"{conf_name}. htlc_minimum_msat too high: {self.htlc_minimum_msat} msat")
        HTLC_MINIMUM_MSAT_MIN = 0  # should be at least 1 really, but apparently some nodes are sending zero...
        if self.htlc_minimum_msat < HTLC_MINIMUM_MSAT_MIN:
            raise Exception(f"{conf_name}. htlc_minimum_msat too low: {self.htlc_minimum_msat} msat < {HTLC_MINIMUM_MSAT_MIN}")
        if self.max_accepted_htlcs < 1:
            raise Exception(f"{conf_name}. max_accepted_htlcs too low: {self.max_accepted_htlcs}")
        if self.max_accepted_htlcs > 483:
            raise Exception(f"{conf_name}. max_accepted_htlcs too high: {self.max_accepted_htlcs}")
        if self.to_self_delay > MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED:
            raise Exception(f"{conf_name}. to_self_delay too high: {self.to_self_delay} > {MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED}")
        if self.max_htlc_value_in_flight_msat < min(1000 * funding_sat, 100_000_000):
            raise Exception(f"{conf_name}. max_htlc_value_in_flight_msat is too small: {self.max_htlc_value_in_flight_msat}")


@attr.s
class LocalConfig(Config):
    channel_seed = attr.ib(type=bytes, converter=hex_to_bytes)  # type: Optional[bytes]
    funding_locked_received = attr.ib(type=bool)
    was_announced = attr.ib(type=bool)
    current_commitment_signature = attr.ib(type=bytes, converter=hex_to_bytes)
    current_htlc_signatures = attr.ib(type=bytes, converter=hex_to_bytes)
    per_commitment_secret_seed = attr.ib(type=bytes, converter=hex_to_bytes)

    @classmethod
    def from_seed(self, **kwargs):
        channel_seed = kwargs['channel_seed']
        static_remotekey = kwargs.pop('static_remotekey')
        node = BIP32Node.from_rootseed(channel_seed, xtype='standard')
        keypair_generator = lambda family: generate_keypair(node, family)
        kwargs['per_commitment_secret_seed'] = keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey
        kwargs['multisig_key'] = keypair_generator(LnKeyFamily.MULTISIG)
        kwargs['htlc_basepoint'] = keypair_generator(LnKeyFamily.HTLC_BASE)
        kwargs['delayed_basepoint'] = keypair_generator(LnKeyFamily.DELAY_BASE)
        kwargs['revocation_basepoint'] = keypair_generator(LnKeyFamily.REVOCATION_BASE)
        kwargs['payment_basepoint'] = OnlyPubkeyKeypair(static_remotekey) if static_remotekey else keypair_generator(LnKeyFamily.PAYMENT_BASE)
        return LocalConfig(**kwargs)

    def validate_params(self, *, funding_sat: int) -> None:
        conf_name = type(self).__name__
        # run base checks regardless whether LOCAL/REMOTE config
        super().validate_params(funding_sat=funding_sat)
        # run some stricter checks on LOCAL config (make sure we ourselves do the sane thing,
        # even if we are lenient with REMOTE for compatibility reasons)
        HTLC_MINIMUM_MSAT_MIN = 1
        if self.htlc_minimum_msat < HTLC_MINIMUM_MSAT_MIN:
            raise Exception(f"{conf_name}. htlc_minimum_msat too low: {self.htlc_minimum_msat} msat < {HTLC_MINIMUM_MSAT_MIN}")

@attr.s
class RemoteConfig(Config):
    next_per_commitment_point = attr.ib(type=bytes, converter=hex_to_bytes)
    current_per_commitment_point = attr.ib(default=None, type=bytes, converter=hex_to_bytes)

@attr.s
class FeeUpdate(StoredObject):
    rate = attr.ib(type=int)  # in sat/kw
    ctn_local = attr.ib(default=None, type=int)
    ctn_remote = attr.ib(default=None, type=int)

@attr.s
class ChannelConstraints(StoredObject):
    capacity = attr.ib(type=int)
    is_initiator = attr.ib(type=bool)  # note: sometimes also called "funder"
    funding_txn_minimum_depth = attr.ib(type=int)


CHANNEL_BACKUP_VERSION = 0
@attr.s
class ChannelBackupStorage(StoredObject):
    node_id = attr.ib(type=bytes, converter=hex_to_bytes)
    privkey = attr.ib(type=bytes, converter=hex_to_bytes)
    funding_txid = attr.ib(type=str)
    funding_index = attr.ib(type=int, converter=int)
    funding_address = attr.ib(type=str)
    host = attr.ib(type=str)
    port = attr.ib(type=int, converter=int)
    is_initiator = attr.ib(type=bool)
    channel_seed = attr.ib(type=bytes, converter=hex_to_bytes)
    local_delay = attr.ib(type=int, converter=int)
    remote_delay = attr.ib(type=int, converter=int)
    remote_payment_pubkey = attr.ib(type=bytes, converter=hex_to_bytes)
    remote_revocation_pubkey = attr.ib(type=bytes, converter=hex_to_bytes)

    def funding_outpoint(self):
        return Outpoint(self.funding_txid, self.funding_index)

    def channel_id(self):
        chan_id, _ = channel_id_from_funding_tx(self.funding_txid, self.funding_index)
        return chan_id

    def to_bytes(self) -> bytes:
        vds = BCDataStream()
        vds.write_int16(CHANNEL_BACKUP_VERSION)
        vds.write_boolean(self.is_initiator)
        vds.write_bytes(self.privkey, 32)
        vds.write_bytes(self.channel_seed, 32)
        vds.write_bytes(self.node_id, 33)
        vds.write_bytes(bfh(self.funding_txid), 32)
        vds.write_int16(self.funding_index)
        vds.write_string(self.funding_address)
        vds.write_bytes(self.remote_payment_pubkey, 33)
        vds.write_bytes(self.remote_revocation_pubkey, 33)
        vds.write_int16(self.local_delay)
        vds.write_int16(self.remote_delay)
        vds.write_string(self.host)
        vds.write_int16(self.port)
        return bytes(vds.input)

    @staticmethod
    def from_bytes(s):
        vds = BCDataStream()
        vds.write(s)
        version = vds.read_int16()
        if version != CHANNEL_BACKUP_VERSION:
            raise Exception(f"unknown version for channel backup: {version}")
        return ChannelBackupStorage(
            is_initiator = vds.read_boolean(),
            privkey = vds.read_bytes(32).hex(),
            channel_seed = vds.read_bytes(32).hex(),
            node_id = vds.read_bytes(33).hex(),
            funding_txid = vds.read_bytes(32).hex(),
            funding_index = vds.read_int16(),
            funding_address = vds.read_string(),
            remote_payment_pubkey = vds.read_bytes(33).hex(),
            remote_revocation_pubkey = vds.read_bytes(33).hex(),
            local_delay = vds.read_int16(),
            remote_delay = vds.read_int16(),
            host = vds.read_string(),
            port = vds.read_int16())



class ScriptHtlc(NamedTuple):
    redeem_script: bytes
    htlc: 'UpdateAddHtlc'


# FIXME duplicate of TxOutpoint in transaction.py??
@attr.s
class Outpoint(StoredObject):
    txid = attr.ib(type=str)
    output_index = attr.ib(type=int)

    def to_str(self):
        return "{}:{}".format(self.txid, self.output_index)


class PaymentAttemptFailureDetails(NamedTuple):
    sender_idx: Optional[int]
    failure_msg: 'OnionRoutingFailureMessage'
    is_blacklisted: bool


class PaymentAttemptLog(NamedTuple):
    success: bool
    route: Optional['LNPaymentRoute'] = None
    preimage: Optional[bytes] = None
    failure_details: Optional[PaymentAttemptFailureDetails] = None
    exception: Optional[Exception] = None

    def formatted_tuple(self):
        if not self.exception:
            route = self.route
            route_str = '%d'%len(route)
            short_channel_id = None
            if not self.success:
                sender_idx = self.failure_details.sender_idx
                failure_msg = self.failure_details.failure_msg
                if sender_idx is not None:
                    try:
                        short_channel_id = route[sender_idx + 1].short_channel_id
                    except IndexError:
                        # payment destination reported error
                        short_channel_id = _("Destination node")
                message = failure_msg.code_name()
            else:
                short_channel_id = route[-1].short_channel_id
                message = _('Success')
            chan_str = str(short_channel_id) if short_channel_id else _("Unknown")
        else:
            route_str = 'None'
            chan_str = 'N/A'
            message = str(self.exception)
        return route_str, chan_str, message


class BarePaymentAttemptLog(NamedTuple):
    success: bool
    preimage: Optional[bytes] = None
    error_bytes: Optional[bytes] = None
    failure_message: Optional['OnionRoutingFailureMessage'] = None


class LightningError(Exception): pass
class LightningPeerConnectionClosed(LightningError): pass
class UnableToDeriveSecret(LightningError): pass
class HandshakeFailed(LightningError): pass
class ConnStringFormatError(LightningError): pass
class RemoteMisbehaving(LightningError): pass

class NotFoundChanAnnouncementForUpdate(Exception): pass

class PaymentFailure(UserFacingException): pass

# TODO make some of these values configurable?
REDEEM_AFTER_DOUBLE_SPENT_DELAY = 30

CHANNEL_OPENING_TIMEOUT = 24*60*60

MIN_FUNDING_SAT = 200_000

##### CLTV-expiry-delta-related values
# see https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#cltv_expiry_delta-selection

# the minimum cltv_expiry accepted for newly received HTLCs
# note: when changing, consider Blockchain.is_tip_stale()
MIN_FINAL_CLTV_EXPIRY_ACCEPTED = 144
# set it a tiny bit higher for invoices as blocks could get mined
# during forward path of payment
MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE = MIN_FINAL_CLTV_EXPIRY_ACCEPTED + 3

# the deadline for offered HTLCs:
# the deadline after which the channel has to be failed and timed out on-chain
NBLOCK_DEADLINE_AFTER_EXPIRY_FOR_OFFERED_HTLCS = 1

# the deadline for received HTLCs this node has fulfilled:
# the deadline after which the channel has to be failed and the HTLC fulfilled on-chain before its cltv_expiry
NBLOCK_DEADLINE_BEFORE_EXPIRY_FOR_RECEIVED_HTLCS = 72

# the cltv_expiry_delta for channels when we are forwarding payments
NBLOCK_OUR_CLTV_EXPIRY_DELTA = 144
OUR_FEE_BASE_MSAT = 1000
OUR_FEE_PROPORTIONAL_MILLIONTHS = 1

NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE = 28 * 144

MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED = 2016

class RevocationStore:
    # closely based on code in lightningnetwork/lnd

    START_INDEX = 2 ** 48 - 1

    def __init__(self, storage):
        if len(storage) == 0:
            storage['index'] = self.START_INDEX
            storage['buckets'] = {}
        self.storage = storage
        self.buckets = storage['buckets']

    def add_next_entry(self, hsh):
        index = self.storage['index']
        new_element = ShachainElement(index=index, secret=hsh)
        bucket = count_trailing_zeros(index)
        for i in range(0, bucket):
            this_bucket = self.buckets[i]
            e = shachain_derive(new_element, this_bucket.index)
            if e != this_bucket:
                raise Exception("hash is not derivable: {} {} {}".format(bh2u(e.secret), bh2u(this_bucket.secret), this_bucket.index))
        self.buckets[bucket] = new_element
        self.storage['index'] = index - 1

    def retrieve_secret(self, index: int) -> bytes:
        assert index <= self.START_INDEX, index
        for i in range(0, 49):
            bucket = self.buckets.get(i)
            if bucket is None:
                raise UnableToDeriveSecret()
            try:
                element = shachain_derive(bucket, index)
            except UnableToDeriveSecret:
                continue
            return element.secret
        raise UnableToDeriveSecret()

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
    p = ecc.ECPubkey(basepoint) + ecc.GENERATOR * ecc.string_to_number(sha256(per_commitment_point + basepoint))
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
    return int.to_bytes(sum, length=32, byteorder='big', signed=False)


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
    output = PartialTxOutput.from_address_and_value(p2wsh, final_amount_sat)
    return script, output

def make_htlc_tx_witness(remotehtlcsig: bytes, localhtlcsig: bytes,
                         payment_preimage: bytes, witness_script: bytes) -> bytes:
    assert type(remotehtlcsig) is bytes
    assert type(localhtlcsig) is bytes
    assert type(payment_preimage) is bytes
    assert type(witness_script) is bytes
    return bfh(transaction.construct_witness([0, remotehtlcsig, localhtlcsig, payment_preimage, witness_script]))

def make_htlc_tx_inputs(htlc_output_txid: str, htlc_output_index: int,
                        amount_msat: int, witness_script: str) -> List[PartialTxInput]:
    assert type(htlc_output_txid) is str
    assert type(htlc_output_index) is int
    assert type(amount_msat) is int
    assert type(witness_script) is str
    txin = PartialTxInput(prevout=TxOutpoint(txid=bfh(htlc_output_txid), out_idx=htlc_output_index),
                          nsequence=0)
    txin.witness_script = bfh(witness_script)
    txin.script_sig = b''
    txin._trusted_value_sats = amount_msat // 1000
    c_inputs = [txin]
    return c_inputs

def make_htlc_tx(*, cltv_expiry: int, inputs: List[PartialTxInput], output: PartialTxOutput) -> PartialTransaction:
    assert type(cltv_expiry) is int
    c_outputs = [output]
    tx = PartialTransaction.from_io(inputs, c_outputs, locktime=cltv_expiry, version=2)
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


def get_ordered_channel_configs(chan: 'AbstractChannel', for_us: bool) -> Tuple[Union[LocalConfig, RemoteConfig],
                                                                                Union[LocalConfig, RemoteConfig]]:
    conf =       chan.config[LOCAL] if     for_us else chan.config[REMOTE]
    other_conf = chan.config[LOCAL] if not for_us else chan.config[REMOTE]
    return conf, other_conf


def possible_output_idxs_of_htlc_in_ctx(*, chan: 'Channel', pcp: bytes, subject: 'HTLCOwner',
                                        htlc_direction: 'Direction', ctx: Transaction,
                                        htlc: 'UpdateAddHtlc') -> Set[int]:
    amount_msat, cltv_expiry, payment_hash = htlc.amount_msat, htlc.cltv_expiry, htlc.payment_hash
    for_us = subject == LOCAL
    conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=for_us)

    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    other_htlc_pubkey = derive_pubkey(other_conf.htlc_basepoint.pubkey, pcp)
    htlc_pubkey = derive_pubkey(conf.htlc_basepoint.pubkey, pcp)
    preimage_script = make_htlc_output_witness_script(is_received_htlc=htlc_direction == RECEIVED,
                                                      remote_revocation_pubkey=other_revocation_pubkey,
                                                      remote_htlc_pubkey=other_htlc_pubkey,
                                                      local_htlc_pubkey=htlc_pubkey,
                                                      payment_hash=payment_hash,
                                                      cltv_expiry=cltv_expiry)
    htlc_address = redeem_script_to_address('p2wsh', bh2u(preimage_script))
    candidates = ctx.get_output_idxs_from_address(htlc_address)
    return {output_idx for output_idx in candidates
            if ctx.outputs()[output_idx].value == htlc.amount_msat // 1000}


def map_htlcs_to_ctx_output_idxs(*, chan: 'Channel', ctx: Transaction, pcp: bytes,
                                 subject: 'HTLCOwner', ctn: int) -> Dict[Tuple['Direction', 'UpdateAddHtlc'], Tuple[int, int]]:
    """Returns a dict from (htlc_dir, htlc) to (ctx_output_idx, htlc_relative_idx)"""
    htlc_to_ctx_output_idx_map = {}  # type: Dict[Tuple[Direction, UpdateAddHtlc], int]
    unclaimed_ctx_output_idxs = set(range(len(ctx.outputs())))
    offered_htlcs = chan.included_htlcs(subject, SENT, ctn=ctn)
    offered_htlcs.sort(key=lambda htlc: htlc.cltv_expiry)
    received_htlcs = chan.included_htlcs(subject, RECEIVED, ctn=ctn)
    received_htlcs.sort(key=lambda htlc: htlc.cltv_expiry)
    for direction, htlcs in zip([SENT, RECEIVED], [offered_htlcs, received_htlcs]):
        for htlc in htlcs:
            cands = sorted(possible_output_idxs_of_htlc_in_ctx(chan=chan,
                                                               pcp=pcp,
                                                               subject=subject,
                                                               htlc_direction=direction,
                                                               ctx=ctx,
                                                               htlc=htlc))
            for ctx_output_idx in cands:
                if ctx_output_idx in unclaimed_ctx_output_idxs:
                    unclaimed_ctx_output_idxs.discard(ctx_output_idx)
                    htlc_to_ctx_output_idx_map[(direction, htlc)] = ctx_output_idx
                    break
    # calc htlc_relative_idx
    inverse_map = {ctx_output_idx: (direction, htlc)
                   for ((direction, htlc), ctx_output_idx) in htlc_to_ctx_output_idx_map.items()}

    return {inverse_map[ctx_output_idx]: (ctx_output_idx, htlc_relative_idx)
            for htlc_relative_idx, ctx_output_idx in enumerate(sorted(inverse_map))}


def make_htlc_tx_with_open_channel(*, chan: 'Channel', pcp: bytes, subject: 'HTLCOwner', ctn: int,
                                   htlc_direction: 'Direction', commit: Transaction, ctx_output_idx: int,
                                   htlc: 'UpdateAddHtlc', name: str = None) -> Tuple[bytes, PartialTransaction]:
    amount_msat, cltv_expiry, payment_hash = htlc.amount_msat, htlc.cltv_expiry, htlc.payment_hash
    for_us = subject == LOCAL
    conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=for_us)

    delayedpubkey = derive_pubkey(conf.delayed_basepoint.pubkey, pcp)
    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    other_htlc_pubkey = derive_pubkey(other_conf.htlc_basepoint.pubkey, pcp)
    htlc_pubkey = derive_pubkey(conf.htlc_basepoint.pubkey, pcp)
    # HTLC-success for the HTLC spending from a received HTLC output
    # if we do not receive, and the commitment tx is not for us, they receive, so it is also an HTLC-success
    is_htlc_success = htlc_direction == RECEIVED
    witness_script_of_htlc_tx_output, htlc_tx_output = make_htlc_tx_output(
        amount_msat = amount_msat,
        local_feerate = chan.get_feerate(subject, ctn=ctn),
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
    htlc_tx_inputs = make_htlc_tx_inputs(
        commit.txid(), ctx_output_idx,
        amount_msat=amount_msat,
        witness_script=bh2u(preimage_script))
    if is_htlc_success:
        cltv_expiry = 0
    htlc_tx = make_htlc_tx(cltv_expiry=cltv_expiry, inputs=htlc_tx_inputs, output=htlc_tx_output)
    return witness_script_of_htlc_tx_output, htlc_tx

def make_funding_input(local_funding_pubkey: bytes, remote_funding_pubkey: bytes,
        funding_pos: int, funding_txid: str, funding_sat: int) -> PartialTxInput:
    pubkeys = sorted([bh2u(local_funding_pubkey), bh2u(remote_funding_pubkey)])
    # commitment tx input
    prevout = TxOutpoint(txid=bfh(funding_txid), out_idx=funding_pos)
    c_input = PartialTxInput(prevout=prevout)
    c_input.script_type = 'p2wsh'
    c_input.pubkeys = [bfh(pk) for pk in pubkeys]
    c_input.num_sig = 2
    c_input._trusted_value_sats = funding_sat
    return c_input

class HTLCOwner(IntFlag):
    LOCAL = 1
    REMOTE = -LOCAL

    def inverted(self) -> 'HTLCOwner':
        return -self

    def __neg__(self) -> 'HTLCOwner':
        return HTLCOwner(super().__neg__())


class Direction(IntFlag):
    SENT = -1     # in the context of HTLCs: "offered" HTLCs
    RECEIVED = 1  # in the context of HTLCs: "received" HTLCs

SENT = Direction.SENT
RECEIVED = Direction.RECEIVED

LOCAL = HTLCOwner.LOCAL
REMOTE = HTLCOwner.REMOTE

def make_commitment_outputs(*, fees_per_participant: Mapping[HTLCOwner, int], local_amount_msat: int, remote_amount_msat: int,
        local_script: str, remote_script: str, htlcs: List[ScriptHtlc], dust_limit_sat: int) -> Tuple[List[PartialTxOutput], List[PartialTxOutput]]:
    # BOLT-03: "Base commitment transaction fees are extracted from the funder's amount;
    #           if that amount is insufficient, the entire amount of the funder's output is used."
    #   -> if funder cannot afford feerate, their output might go negative, so take max(0, x) here:
    to_local_amt = max(0, local_amount_msat - fees_per_participant[LOCAL])
    to_local = PartialTxOutput(scriptpubkey=bfh(local_script), value=to_local_amt // 1000)
    to_remote_amt = max(0, remote_amount_msat - fees_per_participant[REMOTE])
    to_remote = PartialTxOutput(scriptpubkey=bfh(remote_script), value=to_remote_amt // 1000)

    non_htlc_outputs = [to_local, to_remote]
    htlc_outputs = []
    for script, htlc in htlcs:
        addr = bitcoin.redeem_script_to_address('p2wsh', bh2u(script))
        htlc_outputs.append(PartialTxOutput(scriptpubkey=bfh(address_to_script(addr)),
                                            value=htlc.amount_msat // 1000))

    # trim outputs
    c_outputs_filtered = list(filter(lambda x: x.value >= dust_limit_sat, non_htlc_outputs + htlc_outputs))
    return htlc_outputs, c_outputs_filtered


def offered_htlc_trim_threshold_sat(*, dust_limit_sat: int, feerate: int) -> int:
    # offered htlcs strictly below this amount will be trimmed (from ctx).
    # feerate is in sat/kw
    # returns value in sat
    weight = HTLC_TIMEOUT_WEIGHT
    return dust_limit_sat + weight * feerate // 1000


def received_htlc_trim_threshold_sat(*, dust_limit_sat: int, feerate: int) -> int:
    # received htlcs strictly below this amount will be trimmed (from ctx).
    # feerate is in sat/kw
    # returns value in sat
    weight = HTLC_SUCCESS_WEIGHT
    return dust_limit_sat + weight * feerate // 1000


def fee_for_htlc_output(*, feerate: int) -> int:
    # feerate is in sat/kw
    # returns fee in msat
    return feerate * HTLC_OUTPUT_WEIGHT


def calc_fees_for_commitment_tx(*, num_htlcs: int, feerate: int,
                                is_local_initiator: bool, round_to_sat: bool = True) -> Dict['HTLCOwner', int]:
    # feerate is in sat/kw
    # returns fees in msats
    # note: BOLT-02 specifies that msat fees need to be rounded down to sat.
    #       However, the rounding needs to happen for the total fees, so if the return value
    #       is to be used as part of additional fee calculation then rounding should be done after that.
    overall_weight = COMMITMENT_TX_WEIGHT + num_htlcs * HTLC_OUTPUT_WEIGHT
    fee = feerate * overall_weight
    if round_to_sat:
        fee = fee // 1000 * 1000
    return {
        LOCAL: fee if is_local_initiator else 0,
        REMOTE: fee if not is_local_initiator else 0,
    }


def make_commitment(
        *,
        ctn: int,
        local_funding_pubkey: bytes,
        remote_funding_pubkey: bytes,
        remote_payment_pubkey: bytes,
        funder_payment_basepoint: bytes,
        fundee_payment_basepoint: bytes,
        revocation_pubkey: bytes,
        delayed_pubkey: bytes,
        to_self_delay: int,
        funding_txid: str,
        funding_pos: int,
        funding_sat: int,
        local_amount: int,
        remote_amount: int,
        dust_limit_sat: int,
        fees_per_participant: Mapping[HTLCOwner, int],
        htlcs: List[ScriptHtlc]
) -> PartialTransaction:
    c_input = make_funding_input(local_funding_pubkey, remote_funding_pubkey,
                                 funding_pos, funding_txid, funding_sat)
    obs = get_obscured_ctn(ctn, funder_payment_basepoint, fundee_payment_basepoint)
    locktime = (0x20 << 24) + (obs & 0xffffff)
    sequence = (0x80 << 24) + (obs >> 24)
    c_input.nsequence = sequence

    c_inputs = [c_input]

    # commitment tx outputs
    local_address = make_commitment_output_to_local_address(revocation_pubkey, to_self_delay, delayed_pubkey)
    remote_address = make_commitment_output_to_remote_address(remote_payment_pubkey)
    # note: it is assumed that the given 'htlcs' are all non-dust (dust htlcs already trimmed)

    # BOLT-03: "Transaction Input and Output Ordering
    #           Lexicographic ordering: see BIP69. In the case of identical HTLC outputs,
    #           the outputs are ordered in increasing cltv_expiry order."
    # so we sort by cltv_expiry now; and the later BIP69-sort is assumed to be *stable*
    htlcs = list(htlcs)
    htlcs.sort(key=lambda x: x.htlc.cltv_expiry)

    htlc_outputs, c_outputs_filtered = make_commitment_outputs(
        fees_per_participant=fees_per_participant,
        local_amount_msat=local_amount,
        remote_amount_msat=remote_amount,
        local_script=address_to_script(local_address),
        remote_script=address_to_script(remote_address),
        htlcs=htlcs,
        dust_limit_sat=dust_limit_sat)

    assert sum(x.value for x in c_outputs_filtered) <= funding_sat, (c_outputs_filtered, funding_sat)

    # create commitment tx
    tx = PartialTransaction.from_io(c_inputs, c_outputs_filtered, locktime=locktime, version=2)
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

def sign_and_get_sig_string(tx: PartialTransaction, local_config, remote_config):
    tx.sign({bh2u(local_config.multisig_key.pubkey): (local_config.multisig_key.privkey, True)})
    sig = tx.inputs()[0].part_sigs[local_config.multisig_key.pubkey]
    sig_64 = sig_string_from_der_sig(sig[:-1])
    return sig_64

def funding_output_script(local_config, remote_config) -> str:
    return funding_output_script_from_keys(local_config.multisig_key.pubkey, remote_config.multisig_key.pubkey)

def funding_output_script_from_keys(pubkey1: bytes, pubkey2: bytes) -> str:
    pubkeys = sorted([bh2u(pubkey1), bh2u(pubkey2)])
    return transaction.multisig_script(pubkeys, 2)


def get_obscured_ctn(ctn: int, funder: bytes, fundee: bytes) -> int:
    mask = int.from_bytes(sha256(funder + fundee)[-6:], 'big')
    return ctn ^ mask

def extract_ctn_from_tx(tx: Transaction, txin_index: int, funder_payment_basepoint: bytes,
                        fundee_payment_basepoint: bytes) -> int:
    tx.deserialize()
    locktime = tx.locktime
    sequence = tx.inputs()[txin_index].nsequence
    obs = ((sequence & 0xffffff) << 24) + (locktime & 0xffffff)
    return get_obscured_ctn(obs, funder_payment_basepoint, fundee_payment_basepoint)

def extract_ctn_from_tx_and_chan(tx: Transaction, chan: 'AbstractChannel') -> int:
    funder_conf = chan.config[LOCAL] if     chan.is_initiator() else chan.config[REMOTE]
    fundee_conf = chan.config[LOCAL] if not chan.is_initiator() else chan.config[REMOTE]
    return extract_ctn_from_tx(tx, txin_index=0,
                               funder_payment_basepoint=funder_conf.payment_basepoint.pubkey,
                               fundee_payment_basepoint=fundee_conf.payment_basepoint.pubkey)

def get_ecdh(priv: bytes, pub: bytes) -> bytes:
    pt = ECPubkey(pub) * string_to_number(priv)
    return sha256(pt.get_public_key_bytes())


class LnFeatureContexts(enum.Flag):
    INIT = enum.auto()
    NODE_ANN = enum.auto()
    CHAN_ANN_AS_IS = enum.auto()
    CHAN_ANN_ALWAYS_ODD = enum.auto()
    CHAN_ANN_ALWAYS_EVEN = enum.auto()
    INVOICE = enum.auto()

LNFC = LnFeatureContexts

_ln_feature_direct_dependencies = defaultdict(set)  # type: Dict[LnFeatures, Set[LnFeatures]]
_ln_feature_contexts = {}  # type: Dict[LnFeatures, LnFeatureContexts]

class LnFeatures(IntFlag):
    OPTION_DATA_LOSS_PROTECT_REQ = 1 << 0
    OPTION_DATA_LOSS_PROTECT_OPT = 1 << 1
    _ln_feature_contexts[OPTION_DATA_LOSS_PROTECT_OPT] = (LNFC.INIT | LnFeatureContexts.NODE_ANN)
    _ln_feature_contexts[OPTION_DATA_LOSS_PROTECT_REQ] = (LNFC.INIT | LnFeatureContexts.NODE_ANN)

    INITIAL_ROUTING_SYNC = 1 << 3
    _ln_feature_contexts[INITIAL_ROUTING_SYNC] = LNFC.INIT

    OPTION_UPFRONT_SHUTDOWN_SCRIPT_REQ = 1 << 4
    OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT = 1 << 5
    _ln_feature_contexts[OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_UPFRONT_SHUTDOWN_SCRIPT_REQ] = (LNFC.INIT | LNFC.NODE_ANN)

    GOSSIP_QUERIES_REQ = 1 << 6
    GOSSIP_QUERIES_OPT = 1 << 7
    _ln_feature_contexts[GOSSIP_QUERIES_OPT] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[GOSSIP_QUERIES_REQ] = (LNFC.INIT | LNFC.NODE_ANN)

    VAR_ONION_REQ = 1 << 8
    VAR_ONION_OPT = 1 << 9
    _ln_feature_contexts[VAR_ONION_OPT] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)
    _ln_feature_contexts[VAR_ONION_REQ] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)

    GOSSIP_QUERIES_EX_REQ = 1 << 10
    GOSSIP_QUERIES_EX_OPT = 1 << 11
    _ln_feature_direct_dependencies[GOSSIP_QUERIES_EX_OPT] = {GOSSIP_QUERIES_OPT}
    _ln_feature_contexts[GOSSIP_QUERIES_EX_OPT] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[GOSSIP_QUERIES_EX_REQ] = (LNFC.INIT | LNFC.NODE_ANN)

    OPTION_STATIC_REMOTEKEY_REQ = 1 << 12
    OPTION_STATIC_REMOTEKEY_OPT = 1 << 13
    _ln_feature_contexts[OPTION_STATIC_REMOTEKEY_OPT] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_STATIC_REMOTEKEY_REQ] = (LNFC.INIT | LNFC.NODE_ANN)

    PAYMENT_SECRET_REQ = 1 << 14
    PAYMENT_SECRET_OPT = 1 << 15
    _ln_feature_direct_dependencies[PAYMENT_SECRET_OPT] = {VAR_ONION_OPT}
    _ln_feature_contexts[PAYMENT_SECRET_OPT] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)
    _ln_feature_contexts[PAYMENT_SECRET_REQ] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)

    BASIC_MPP_REQ = 1 << 16
    BASIC_MPP_OPT = 1 << 17
    _ln_feature_direct_dependencies[BASIC_MPP_OPT] = {PAYMENT_SECRET_OPT}
    _ln_feature_contexts[BASIC_MPP_OPT] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)
    _ln_feature_contexts[BASIC_MPP_REQ] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)

    OPTION_SUPPORT_LARGE_CHANNEL_REQ = 1 << 18
    OPTION_SUPPORT_LARGE_CHANNEL_OPT = 1 << 19
    _ln_feature_contexts[OPTION_SUPPORT_LARGE_CHANNEL_OPT] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.CHAN_ANN_ALWAYS_EVEN)
    _ln_feature_contexts[OPTION_SUPPORT_LARGE_CHANNEL_REQ] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.CHAN_ANN_ALWAYS_EVEN)

    def validate_transitive_dependecies(self) -> bool:
        # for all even bit set, set corresponding odd bit:
        features = self  # copy
        flags = list_enabled_bits(features)
        for flag in flags:
            if flag % 2 == 0:
                features |= 1 << get_ln_flag_pair_of_bit(flag)
        # Check dependencies. We only check that the direct dependencies of each flag set
        # are satisfied: this implies that transitive dependencies are also satisfied.
        flags = list_enabled_bits(features)
        for flag in flags:
            for dependency in _ln_feature_direct_dependencies[1 << flag]:
                if not (dependency & features):
                    return False
        return True

    def for_init_message(self) -> 'LnFeatures':
        features = LnFeatures(0)
        for flag in list_enabled_bits(self):
            if LnFeatureContexts.INIT & _ln_feature_contexts[1 << flag]:
                features |= (1 << flag)
        return features

    def for_node_announcement(self) -> 'LnFeatures':
        features = LnFeatures(0)
        for flag in list_enabled_bits(self):
            if LnFeatureContexts.NODE_ANN & _ln_feature_contexts[1 << flag]:
                features |= (1 << flag)
        return features

    def for_invoice(self) -> 'LnFeatures':
        features = LnFeatures(0)
        for flag in list_enabled_bits(self):
            if LnFeatureContexts.INVOICE & _ln_feature_contexts[1 << flag]:
                features |= (1 << flag)
        return features

    def for_channel_announcement(self) -> 'LnFeatures':
        features = LnFeatures(0)
        for flag in list_enabled_bits(self):
            ctxs = _ln_feature_contexts[1 << flag]
            if LnFeatureContexts.CHAN_ANN_AS_IS & ctxs:
                features |= (1 << flag)
            elif LnFeatureContexts.CHAN_ANN_ALWAYS_EVEN & ctxs:
                if flag % 2 == 0:
                    features |= (1 << flag)
            elif LnFeatureContexts.CHAN_ANN_ALWAYS_ODD & ctxs:
                if flag % 2 == 0:
                    flag = get_ln_flag_pair_of_bit(flag)
                features |= (1 << flag)
        return features


del LNFC  # name is ambiguous without context

# features that are actually implemented and understood in our codebase:
# (note: this is not what we send in e.g. init!)
# (note: specify both OPT and REQ here)
LN_FEATURES_IMPLEMENTED = (
        LnFeatures(0)
        | LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT | LnFeatures.OPTION_DATA_LOSS_PROTECT_REQ
        | LnFeatures.GOSSIP_QUERIES_OPT | LnFeatures.GOSSIP_QUERIES_REQ
        | LnFeatures.OPTION_STATIC_REMOTEKEY_OPT | LnFeatures.OPTION_STATIC_REMOTEKEY_REQ
        | LnFeatures.VAR_ONION_OPT | LnFeatures.VAR_ONION_REQ
        | LnFeatures.PAYMENT_SECRET_OPT | LnFeatures.PAYMENT_SECRET_REQ
)


def get_ln_flag_pair_of_bit(flag_bit: int) -> int:
    """Ln Feature flags are assigned in pairs, one even, one odd. See BOLT-09.
    Return the other flag from the pair.
    e.g. 6 -> 7
    e.g. 7 -> 6
    """
    if flag_bit % 2 == 0:
        return flag_bit + 1
    else:
        return flag_bit - 1



class IncompatibleOrInsaneFeatures(Exception): pass
class UnknownEvenFeatureBits(IncompatibleOrInsaneFeatures): pass
class IncompatibleLightningFeatures(IncompatibleOrInsaneFeatures): pass


def ln_compare_features(our_features: 'LnFeatures', their_features: int) -> 'LnFeatures':
    """Returns negotiated features.
    Raises IncompatibleLightningFeatures if incompatible.
    """
    our_flags = set(list_enabled_bits(our_features))
    their_flags = set(list_enabled_bits(their_features))
    # check that they have our required features, and disable the optional features they don't have
    for flag in our_flags:
        if flag not in their_flags and get_ln_flag_pair_of_bit(flag) not in their_flags:
            # they don't have this feature we wanted :(
            if flag % 2 == 0:  # even flags are compulsory
                raise IncompatibleLightningFeatures(f"remote does not support {LnFeatures(1 << flag)!r}")
            our_features ^= 1 << flag  # disable flag
        else:
            # They too have this flag.
            # For easier feature-bit-testing, if this is an even flag, we also
            # set the corresponding odd flag now.
            if flag % 2 == 0 and our_features & (1 << flag):
                our_features |= 1 << get_ln_flag_pair_of_bit(flag)
    # check that we have their required features
    for flag in their_flags:
        if flag not in our_flags and get_ln_flag_pair_of_bit(flag) not in our_flags:
            # we don't have this feature they wanted :(
            if flag % 2 == 0:  # even flags are compulsory
                raise IncompatibleLightningFeatures(f"remote wanted feature we don't have: {LnFeatures(1 << flag)!r}")
    return our_features


def validate_features(features: int) -> None:
    """Raises IncompatibleOrInsaneFeatures if
    - a mandatory feature is listed that we don't recognize, or
    - the features are inconsistent
    """
    features = LnFeatures(features)
    enabled_features = list_enabled_bits(features)
    for fbit in enabled_features:
        if (1 << fbit) & LN_FEATURES_IMPLEMENTED == 0 and fbit % 2 == 0:
            raise UnknownEvenFeatureBits(fbit)
    if not features.validate_transitive_dependecies():
        raise IncompatibleOrInsaneFeatures("not all transitive dependencies are set")


def derive_payment_secret_from_payment_preimage(payment_preimage: bytes) -> bytes:
    """Returns secret to be put into invoice.
    Derivation is deterministic, based on the preimage.
    Crucially the payment_hash must be derived in an independent way from this.
    """
    # Note that this could be random data too, but then we would need to store it.
    # We derive it identically to clightning, so that we cannot be distinguished:
    # https://github.com/ElementsProject/lightning/blob/faac4b28adee5221e83787d64cd5d30b16b62097/lightningd/invoice.c#L115
    modified = bytearray(payment_preimage)
    modified[0] ^= 1
    return sha256(bytes(modified))


class LNPeerAddr:

    def __init__(self, host: str, port: int, pubkey: bytes):
        assert isinstance(host, str), repr(host)
        assert isinstance(port, int), repr(port)
        assert isinstance(pubkey, bytes), repr(pubkey)
        try:
            net_addr = NetAddress(host, port)  # this validates host and port
        except Exception as e:
            raise ValueError(f"cannot construct LNPeerAddr: invalid host or port (host={host}, port={port})") from e
        # note: not validating pubkey as it would be too expensive:
        # if not ECPubkey.is_pubkey_bytes(pubkey): raise ValueError()
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self._net_addr_str = str(net_addr)

    def __str__(self):
        return '{}@{}'.format(self.pubkey.hex(), self.net_addr_str())

    def __repr__(self):
        return f'<LNPeerAddr host={self.host} port={self.port} pubkey={self.pubkey.hex()}>'

    def net_addr_str(self) -> str:
        return self._net_addr_str

    def __eq__(self, other):
        if not isinstance(other, LNPeerAddr):
            return False
        return (self.host == other.host
                and self.port == other.port
                and self.pubkey == other.pubkey)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.host, self.port, self.pubkey))


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
                    funding_txid: str, funding_pos: int, funding_sat: int,
                    outputs: List[PartialTxOutput]) -> PartialTransaction:
    c_input = make_funding_input(local_funding_pubkey, remote_funding_pubkey,
        funding_pos, funding_txid, funding_sat)
    c_input.nsequence = 0xFFFF_FFFF
    tx = PartialTransaction.from_io([c_input], outputs, locktime=0, version=2)
    return tx


def split_host_port(host_port: str) -> Tuple[str, str]: # port returned as string
    ipv6  = re.compile(r'\[(?P<host>[:0-9a-f]+)\](?P<port>:\d+)?$')
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
    MULTISIG = 0 | BIP32_PRIME
    REVOCATION_BASE = 1 | BIP32_PRIME
    HTLC_BASE = 2 | BIP32_PRIME
    PAYMENT_BASE = 3 | BIP32_PRIME
    DELAY_BASE = 4 | BIP32_PRIME
    REVOCATION_ROOT = 5 | BIP32_PRIME
    NODE_KEY = 6


def generate_keypair(node: BIP32Node, key_family: LnKeyFamily) -> Keypair:
    node2 = node.subkey_at_private_derivation([key_family, 0, 0])
    k = node2.eckey.get_secret_bytes()
    cK = ecc.ECPrivkey(k).get_public_key_bytes()
    return Keypair(cK, k)



NUM_MAX_HOPS_IN_PAYMENT_PATH = 20
NUM_MAX_EDGES_IN_PAYMENT_PATH = NUM_MAX_HOPS_IN_PAYMENT_PATH


class ShortChannelID(bytes):

    def __repr__(self):
        return f"<ShortChannelID: {format_short_channel_id(self)}>"

    def __str__(self):
        return format_short_channel_id(self)

    @classmethod
    def from_components(cls, block_height: int, tx_pos_in_block: int, output_index: int) -> 'ShortChannelID':
        bh = block_height.to_bytes(3, byteorder='big')
        tpos = tx_pos_in_block.to_bytes(3, byteorder='big')
        oi = output_index.to_bytes(2, byteorder='big')
        return ShortChannelID(bh + tpos + oi)

    @classmethod
    def normalize(cls, data: Union[None, str, bytes, 'ShortChannelID']) -> Optional['ShortChannelID']:
        if isinstance(data, ShortChannelID) or data is None:
            return data
        if isinstance(data, str):
            assert len(data) == 16
            return ShortChannelID.fromhex(data)
        if isinstance(data, (bytes, bytearray)):
            assert len(data) == 8
            return ShortChannelID(data)

    @property
    def block_height(self) -> int:
        return int.from_bytes(self[:3], byteorder='big')

    @property
    def txpos(self) -> int:
        return int.from_bytes(self[3:6], byteorder='big')

    @property
    def output_index(self) -> int:
        return int.from_bytes(self[6:8], byteorder='big')


def format_short_channel_id(short_channel_id: Optional[bytes]):
    if not short_channel_id:
        return _('Not yet available')
    return str(int.from_bytes(short_channel_id[:3], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[3:6], 'big')) \
        + 'x' + str(int.from_bytes(short_channel_id[6:], 'big'))


@attr.s(frozen=True)
class UpdateAddHtlc:
    amount_msat = attr.ib(type=int, kw_only=True)
    payment_hash = attr.ib(type=bytes, kw_only=True, converter=hex_to_bytes)
    cltv_expiry = attr.ib(type=int, kw_only=True)
    timestamp = attr.ib(type=int, kw_only=True)
    htlc_id = attr.ib(type=int, kw_only=True, default=None)

    @classmethod
    def from_tuple(cls, amount_msat, payment_hash, cltv_expiry, htlc_id, timestamp) -> 'UpdateAddHtlc':
        return cls(amount_msat=amount_msat,
                   payment_hash=payment_hash,
                   cltv_expiry=cltv_expiry,
                   htlc_id=htlc_id,
                   timestamp=timestamp)

    def to_tuple(self):
        return (self.amount_msat, self.payment_hash, self.cltv_expiry, self.htlc_id, self.timestamp)


class OnionFailureCodeMetaFlag(IntFlag):
    BADONION = 0x8000
    PERM     = 0x4000
    NODE     = 0x2000
    UPDATE   = 0x1000

