# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from enum import IntFlag, IntEnum
import enum
import json
from collections import namedtuple, defaultdict
from typing import NamedTuple, List, Tuple, Mapping, Optional, TYPE_CHECKING, Union, Dict, Set, Sequence
import re
import sys

import attr
from aiorpcx import NetAddress

from .util import bfh, inv_dict, UserFacingException
from .util import list_enabled_bits
from .util import ShortID as ShortChannelID
from .util import format_short_id as format_short_channel_id

from .crypto import sha256, pw_decode_with_version_and_mac
from .transaction import (Transaction, PartialTransaction, PartialTxInput, TxOutpoint,
                          PartialTxOutput, opcodes, TxOutput)
from .ecc import CURVE_ORDER, ecdsa_sig64_from_der_sig, ECPubkey, string_to_number
from . import ecc, bitcoin, crypto, transaction
from . import descriptor
from .bitcoin import (redeem_script_to_address, address_to_script,
                      construct_witness, construct_script)
from . import segwit_addr
from .i18n import _
from .lnaddr import lndecode
from .bip32 import BIP32Node, BIP32_PRIME
from .transaction import BCDataStream, OPPushDataGeneric
from .logging import get_logger


if TYPE_CHECKING:
    from .lnchannel import Channel, AbstractChannel
    from .lnrouter import LNPaymentRoute
    from .lnonion import OnionRoutingFailure
    from .simple_config import SimpleConfig


_logger = get_logger(__name__)


# defined in BOLT-03:
HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703
COMMITMENT_TX_WEIGHT = 724
HTLC_OUTPUT_WEIGHT = 172

LN_MAX_FUNDING_SAT_LEGACY = pow(2, 24) - 1
DUST_LIMIT_MAX = 1000


from .json_db import StoredObject, stored_in, stored_as


def channel_id_from_funding_tx(funding_txid: str, funding_index: int) -> Tuple[bytes, bytes]:
    funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
    i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
    return i.to_bytes(32, 'big'), funding_txid_bytes

hex_to_bytes = lambda v: v if isinstance(v, bytes) else bytes.fromhex(v) if v is not None else None
bytes_to_hex = lambda v: repr(v.hex()) if v is not None else None
json_to_keypair = lambda v: v if isinstance(v, OnlyPubkeyKeypair) else Keypair(**v) if len(v)==2 else OnlyPubkeyKeypair(**v)


def serialize_htlc_key(scid: bytes, htlc_id: int) -> str:
    return scid.hex() + ':%d'%htlc_id


def deserialize_htlc_key(htlc_key: str) -> Tuple[bytes, int]:
    scid, htlc_id = htlc_key.split(':')
    return bytes.fromhex(scid), int(htlc_id)


@attr.s
class OnlyPubkeyKeypair(StoredObject):
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

@attr.s
class ChannelConfig(StoredObject):
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
    upfront_shutdown_script = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
    announcement_node_sig = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
    announcement_bitcoin_sig = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

    def validate_params(self, *, funding_sat: int, config: 'SimpleConfig', peer_features: 'LnFeatures') -> None:
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
        if funding_sat < MIN_FUNDING_SAT:
            raise Exception(f"funding_sat too low: {funding_sat} sat < {MIN_FUNDING_SAT}")
        if not peer_features.supports(LnFeatures.OPTION_SUPPORT_LARGE_CHANNEL_OPT):
            # MUST set funding_satoshis to less than 2^24 satoshi
            if funding_sat > LN_MAX_FUNDING_SAT_LEGACY:
                raise Exception(f"funding_sat too high: {funding_sat} sat > {LN_MAX_FUNDING_SAT_LEGACY} (legacy limit)")
        if funding_sat > config.LIGHTNING_MAX_FUNDING_SAT:
            raise Exception(f"funding_sat too high: {funding_sat} sat > {config.LIGHTNING_MAX_FUNDING_SAT} (config setting)")
        # MUST set push_msat to equal or less than 1000 * funding_satoshis
        if not (0 <= self.initial_msat <= 1000 * funding_sat):
            raise Exception(f"{conf_name}. insane initial_msat={self.initial_msat}. (funding_sat={funding_sat})")
        if self.reserve_sat < self.dust_limit_sat:
            raise Exception(f"{conf_name}. MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis")
        if self.dust_limit_sat < bitcoin.DUST_LIMIT_UNKNOWN_SEGWIT:
            raise Exception(f"{conf_name}. dust limit too low: {self.dust_limit_sat} sat")
        if self.dust_limit_sat > DUST_LIMIT_MAX:
            raise Exception(f"{conf_name}. dust limit too high: {self.dust_limit_sat} sat")
        if self.reserve_sat > funding_sat // 100:
            raise Exception(f"{conf_name}. reserve too high: {self.reserve_sat}, funding_sat: {funding_sat}")
        if self.htlc_minimum_msat > 1_000:
            raise Exception(f"{conf_name}. htlc_minimum_msat too high: {self.htlc_minimum_msat} msat")
        HTLC_MINIMUM_MSAT_MIN = 0  # should be at least 1 really, but apparently some nodes are sending zero...
        if self.htlc_minimum_msat < HTLC_MINIMUM_MSAT_MIN:
            raise Exception(f"{conf_name}. htlc_minimum_msat too low: {self.htlc_minimum_msat} msat < {HTLC_MINIMUM_MSAT_MIN}")
        if self.max_accepted_htlcs < 5:
            raise Exception(f"{conf_name}. max_accepted_htlcs too low: {self.max_accepted_htlcs}")
        if self.max_accepted_htlcs > 483:
            raise Exception(f"{conf_name}. max_accepted_htlcs too high: {self.max_accepted_htlcs}")
        if self.to_self_delay > MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED:
            raise Exception(f"{conf_name}. to_self_delay too high: {self.to_self_delay} > {MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED}")
        if self.max_htlc_value_in_flight_msat < min(1000 * funding_sat, 100_000_000):
            raise Exception(f"{conf_name}. max_htlc_value_in_flight_msat is too small: {self.max_htlc_value_in_flight_msat}")

    @classmethod
    def cross_validate_params(
            cls,
            *,
            local_config: 'LocalConfig',
            remote_config: 'RemoteConfig',
            funding_sat: int,
            is_local_initiator: bool,  # whether we are the funder
            initial_feerate_per_kw: int,
            config: 'SimpleConfig',
            peer_features: 'LnFeatures',
    ) -> None:
        # first we validate the configs separately
        local_config.validate_params(funding_sat=funding_sat, config=config, peer_features=peer_features)
        remote_config.validate_params(funding_sat=funding_sat, config=config, peer_features=peer_features)
        # now do tests that need access to both configs
        if is_local_initiator:
            funder, fundee = LOCAL, REMOTE
            funder_config, fundee_config = local_config, remote_config
        else:
            funder, fundee = REMOTE, LOCAL
            funder_config, fundee_config = remote_config, local_config
        # if channel_reserve_satoshis is less than dust_limit_satoshis within the open_channel message:
        #     MUST reject the channel.
        if remote_config.reserve_sat < local_config.dust_limit_sat:
            raise Exception("violated constraint: remote_config.reserve_sat < local_config.dust_limit_sat")
        # if channel_reserve_satoshis from the open_channel message is less than dust_limit_satoshis:
        #     MUST reject the channel.
        if local_config.reserve_sat < remote_config.dust_limit_sat:
            raise Exception("violated constraint: local_config.reserve_sat < remote_config.dust_limit_sat")
        # The receiving node MUST fail the channel if:
        #     the funder's amount for the initial commitment transaction is not
        #     sufficient for full fee payment.
        if funder_config.initial_msat < calc_fees_for_commitment_tx(
                num_htlcs=0,
                feerate=initial_feerate_per_kw,
                is_local_initiator=is_local_initiator)[funder]:
            raise Exception(
                "the funder's amount for the initial commitment transaction "
                "is not sufficient for full fee payment")
        # The receiving node MUST fail the channel if:
        #     both to_local and to_remote amounts for the initial commitment transaction are
        #     less than or equal to channel_reserve_satoshis (see BOLT 3).
        if (max(local_config.initial_msat, remote_config.initial_msat)
                <= 1000 * max(local_config.reserve_sat, remote_config.reserve_sat)):
            raise Exception(
                "both to_local and to_remote amounts for the initial commitment "
                "transaction are less than or equal to channel_reserve_satoshis")
        from .simple_config import FEERATE_PER_KW_MIN_RELAY_LIGHTNING
        if initial_feerate_per_kw < FEERATE_PER_KW_MIN_RELAY_LIGHTNING:
            raise Exception(f"feerate lower than min relay fee. {initial_feerate_per_kw} sat/kw.")


@stored_as('local_config')
@attr.s
class LocalConfig(ChannelConfig):
    channel_seed = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)  # type: Optional[bytes]
    funding_locked_received = attr.ib(type=bool)
    current_commitment_signature = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
    current_htlc_signatures = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
    per_commitment_secret_seed = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

    @classmethod
    def from_seed(cls, **kwargs):
        channel_seed = kwargs['channel_seed']
        static_remotekey = kwargs.pop('static_remotekey')
        node = BIP32Node.from_rootseed(channel_seed, xtype='standard')
        keypair_generator = lambda family: generate_keypair(node, family)
        kwargs['per_commitment_secret_seed'] = keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey
        kwargs['multisig_key'] = keypair_generator(LnKeyFamily.MULTISIG)
        kwargs['htlc_basepoint'] = keypair_generator(LnKeyFamily.HTLC_BASE)
        kwargs['delayed_basepoint'] = keypair_generator(LnKeyFamily.DELAY_BASE)
        kwargs['revocation_basepoint'] = keypair_generator(LnKeyFamily.REVOCATION_BASE)
        if static_remotekey:
            kwargs['payment_basepoint'] = OnlyPubkeyKeypair(static_remotekey)
        else:
            # we expect all our channels to use option_static_remotekey, so ending up here likely indicates an issue...
            kwargs['payment_basepoint'] = keypair_generator(LnKeyFamily.PAYMENT_BASE)
        return LocalConfig(**kwargs)

    def validate_params(self, *, funding_sat: int, config: 'SimpleConfig', peer_features: 'LnFeatures') -> None:
        conf_name = type(self).__name__
        # run base checks regardless whether LOCAL/REMOTE config
        super().validate_params(funding_sat=funding_sat, config=config, peer_features=peer_features)
        # run some stricter checks on LOCAL config (make sure we ourselves do the sane thing,
        # even if we are lenient with REMOTE for compatibility reasons)
        HTLC_MINIMUM_MSAT_MIN = 1
        if self.htlc_minimum_msat < HTLC_MINIMUM_MSAT_MIN:
            raise Exception(f"{conf_name}. htlc_minimum_msat too low: {self.htlc_minimum_msat} msat < {HTLC_MINIMUM_MSAT_MIN}")

@stored_as('remote_config')
@attr.s
class RemoteConfig(ChannelConfig):
    next_per_commitment_point = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
    current_per_commitment_point = attr.ib(default=None, type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

@stored_in('fee_updates')
@attr.s
class FeeUpdate(StoredObject):
    rate = attr.ib(type=int)  # in sat/kw
    ctn_local = attr.ib(default=None, type=int)
    ctn_remote = attr.ib(default=None, type=int)

@stored_as('constraints')
@attr.s
class ChannelConstraints(StoredObject):
    flags = attr.ib(type=int, converter=int)
    capacity = attr.ib(type=int)  # in sat
    is_initiator = attr.ib(type=bool)  # note: sometimes also called "funder"
    funding_txn_minimum_depth = attr.ib(type=int)


CHANNEL_BACKUP_VERSION_LATEST = 1
KNOWN_CHANNEL_BACKUP_VERSIONS = (0, 1,)
assert CHANNEL_BACKUP_VERSION_LATEST in KNOWN_CHANNEL_BACKUP_VERSIONS

@attr.s
class ChannelBackupStorage(StoredObject):
    funding_txid = attr.ib(type=str)
    funding_index = attr.ib(type=int, converter=int)
    funding_address = attr.ib(type=str)
    is_initiator = attr.ib(type=bool)

    def funding_outpoint(self):
        return Outpoint(self.funding_txid, self.funding_index)

    def channel_id(self):
        chan_id, _ = channel_id_from_funding_tx(self.funding_txid, self.funding_index)
        return chan_id

@stored_in('onchain_channel_backups')
@attr.s
class OnchainChannelBackupStorage(ChannelBackupStorage):
    node_id_prefix = attr.ib(type=bytes, converter=hex_to_bytes)  # remote node pubkey

@stored_in('imported_channel_backups')
@attr.s
class ImportedChannelBackupStorage(ChannelBackupStorage):
    node_id = attr.ib(type=bytes, converter=hex_to_bytes)  # remote node pubkey
    privkey = attr.ib(type=bytes, converter=hex_to_bytes)  # local node privkey
    host = attr.ib(type=str)
    port = attr.ib(type=int, converter=int)
    channel_seed = attr.ib(type=bytes, converter=hex_to_bytes)
    local_delay = attr.ib(type=int, converter=int)
    remote_delay = attr.ib(type=int, converter=int)
    remote_payment_pubkey = attr.ib(type=bytes, converter=hex_to_bytes)
    remote_revocation_pubkey = attr.ib(type=bytes, converter=hex_to_bytes)
    local_payment_pubkey = attr.ib(type=bytes, converter=hex_to_bytes)  # type: Optional[bytes]

    def to_bytes(self) -> bytes:
        vds = BCDataStream()
        vds.write_uint16(CHANNEL_BACKUP_VERSION_LATEST)
        vds.write_boolean(self.is_initiator)
        vds.write_bytes(self.privkey, 32)
        vds.write_bytes(self.channel_seed, 32)
        vds.write_bytes(self.node_id, 33)
        vds.write_bytes(bfh(self.funding_txid), 32)
        vds.write_uint16(self.funding_index)
        vds.write_string(self.funding_address)
        vds.write_bytes(self.remote_payment_pubkey, 33)
        vds.write_bytes(self.remote_revocation_pubkey, 33)
        vds.write_uint16(self.local_delay)
        vds.write_uint16(self.remote_delay)
        vds.write_string(self.host)
        vds.write_uint16(self.port)
        vds.write_bytes(self.local_payment_pubkey, 33)
        return bytes(vds.input)

    @staticmethod
    def from_bytes(s: bytes) -> "ImportedChannelBackupStorage":
        vds = BCDataStream()
        vds.write(s)
        version = vds.read_uint16()
        if version not in KNOWN_CHANNEL_BACKUP_VERSIONS:
            raise Exception(f"unknown version for channel backup: {version}")
        is_initiator = vds.read_boolean()
        privkey = vds.read_bytes(32)
        channel_seed = vds.read_bytes(32)
        node_id = vds.read_bytes(33)
        funding_txid = vds.read_bytes(32).hex()
        funding_index = vds.read_uint16()
        funding_address = vds.read_string()
        remote_payment_pubkey = vds.read_bytes(33)
        remote_revocation_pubkey = vds.read_bytes(33)
        local_delay = vds.read_uint16()
        remote_delay = vds.read_uint16()
        host = vds.read_string()
        port = vds.read_uint16()
        if version >= 1:
            local_payment_pubkey = vds.read_bytes(33)
        else:
            local_payment_pubkey = None
        return ImportedChannelBackupStorage(
            is_initiator=is_initiator,
            privkey=privkey,
            channel_seed=channel_seed,
            node_id=node_id,
            funding_txid=funding_txid,
            funding_index=funding_index,
            funding_address=funding_address,
            remote_payment_pubkey=remote_payment_pubkey,
            remote_revocation_pubkey=remote_revocation_pubkey,
            local_delay=local_delay,
            remote_delay=remote_delay,
            host=host,
            port=port,
            local_payment_pubkey=local_payment_pubkey,
        )

    @staticmethod
    def from_encrypted_str(data: str, *, password: str) -> "ImportedChannelBackupStorage":
        if not data.startswith('channel_backup:'):
            raise ValueError("missing or invalid magic bytes")
        encrypted = data[15:]
        decrypted = pw_decode_with_version_and_mac(encrypted, password)
        return ImportedChannelBackupStorage.from_bytes(decrypted)


class ScriptHtlc(NamedTuple):
    redeem_script: bytes
    htlc: 'UpdateAddHtlc'


# FIXME duplicate of TxOutpoint in transaction.py??
@stored_as('funding_outpoint')
@attr.s
class Outpoint(StoredObject):
    txid = attr.ib(type=str)
    output_index = attr.ib(type=int)

    def to_str(self):
        return "{}:{}".format(self.txid, self.output_index)


class HtlcLog(NamedTuple):
    success: bool
    amount_msat: int  # amount for receiver (e.g. from invoice)
    route: Optional['LNPaymentRoute'] = None
    preimage: Optional[bytes] = None
    error_bytes: Optional[bytes] = None
    failure_msg: Optional['OnionRoutingFailure'] = None
    sender_idx: Optional[int] = None
    trampoline_fee_level: Optional[int] = None

    def formatted_tuple(self):
        route = self.route
        route_str = '%d'%len(route)
        short_channel_id = None
        if not self.success:
            sender_idx = self.sender_idx
            failure_msg = self.failure_msg
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
        return route_str, chan_str, message


class LightningError(Exception): pass
class LightningPeerConnectionClosed(LightningError): pass
class UnableToDeriveSecret(LightningError): pass
class HandshakeFailed(LightningError): pass
class ConnStringFormatError(LightningError): pass
class RemoteMisbehaving(LightningError): pass

class NotFoundChanAnnouncementForUpdate(Exception): pass
class InvalidGossipMsg(Exception):
    """e.g. signature check failed"""

class PaymentFailure(UserFacingException): pass
class NoPathFound(PaymentFailure):
    def __str__(self):
        return _('No path found')


class LNProtocolError(Exception):
    """Raised in peer methods to trigger an error message."""


class LNProtocolWarning(Exception):
    """Raised in peer methods to trigger a warning message."""



# TODO make some of these values configurable?
REDEEM_AFTER_DOUBLE_SPENT_DELAY = 30

CHANNEL_OPENING_TIMEOUT = 24*60*60

# Small capacity channels are problematic for many reasons. As the onchain fees start to become
# significant compared to the capacity, things start to break down. e.g. the counterparty
# force-closing the channel costs much of the funds in the channel.
# Closing a channel uses ~200 vbytes onchain, feerates could spike to 100 sat/vbyte or even higher;
# that in itself is already 20_000 sats. This mining fee is reserved and cannot be used for payments.
# The value below is chosen arbitrarily to be one order of magnitude higher than that.
MIN_FUNDING_SAT = 200_000

##### CLTV-expiry-delta-related values
# see https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#cltv_expiry_delta-selection

# the minimum cltv_expiry accepted for newly received HTLCs
# note: when changing, consider Blockchain.is_tip_stale()
MIN_FINAL_CLTV_DELTA_ACCEPTED = 144
# set it a tiny bit higher for invoices as blocks could get mined
# during forward path of payment
MIN_FINAL_CLTV_DELTA_FOR_INVOICE = MIN_FINAL_CLTV_DELTA_ACCEPTED + 3

# the deadline for offered HTLCs:
# the deadline after which the channel has to be failed and timed out on-chain
NBLOCK_DEADLINE_DELTA_AFTER_EXPIRY_FOR_OFFERED_HTLCS = 1

# the deadline for received HTLCs this node has fulfilled:
# the deadline after which the channel has to be failed and the HTLC fulfilled on-chain before its cltv_expiry
NBLOCK_DEADLINE_DELTA_BEFORE_EXPIRY_FOR_RECEIVED_HTLCS = 72

NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE = 28 * 144

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
                raise Exception("hash is not derivable: {} {} {}".format(e.secret.hex(), this_bucket.secret.hex(), this_bucket.index))
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

class ShachainElement(NamedTuple):
    secret: bytes
    index: int

    def __str__(self):
        return "ShachainElement(" + self.secret.hex() + "," + str(self.index) + ")"

    @stored_in('buckets', tuple)
    def read(*x):
        return ShachainElement(bfh(x[0]), int(x[1]))


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


def make_htlc_tx_output(
    amount_msat, local_feerate, revocationpubkey, local_delayedpubkey, success, to_self_delay,
) -> Tuple[bytes, PartialTxOutput]:
    assert type(amount_msat) is int
    assert type(local_feerate) is int
    script = make_commitment_output_to_local_witness_script(
        revocation_pubkey=revocationpubkey,
        to_self_delay=to_self_delay,
        delayed_pubkey=local_delayedpubkey,
    )

    p2wsh = bitcoin.redeem_script_to_address('p2wsh', script)
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
    return construct_witness([0, remotehtlcsig, localhtlcsig, payment_preimage, witness_script])

def make_htlc_tx_inputs(htlc_output_txid: str, htlc_output_index: int,
                        amount_msat: int, witness_script: bytes) -> List[PartialTxInput]:
    assert type(htlc_output_txid) is str
    assert type(htlc_output_index) is int
    assert type(amount_msat) is int
    assert type(witness_script) is bytes
    txin = PartialTxInput(prevout=TxOutpoint(txid=bfh(htlc_output_txid), out_idx=htlc_output_index),
                          nsequence=0)
    txin.witness_script = witness_script
    txin.script_sig = b''
    txin._trusted_value_sats = amount_msat // 1000
    c_inputs = [txin]
    return c_inputs

def make_htlc_tx(*, cltv_abs: int, inputs: List[PartialTxInput], output: PartialTxOutput) -> PartialTransaction:
    assert type(cltv_abs) is int
    c_outputs = [output]
    tx = PartialTransaction.from_io(inputs, c_outputs, locktime=cltv_abs, version=2)
    return tx

def make_offered_htlc(
    *,
    revocation_pubkey: bytes,
    remote_htlcpubkey: bytes,
    local_htlcpubkey: bytes,
    payment_hash: bytes,
) -> bytes:
    assert type(revocation_pubkey) is bytes
    assert type(remote_htlcpubkey) is bytes
    assert type(local_htlcpubkey) is bytes
    assert type(payment_hash) is bytes
    script = construct_script([
        opcodes.OP_DUP,
        opcodes.OP_HASH160,
        bitcoin.hash_160(revocation_pubkey),
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_CHECKSIG,
        opcodes.OP_ELSE,
        remote_htlcpubkey,
        opcodes.OP_SWAP,
        opcodes.OP_SIZE,
        32,
        opcodes.OP_EQUAL,
        opcodes.OP_NOTIF,
        opcodes.OP_DROP,
        2,
        opcodes.OP_SWAP,
        local_htlcpubkey,
        2,
        opcodes.OP_CHECKMULTISIG,
        opcodes.OP_ELSE,
        opcodes.OP_HASH160,
        crypto.ripemd(payment_hash),
        opcodes.OP_EQUALVERIFY,
        opcodes.OP_CHECKSIG,
        opcodes.OP_ENDIF,
        opcodes.OP_ENDIF,
    ])
    return script

def make_received_htlc(
    *,
    revocation_pubkey: bytes,
    remote_htlcpubkey: bytes,
    local_htlcpubkey: bytes,
    payment_hash: bytes,
    cltv_abs: int,
) -> bytes:
    for i in [revocation_pubkey, remote_htlcpubkey, local_htlcpubkey, payment_hash]:
        assert type(i) is bytes
    assert type(cltv_abs) is int

    script = construct_script([
        opcodes.OP_DUP,
        opcodes.OP_HASH160,
        bitcoin.hash_160(revocation_pubkey),
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_CHECKSIG,
        opcodes.OP_ELSE,
        remote_htlcpubkey,
        opcodes.OP_SWAP,
        opcodes.OP_SIZE,
        32,
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_HASH160,
        crypto.ripemd(payment_hash),
        opcodes.OP_EQUALVERIFY,
        2,
        opcodes.OP_SWAP,
        local_htlcpubkey,
        2,
        opcodes.OP_CHECKMULTISIG,
        opcodes.OP_ELSE,
        opcodes.OP_DROP,
        cltv_abs,
        opcodes.OP_CHECKLOCKTIMEVERIFY,
        opcodes.OP_DROP,
        opcodes.OP_CHECKSIG,
        opcodes.OP_ENDIF,
        opcodes.OP_ENDIF,
    ])
    return script

WITNESS_TEMPLATE_OFFERED_HTLC = [
    opcodes.OP_DUP,
    opcodes.OP_HASH160,
    OPPushDataGeneric(None),
    opcodes.OP_EQUAL,
    opcodes.OP_IF,
    opcodes.OP_CHECKSIG,
    opcodes.OP_ELSE,
    OPPushDataGeneric(None),
    opcodes.OP_SWAP,
    opcodes.OP_SIZE,
    OPPushDataGeneric(lambda x: x==1),
    opcodes.OP_EQUAL,
    opcodes.OP_NOTIF,
    opcodes.OP_DROP,
    opcodes.OP_2,
    opcodes.OP_SWAP,
    OPPushDataGeneric(None),
    opcodes.OP_2,
    opcodes.OP_CHECKMULTISIG,
    opcodes.OP_ELSE,
    opcodes.OP_HASH160,
    OPPushDataGeneric(None),
    opcodes.OP_EQUALVERIFY,
    opcodes.OP_CHECKSIG,
    opcodes.OP_ENDIF,
    opcodes.OP_ENDIF,
]

WITNESS_TEMPLATE_RECEIVED_HTLC = [
    opcodes.OP_DUP,
    opcodes.OP_HASH160,
    OPPushDataGeneric(None),
    opcodes.OP_EQUAL,
    opcodes.OP_IF,
    opcodes.OP_CHECKSIG,
    opcodes.OP_ELSE,
    OPPushDataGeneric(None),
    opcodes.OP_SWAP,
    opcodes.OP_SIZE,
    OPPushDataGeneric(lambda x: x==1),
    opcodes.OP_EQUAL,
    opcodes.OP_IF,
    opcodes.OP_HASH160,
    OPPushDataGeneric(None),
    opcodes.OP_EQUALVERIFY,
    opcodes.OP_2,
    opcodes.OP_SWAP,
    OPPushDataGeneric(None),
    opcodes.OP_2,
    opcodes.OP_CHECKMULTISIG,
    opcodes.OP_ELSE,
    opcodes.OP_DROP,
    OPPushDataGeneric(None),
    opcodes.OP_CHECKLOCKTIMEVERIFY,
    opcodes.OP_DROP,
    opcodes.OP_CHECKSIG,
    opcodes.OP_ENDIF,
    opcodes.OP_ENDIF,
]


def make_htlc_output_witness_script(
    *,
    is_received_htlc: bool,
    remote_revocation_pubkey: bytes,
    remote_htlc_pubkey: bytes,
    local_htlc_pubkey: bytes,
    payment_hash: bytes,
    cltv_abs: Optional[int],
) -> bytes:
    if is_received_htlc:
        return make_received_htlc(revocation_pubkey=remote_revocation_pubkey,
                                  remote_htlcpubkey=remote_htlc_pubkey,
                                  local_htlcpubkey=local_htlc_pubkey,
                                  payment_hash=payment_hash,
                                  cltv_abs=cltv_abs)
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
    amount_msat, cltv_abs, payment_hash = htlc.amount_msat, htlc.cltv_abs, htlc.payment_hash
    for_us = subject == LOCAL
    conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=for_us)

    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
    other_htlc_pubkey = derive_pubkey(other_conf.htlc_basepoint.pubkey, pcp)
    htlc_pubkey = derive_pubkey(conf.htlc_basepoint.pubkey, pcp)
    witness_script = make_htlc_output_witness_script(
        is_received_htlc=htlc_direction == RECEIVED,
        remote_revocation_pubkey=other_revocation_pubkey,
        remote_htlc_pubkey=other_htlc_pubkey,
        local_htlc_pubkey=htlc_pubkey,
        payment_hash=payment_hash,
        cltv_abs=cltv_abs,
    )
    htlc_address = redeem_script_to_address('p2wsh', witness_script)
    candidates = ctx.get_output_idxs_from_address(htlc_address)
    return {output_idx for output_idx in candidates
            if ctx.outputs()[output_idx].value == htlc.amount_msat // 1000}


def map_htlcs_to_ctx_output_idxs(*, chan: 'Channel', ctx: Transaction, pcp: bytes,
                                 subject: 'HTLCOwner', ctn: int) -> Dict[Tuple['Direction', 'UpdateAddHtlc'], Tuple[int, int]]:
    """Returns a dict from (htlc_dir, htlc) to (ctx_output_idx, htlc_relative_idx)"""
    htlc_to_ctx_output_idx_map = {}  # type: Dict[Tuple[Direction, UpdateAddHtlc], int]
    unclaimed_ctx_output_idxs = set(range(len(ctx.outputs())))
    offered_htlcs = chan.included_htlcs(subject, SENT, ctn=ctn)
    offered_htlcs.sort(key=lambda htlc: htlc.cltv_abs)
    received_htlcs = chan.included_htlcs(subject, RECEIVED, ctn=ctn)
    received_htlcs.sort(key=lambda htlc: htlc.cltv_abs)
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
    amount_msat, cltv_abs, payment_hash = htlc.amount_msat, htlc.cltv_abs, htlc.payment_hash
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
    witness_script_in = make_htlc_output_witness_script(
        is_received_htlc=is_htlc_success,
        remote_revocation_pubkey=other_revocation_pubkey,
        remote_htlc_pubkey=other_htlc_pubkey,
        local_htlc_pubkey=htlc_pubkey,
        payment_hash=payment_hash,
        cltv_abs=cltv_abs,
    )
    htlc_tx_inputs = make_htlc_tx_inputs(
        commit.txid(), ctx_output_idx,
        amount_msat=amount_msat,
        witness_script=witness_script_in)
    if is_htlc_success:
        cltv_abs = 0
    htlc_tx = make_htlc_tx(cltv_abs=cltv_abs, inputs=htlc_tx_inputs, output=htlc_tx_output)
    return witness_script_of_htlc_tx_output, htlc_tx

def make_funding_input(local_funding_pubkey: bytes, remote_funding_pubkey: bytes,
        funding_pos: int, funding_txid: str, funding_sat: int) -> PartialTxInput:
    pubkeys = sorted([local_funding_pubkey.hex(), remote_funding_pubkey.hex()])
    # commitment tx input
    prevout = TxOutpoint(txid=bfh(funding_txid), out_idx=funding_pos)
    c_input = PartialTxInput(prevout=prevout)

    ppubkeys = [descriptor.PubkeyProvider.parse(pk) for pk in pubkeys]
    multi = descriptor.MultisigDescriptor(pubkeys=ppubkeys, thresh=2, is_sorted=True)
    c_input.script_descriptor = descriptor.WSHDescriptor(subdescriptor=multi)
    c_input._trusted_value_sats = funding_sat
    return c_input


class HTLCOwner(IntEnum):
    LOCAL = 1
    REMOTE = -LOCAL

    def inverted(self) -> 'HTLCOwner':
        return -self

    def __neg__(self) -> 'HTLCOwner':
        return HTLCOwner(super().__neg__())


class Direction(IntEnum):
    SENT = -1     # in the context of HTLCs: "offered" HTLCs
    RECEIVED = 1  # in the context of HTLCs: "received" HTLCs

SENT = Direction.SENT
RECEIVED = Direction.RECEIVED

LOCAL = HTLCOwner.LOCAL
REMOTE = HTLCOwner.REMOTE

def make_commitment_outputs(*, fees_per_participant: Mapping[HTLCOwner, int], local_amount_msat: int, remote_amount_msat: int,
        local_script: bytes, remote_script: bytes, htlcs: List[ScriptHtlc], dust_limit_sat: int) -> Tuple[List[PartialTxOutput], List[PartialTxOutput]]:
    # BOLT-03: "Base commitment transaction fees are extracted from the funder's amount;
    #           if that amount is insufficient, the entire amount of the funder's output is used."
    #   -> if funder cannot afford feerate, their output might go negative, so take max(0, x) here:
    to_local_amt = max(0, local_amount_msat - fees_per_participant[LOCAL])
    to_local = PartialTxOutput(scriptpubkey=local_script, value=to_local_amt // 1000)
    to_remote_amt = max(0, remote_amount_msat - fees_per_participant[REMOTE])
    to_remote = PartialTxOutput(scriptpubkey=remote_script, value=to_remote_amt // 1000)

    non_htlc_outputs = [to_local, to_remote]
    htlc_outputs = []
    for script, htlc in htlcs:
        addr = bitcoin.redeem_script_to_address('p2wsh', script)
        htlc_outputs.append(PartialTxOutput(scriptpubkey=address_to_script(addr),
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
    htlcs.sort(key=lambda x: x.htlc.cltv_abs)

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
        revocation_pubkey: bytes, to_self_delay: int, delayed_pubkey: bytes,
) -> bytes:
    assert type(revocation_pubkey) is bytes
    assert type(to_self_delay) is int
    assert type(delayed_pubkey) is bytes
    script = construct_script([
        opcodes.OP_IF,
        revocation_pubkey,
        opcodes.OP_ELSE,
        to_self_delay,
        opcodes.OP_CHECKSEQUENCEVERIFY,
        opcodes.OP_DROP,
        delayed_pubkey,
        opcodes.OP_ENDIF,
        opcodes.OP_CHECKSIG,
    ])
    return script

def make_commitment_output_to_local_address(
        revocation_pubkey: bytes, to_self_delay: int, delayed_pubkey: bytes) -> str:
    local_script = make_commitment_output_to_local_witness_script(revocation_pubkey, to_self_delay, delayed_pubkey)
    return bitcoin.redeem_script_to_address('p2wsh', local_script)

def make_commitment_output_to_remote_address(remote_payment_pubkey: bytes) -> str:
    return bitcoin.pubkey_to_address('p2wpkh', remote_payment_pubkey.hex())

def sign_and_get_sig_string(tx: PartialTransaction, local_config, remote_config):
    tx.sign({local_config.multisig_key.pubkey: local_config.multisig_key.privkey})
    sig = tx.inputs()[0].sigs_ecdsa[local_config.multisig_key.pubkey]
    sig_64 = ecdsa_sig64_from_der_sig(sig[:-1])
    return sig_64

def funding_output_script(local_config: 'LocalConfig', remote_config: 'RemoteConfig') -> bytes:
    return funding_output_script_from_keys(local_config.multisig_key.pubkey, remote_config.multisig_key.pubkey)

def funding_output_script_from_keys(pubkey1: bytes, pubkey2: bytes) -> bytes:
    pubkeys = sorted([pubkey1.hex(), pubkey2.hex()])
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
    _ln_feature_contexts[OPTION_SUPPORT_LARGE_CHANNEL_OPT] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_SUPPORT_LARGE_CHANNEL_REQ] = (LNFC.INIT | LNFC.NODE_ANN)

    # Temporary number.
    OPTION_TRAMPOLINE_ROUTING_REQ_ECLAIR = 1 << 148
    OPTION_TRAMPOLINE_ROUTING_OPT_ECLAIR = 1 << 149

    _ln_feature_contexts[OPTION_TRAMPOLINE_ROUTING_REQ_ECLAIR] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)
    _ln_feature_contexts[OPTION_TRAMPOLINE_ROUTING_OPT_ECLAIR] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)

    # We use a different bit because Phoenix cannot do end-to-end multi-trampoline routes
    OPTION_TRAMPOLINE_ROUTING_REQ_ELECTRUM = 1 << 150
    OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM = 1 << 151

    _ln_feature_contexts[OPTION_TRAMPOLINE_ROUTING_REQ_ELECTRUM] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)
    _ln_feature_contexts[OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM] = (LNFC.INIT | LNFC.NODE_ANN | LNFC.INVOICE)

    OPTION_SHUTDOWN_ANYSEGWIT_REQ = 1 << 26
    OPTION_SHUTDOWN_ANYSEGWIT_OPT = 1 << 27

    _ln_feature_contexts[OPTION_SHUTDOWN_ANYSEGWIT_REQ] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_SHUTDOWN_ANYSEGWIT_OPT] = (LNFC.INIT | LNFC.NODE_ANN)

    OPTION_CHANNEL_TYPE_REQ = 1 << 44
    OPTION_CHANNEL_TYPE_OPT = 1 << 45

    _ln_feature_contexts[OPTION_CHANNEL_TYPE_REQ] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_CHANNEL_TYPE_OPT] = (LNFC.INIT | LNFC.NODE_ANN)

    OPTION_SCID_ALIAS_REQ = 1 << 46
    OPTION_SCID_ALIAS_OPT = 1 << 47

    _ln_feature_contexts[OPTION_SCID_ALIAS_REQ] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_SCID_ALIAS_OPT] = (LNFC.INIT | LNFC.NODE_ANN)

    OPTION_ZEROCONF_REQ = 1 << 50
    OPTION_ZEROCONF_OPT = 1 << 51

    _ln_feature_direct_dependencies[OPTION_ZEROCONF_OPT] = {OPTION_SCID_ALIAS_OPT}
    _ln_feature_contexts[OPTION_ZEROCONF_REQ] = (LNFC.INIT | LNFC.NODE_ANN)
    _ln_feature_contexts[OPTION_ZEROCONF_OPT] = (LNFC.INIT | LNFC.NODE_ANN)

    def validate_transitive_dependencies(self) -> bool:
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

    def supports(self, feature: 'LnFeatures') -> bool:
        """Returns whether given feature is enabled.

        Helper function that tries to hide the complexity of even/odd bits.
        For example, instead of:
          bool(myfeatures & LnFeatures.VAR_ONION_OPT or myfeatures & LnFeatures.VAR_ONION_REQ)
        you can do:
          myfeatures.supports(LnFeatures.VAR_ONION_OPT)
        """
        if (1 << (feature.bit_length() - 1)) != feature:
            raise ValueError(f"'feature' cannot be a combination of features: {feature}")
        if feature.bit_length() % 2 == 0:  # feature is OPT
            feature_other = feature >> 1
        else:  # feature is REQ
            feature_other = feature << 1
        return (self & feature != 0) or (self & feature_other != 0)

    def get_names(self) -> Sequence[str]:
        r = []
        for flag in list_enabled_bits(self):
            feature_name = LnFeatures(1 << flag).name
            r.append(feature_name or f"bit_{flag}")
        return r

    if hasattr(IntFlag, "_numeric_repr_"):  # python 3.11+
        # performance improvement (avoid base2<->base10), see #8403
        _numeric_repr_ = hex

    def __repr__(self):
        # performance improvement (avoid base2<->base10), see #8403
        return f"<{self._name_}: {hex(self._value_)}>"

    def __str__(self):
        # performance improvement (avoid base2<->base10), see #8403
        return hex(self._value_)


@stored_as('channel_type', _type=None)
class ChannelType(IntFlag):
    OPTION_LEGACY_CHANNEL = 0
    OPTION_STATIC_REMOTEKEY = 1 << 12
    OPTION_ANCHOR_OUTPUTS = 1 << 20
    OPTION_ANCHORS_ZERO_FEE_HTLC_TX = 1 << 22
    OPTION_SCID_ALIAS = 1 << 46
    OPTION_ZEROCONF = 1 << 50

    def discard_unknown_and_check(self):
        """Discards unknown flags and checks flag combination."""
        flags = list_enabled_bits(self)
        known_channel_types = []
        for flag in flags:
            channel_type = ChannelType(1 << flag)
            if channel_type.name:
                known_channel_types.append(channel_type)
        final_channel_type = known_channel_types[0]
        for channel_type in known_channel_types[1:]:
            final_channel_type |= channel_type

        final_channel_type.check_combinations()
        return final_channel_type

    def check_combinations(self):
        basic_type = self & ~(ChannelType.OPTION_SCID_ALIAS | ChannelType.OPTION_ZEROCONF)
        if basic_type not in [
                ChannelType.OPTION_STATIC_REMOTEKEY,
                ChannelType.OPTION_ANCHOR_OUTPUTS | ChannelType.OPTION_STATIC_REMOTEKEY,
                ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX | ChannelType.OPTION_STATIC_REMOTEKEY
        ]:
            raise ValueError("Channel type is not a valid flag combination.")

    def complies_with_features(self, features: LnFeatures) -> bool:
        flags = list_enabled_bits(self)
        complies = True
        for flag in flags:
            feature = LnFeatures(1 << flag)
            complies &= features.supports(feature)
        return complies

    def to_bytes_minimal(self):
        # MUST use the smallest bitmap possible to represent the channel type.
        bit_length =self.value.bit_length()
        byte_length = bit_length // 8 + int(bool(bit_length % 8))
        return self.to_bytes(byte_length, byteorder='big')

    @property
    def name_minimal(self):
        if self.name:
            return self.name.replace('OPTION_', '')
        else:
            return str(self)


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
        | LnFeatures.BASIC_MPP_OPT | LnFeatures.BASIC_MPP_REQ
        | LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM | LnFeatures.OPTION_TRAMPOLINE_ROUTING_REQ_ELECTRUM
        | LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_OPT | LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_REQ
        | LnFeatures.OPTION_CHANNEL_TYPE_OPT | LnFeatures.OPTION_CHANNEL_TYPE_REQ
        | LnFeatures.OPTION_SCID_ALIAS_OPT | LnFeatures.OPTION_SCID_ALIAS_REQ
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


if hasattr(sys, "get_int_max_str_digits"):
    # check that the user or other library has not lowered the limit (from default)
    assert sys.get_int_max_str_digits() >= 4300, f"sys.get_int_max_str_digits() too low: {sys.get_int_max_str_digits()}"


def validate_features(features: int) -> LnFeatures:
    """Raises IncompatibleOrInsaneFeatures if
    - a mandatory feature is listed that we don't recognize, or
    - the features are inconsistent
    For convenience, returns the parsed features.
    """
    if features.bit_length() > 10_000:
        # This is an implementation-specific limit for how high feature bits we allow.
        # Needed as LnFeatures subclasses IntFlag, and uses ints internally.
        # See https://docs.python.org/3/library/stdtypes.html#integer-string-conversion-length-limitation
        raise IncompatibleOrInsaneFeatures(f"features bitvector too large: {features.bit_length()=} > 10_000")
    features = LnFeatures(features)
    enabled_features = list_enabled_bits(features)
    for fbit in enabled_features:
        if (1 << fbit) & LN_FEATURES_IMPLEMENTED == 0 and fbit % 2 == 0:
            raise UnknownEvenFeatureBits(fbit)
    if not features.validate_transitive_dependencies():
        raise IncompatibleOrInsaneFeatures(f"not all transitive dependencies are set. "
                                           f"features={features}")
    return features


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
    # note: while not programmatically enforced, this class is meant to be *immutable*

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
        self._net_addr = net_addr

    def __str__(self):
        return '{}@{}'.format(self.pubkey.hex(), self.net_addr_str())

    @classmethod
    def from_str(cls, s):
        node_id, rest = extract_nodeid(s)
        host, port = split_host_port(rest)
        return LNPeerAddr(host, int(port), node_id)

    def __repr__(self):
        return f'<LNPeerAddr host={self.host} port={self.port} pubkey={self.pubkey.hex()}>'

    def net_addr(self) -> NetAddress:
        return self._net_addr

    def net_addr_str(self) -> str:
        return str(self._net_addr)

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
    decoded_bech32 = segwit_addr.bech32_decode(bech32_pubkey)
    hrp = decoded_bech32.hrp
    data_5bits = decoded_bech32.data
    if decoded_bech32.encoding is None:
        raise ValueError("Bad bech32 checksum")
    if decoded_bech32.encoding != segwit_addr.Encoding.BECH32:
        raise ValueError("Bad bech32 encoding: must be using vanilla BECH32")
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


def extract_nodeid(connect_contents: str) -> Tuple[bytes, Optional[str]]:
    """Takes a connection-string-like str, and returns a tuple (node_id, rest),
    where rest is typically a host (with maybe port). Examples:
    - extract_nodeid(pubkey@host:port) == (pubkey, host:port)
    - extract_nodeid(pubkey@host) == (pubkey, host)
    - extract_nodeid(pubkey) == (pubkey, None)
    - extract_nodeid(bolt11_invoice) == (pubkey, None)
    Can raise ConnStringFormatError.
    """
    rest = None
    try:
        # connection string?
        nodeid_hex, rest = connect_contents.split("@", 1)
    except ValueError:
        try:
            # invoice?
            invoice = lndecode(connect_contents)
            nodeid_bytes = invoice.pubkey.serialize()
            nodeid_hex = nodeid_bytes.hex()
        except Exception:
            # node id as hex?
            nodeid_hex = connect_contents
    if rest == '':
        raise ConnStringFormatError(_('At least a hostname must be supplied after the at symbol.'))
    try:
        node_id = bfh(nodeid_hex)
        if len(node_id) != 33:
            raise Exception()
    except Exception:
        raise ConnStringFormatError(_('Invalid node ID, must be 33 bytes and hexadecimal'))
    return node_id, rest


# key derivation
# originally based on lnd/keychain/derivation.go
# notes:
# - Add a new path for each use case. Do not reuse existing paths.
#   (to avoid having to carefully consider if reuse would be safe)
# - Always prefer to use hardened derivation for new paths you add.
#   (to avoid having to carefully consider if unhardened would be safe)
class LnKeyFamily(IntEnum):
    MULTISIG = 0 | BIP32_PRIME
    REVOCATION_BASE = 1 | BIP32_PRIME
    HTLC_BASE = 2 | BIP32_PRIME
    PAYMENT_BASE = 3 | BIP32_PRIME
    DELAY_BASE = 4 | BIP32_PRIME
    REVOCATION_ROOT = 5 | BIP32_PRIME
    NODE_KEY = 6
    BACKUP_CIPHER = 7 | BIP32_PRIME
    PAYMENT_SECRET_KEY = 8 | BIP32_PRIME


def generate_keypair(node: BIP32Node, key_family: LnKeyFamily) -> Keypair:
    node2 = node.subkey_at_private_derivation([key_family, 0, 0])
    k = node2.eckey.get_secret_bytes()
    cK = ecc.ECPrivkey(k).get_public_key_bytes()
    return Keypair(cK, k)



NUM_MAX_HOPS_IN_PAYMENT_PATH = 20
NUM_MAX_EDGES_IN_PAYMENT_PATH = NUM_MAX_HOPS_IN_PAYMENT_PATH





@attr.s(frozen=True)
class UpdateAddHtlc:
    amount_msat = attr.ib(type=int, kw_only=True)
    payment_hash = attr.ib(type=bytes, kw_only=True, converter=hex_to_bytes, repr=lambda val: val.hex())
    cltv_abs = attr.ib(type=int, kw_only=True)
    timestamp = attr.ib(type=int, kw_only=True)
    htlc_id = attr.ib(type=int, kw_only=True, default=None)

    @stored_in('adds', tuple)
    def from_tuple(amount_msat, payment_hash, cltv_abs, htlc_id, timestamp) -> 'UpdateAddHtlc':
        return UpdateAddHtlc(
            amount_msat=amount_msat,
            payment_hash=payment_hash,
            cltv_abs=cltv_abs,
            htlc_id=htlc_id,
            timestamp=timestamp)

    def to_json(self):
        return (self.amount_msat, self.payment_hash, self.cltv_abs, self.htlc_id, self.timestamp)


class OnionFailureCodeMetaFlag(IntFlag):
    BADONION = 0x8000
    PERM     = 0x4000
    NODE     = 0x2000
    UPDATE   = 0x1000


class PaymentFeeBudget(NamedTuple):
    fee_msat: int

    # The cltv budget covers the cost of route to get to the destination, but excluding the
    # cltv-delta the destination wants for itself. (e.g. "min_final_cltv_delta" is excluded)
    cltv: int  # this is cltv-delta-like, no absolute heights here!

    #num_htlc: int

    @classmethod
    def default(cls, *, invoice_amount_msat: int, config: 'SimpleConfig') -> 'PaymentFeeBudget':
        millionths_orig = config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS
        millionths = min(max(0, millionths_orig), 250_000)  # clamp into [0, 25%]
        cutoff_orig = config.LIGHTNING_PAYMENT_FEE_CUTOFF_MSAT
        cutoff = min(max(0, cutoff_orig), 10_000_000)  # clamp into [0, 10k sat]
        if millionths != millionths_orig:
            _logger.warning(
                f"PaymentFeeBudget. found insane fee millionths in config. "
                f"clamped: {millionths_orig}->{millionths}")
        if cutoff != cutoff_orig:
            _logger.warning(
                f"PaymentFeeBudget. found insane fee cutoff in config. "
                f"clamped: {cutoff_orig}->{cutoff}")
        # for small payments, fees <= constant cutoff are fine
        # for large payments, the max fee is percentage-based
        fee_msat = invoice_amount_msat * millionths // 1_000_000
        fee_msat = max(fee_msat, cutoff)
        return PaymentFeeBudget(
            fee_msat=fee_msat,
            cltv=NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE,
        )
