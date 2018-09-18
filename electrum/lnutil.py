from enum import IntFlag
import json
from collections import namedtuple
from typing import NamedTuple

from .util import bfh, bh2u, inv_dict
from .crypto import sha256
from .transaction import Transaction
from .ecc import CURVE_ORDER, sig_string_from_der_sig, ECPubkey, string_to_number
from . import ecc, bitcoin, crypto, transaction
from .transaction import opcodes, TxOutput
from .bitcoin import push_script
from . import segwit_addr

HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703

Keypair = namedtuple("Keypair", ["pubkey", "privkey"])
ChannelConfig = namedtuple("ChannelConfig", [
    "payment_basepoint", "multisig_key", "htlc_basepoint", "delayed_basepoint", "revocation_basepoint",
    "to_self_delay", "dust_limit_sat", "max_htlc_value_in_flight_msat", "max_accepted_htlcs", "initial_msat"])
OnlyPubkeyKeypair = namedtuple("OnlyPubkeyKeypair", ["pubkey"])
RemoteState = namedtuple("RemoteState", ["ctn", "next_per_commitment_point", "amount_msat", "revocation_store", "current_per_commitment_point", "next_htlc_id", "feerate"])
LocalState = namedtuple("LocalState", ["ctn", "per_commitment_secret_seed", "amount_msat", "next_htlc_id", "funding_locked_received", "was_announced", "current_commitment_signature", "current_htlc_signatures", "feerate"])
ChannelConstraints = namedtuple("ChannelConstraints", ["capacity", "is_initiator", "funding_txn_minimum_depth"])
#OpenChannel = namedtuple("OpenChannel", ["channel_id", "short_channel_id", "funding_outpoint", "local_config", "remote_config", "remote_state", "local_state", "constraints", "node_id"])

class Outpoint(NamedTuple("Outpoint", [('txid', str), ('output_index', int)])):
    def to_str(self):
        return "{}:{}".format(self.txid, self.output_index)


class UnableToDeriveSecret(Exception): pass


class RevocationStore:
    """ taken from lnd """

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

def derive_pubkey(basepoint: bytes, per_commitment_point: bytes) -> bytes:
    p = ecc.ECPubkey(basepoint) + ecc.generator() * ecc.string_to_number(sha256(per_commitment_point + basepoint))
    return p.get_public_key_bytes()

def derive_privkey(secret: int, per_commitment_point: bytes) -> int:
    assert type(secret) is int
    basepoint = secret_to_pubkey(secret)
    basepoint = secret + ecc.string_to_number(sha256(per_commitment_point + basepoint))
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
        + bytes([opcodes.OP_CSV, opcodes.OP_DROP]) \
        + bfh(push_script(bh2u(local_delayedpubkey))) \
        + bytes([opcodes.OP_ENDIF, opcodes.OP_CHECKSIG])

    p2wsh = bitcoin.redeem_script_to_address('p2wsh', bh2u(script))
    weight = HTLC_SUCCESS_WEIGHT if success else HTLC_TIMEOUT_WEIGHT
    fee = local_feerate * weight
    fee = fee // 1000 * 1000
    final_amount_sat = (amount_msat - fee) // 1000
    assert final_amount_sat > 0, final_amount_sat
    output = TxOutput(bitcoin.TYPE_ADDRESS, p2wsh, final_amount_sat)
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
        local_feerate = chan.pending_feerate(LOCAL if for_us else REMOTE),
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


def make_commitment(ctn, local_funding_pubkey, remote_funding_pubkey,
                    remote_payment_pubkey, payment_basepoint,
                    remote_payment_basepoint, revocation_pubkey,
                    delayed_pubkey, to_self_delay, funding_txid,
                    funding_pos, funding_sat, local_amount, remote_amount,
                    dust_limit_sat, local_feerate, for_us, we_are_initiator,
                    htlcs):

    pubkeys = sorted([bh2u(local_funding_pubkey), bh2u(remote_funding_pubkey)])
    payments = [payment_basepoint, remote_payment_basepoint]
    if not we_are_initiator:
        payments.reverse()
    obs = get_obscured_ctn(ctn, *payments)
    locktime = (0x20 << 24) + (obs & 0xffffff)
    sequence = (0x80 << 24) + (obs >> 24)
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
    local_address = make_commitment_output_to_local_address(revocation_pubkey, to_self_delay, delayed_pubkey)
    remote_address = make_commitment_output_to_remote_address(remote_payment_pubkey)
    # TODO trim htlc outputs here while also considering 2nd stage htlc transactions
    fee = local_feerate * overall_weight(len(htlcs))
    fee = fee // 1000 * 1000
    we_pay_fee = for_us == we_are_initiator
    to_local_amt = local_amount - (fee if we_pay_fee else 0)
    to_local = TxOutput(bitcoin.TYPE_ADDRESS, local_address, to_local_amt // 1000)
    to_remote_amt = remote_amount - (fee if not we_pay_fee else 0)
    to_remote = TxOutput(bitcoin.TYPE_ADDRESS, remote_address, to_remote_amt // 1000)
    c_outputs = [to_local, to_remote]
    for script, msat_amount in htlcs:
        c_outputs += [TxOutput(bitcoin.TYPE_ADDRESS,
                               bitcoin.redeem_script_to_address('p2wsh', bh2u(script)),
                               msat_amount // 1000)]

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

def make_commitment_output_to_local_witness_script(
        revocation_pubkey: bytes, to_self_delay: int, delayed_pubkey: bytes) -> bytes:
    local_script = bytes([opcodes.OP_IF]) + bfh(push_script(bh2u(revocation_pubkey))) + bytes([opcodes.OP_ELSE]) + bitcoin.add_number_to_script(to_self_delay) \
                   + bytes([opcodes.OP_CSV, opcodes.OP_DROP]) + bfh(push_script(bh2u(delayed_pubkey))) + bytes([opcodes.OP_ENDIF, opcodes.OP_CHECKSIG])
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

def get_obscured_ctn(ctn: int, local: bytes, remote: bytes) -> int:
    mask = int.from_bytes(sha256(local + remote)[-6:], 'big')
    return ctn ^ mask

def extract_ctn_from_tx(tx, txin_index: int, local_payment_basepoint: bytes,
                        remote_payment_basepoint: bytes) -> int:
    tx.deserialize()
    locktime = tx.locktime
    sequence = tx.inputs()[txin_index]['sequence']
    obs = ((sequence & 0xffffff) << 24) + (locktime & 0xffffff)
    return get_obscured_ctn(obs, local_payment_basepoint, remote_payment_basepoint)

def extract_ctn_from_tx_and_chan(tx, chan) -> int:
    local_pubkey = chan.local_config.payment_basepoint.pubkey
    remote_pubkey = chan.remote_config.payment_basepoint.pubkey
    return extract_ctn_from_tx(tx, txin_index=0,
                               local_payment_basepoint=local_pubkey,
                               remote_payment_basepoint=remote_pubkey)

def overall_weight(num_htlc):
    return 500 + 172 * num_htlc + 224

def get_ecdh(priv: bytes, pub: bytes) -> bytes:
    pt = ECPubkey(pub) * string_to_number(priv)
    return sha256(pt.get_public_key_bytes())


LN_LOCAL_FEATURE_BITS = {
    0: 'option_data_loss_protect_req',
    1: 'option_data_loss_protect_opt',
    3: 'initial_routing_sync',
    4: 'option_upfront_shutdown_script_req',
    5: 'option_upfront_shutdown_script_opt',
    6: 'gossip_queries_req',
    7: 'gossip_queries_opt',
}
LN_LOCAL_FEATURE_BITS_INV = inv_dict(LN_LOCAL_FEATURE_BITS)

LN_GLOBAL_FEATURE_BITS = {}
LN_GLOBAL_FEATURE_BITS_INV = inv_dict(LN_GLOBAL_FEATURE_BITS)


class LNPeerAddr(namedtuple('LNPeerAddr', ['host', 'port', 'pubkey'])):
    __slots__ = ()

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


class PaymentFailure(Exception): pass

class HTLCOwner(IntFlag):
    LOCAL = 1
    REMOTE = -LOCAL

    SENT = LOCAL
    RECEIVED = REMOTE

SENT = HTLCOwner.SENT
RECEIVED = HTLCOwner.RECEIVED
LOCAL = HTLCOwner.LOCAL
REMOTE = HTLCOwner.REMOTE
