#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Some basic validation primitives
"""

from . import fusion_pb2 as pb
from . import pedersen
from .util import FusionError, sha256, size_of_input, size_of_output, component_fee, dust_limit, pubkeys_from_privkey
from . import encrypt
from .protocol import Protocol

from electroncash.address import Address
from electroncash.transaction import TYPE_ADDRESS, get_address_from_output_script
import electroncash.schnorr as schnorr

from google.protobuf.message import DecodeError


class ValidationError(FusionError):
    # This specifically regards malformed requests.
    def __str__(self):
        return f'Validation error: {self.args[0]}'


def component_contrib(component, feerate):
    ctype = component.WhichOneof('component')
    if ctype == 'input':
        inp = component.input
        return inp.amount - component_fee(size_of_input(inp.pubkey), feerate)
    elif ctype == 'output':
        out = component.output
        return - out.amount - component_fee(size_of_output(out.scriptpubkey), feerate)
    elif ctype == 'blank':
        return 0

def check(boolean, fail_message):
    if not boolean:
        raise ValidationError(fail_message)

def proto_strict_parse(msg, blob):
    """Perform a very strict parsing of the binary blob into the given protobuf
    type."""
    try:
        if msg.ParseFromString(blob) != len(blob):
            raise DecodeError
    except DecodeError:
        raise ValidationError("decode error")
    check(msg.IsInitialized(), "missing fields")
    check(not msg.UnknownFields(), "has extra fields")
    # Protobuf silently ignores unwanted repeated tags, and gives no direct way
    # to detect this. This sucks because it means someone could send us a giant
    # message even if we check all fields' lengths. This is the only way to
    # detect it.
    check(msg.ByteSize() == len(blob), "encoding too long")
    return msg


def check_playercommit(msg, min_excess_fee, max_excess_fee, num_components):
    # validate a PlayerCommit message; return the parsed InitialCommitments
    check(len(msg.initial_commitments) == num_components, "wrong number of component commitments")
    check(len(msg.blind_sig_requests) == num_components, "wrong number of blind sig requests")

    check(min_excess_fee <= msg.excess_fee <= max_excess_fee, "bad excess fee")
    check(len(msg.random_number_commitment) == 32, "bad random commit")
    check(len(msg.pedersen_total_nonce) == 32, "bad nonce")
    check(all(len(r) == 32 for r in msg.blind_sig_requests), "bad blind sig request")

    commit_messages = []
    for cblob in msg.initial_commitments:
        cmsg = proto_strict_parse(pb.InitialCommitment(), cblob)
        check(len(cmsg.salted_component_hash) == 32, "bad salted hash")
        P = cmsg.amount_commitment
        check(len(P) == 65 and P[0] == 4, "bad commitment point")
        check(len(cmsg.communication_key) == 33 and cmsg.communication_key[0] in (2,3), "bad communication key")
        commit_messages.append(cmsg)

    # Verify pedersen commitment
    try:
        pointsum = pedersen.add_points([m.amount_commitment for m in commit_messages])
        claimed_commit = Protocol.PEDERSEN.commit(msg.excess_fee, int.from_bytes(msg.pedersen_total_nonce,'big'))
    except Exception as e:
        raise ValidationError("pedersen commitment verification error")
    check(pointsum == claimed_commit.P_uncompressed, "pedersen commitment mismatch")

    return commit_messages

def check_covert_component(msg, round_pubkey, component_feerate):
    message_hash = sha256(msg.component)
    check(len(msg.signature) == 64, "bad message signature")
    check(schnorr.verify(round_pubkey, msg.signature, message_hash), "bad message signature")

    cmsg = proto_strict_parse(pb.Component(), msg.component)
    check(len(cmsg.salt_commitment) == 32, "bad salt commitment")
    ctype = cmsg.WhichOneof('component')
    if ctype == 'input':
        inp = cmsg.input
        check(len(inp.prev_txid) == 32, "bad txid")
        check(   (len(inp.pubkey) == 33 and inp.pubkey[0] in (2,3))
              or (len(inp.pubkey) == 65 and inp.pubkey[0] == 4),
              "bad pubkey")
        sort_key = ('i', inp.prev_txid[::-1], inp.prev_index, cmsg.salt_commitment)
    elif ctype == 'output':
        out = cmsg.output
        atype, addr = get_address_from_output_script(out.scriptpubkey)
        check(atype == TYPE_ADDRESS, "output is not address")
        check(out.amount >= dust_limit(len(out.scriptpubkey)), "dust output")
        sort_key = ('o', out.amount, out.scriptpubkey, cmsg.salt_commitment)
    elif ctype == 'blank':
        sort_key = ('b', cmsg.salt_commitment)
    else:
        raise ValidationError('missing component details')

    # Note: for each sort type we use salt_commitment as a tie-breaker, just to
    # make sure that original ordering is forgotten. Of course salt_commitment
    # doesn't have to be unique, but it's unique for all honest players.

    return sort_key, component_contrib(cmsg, component_feerate)

def validate_proof_internal(proofblob, commitment, all_components, bad_components, component_feerate):
    """ Validate a proof as far as we can without checking blockchain.

    Returns the deserialized InputComponent for further checking, if it was an
    input. """
    msg = proto_strict_parse(pb.Proof(), proofblob)

    try:
        componentblob = all_components[msg.component_idx]
    except IndexError:
        raise ValidationError("component index out of range")

    check(msg.component_idx not in bad_components, "component in bad list")

    # these deserializations should always succeed since we've already done them before.
    comp = pb.Component()
    comp.ParseFromString(componentblob)
    assert comp.IsInitialized()

    check(len(msg.salt) == 32, "salt wrong length")
    check(sha256(msg.salt) == comp.salt_commitment, "salt commitment mismatch")
    check(sha256(msg.salt + componentblob) == commitment.salted_component_hash, "salted component hash mismatch")

    contrib = component_contrib(comp, component_feerate)

    P_committed = commitment.amount_commitment
    claimed_commit = Protocol.PEDERSEN.commit(contrib, int.from_bytes(msg.pedersen_nonce,'big'))
    check(P_committed == claimed_commit.P_uncompressed, "pedersen commitment mismatch")

    if comp.WhichOneof('component') == 'input':
        return comp.input
    else:
        return None


def validate_blame(blame, encproof, src_commit_blob, dest_commit_blob, all_components, bad_components, component_feerate):
    """ Validate a BlameProof. Can:
    - return string indicating why the accused (src) is guilty
    - raise ValidationError, if the accuser (dest) was blatantly wrong.
    - return input component for further investigation, if everything internal checked out.
    """
    dest_commit = pb.InitialCommitment()
    dest_commit.ParseFromString(dest_commit_blob)
    dest_pubkey = dest_commit.communication_key

    src_commit = pb.InitialCommitment()
    src_commit.ParseFromString(src_commit_blob)

    decrypter = blame.WhichOneof('decrypter')
    if decrypter == 'privkey':
        privkey = blame.privkey
        check(len(privkey) == 32, 'bad blame privkey')
        pubU, pubC = pubkeys_from_privkey(privkey)
        check(dest_commit.communication_key == pubC, 'bad blame privkey')
        try:
            encrypt.decrypt(encproof, privkey)
        except encrypt.DecryptionFailed:
            # good! the blame was telling us about decryption failure and they were right.
            return 'undecryptable'
        raise ValidationError('blame gave privkey but decryption worked')
    elif decrypter != 'session_key':
        raise ValidationError('unknown blame decrypter')
    key = blame.session_key
    check(len(key) == 32, 'bad blame session key')
    try:
        proofblob = encrypt.decrypt_with_symmkey(encproof, key)
    except encrypt.DecryptionFailed:
        raise ValidationError('bad blame session key')

    try:
        inpcomp = validate_proof_internal(proofblob, src_commit, all_components, bad_components, component_feerate)
    except ValidationError as e:
        # good! the blame told us something was wrong, and it was right
        return e.args[0]

    # OK so the proof was good and internally consistent, that means the only
    # reason they should be sending us a blame is if it's an inconsistency with
    # blockchain.
    if not blame.need_lookup_blockchain:
        raise ValidationError('blame indicated internal inconsistency, none found!')

    if inpcomp is None:
        raise ValidationError('blame indicated blockchain error on a non-input component')

    return inpcomp


def check_input_electrumx(network, inpcomp):
    """ Check an InputComponent against electrumx service. This can be a bit slow
    since it gets all utxos on that address.

    Returns normally if the check passed. Raises ValidationError if the input is not
    consistent with blockchain (according to server), and raises other exceptions if
    the server times out or gives an unexpected kind of response.
    """
    address = Address.from_pubkey(inpcomp.pubkey)
    prevhash = inpcomp.prev_txid[::-1].hex()
    prevn = inpcomp.prev_index
    sh = address.to_scripthash_hex()
    u = network.synchronous_get(('blockchain.scripthash.listunspent', [sh]), timeout=5)
    for item in u:
        if prevhash == item['tx_hash'] and prevn == item['tx_pos']:
            break
    else:
        raise ValidationError('missing or spent or scriptpubkey mismatch')

    check(item['height'] > 0, 'not confirmed')
    check(item['value'] == inpcomp.amount, 'amount mismatch')
    # Not checked: is it a coinbase? is it matured?
    # A feasible strategy to identify unmatured coinbase is to cache the results
    # of blockchain.transaction.id_from_pos(height, 0) from the last 100 blocks.
