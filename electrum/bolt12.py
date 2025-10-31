# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum developers
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

import copy
import io
import os
import time
from decimal import Decimal

from typing import TYPE_CHECKING, Union, Optional, List, Tuple, Sequence

import electrum_ecc as ecc

from . import constants
from .bitcoin import COIN
from .crypto import sha256
from .lnaddr import LnAddr
from .lnmsg import OnionWireSerializer, batched
from .onion_message import Timeout, get_blinded_paths_to_me
from .segwit_addr import bech32_decode, DecodedBech32, convertbits

if TYPE_CHECKING:
    from .lnworker import LNWallet


def is_offer(data: str) -> bool:
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    if d == DecodedBech32(None, None, None):
        return False
    return d.hrp == 'lno'


def matches_our_chain(chains: bytes) -> bool:
    # chains is a 32 bytes record list stored in a single bytes object (see TODO above lnmsg._read_field)
    if not chains:
        # empty chains is indicative of only Bitcoin mainnet
        return True if constants.net == constants.BitcoinMainnet else False
    chains = list(batched(chains, 32))
    chain_hash = constants.net.rev_genesis_bytes()
    return tuple(chain_hash) in chains


def bolt12_bech32_to_bytes(data: str) -> bytes:
    d = bech32_decode(data, ignore_long_length=True, with_checksum=False)
    d = bytes(convertbits(d.data, 5, 8))
    # we bomb on trailing 0, remove
    while d[-1] == 0:
        d = d[:-1]
    return d

def decode_offer(data: Union[str, bytes]) -> dict:
    d = bolt12_bech32_to_bytes(data) if isinstance(data, str) else data
    with io.BytesIO(d) as f:
        result = OnionWireSerializer.read_tlv_stream(fd=f, tlv_stream_name='offer')
    offer_chains = result.get('offer_chains')
    chains = offer_chains.get('chains') if offer_chains else None
    if not matches_our_chain(chains):
        raise Exception('no matching chain')
    return result


def decode_invoice_request(data: Union[str, bytes]) -> dict:
    d = bolt12_bech32_to_bytes(data) if isinstance(data, str) else data
    with io.BytesIO(d) as f:
        result = OnionWireSerializer.read_tlv_stream(fd=f, tlv_stream_name='invoice_request', signing_key_path=['invreq_payer_id', 'key'])
    invreq_chain = result.get('invreq_chain')
    chain = invreq_chain.get('chain') if invreq_chain else None
    if not matches_our_chain(chain):
        raise Exception('no matching chain')
    return result


def decode_invoice(data: Union[str, bytes]) -> dict:
    d = bolt12_bech32_to_bytes(data) if isinstance(data, str) else data
    with io.BytesIO(d) as f:
        return OnionWireSerializer.read_tlv_stream(fd=f, tlv_stream_name='invoice', signing_key_path=['invoice_node_id', 'node_id'])


def encode_offer(data: dict):
    with io.BytesIO() as fd:
        OnionWireSerializer.write_tlv_stream(fd=fd, tlv_stream_name='offer', **data)
        return fd.getvalue()


def encode_invoice_request(data: dict, payer_key: bytes) -> bytes:
    with io.BytesIO() as fd:
        OnionWireSerializer.write_tlv_stream(fd=fd, tlv_stream_name='invoice_request', signing_key=payer_key, **data)
        return fd.getvalue()


def encode_invoice(data: dict, signing_key: bytes) -> bytes:
    with io.BytesIO() as fd:
        OnionWireSerializer.write_tlv_stream(fd=fd, tlv_stream_name='invoice', signing_key=signing_key, **data)
        return fd.getvalue()


def to_lnaddr(data: dict) -> LnAddr:
    # FIXME: abusing BOLT11 oriented LnAddr for BOLT12 fields
    net = constants.net
    addr = LnAddr()

    # NOTE: CLN puts the real node_id here, which is defeats the whole purpose of blinded paths
    # also, this should not be used as routing destination in payments (introduction point in set of blinded paths
    # must be used instead
    pubkey = data.get('invoice_node_id').get('node_id')

    class WrappedBytesKey:
        serialize = lambda: pubkey
    addr.pubkey = WrappedBytesKey
    addr.net = net
    addr.date = data.get('invoice_created_at').get('timestamp')
    addr.paymenthash = data.get('invoice_payment_hash').get('payment_hash')
    addr.payment_secret = b'\x00' * 32  # Note: payment secret is not needed, recipient can use path_id in encrypted_recipient_data
    msat = data.get('invoice_amount', {}).get('msat', None)
    if msat is not None:
        addr.amount = Decimal(msat) / COIN / 1000
    fallbacks = data.get('invoice_fallbacks', [])
    fallbacks = list(filter(lambda x: x['version'] <= 16 and 2 <= len(x['address'] <= 40), fallbacks))
    if fallbacks:
        addr.tags.append(('f', fallbacks[0]))
    exp = data.get('invoice_relative_expiry', {}).get('seconds_from_creation', 0)
    if exp:
        addr.tags.append(('x', int(exp)))

    return addr


async def request_invoice(
        lnwallet: 'LNWallet',
        bolt12_offer: dict,
        amount_msat: int,
        *,
        note: Optional[str] = None,
        reply_paths: List[bytes] = None
) -> Tuple[dict, bytes]:
    #   - if it chooses to send an `invoice_request`, it sends an onion message:
    #     - if `offer_paths` is set:
    #       - MUST send the onion message via any path in `offer_paths` to the final `onion_msg_hop`.`blinded_node_id` in that path
    #     - otherwise:
    #       - MUST send the onion message to `offer_issuer_id`
    #     - MAY send more than one `invoice_request` onion message at once.

    offer_paths = bolt12_offer.get('offer_paths')
    if offer_paths:
        paths = offer_paths.get('paths')  # type?
        assert len(paths)
        path = paths[0]  # TODO: round robin all
        with io.BytesIO() as fd:
            OnionWireSerializer.write_field(fd=fd, field_type='blinded_path', count=1, value=path)
            node_id = fd.getvalue()
    else:
        node_id = bolt12_offer['offer_issuer_id']['id']

    # spec: MUST set invreq_payer_id to a transient public key.
    # spec: MUST remember the secret key corresponding to invreq_payer_id.
    session_key = os.urandom(32)
    blinding = ecc.ECPrivkey(session_key).get_public_key_bytes()

    # One is a response to an offer; this contains the `offer_issuer_id` or `offer_paths` and
    # all other offer details, and is generally received over an onion
    # message: if it's valid and refers to a known offer, the response is
    # generally to reply with an `invoice` using the `reply_path` field of
    # the onion message.
    invreq_data = copy.deepcopy(bolt12_offer)  # include all fields of the offer
    invreq_data.update({
        'invreq_payer_id': {'key': blinding},
        'invreq_metadata': {'blob': os.urandom(8)},  # TODO: fill invreq_metadata unique, and store for association
        'invreq_amount': {'msat': amount_msat},
    })

    if note:
        invreq_data['invreq_payer_note'] = {'note': note}

    if constants.net != constants.BitcoinMainnet:
        invreq_data['invreq_chain'] = {'chain': constants.net.rev_genesis_bytes()}

    invreq_tlv = encode_invoice_request(invreq_data, session_key)
    req_payload = {
        'invoice_request': {'invoice_request': invreq_tlv}
    }

    try:
        lnwallet.logger.info(f'requesting bolt12 invoice')
        rcpt_data, payload = await lnwallet.onion_message_manager.submit_send(
            payload=req_payload, node_id_or_blinded_path=node_id
        )
        lnwallet.logger.debug(f'{rcpt_data=} {payload=}')
        if 'invoice_error' in payload:
            return _raise_invoice_error(payload)
        if 'invoice' not in payload:
            raise Exception('reply is not an invoice')
        invoice_tlv = payload['invoice']['invoice']
        with io.BytesIO(invoice_tlv) as fd:
            invoice_data = OnionWireSerializer.read_tlv_stream(
                fd=fd, tlv_stream_name='invoice', signing_key_path=('invoice_node_id', 'node_id')
            )
        lnwallet.logger.info('received bolt12 invoice')
        lnwallet.logger.debug(f'invoice_data: {invoice_data!r}')
    except Timeout:
        lnwallet.logger.info('timeout waiting for bolt12 invoice')
        raise
    except Exception as e:
        lnwallet.logger.error(f'error requesting bolt12 invoice: {e!r}')
        raise

    # validation https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
    if any(invoice_data.get(x) is None for x in [
            'invoice_amount', 'invoice_created_at', 'invoice_payment_hash',
            'invoice_node_id', 'invoice_paths', 'invoice_blindedpay'
    ]):
        raise Exception('invalid bolt12 invoice')
    # TODO:
    # - invreq is equal checks
    # - invoice_features checks
    # - invoice_paths empty
    # - invoice_blindedpay.payinfo matches invoice_paths.blinded_path and features
    # - invoice in response to invoice_request:
    #   - MUST reject the invoice if all fields in ranges 0 to 159 and 1000000000 to 2999999999 (inclusive) do not exactly match the invoice request.
    #   - MUST reject the invoice if invoice_node_id is not equal to offer_issuer_id if offer_issuer_id is present
    #   - otherwise MUST reject the invoice if invoice_node_id is not equal to the final blinded_node_id it sent the invoice request to.
    #   - MUST reject the invoice if invoice_amount is not equal to invreq_amount if invreq_amount is present
    #   - otherwise SHOULD confirm authorization if invoice_amount.msat is not within the amount range authorized.
    # - fallback address checks
    # - MUST reject the invoice if it did not arrive via one of the paths in invreq_paths

    return invoice_data, invoice_tlv


def verify_request_and_create_invoice(
        lnwallet: 'LNWallet',
        bolt12_offer: dict,
        bolt12_invreq: dict,
        preimage,
) -> dict:
    # TODO check offer fields in invreq are equal
    # TODO check constraints, like expiry, offer_amount etc
    # copy the invreq and offer fields
    invoice = copy.deepcopy(bolt12_invreq)
    del invoice['signature']  # remove the signature from the invreq
    now = int(time.time())
    invoice_payment_hash = sha256(preimage)
    invoice.update({
        'invoice_created_at': {'timestamp': now},
        'invoice_relative_expiry': {'seconds_from_creation': 3600},  # TODO hardcoded
        'invoice_payment_hash': {'payment_hash': invoice_payment_hash}
    })

    # spec: if invreq_amount is present: MUST set invoice_amount to invreq_amount
    # otherwise: 'expected' amount (or amount == 0 invoice? or min_htlc_msat from channel set?)
    amount_msat = 0
    if bolt12_invreq.get('invreq_amount'):
        amount_msat = bolt12_invreq['invreq_amount']['msat']
    invoice.update({
        'invoice_amount': {'msat': amount_msat}
    })

    # spec: if offer_issuer_id is present: MUST set invoice_node_id to the offer_issuer_id
    # spec: otherwise, if offer_paths is present: MUST set invoice_node_id to the final blinded_node_id
    # on the path it received the invoice request
    if bolt12_offer.get('offer_issuer_id'):
        invoice.update({
            'invoice_node_id': {'node_id': bolt12_offer['offer_issuer_id']['id']}
        })
    else:
        # we don't have invreq used path available here atm.
        raise Exception('branch not implemented, electrum should set offer_issuer_id')

    invoice_paths, payinfo = get_blinded_paths_to_me(lnwallet)
    invoice.update({
        'invoice_paths': {'paths': invoice_paths},
        'invoice_blindedpay': {'payinfo': payinfo}
    })

    return invoice


# wraps remote invoice_error
class Bolt12InvoiceError(Exception): pass


def _raise_invoice_error(payload):
    invoice_error_tlv = payload['invoice_error']['invoice_error']
    with io.BytesIO(invoice_error_tlv) as fd:
        invoice_error = OnionWireSerializer.read_tlv_stream(fd=fd, tlv_stream_name='invoice_error')
    raise Bolt12InvoiceError(invoice_error.get('error', {}).get('msg'))
