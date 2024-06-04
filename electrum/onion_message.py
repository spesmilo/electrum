# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2023-2024 Thomas Voegtlin
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
import asyncio
import copy
import io
import os
import threading
from typing import TYPE_CHECKING, Optional

from electrum import ecc
from electrum.logging import get_logger, Logger
from electrum.crypto import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from electrum.lnmsg import OnionWireSerializer
from electrum.lnonion import (get_shared_secrets_along_route2, get_bolt04_onion_key, OnionPacket, process_onion_packet,
                              OnionHopsDataSingle, new_onion_packet2)
from electrum.lnutil import get_ecdh
from electrum.util import OldTaskGroup, now, bfh

if TYPE_CHECKING:
    from electrum.lnworker import LNWallet
    from electrum.network import Network

logger = get_logger(__name__)


def create_reply_path(lnwallet: 'LNWallet', session_key: bytes, reply_data: bytes):
    # TODO: pass route from introduction point to me
    # for now, hardcoded direct single hop (introduction point = me)
    introduction_point = lnwallet.node_keypair.pubkey
    route = [introduction_point]

    blinding = ecc.ECPrivkey(session_key).get_public_key_bytes()

    onionmsg_hops = []
    shared_secrets, blinded_node_ids = get_shared_secrets_along_route2(route, session_key)
    for i, node_id in enumerate(route):
        is_non_final_node = i < len(route) - 1

        if is_non_final_node:
            recipient_data = {
                # SHOULD add padding data to ensure all encrypted_data_tlv(i) have the same length
                'next_node_id': {'node_id': node_id}
            }
        else:
            recipient_data = {
                # SHOULD add padding data to ensure all encrypted_data_tlv(i) have the same length
                'path_id': {'data': reply_data}
            }

        with io.BytesIO() as recipient_data_fd:
            OnionWireSerializer.write_tlv_stream(fd=recipient_data_fd,
                                                 tlv_stream_name='encrypted_data_tlv',
                                                 **recipient_data)
            recipient_data_tlv = recipient_data_fd.getvalue()

        rho_key = get_bolt04_onion_key(b'rho', shared_secrets[0])
        encrypted_recipient_data = chacha20_poly1305_encrypt(key=rho_key, nonce=bytes(12), data=recipient_data_tlv)
        logger.debug(f'MAC: {encrypted_recipient_data[-16:].hex()}')

        hopdata = {
            'blinded_node_id': blinded_node_ids[i],
            'enclen': len(encrypted_recipient_data),
            'encrypted_recipient_data': encrypted_recipient_data
        }
        onionmsg_hops.append(hopdata)

    reply_path = {
        'first_node_id': introduction_point,
        'blinding': blinding,
        'num_hops': len(onionmsg_hops),
        'path': onionmsg_hops
    }

    return reply_path


def blinding_privkey(privkey, blinding):
    shared_secret = get_ecdh(privkey, blinding)
    b_hmac = get_bolt04_onion_key(b'blinded_node_id', shared_secret)
    b_hmac_int = int.from_bytes(b_hmac, byteorder="big")

    our_privkey_int = int.from_bytes(privkey, byteorder="big")
    our_privkey_int = our_privkey_int * b_hmac_int % ecc.CURVE_ORDER
    our_privkey = our_privkey_int.to_bytes(32, byteorder="big")

    return our_privkey


def on_onion_message_forward(recipient_data, onion_packet):
    if recipient_data.get('path_id'):
        raise Exception('cannot forward onion_message, path_id in encrypted_data_tlv')
    if not recipient_data.get('next_node_id'):
        raise Exception('cannot forward onion_message, next_node_id missing in encrypted_data_tlv')
    raise Exception('onion_message forwarding not implemented')


class OnionMessageManager(Logger):
    """handle state around onion message sends and receives
    - association between onion message and their replies
    - manage re-send attempts, TODO: iterate through routes (both directions)"""

    def __init__(self, lnwallet: 'LNWallet'):
        Logger.__init__(self)
        self.network = None  # type: Optional['Network']
        self.taskgroup = None  # type: OldTaskGroup
        self.lnwallet = lnwallet

        self.pending = {}
        self.pending_lock = threading.Lock()

    def start_network(self, *, network: 'Network'):
        assert network
        assert self.network is None, "already started"
        self.network = network
        self.taskgroup = OldTaskGroup()
        asyncio.run_coroutine_threadsafe(self.main_loop(), self.network.asyncio_loop)

    async def main_loop(self):
        self.logger.info("starting taskgroup.")
        try:
            async with self.taskgroup as group:
                await group.spawn(self.process())
        except Exception as e:
            self.logger.exception("taskgroup died.")
        else:
            self.logger.info("taskgroup stopped.")

    async def stop(self):
        await self.taskgroup.cancel_remaining()

    async def process(self):
        while True:
            await asyncio.sleep(2)
            with self.pending_lock:
                for key, pending_item in self.pending.items():
                    state = pending_item[0]
                    if now() - state['submitted'] > 120:  # expired
                        continue
                    if now() - state['last_attempt'] > 5:
                        state['last_attempt'] = now()
                        self.logger.debug('spawning onionmsg send')
                        await self.taskgroup.spawn(self.send_pending_onion_message(key))

    def on_onion_message_received(self, recipient_data, payload):
        # we are destination, sanity checks
        if 'allowed_features' in recipient_data:
            pass  # TODO: features check
        # if `path_id` is set and corresponds to a path the reader has previously published in a `reply_path`:
        #   - if the onion message is not a reply to that previous onion:
        #     - MUST ignore the onion message
        # TODO: store reply_path and lookup here
        if 'path_id' not in recipient_data:
            # unsolicited onion_message
            self.on_onion_message_received_unsolicited(recipient_data, payload)
            return

        # check if this reply is associated with a known request
        correl_data = recipient_data['path_id'].get('data')
        if not correl_data[:15] == b'electrum_invreq':
            logger.warning('not a reply to our request')
            return
        if not correl_data[15:] in self.pending:
            logger.warning('not a reply to our request')
            return

        with self.pending_lock:
            del self.pending[correl_data[15:]]

        # hardcoded, assumed invoice response
        invoice_tlv = payload['invoice']['invoice']
        with io.BytesIO(invoice_tlv) as fd:
            invoice_data = OnionWireSerializer.read_tlv_stream(fd=fd, tlv_stream_name='invoice')

        logger.debug(f'invoice {invoice_data!r}')

    def on_onion_message_received_unsolicited(self, recipient_data, payload):
        logger.debug('unsolicited onion_message received')
        logger.debug(f'recipient data: {recipient_data!r}')
        logger.debug(f'payload: {payload!r}')

        if 'message' not in payload:
            logger.error('Unsupported onion message payload')
            return

        if 'text' not in payload['message'] or not isinstance(payload['message']['text'], bytes):
            logger.error('Malformed \'message\' payload')
            return

        try:
            text = payload['message']['text'].decode('utf-8')
        except Exception as e:
            self.logger.error(f'Malformed \'message\' payload: {e!r}')
            return

        self.logger.info(f'onion message with text received: {text}')

    def on_onion_message(self, payload):
        blinding = payload.get('blinding')
        if not blinding:
            logger.error('missing blinding')
            return
        packet = payload.get('onion_message_packet')
        if payload.get('len', 0) != len(packet):
            logger.error('invalid/missing length')
            return

        logger.debug('handling onion message')

        onion_packet = OnionPacket.from_bytes(packet)

        our_privkey = blinding_privkey(self.lnwallet.node_keypair.privkey, blinding)
        processed_onion_packet = process_onion_packet(onion_packet, our_privkey, tlv_stream_name='onionmsg_tlv')
        payload = processed_onion_packet.hop_data.payload

        logger.debug(f'onion peeled: {processed_onion_packet!r}')

        if not processed_onion_packet.are_we_final:
            if any(lambda x: x not in ['encrypted_recipient_data'] for x in payload.keys()):
                raise Exception('unexpected data in payload')  # non-final nodes only encrypted_recipient_data

        # decrypt
        shared_secret = get_ecdh(self.lnwallet.node_keypair.privkey, blinding)
        rho_key = get_bolt04_onion_key(b'rho', shared_secret)
        encrypted_recipient_data = payload['encrypted_recipient_data']['encrypted_recipient_data']
        recipient_data_bytes = chacha20_poly1305_decrypt(key=rho_key, nonce=bytes(12), data=encrypted_recipient_data)

        # parse
        with io.BytesIO(recipient_data_bytes) as fd:
            recipient_data = OnionWireSerializer.read_tlv_stream(fd=fd, tlv_stream_name='encrypted_data_tlv')

        logger.debug(f'parsed recipient_data: {recipient_data!r}')

        if processed_onion_packet.are_we_final:
            self.on_onion_message_received(recipient_data, payload)
        else:
            on_onion_message_forward(recipient_data, processed_onion_packet.next_packet)

    def submit_onion_message(self, *, payload: dict, session_key: bytes, peer):
        self.logger.debug('submit_onion_message')
        key = os.urandom(16)
        state = {
            'submitted': now(),
            'last_attempt': 0,
            'peer': peer  # TODO remove, just for testing
        }
        self.pending[key] = (state, payload, session_key)
        return key

    async def send_pending_onion_message(self, key):
        """adds reply_path to payload"""
        self.logger.debug('send_pending_onion_message')

        state, payload, session_key = self.pending[key]

        reply_path = create_reply_path(self.lnwallet, session_key, b'electrum_invreq' + key)

        final_payload = copy.deepcopy(payload)
        final_payload['reply_path'] = {'path': reply_path}

        hops_data = [
            OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv', payload=final_payload)
        ]

        peer = state['peer']  # TODO remove just for testing

        # direct to peer
        payment_path_pubkeys = [
            peer.pubkey
        ]

        packet = new_onion_packet2(payment_path_pubkeys, session_key, hops_data)
        packet_b = packet.to_bytes()

        blinding = ecc.ECPrivkey(session_key).get_public_key_bytes()

        peer.send_message(
            "onion_message",
            blinding=blinding,
            len=len(packet_b),
            onion_message_packet=packet_b
        )
