# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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
import threading
from aiorpcx import TaskGroup

from . import lnbase
from . import bitcoin
from . import ecc
from .util import ThreadJob, bh2u, bfh
from .lnutil import invert_short_channel_id, funding_output_script_from_keys
from .verifier import verify_tx_is_in_block, MerkleVerificationFailure
from .transaction import Transaction


class LNChanAnnVerifier(ThreadJob):
    """ Verify channel announcements for the Channel DB """

    def __init__(self, network, channel_db):
        self.network = network
        self.channel_db = channel_db
        self.lock = threading.Lock()

        # items only removed when whole verification succeeds for them.
        # fixme: if it fails, it will never succeed
        self.started_verifying_channel = set()  # short_channel_id

        self.unverified_channel_info = {}  # short_channel_id -> channel_info

    def add_new_channel_info(self, channel_info):
        short_channel_id = channel_info.channel_id
        if short_channel_id in self.unverified_channel_info:
            return
        if not verify_sigs_for_channel_announcement(channel_info.msg_payload):
            return
        with self.lock:
            self.unverified_channel_info[short_channel_id] = channel_info

    def get_pending_channel_info(self, short_channel_id):
        return self.unverified_channel_info.get(short_channel_id, None)

    async def main(self):
        while True:
            async with TaskGroup() as tg:
                await self.iteration(tg)
            await asyncio.sleep(0.1)

    async def iteration(self, tg):
        interface = self.network.interface
        if not interface:
            return

        blockchain = interface.blockchain
        if not blockchain:
            return

        with self.lock:
            unverified_channel_info = list(self.unverified_channel_info)

        for short_channel_id in unverified_channel_info:
            if short_channel_id in self.started_verifying_channel:
                continue
            block_height, tx_pos, output_idx = invert_short_channel_id(short_channel_id)
            # only resolve short_channel_id if headers are available.
            header = blockchain.read_header(block_height)
            if header is None:
                index = block_height // 2016
                if index < len(blockchain.checkpoints):
                    await tg.spawn(self.network.request_chunk(block_height, None, can_return_early=True))
                continue
            await tg.spawn(self.verify_channel(block_height, tx_pos, short_channel_id))
            #self.print_error('requested short_channel_id', bh2u(short_channel_id))

    async def verify_channel(self, block_height, tx_pos, short_channel_id):
        with self.lock:
            self.started_verifying_channel.add(short_channel_id)
        result = await self.network.get_txid_from_txpos(block_height, tx_pos, True)
        tx_hash = result['tx_hash']
        merkle_branch = result['merkle']
        header = self.network.blockchain().read_header(block_height)
        try:
            verify_tx_is_in_block(tx_hash, merkle_branch, tx_pos, header, block_height)
        except MerkleVerificationFailure as e:
            self.print_error(str(e))
            return
        tx = Transaction(await self.network.get_transaction(tx_hash))
        try:
            tx.deserialize()
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return
        if tx_hash != tx.txid():
            self.print_error("received tx does not match expected txid ({} != {})"
                             .format(tx_hash, tx.txid()))
            return
        # check funding output
        channel_info = self.unverified_channel_info[short_channel_id]
        chan_ann = channel_info.msg_payload
        redeem_script = funding_output_script_from_keys(chan_ann['bitcoin_key_1'], chan_ann['bitcoin_key_2'])
        expected_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        output_idx = invert_short_channel_id(short_channel_id)[2]
        try:
            actual_output = tx.outputs()[output_idx]
        except IndexError:
            return
        if expected_address != actual_output[1]:
            return
        # put channel into channel DB
        channel_info.set_capacity(actual_output[2])
        self.channel_db.add_verified_channel_info(short_channel_id, channel_info)
        # remove channel from unverified
        with self.lock:
            self.unverified_channel_info.pop(short_channel_id, None)
            try: self.started_verifying_channel.remove(short_channel_id)
            except KeyError: pass


def verify_sigs_for_channel_announcement(chan_ann: dict) -> bool:
    msg_bytes = lnbase.gen_msg('channel_announcement', **chan_ann)
    pre_hash = msg_bytes[2+256:]
    h = bitcoin.Hash(pre_hash)
    pubkeys = [chan_ann['node_id_1'], chan_ann['node_id_2'], chan_ann['bitcoin_key_1'], chan_ann['bitcoin_key_2']]
    sigs = [chan_ann['node_signature_1'], chan_ann['node_signature_2'], chan_ann['bitcoin_signature_1'], chan_ann['bitcoin_signature_2']]
    for pubkey, sig in zip(pubkeys, sigs):
        if not ecc.verify_signature(pubkey, sig, h):
            return False
    return True


def verify_sig_for_channel_update(chan_upd: dict, node_id: bytes) -> bool:
    msg_bytes = lnbase.gen_msg('channel_update', **chan_upd)
    pre_hash = msg_bytes[2+64:]
    h = bitcoin.Hash(pre_hash)
    sig = chan_upd['signature']
    if not ecc.verify_signature(node_id, sig, h):
        return False
    return True
