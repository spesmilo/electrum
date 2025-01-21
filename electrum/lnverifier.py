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
from typing import TYPE_CHECKING, Dict, Set

import aiorpcx
import electrum_ecc as ecc
from electrum_ecc import ECPubkey

from . import bitcoin
from . import constants
from .util import bfh, NetworkJobOnDefaultServer
from .lnutil import funding_output_script_from_keys, ShortChannelID
from .verifier import verify_tx_is_in_block, MerkleVerificationFailure
from .transaction import Transaction
from .interface import GracefulDisconnect
from .crypto import sha256d
from .lnmsg import decode_msg, encode_msg

if TYPE_CHECKING:
    from .network import Network
    from .lnrouter import ChannelDB


class LNChannelVerifier(NetworkJobOnDefaultServer):
    """ Verify channel announcements for the Channel DB """

    # FIXME the initial routing sync is bandwidth-heavy, and the electrum server
    # will start throttling us, making it even slower. one option would be to
    # spread it over multiple servers.

    def __init__(self, network: 'Network', channel_db: 'ChannelDB'):
        self.channel_db = channel_db
        self.lock = threading.Lock()
        self.unverified_channel_info = {}  # type: Dict[ShortChannelID, dict]  # scid -> msg_dict
        # channel announcements that seem to be invalid:
        self.blacklist = set()  # type: Set[ShortChannelID]
        NetworkJobOnDefaultServer.__init__(self, network)

    def _reset(self):
        super()._reset()
        self.started_verifying_channel = set()  # type: Set[ShortChannelID]

    # TODO make async; and rm self.lock completely
    def add_new_channel_info(self, short_channel_id: ShortChannelID, msg: dict) -> bool:
        if short_channel_id in self.unverified_channel_info:
            return False
        if short_channel_id in self.blacklist:
            return False
        with self.lock:
            self.unverified_channel_info[short_channel_id] = msg
            return True

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        async with taskgroup as group:
            await group.spawn(self.main)

    async def main(self):
        while True:
            await self._verify_some_channels()
            await asyncio.sleep(0.1)

    async def _verify_some_channels(self):
        blockchain = self.network.blockchain()
        local_height = blockchain.height()

        with self.lock:
            unverified_channel_info = list(self.unverified_channel_info)

        for short_channel_id in unverified_channel_info:
            if short_channel_id in self.started_verifying_channel:
                continue
            block_height = short_channel_id.block_height
            # only resolve short_channel_id if headers are available.
            if block_height <= 0 or block_height > local_height:
                continue
            header = blockchain.read_header(block_height)
            if header is None:
                if block_height < constants.net.max_checkpoint():
                    await self.taskgroup.spawn(self.network.request_chunk(block_height, None, can_return_early=True))
                continue
            self.started_verifying_channel.add(short_channel_id)
            await self.taskgroup.spawn(self.verify_channel(block_height, short_channel_id))
            #self.logger.info(f'requested short_channel_id {short_channel_id.hex()}')

    async def verify_channel(self, block_height: int, short_channel_id: ShortChannelID):
        # we are verifying channel announcements as they are from untrusted ln peers.
        # we use electrum servers to do this. however we don't trust electrum servers either...
        try:
            async with self._network_request_semaphore:
                result = await self.network.get_txid_from_txpos(
                    block_height, short_channel_id.txpos, True)
        except aiorpcx.jsonrpc.RPCError:
            # the electrum server is complaining about the txpos for given block.
            # it is not clear what to do now, but let's believe the server.
            self._blacklist_short_channel_id(short_channel_id)
            return
        tx_hash = result['tx_hash']
        merkle_branch = result['merkle']
        # we need to wait if header sync/reorg is still ongoing, hence lock:
        async with self.network.bhi_lock:
            header = self.network.blockchain().read_header(block_height)
        try:
            verify_tx_is_in_block(tx_hash, merkle_branch, short_channel_id.txpos, header, block_height)
        except MerkleVerificationFailure as e:
            # the electrum server sent an incorrect proof. blame is on server, not the ln peer
            raise GracefulDisconnect(e) from e
        try:
            async with self._network_request_semaphore:
                raw_tx = await self.network.get_transaction(tx_hash)
        except aiorpcx.jsonrpc.RPCError as e:
            # the electrum server can't find the tx; but it was the
            # one who told us about the txid!! blame is on server
            raise GracefulDisconnect(e) from e
        tx = Transaction(raw_tx)
        try:
            tx.deserialize()
        except Exception:
            # either bug in client, or electrum server is evil.
            # if we connect to a diff server at some point, let's try again.
            self.logger.warning(f"cannot deserialize transaction, skipping {tx_hash}")
            return
        if tx_hash != tx.txid():
            # either bug in client, or electrum server is evil.
            # if we connect to a diff server at some point, let's try again.
            self.logger.info(f"received tx does not match expected txid ({tx_hash} != {tx.txid()})")
            return
        # check funding output
        chan_ann_msg = self.unverified_channel_info[short_channel_id]
        redeem_script = funding_output_script_from_keys(chan_ann_msg['bitcoin_key_1'], chan_ann_msg['bitcoin_key_2'])
        expected_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        try:
            actual_output = tx.outputs()[short_channel_id.output_index]
        except IndexError:
            self._blacklist_short_channel_id(short_channel_id)
            return
        if expected_address != actual_output.address:
            # FIXME what now? best would be to ban the originating ln peer.
            self.logger.info(f"funding output script mismatch for {short_channel_id}")
            self._remove_channel_from_unverified_db(short_channel_id)
            return
        # put channel into channel DB
        self.channel_db.add_verified_channel_info(chan_ann_msg, capacity_sat=actual_output.value)
        self._remove_channel_from_unverified_db(short_channel_id)

    def _remove_channel_from_unverified_db(self, short_channel_id: ShortChannelID):
        with self.lock:
            self.unverified_channel_info.pop(short_channel_id, None)
        self.started_verifying_channel.discard(short_channel_id)

    def _blacklist_short_channel_id(self, short_channel_id: ShortChannelID) -> None:
        self.blacklist.add(short_channel_id)
        with self.lock:
            self.unverified_channel_info.pop(short_channel_id, None)


def verify_sig_for_channel_update(chan_upd: dict, node_id: bytes) -> bool:
    msg_bytes = chan_upd['raw']
    pre_hash = msg_bytes[2+64:]
    h = sha256d(pre_hash)
    sig = chan_upd['signature']
    if not ECPubkey(node_id).ecdsa_verify(sig, h):
        return False
    return True
