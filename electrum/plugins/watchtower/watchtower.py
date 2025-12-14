#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2023 The Electrum Developers
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
import os
from typing import TYPE_CHECKING
from typing import Dict

from electrum.util import log_exceptions, random_shuffled_copy
from electrum.plugin import BasePlugin
from electrum.sql_db import SqlDB, sql
from electrum.transaction import Transaction, match_script_against_template
from electrum.network import Network
from electrum.address_synchronizer import AddressSynchronizer, TX_HEIGHT_LOCAL
from electrum.wallet_db import WalletDB
from electrum.json_db import JsonDB
from electrum.lnutil import WITNESS_TEMPLATE_RECEIVED_HTLC, WITNESS_TEMPLATE_OFFERED_HTLC
from electrum.logging import Logger
from electrum.util import EventListener, event_listener

from .server import WatchTowerServer

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


class WatchtowerPlugin(BasePlugin):

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.network = Network.get_instance()
        if self.network is None:
            return

        self.watchtower = WatchTower(self.network)
        asyncio.run_coroutine_threadsafe(self.watchtower.start_watching(), self.network.asyncio_loop)
        if watchtower_port := self.config.WATCHTOWER_SERVER_PORT:
            self.server = WatchTowerServer(self.watchtower, self.network, watchtower_port)
            asyncio.run_coroutine_threadsafe(self.network.taskgroup.spawn(self.server.run), self.network.asyncio_loop)


class WatchTower(Logger, EventListener):

    def __init__(self, network: 'Network'):
        Logger.__init__(self)
        self.config = network.config
        json_db = JsonDB('', storage=None)
        wallet_db = WalletDB(json_db.get_stored_dict())
        self.adb = AddressSynchronizer(wallet_db, self.config, name=self.diagnostic_name())
        self.adb.start_network(network)
        self.callbacks = {}  # address -> lambda function
        self.register_callbacks()
        # status gets populated when we run
        self.channel_status = {}
        self.network = network
        self.sweepstore = SweepStore(os.path.join(self.config.path, "watchtower_db"), network)

    def remove_callback(self, address):
        self.callbacks.pop(address, None)

    def add_callback(self, address, callback):
        self.adb.add_address(address)
        self.callbacks[address] = callback

    @event_listener
    async def on_event_blockchain_updated(self, *args):
        await self.trigger_callbacks()

    @event_listener
    async def on_event_wallet_updated(self, wallet):
        # called if we add local tx
        if wallet.adb != self.adb:
            return
        await self.trigger_callbacks()

    @event_listener
    async def on_event_adb_added_verified_tx(self, adb, tx_hash):
        if adb != self.adb:
            return
        await self.trigger_callbacks()

    @event_listener
    async def on_event_adb_set_up_to_date(self, adb):
        if adb != self.adb:
            return
        await self.trigger_callbacks()

    @log_exceptions
    async def trigger_callbacks(self):
        if not self.adb.synchronizer:
            self.logger.info("synchronizer not set yet")
            return
        for address, callback in list(self.callbacks.items()):
            await callback()

    async def stop(self):
        self.unregister_callbacks()
        await self.adb.stop()

    def add_channel(self, outpoint: str, address: str) -> None:
        callback = lambda: self.check_onchain_situation(address, outpoint)
        self.add_callback(address, callback)

    def diagnostic_name(self):
        return "watchtower"

    @log_exceptions
    async def start_watching(self):
        # I need to watch the addresses from sweepstore
        lst = await self.sweepstore.list_channels()
        for outpoint, address in random_shuffled_copy(lst):
            self.add_channel(outpoint, address)

    async def check_onchain_situation(self, address, funding_outpoint):
        # early return if address has not been added yet
        if not self.adb.is_mine(address):
            return
        # inspect_tx_candidate might have added new addresses, in which case we return early
        closing_txid = self.adb.get_spender(funding_outpoint)
        if closing_txid:
            closing_tx = self.adb.get_transaction(closing_txid)
            if closing_tx:
                keep_watching = await self.sweep_commitment_transaction(funding_outpoint, closing_tx)
            else:
                self.logger.info(f"channel {funding_outpoint} closed by {closing_txid}. still waiting for tx itself...")
                keep_watching = True
        else:
            keep_watching = True
        if not keep_watching:
            await self.unwatch_channel(address, funding_outpoint)

    def inspect_tx_candidate(self, outpoint, n: int) -> Dict[str, str]:
        """
        returns a dict of spenders for a transaction of interest.
        subscribes to addresses as a side effect.
        n==0 => outpoint is a channel funding.
        n==1 => outpoint is a commitment or close output: to_local, to_remote or first-stage htlc
        n==2 => outpoint is a second-stage htlc
        """
        prev_txid, index = outpoint.split(':')
        spender_txid = self.adb.db.get_spent_outpoint(prev_txid, int(index))
        result = {outpoint:spender_txid}
        if n == 0:
            if spender_txid is None:
                self.channel_status[outpoint] = 'open'
            elif not self.adb.is_deeply_mined(spender_txid):
                self.channel_status[outpoint] = 'closed (%d)' % self.adb.get_tx_height(spender_txid).conf
            else:
                self.channel_status[outpoint] = 'closed (deep)'
        if spender_txid is None:
            return result
        spender_tx = self.adb.get_transaction(spender_txid)
        if n == 1:
            # if tx input is not a first-stage HTLC, we can stop recursion
            # FIXME: this is not true for anchor channels
            if len(spender_tx.inputs()) != 1:
                return result
            o = spender_tx.inputs()[0]
            witness = o.witness_elements()
            if not witness:
                # This can happen if spender_tx is a local unsigned tx in the wallet history, e.g.:
                # channel is coop-closed, outpoint is for our coop-close output, and spender_tx is an
                # arbitrary wallet-spend.
                return result
            redeem_script = witness[-1]
            if match_script_against_template(redeem_script, WITNESS_TEMPLATE_OFFERED_HTLC):
                #self.logger.info(f"input script matches offered htlc {redeem_script.hex()}")
                pass
            elif match_script_against_template(redeem_script, WITNESS_TEMPLATE_RECEIVED_HTLC):
                #self.logger.info(f"input script matches received htlc {redeem_script.hex()}")
                pass
            else:
                return result
        for i, o in enumerate(spender_tx.outputs()):
            if o.address is None:
                continue
            if not self.adb.is_mine(o.address):
                self.adb.add_address(o.address)
            elif n < 2:
                r = self.inspect_tx_candidate(spender_txid + ':%d' % i, n + 1)
                result.update(r)
        return result

    async def sweep_commitment_transaction(self, funding_outpoint: str, closing_tx: Transaction) -> bool:
        assert closing_tx
        spenders = self.inspect_tx_candidate(funding_outpoint, 0)
        keep_watching = not self.adb.is_deeply_mined(closing_tx.txid())
        for prevout, spender in spenders.items():
            if spender is not None:
                keep_watching |= not self.adb.is_deeply_mined(spender)
                continue
            sweep_txns = await self.sweepstore.get_sweep_tx(funding_outpoint, prevout)
            for tx in sweep_txns:
                await self.broadcast_or_log(funding_outpoint, tx)
                keep_watching = True
        return keep_watching

    async def broadcast_or_log(self, funding_outpoint: str, tx: Transaction):
        height = self.adb.get_tx_height(tx.txid()).height()
        if height != TX_HEIGHT_LOCAL:
            return
        try:
            txid = await self.network.broadcast_transaction(tx)
        except Exception as e:
            self.logger.info(f'broadcast failure: txid={tx.txid()}, funding_outpoint={funding_outpoint}: {repr(e)}')
        else:
            self.logger.info(f'broadcast success: txid={tx.txid()}, funding_outpoint={funding_outpoint}')
            return txid

    async def get_ctn(self, outpoint, addr):
        if addr not in self.callbacks.keys():
            self.logger.info(f'watching new channel: {outpoint} {addr}')
            self.add_channel(outpoint, addr)
        return await self.sweepstore.get_ctn(outpoint, addr)

    def get_num_tx(self, outpoint):
        async def f():
            return await self.sweepstore.get_num_tx(outpoint)
        return self.network.run_from_another_thread(f())

    def list_sweep_tx(self):
        async def f():
            return await self.sweepstore.list_sweep_tx()
        return self.network.run_from_another_thread(f())

    def list_channels(self):
        async def f():
            return await self.sweepstore.list_channels()
        return self.network.run_from_another_thread(f())

    async def unwatch_channel(self, address, funding_outpoint):
        await self.sweepstore.remove_sweep_tx(funding_outpoint)
        await self.sweepstore.remove_channel(funding_outpoint)


create_sweep_txs="""
CREATE TABLE IF NOT EXISTS sweep_txs (
funding_outpoint VARCHAR(34) NOT NULL,
ctn INTEGER NOT NULL,
prevout VARCHAR(34),
tx VARCHAR
)"""

create_channel_info="""
CREATE TABLE IF NOT EXISTS channel_info (
outpoint VARCHAR(34) NOT NULL,
address VARCHAR(32),
PRIMARY KEY(outpoint)
)"""


class SweepStore(SqlDB):

    def __init__(self, path, network):
        super().__init__(network.asyncio_loop, path)

    def create_database(self):
        c = self.conn.cursor()
        c.execute(create_channel_info)
        c.execute(create_sweep_txs)
        self.conn.commit()

    @sql
    def get_sweep_tx(self, funding_outpoint, prevout):
        c = self.conn.cursor()
        c.execute("SELECT tx FROM sweep_txs WHERE funding_outpoint=? AND prevout=?", (funding_outpoint, prevout))
        return [Transaction(r[0].hex()) for r in c.fetchall()]

    @sql
    def list_sweep_tx(self):
        c = self.conn.cursor()
        c.execute("SELECT funding_outpoint FROM sweep_txs")
        return set([r[0] for r in c.fetchall()])

    @sql
    def add_sweep_tx(self, funding_outpoint, ctn, prevout, raw_tx):
        c = self.conn.cursor()
        assert Transaction(raw_tx).is_complete()
        c.execute("""INSERT INTO sweep_txs (funding_outpoint, ctn, prevout, tx) VALUES (?,?,?,?)""", (funding_outpoint, ctn, prevout, bytes.fromhex(raw_tx)))
        self.conn.commit()

    @sql
    def get_num_tx(self, funding_outpoint):
        c = self.conn.cursor()
        c.execute("SELECT count(*) FROM sweep_txs WHERE funding_outpoint=?", (funding_outpoint,))
        return int(c.fetchone()[0])

    @sql
    def get_ctn(self, outpoint, addr):
        if not self._has_channel(outpoint):
            self._add_channel(outpoint, addr)
        c = self.conn.cursor()
        c.execute("SELECT max(ctn) FROM sweep_txs WHERE funding_outpoint=?", (outpoint,))
        return int(c.fetchone()[0] or 0)

    @sql
    def remove_sweep_tx(self, funding_outpoint):
        c = self.conn.cursor()
        c.execute("DELETE FROM sweep_txs WHERE funding_outpoint=?", (funding_outpoint,))
        self.conn.commit()

    def _add_channel(self, outpoint, address):
        c = self.conn.cursor()
        c.execute("INSERT INTO channel_info (address, outpoint) VALUES (?,?)", (address, outpoint))
        self.conn.commit()

    @sql
    def remove_channel(self, outpoint):
        c = self.conn.cursor()
        c.execute("DELETE FROM channel_info WHERE outpoint=?", (outpoint,))
        self.conn.commit()

    def _has_channel(self, outpoint):
        c = self.conn.cursor()
        c.execute("SELECT * FROM channel_info WHERE outpoint=?", (outpoint,))
        r = c.fetchone()
        return r is not None

    @sql
    def get_address(self, outpoint):
        c = self.conn.cursor()
        c.execute("SELECT address FROM channel_info WHERE outpoint=?", (outpoint,))
        r = c.fetchone()
        return r[0] if r else None

    @sql
    def list_channels(self):
        c = self.conn.cursor()
        c.execute("SELECT outpoint, address FROM channel_info")
        return [(r[0], r[1]) for r in c.fetchall()]
