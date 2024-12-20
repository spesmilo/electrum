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


import asyncio, os
from typing import TYPE_CHECKING
from typing import NamedTuple, Dict

from electrum.util import log_exceptions, random_shuffled_copy
from electrum.plugin import BasePlugin, hook
from electrum.sql_db import SqlDB, sql
from electrum.lnwatcher import LNWatcher
from electrum.transaction import Transaction, match_script_against_template
from electrum.network import Network
from electrum.address_synchronizer import AddressSynchronizer, TX_HEIGHT_LOCAL
from electrum.wallet_db import WalletDB
from electrum.lnutil import WITNESS_TEMPLATE_RECEIVED_HTLC, WITNESS_TEMPLATE_OFFERED_HTLC

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
        asyncio.ensure_future(self.watchtower.start_watching())
        if watchtower_port := self.config.WATCHTOWER_SERVER_PORT:
            self.server = WatchTowerServer(self.watchtower, self.network, watchtower_port)
            asyncio.run_coroutine_threadsafe(self.network.taskgroup.spawn(self.server.run), self.network.asyncio_loop)


class WatchTower(LNWatcher):

    LOGGING_SHORTCUT = 'W'

    def __init__(self, network: 'Network'):
        adb = AddressSynchronizer(WalletDB('', storage=None, upgrade=True), network.config, name=self.diagnostic_name())
        adb.start_network(network)
        LNWatcher.__init__(self, adb, network)
        self.network = network
        self.sweepstore = SweepStore(os.path.join(self.network.config.path, "watchtower_db"), network)
        # this maps funding_outpoints to ListenerItems, which have an event for when the watcher is done,
        # and a queue for seeing which txs are being published
        self.tx_progress = {} # type: Dict[str, ListenerItem]

    async def stop(self):
        await super().stop()
        await self.adb.stop()

    def diagnostic_name(self):
        return "local_tower"

    @log_exceptions
    async def start_watching(self):
        # I need to watch the addresses from sweepstore
        lst = await self.sweepstore.list_channels()
        for outpoint, address in random_shuffled_copy(lst):
            self.add_channel(outpoint, address)

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
            elif not self.is_deeply_mined(spender_txid):
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
                r = self.inspect_tx_candidate(spender_txid+':%d'%i, n+1)
                result.update(r)
        return result

    async def sweep_commitment_transaction(self, funding_outpoint, closing_tx):
        spenders = self.inspect_tx_candidate(funding_outpoint, 0)
        keep_watching = False
        for prevout, spender in spenders.items():
            if spender is not None:
                keep_watching |= not self.is_deeply_mined(spender)
                continue
            sweep_txns = await self.sweepstore.get_sweep_tx(funding_outpoint, prevout)
            for tx in sweep_txns:
                await self.broadcast_or_log(funding_outpoint, tx)
                keep_watching = True
        return keep_watching

    async def broadcast_or_log(self, funding_outpoint: str, tx: Transaction):
        height = self.adb.get_tx_height(tx.txid()).height
        if height != TX_HEIGHT_LOCAL:
            return
        try:
            txid = await self.network.broadcast_transaction(tx)
        except Exception as e:
            self.logger.info(f'broadcast failure: txid={tx.txid()}, funding_outpoint={funding_outpoint}: {repr(e)}')
        else:
            self.logger.info(f'broadcast success: txid={tx.txid()}, funding_outpoint={funding_outpoint}')
            if funding_outpoint in self.tx_progress:
                await self.tx_progress[funding_outpoint].tx_queue.put(tx)
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
        await super().unwatch_channel(address, funding_outpoint)
        await self.sweepstore.remove_sweep_tx(funding_outpoint)
        await self.sweepstore.remove_channel(funding_outpoint)
        if funding_outpoint in self.tx_progress:
            self.tx_progress[funding_outpoint].all_done.set()

    async def update_channel_state(self, *args, **kwargs):
        pass



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


