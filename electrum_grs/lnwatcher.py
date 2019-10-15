# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import NamedTuple, Iterable, TYPE_CHECKING
import os
import queue
import threading
import concurrent
from collections import defaultdict
import asyncio
from enum import IntEnum, auto
from typing import NamedTuple, Dict

from .sql_db import SqlDB, sql
from .json_db import JsonDB
from .util import bh2u, bfh, log_exceptions, ignore_exceptions
from . import wallet
from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer, TX_HEIGHT_LOCAL, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED
from .transaction import Transaction

if TYPE_CHECKING:
    from .network import Network

class ListenerItem(NamedTuple):
    # this is triggered when the lnwatcher is all done with the outpoint used as index in LNWatcher.tx_progress
    all_done : asyncio.Event
    # txs we broadcast are put on this queue so that the test can wait for them to get mined
    tx_queue : asyncio.Queue

class TxMinedDepth(IntEnum):
    """ IntEnum because we call min() in get_deepest_tx_mined_depth_for_txids """
    DEEP = auto()
    SHALLOW = auto()
    MEMPOOL = auto()
    FREE = auto()


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
        super().__init__(network, path)

    def create_database(self):
        c = self.conn.cursor()
        c.execute(create_channel_info)
        c.execute(create_sweep_txs)
        self.conn.commit()

    @sql
    def get_sweep_tx(self, funding_outpoint, prevout):
        c = self.conn.cursor()
        c.execute("SELECT tx FROM sweep_txs WHERE funding_outpoint=? AND prevout=?", (funding_outpoint, prevout))
        return [Transaction(bh2u(r[0])) for r in c.fetchall()]

    @sql
    def list_sweep_tx(self):
        c = self.conn.cursor()
        c.execute("SELECT funding_outpoint FROM sweep_txs")
        return set([r[0] for r in c.fetchall()])

    @sql
    def add_sweep_tx(self, funding_outpoint, ctn, prevout, tx):
        c = self.conn.cursor()
        c.execute("""INSERT INTO sweep_txs (funding_outpoint, ctn, prevout, tx) VALUES (?,?,?,?)""", (funding_outpoint, ctn, prevout, bfh(str(tx))))
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



class LNWatcher(AddressSynchronizer):
    verbosity_filter = 'W'

    def __init__(self, network: 'Network'):
        AddressSynchronizer.__init__(self, JsonDB({}, manual_upgrades=False))
        self.config = network.config
        self.channels = {}
        self.network = network
        self.network.register_callback(self.on_network_update,
                                       ['network_updated', 'blockchain_updated', 'verified', 'wallet_updated'])
        # status gets populated when we run
        self.channel_status = {}

    def get_channel_status(self, outpoint):
        return self.channel_status.get(outpoint, 'unknown')

    def add_channel(self, outpoint, address):
        self.add_address(address)
        self.channels[address] = outpoint

    async def unwatch_channel(self, address, funding_outpoint):
        pass

    @log_exceptions
    async def on_network_update(self, event, *args):
        if event in ('verified', 'wallet_updated'):
            if args[0] != self:
                return
        if not self.synchronizer:
            self.logger.info("synchronizer not set yet")
            return
        if not self.up_to_date:
            return
        for address, outpoint in self.channels.items():
            await self.check_onchain_situation(address, outpoint)

    async def check_onchain_situation(self, address, funding_outpoint):
        keep_watching, spenders = self.inspect_tx_candidate(funding_outpoint, 0)
        funding_txid = funding_outpoint.split(':')[0]
        funding_height = self.get_tx_height(funding_txid)
        closing_txid = spenders.get(funding_outpoint)
        if closing_txid is None:
            self.network.trigger_callback('channel_open', funding_outpoint, funding_txid, funding_height)
        else:
            closing_height = self.get_tx_height(closing_txid)
            closing_tx = self.db.get_transaction(closing_txid)
            if not closing_tx:
                self.logger.info(f"channel {funding_outpoint} closed by {closing_txid}. still waiting for tx itself...")
                return
            self.network.trigger_callback('channel_closed', funding_outpoint, spenders,
                                          funding_txid, funding_height, closing_txid,
                                          closing_height, closing_tx)  # FIXME sooo many args..
            # TODO: add tests for local_watchtower
            await self.do_breach_remedy(funding_outpoint, spenders)
        if not keep_watching:
            await self.unwatch_channel(address, funding_outpoint)

    async def do_breach_remedy(self, funding_outpoints, spenders):
        # overloaded in WatchTower
        pass

    def inspect_tx_candidate(self, outpoint, n):
        # FIXME: instead of stopping recursion at n == 2,
        # we should detect which outputs are HTLCs
        prev_txid, index = outpoint.split(':')
        txid = self.db.get_spent_outpoint(prev_txid, int(index))
        result = {outpoint:txid}
        if txid is None:
            self.channel_status[outpoint] = 'open'
            #self.logger.info('keep watching because outpoint is unspent')
            return True, result
        keep_watching = (self.get_tx_mined_depth(txid) != TxMinedDepth.DEEP)
        if keep_watching:
            self.channel_status[outpoint] = 'closed (%d)' % self.get_tx_height(txid).conf
            #self.logger.info('keep watching because spending tx is not deep')
        else:
            self.channel_status[outpoint] = 'closed (deep)'

        tx = self.db.get_transaction(txid)
        for i, o in enumerate(tx.outputs()):
            if o.address not in self.get_addresses():
                self.add_address(o.address)
                keep_watching = True
            elif n < 2:
                k, r = self.inspect_tx_candidate(txid+':%d'%i, n+1)
                keep_watching |= k
                result.update(r)
        return keep_watching, result

    def get_tx_mined_depth(self, txid: str):
        if not txid:
            return TxMinedDepth.FREE
        tx_mined_depth = self.get_tx_height(txid)
        height, conf = tx_mined_depth.height, tx_mined_depth.conf
        if conf > 100:
            return TxMinedDepth.DEEP
        elif conf > 0:
            return TxMinedDepth.SHALLOW
        elif height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT):
            return TxMinedDepth.MEMPOOL
        elif height == TX_HEIGHT_LOCAL:
            return TxMinedDepth.FREE
        elif height > 0 and conf == 0:
            # unverified but claimed to be mined
            return TxMinedDepth.MEMPOOL
        else:
            raise NotImplementedError()


class WatchTower(LNWatcher):

    verbosity_filter = 'W'

    def __init__(self, network):
        LNWatcher.__init__(self, network)
        self.network = network
        self.sweepstore = SweepStore(os.path.join(self.network.config.path, "watchtower_db"), network)
        # this maps funding_outpoints to ListenerItems, which have an event for when the watcher is done,
        # and a queue for seeing which txs are being published
        self.tx_progress = {} # type: Dict[str, ListenerItem]

    async def start_watching(self):
        # I need to watch the addresses from sweepstore
        l = await self.sweepstore.list_channels()
        for outpoint, address in l:
            self.add_channel(outpoint, address)

    async def do_breach_remedy(self, funding_outpoint, spenders):
        for prevout, spender in spenders.items():
            if spender is not None:
                continue
            sweep_txns = await self.sweepstore.get_sweep_tx(funding_outpoint, prevout)
            for tx in sweep_txns:
                await self.broadcast_or_log(funding_outpoint, tx)

    async def broadcast_or_log(self, funding_outpoint: str, tx: Transaction):
        height = self.get_tx_height(tx.txid()).height
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

    def get_ctn(self, outpoint, addr):
        async def f():
            return await self.sweepstore.get_ctn(outpoint, addr)
        return self.network.run_from_another_thread(f())

    def get_num_tx(self, outpoint):
        async def f():
            return await self.sweepstore.get_num_tx(outpoint)
        return self.network.run_from_another_thread(f())

    def add_sweep_tx(self, funding_outpoint: str, ctn:int, prevout: str, tx: str):
        async def f():
            return await self.sweepstore.add_sweep_tx(funding_outpoint, ctn, prevout, tx)
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
        self.logger.info(f'unwatching {funding_outpoint}')
        await self.sweepstore.remove_sweep_tx(funding_outpoint)
        await self.sweepstore.remove_channel(funding_outpoint)
        if funding_outpoint in self.tx_progress:
            self.tx_progress[funding_outpoint].all_done.set()
