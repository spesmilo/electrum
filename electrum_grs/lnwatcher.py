# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import NamedTuple, Iterable, TYPE_CHECKING
import os
import asyncio
from enum import IntEnum, auto
from typing import NamedTuple, Dict

from . import util
from .sql_db import SqlDB, sql
from .wallet_db import WalletDB
from .util import bh2u, bfh, log_exceptions, ignore_exceptions, TxMinedInfo, random_shuffled_copy
from .address_synchronizer import AddressSynchronizer, TX_HEIGHT_LOCAL, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED
from .transaction import Transaction, TxOutpoint

if TYPE_CHECKING:
    from .network import Network
    from .lnsweep import SweepInfo
    from .lnworker import LNWallet

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
        return [Transaction(bh2u(r[0])) for r in c.fetchall()]

    @sql
    def list_sweep_tx(self):
        c = self.conn.cursor()
        c.execute("SELECT funding_outpoint FROM sweep_txs")
        return set([r[0] for r in c.fetchall()])

    @sql
    def add_sweep_tx(self, funding_outpoint, ctn, prevout, raw_tx):
        c = self.conn.cursor()
        assert Transaction(raw_tx).is_complete()
        c.execute("""INSERT INTO sweep_txs (funding_outpoint, ctn, prevout, tx) VALUES (?,?,?,?)""", (funding_outpoint, ctn, prevout, bfh(raw_tx)))
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
    LOGGING_SHORTCUT = 'W'

    def __init__(self, network: 'Network'):
        AddressSynchronizer.__init__(self, WalletDB({}, manual_upgrades=False))
        self.config = network.config
        self.callbacks = {} # address -> lambda: coroutine
        self.network = network
        util.register_callback(
            self.on_network_update,
            ['network_updated', 'blockchain_updated', 'verified', 'wallet_updated', 'fee'])

        # status gets populated when we run
        self.channel_status = {}

    def stop(self):
        super().stop()
        util.unregister_callback(self.on_network_update)

    def get_channel_status(self, outpoint):
        return self.channel_status.get(outpoint, 'unknown')

    def add_channel(self, outpoint: str, address: str) -> None:
        assert isinstance(outpoint, str)
        assert isinstance(address, str)
        cb = lambda: self.check_onchain_situation(address, outpoint)
        self.add_callback(address, cb)

    async def unwatch_channel(self, address, funding_outpoint):
        self.logger.info(f'unwatching {funding_outpoint}')
        self.remove_callback(address)

    def remove_callback(self, address):
        self.callbacks.pop(address, None)

    def add_callback(self, address, callback):
        self.add_address(address)
        self.callbacks[address] = callback

    @log_exceptions
    async def on_network_update(self, event, *args):
        if event in ('verified', 'wallet_updated'):
            if args[0] != self:
                return
        if not self.synchronizer:
            self.logger.info("synchronizer not set yet")
            return
        for address, callback in list(self.callbacks.items()):
            await callback()

    async def check_onchain_situation(self, address, funding_outpoint):
        # early return if address has not been added yet
        if not self.is_mine(address):
            return
        spenders = self.inspect_tx_candidate(funding_outpoint, 0)
        # inspect_tx_candidate might have added new addresses, in which case we return ealy
        if not self.is_up_to_date():
            return
        funding_txid = funding_outpoint.split(':')[0]
        funding_height = self.get_tx_height(funding_txid)
        closing_txid = spenders.get(funding_outpoint)
        closing_height = self.get_tx_height(closing_txid)
        if closing_txid:
            closing_tx = self.db.get_transaction(closing_txid)
            if closing_tx:
                keep_watching = await self.do_breach_remedy(funding_outpoint, closing_tx, spenders)
            else:
                self.logger.info(f"channel {funding_outpoint} closed by {closing_txid}. still waiting for tx itself...")
                keep_watching = True
        else:
            keep_watching = True
        await self.update_channel_state(
            funding_outpoint=funding_outpoint,
            funding_txid=funding_txid,
            funding_height=funding_height,
            closing_txid=closing_txid,
            closing_height=closing_height,
            keep_watching=keep_watching)
        if not keep_watching:
            await self.unwatch_channel(address, funding_outpoint)

    async def do_breach_remedy(self, funding_outpoint, closing_tx, spenders) -> bool:
        raise NotImplementedError()  # implemented by subclasses

    async def update_channel_state(self, *, funding_outpoint: str, funding_txid: str,
                                   funding_height: TxMinedInfo, closing_txid: str,
                                   closing_height: TxMinedInfo, keep_watching: bool) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def inspect_tx_candidate(self, outpoint, n):
        prev_txid, index = outpoint.split(':')
        txid = self.db.get_spent_outpoint(prev_txid, int(index))
        result = {outpoint:txid}
        if txid is None:
            self.channel_status[outpoint] = 'open'
            return result
        if n == 0 and not self.is_deeply_mined(txid):
            self.channel_status[outpoint] = 'closed (%d)' % self.get_tx_height(txid).conf
        else:
            self.channel_status[outpoint] = 'closed (deep)'
        tx = self.db.get_transaction(txid)
        for i, o in enumerate(tx.outputs()):
            if not self.is_mine(o.address):
                self.add_address(o.address)
            elif n < 2:
                r = self.inspect_tx_candidate(txid+':%d'%i, n+1)
                result.update(r)
        return result

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

    def is_deeply_mined(self, txid):
        return self.get_tx_mined_depth(txid) == TxMinedDepth.DEEP


class WatchTower(LNWatcher):

    LOGGING_SHORTCUT = 'W'

    def __init__(self, network):
        LNWatcher.__init__(self, network)
        self.network = network
        self.sweepstore = SweepStore(os.path.join(self.network.config.path, "watchtower_db"), network)
        # this maps funding_outpoints to ListenerItems, which have an event for when the watcher is done,
        # and a queue for seeing which txs are being published
        self.tx_progress = {} # type: Dict[str, ListenerItem]

    async def start_watching(self):
        # I need to watch the addresses from sweepstore
        lst = await self.sweepstore.list_channels()
        for outpoint, address in random_shuffled_copy(lst):
            self.add_channel(outpoint, address)

    async def do_breach_remedy(self, funding_outpoint, closing_tx, spenders):
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




class LNWalletWatcher(LNWatcher):

    def __init__(self, lnworker: 'LNWallet', network: 'Network'):
        LNWatcher.__init__(self, network)
        self.network = network
        self.lnworker = lnworker

    @ignore_exceptions
    @log_exceptions
    async def update_channel_state(self, *, funding_outpoint: str, funding_txid: str,
                                   funding_height: TxMinedInfo, closing_txid: str,
                                   closing_height: TxMinedInfo, keep_watching: bool) -> None:
        chan = self.lnworker.channel_by_txo(funding_outpoint)
        if not chan:
            return
        chan.update_onchain_state(funding_txid=funding_txid,
                                  funding_height=funding_height,
                                  closing_txid=closing_txid,
                                  closing_height=closing_height,
                                  keep_watching=keep_watching)
        await self.lnworker.on_channel_update(chan)

    async def do_breach_remedy(self, funding_outpoint, closing_tx, spenders):
        chan = self.lnworker.channel_by_txo(funding_outpoint)
        if not chan:
            return False
        # detect who closed and set sweep_info
        sweep_info_dict = chan.sweep_ctx(closing_tx)
        keep_watching = False if sweep_info_dict else not self.is_deeply_mined(closing_tx.txid())
        self.logger.info(f'(chan {chan.get_id_for_log()}) sweep_info_dict {[x.name for x in sweep_info_dict.values()]}')
        # create and broadcast transaction
        for prevout, sweep_info in sweep_info_dict.items():
            name = sweep_info.name + ' ' + chan.get_id_for_log()
            spender_txid = spenders.get(prevout)
            if spender_txid is not None:
                spender_tx = self.db.get_transaction(spender_txid)
                if not spender_tx:
                    keep_watching = True
                    continue
                e_htlc_tx = chan.maybe_sweep_revoked_htlc(closing_tx, spender_tx)
                if e_htlc_tx:
                    spender2 = spenders.get(spender_txid+':0')
                    if spender2:
                        self.logger.info(f'(chan {chan.get_id_for_log()}) htlc is already spent {name}: {prevout}')
                        keep_watching |= not self.is_deeply_mined(spender2)
                    else:
                        self.logger.info(f'(chan {chan.get_id_for_log()}) trying to redeem htlc {name}: {prevout}')
                        await self.try_redeem(spender_txid+':0', e_htlc_tx, name)
                        keep_watching = True
                else:
                    self.logger.info(f'(chan {chan.get_id_for_log()}) outpoint already spent {name}: {prevout}')
                    keep_watching |= not self.is_deeply_mined(spender_txid)
                    txin_idx = spender_tx.get_input_idx_that_spent_prevout(TxOutpoint.from_str(prevout))
                    assert txin_idx is not None
                    spender_txin = spender_tx.inputs()[txin_idx]
                    chan.extract_preimage_from_htlc_txin(spender_txin)
            else:
                self.logger.info(f'(chan {chan.get_id_for_log()}) trying to redeem {name}: {prevout}')
                await self.try_redeem(prevout, sweep_info, name)
                keep_watching = True
        return keep_watching

    @log_exceptions
    async def try_redeem(self, prevout: str, sweep_info: 'SweepInfo', name: str) -> None:
        prev_txid, prev_index = prevout.split(':')
        broadcast = True
        if sweep_info.cltv_expiry:
            local_height = self.network.get_local_height()
            remaining = sweep_info.cltv_expiry - local_height
            if remaining > 0:
                self.logger.info('waiting for {}: CLTV ({} > {}), prevout {}'
                                 .format(name, local_height, sweep_info.cltv_expiry, prevout))
                broadcast = False
        if sweep_info.csv_delay:
            prev_height = self.get_tx_height(prev_txid)
            remaining = sweep_info.csv_delay - prev_height.conf
            if remaining > 0:
                self.logger.info('waiting for {}: CSV ({} >= {}), prevout: {}'
                                 .format(name, prev_height.conf, sweep_info.csv_delay, prevout))
                broadcast = False
        tx = sweep_info.gen_tx()
        if tx is None:
            self.logger.info(f'{name} could not claim output: {prevout}, dust')
        self.lnworker.wallet.set_label(tx.txid(), name)
        if broadcast:
            await self.network.try_broadcasting(tx, name)
        else:
            # it's OK to add local transaction, the fee will be recomputed
            try:
                tx_was_added = self.lnworker.wallet.add_future_tx(tx, remaining)
            except Exception as e:
                self.logger.info(f'could not add future tx: {name}. prevout: {prevout} {str(e)}')
                tx_was_added = False
            if tx_was_added:
                self.logger.info(f'added future tx: {name}. prevout: {prevout}')
                util.trigger_callback('wallet_updated', self.lnworker.wallet)
