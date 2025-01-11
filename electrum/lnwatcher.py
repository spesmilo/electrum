# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import NamedTuple, Iterable, TYPE_CHECKING
import os
import copy
import asyncio
from enum import IntEnum, auto
from typing import NamedTuple, Dict

from . import util
from .wallet_db import WalletDB
from .util import bfh, log_exceptions, ignore_exceptions, TxMinedInfo, random_shuffled_copy
from .address_synchronizer import AddressSynchronizer, TX_HEIGHT_LOCAL, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_FUTURE
from .transaction import Transaction, TxOutpoint, PartialTransaction
from .logging import Logger


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




from .util import EventListener, event_listener

class LNWatcher(Logger, EventListener):

    LOGGING_SHORTCUT = 'W'

    def __init__(self, adb: 'AddressSynchronizer', network: 'Network'):

        Logger.__init__(self)
        self.adb = adb
        self.config = network.config
        self.callbacks = {} # address -> lambda: coroutine
        self.network = network
        self.register_callbacks()
        # status gets populated when we run
        self.channel_status = {}

    async def stop(self):
        self.unregister_callbacks()

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

    async def check_onchain_situation(self, address, funding_outpoint):
        # early return if address has not been added yet
        if not self.adb.is_mine(address):
            return
        # inspect_tx_candidate might have added new addresses, in which case we return early
        if not self.adb.is_up_to_date():
            return
        funding_txid = funding_outpoint.split(':')[0]
        funding_height = self.adb.get_tx_height(funding_txid)
        closing_txid = self.get_spender(funding_outpoint)
        closing_height = self.adb.get_tx_height(closing_txid)
        if closing_txid:
            closing_tx = self.adb.get_transaction(closing_txid)
            if closing_tx:
                keep_watching = await self.sweep_commitment_transaction(funding_outpoint, closing_tx)
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

    async def sweep_commitment_transaction(self, funding_outpoint, closing_tx) -> bool:
        raise NotImplementedError()  # implemented by subclasses

    async def update_channel_state(self, *, funding_outpoint: str, funding_txid: str,
                                   funding_height: TxMinedInfo, closing_txid: str,
                                   closing_height: TxMinedInfo, keep_watching: bool) -> None:
        raise NotImplementedError()  # implemented by subclasses


    def get_spender(self, outpoint) -> str:
        """
        returns txid spending outpoint.
        subscribes to addresses as a side effect.
        """
        prev_txid, index = outpoint.split(':')
        spender_txid = self.adb.db.get_spent_outpoint(prev_txid, int(index))
        # discard local spenders
        tx_mined_status = self.adb.get_tx_height(spender_txid)
        if tx_mined_status.height in [TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE]:
            spender_txid = None
        if not spender_txid:
            return
        spender_tx = self.adb.get_transaction(spender_txid)
        for i, o in enumerate(spender_tx.outputs()):
            if o.address is None:
                continue
            if not self.adb.is_mine(o.address):
                self.adb.add_address(o.address)
        return spender_txid

    def get_tx_mined_depth(self, txid: str):
        if not txid:
            return TxMinedDepth.FREE
        tx_mined_depth = self.adb.get_tx_height(txid)
        height, conf = tx_mined_depth.height, tx_mined_depth.conf
        if conf > 100:
            return TxMinedDepth.DEEP
        elif conf > 0:
            return TxMinedDepth.SHALLOW
        elif height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT):
            return TxMinedDepth.MEMPOOL
        elif height in (TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE):
            return TxMinedDepth.FREE
        elif height > 0 and conf == 0:
            # unverified but claimed to be mined
            return TxMinedDepth.MEMPOOL
        else:
            raise NotImplementedError()

    def is_deeply_mined(self, txid):
        return self.get_tx_mined_depth(txid) == TxMinedDepth.DEEP




class LNWalletWatcher(LNWatcher):

    def __init__(self, lnworker: 'LNWallet', network: 'Network'):
        self.network = network
        self.lnworker = lnworker
        LNWatcher.__init__(self, lnworker.wallet.adb, network)

    @event_listener
    async def on_event_blockchain_updated(self, *args):
        # overload parent method with cache invalidation
        # we invalidate the cache on each new block because
        # some processes affect the list of sweep transactions
        # (hold invoice preimage revealed, MPP completed, etc)
        for chan in self.lnworker.channels.values():
            chan._sweep_info.clear()
        await self.trigger_callbacks()

    def diagnostic_name(self):
        return f"{self.lnworker.wallet.diagnostic_name()}-LNW"

    @ignore_exceptions
    @log_exceptions
    async def update_channel_state(self, *, funding_outpoint: str, funding_txid: str,
                                   funding_height: TxMinedInfo, closing_txid: str,
                                   closing_height: TxMinedInfo, keep_watching: bool) -> None:
        chan = self.lnworker.channel_by_txo(funding_outpoint)
        if not chan:
            return
        chan.update_onchain_state(
            funding_txid=funding_txid,
            funding_height=funding_height,
            closing_txid=closing_txid,
            closing_height=closing_height,
            keep_watching=keep_watching)
        await self.lnworker.handle_onchain_state(chan)

    @log_exceptions
    async def sweep_commitment_transaction(self, funding_outpoint, closing_tx) -> bool:
        """This function is called when a channel was closed. In this case
        we need to check for redeemable outputs of the commitment transaction
        or spenders down the line (HTLC-timeout/success transactions).

        Returns whether we should continue to monitor."""
        chan = self.lnworker.channel_by_txo(funding_outpoint)
        if not chan:
            return False
        chan_id_for_log = chan.get_id_for_log()
        # detect who closed and get information about how to claim outputs
        sweep_info_dict = chan.sweep_ctx(closing_tx)
        #self.logger.info(f"do_breach_remedy: {[x.name for x in sweep_info_dict.values()]}")
        keep_watching = False if sweep_info_dict else not self.is_deeply_mined(closing_tx.txid())
        # create and broadcast transactions
        for prevout, sweep_info in sweep_info_dict.items():
            prev_txid, prev_index = prevout.split(':')
            name = sweep_info.name + ' ' + chan.get_id_for_log()
            self.lnworker.wallet.set_default_label(prevout, name)
            if not self.adb.get_transaction(prev_txid):
                # do not keep watching if prevout does not exist
                self.logger.info(f'prevout does not exist for {name}: {prevout}')
                continue
            spender_txid = self.get_spender(prevout)
            spender_tx = self.adb.get_transaction(spender_txid) if spender_txid else None
            if spender_tx:
                # the spender might be the remote, revoked or not
                htlc_sweepinfo = chan.maybe_sweep_htlcs(closing_tx, spender_tx)
                for prevout2, htlc_sweep_info in htlc_sweepinfo.items():
                    htlc_tx_spender = self.get_spender(prevout2)
                    self.lnworker.wallet.set_default_label(prevout2, htlc_sweep_info.name)
                    if htlc_tx_spender:
                        keep_watching |= not self.is_deeply_mined(htlc_tx_spender)
                    else:
                        keep_watching = True
                        await self.maybe_redeem(htlc_sweep_info)
                # extract preimage
                keep_watching |= not self.is_deeply_mined(spender_txid)
                txin_idx = spender_tx.get_input_idx_that_spent_prevout(TxOutpoint.from_str(prevout))
                if txin_idx is not None:
                    spender_txin = spender_tx.inputs()[txin_idx]
                    chan.extract_preimage_from_htlc_txin(spender_txin)
            else:
                keep_watching = True
                # broadcast or maybe update our own tx
                await self.maybe_redeem(sweep_info)
        return keep_watching


    async def maybe_redeem(self, sweep_info: 'SweepInfo') -> None:
        if not (sweep_info.cltv_abs or sweep_info.csv_delay):
            # used to control settling of htlcs onchain for testing purposes
            # careful, this prevents revocation as well
            if not self.lnworker.enable_htlc_settle_onchain:
                return
        self.lnworker.wallet.txengine.add_sweep_info(sweep_info)
