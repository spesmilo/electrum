# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import TYPE_CHECKING

from .util import TxMinedInfo, BelowDustLimit
from .util import EventListener, event_listener
from .transaction import Transaction, TxOutpoint
from .logging import Logger


if TYPE_CHECKING:
    from .network import Network
    from .lnsweep import SweepInfo
    from .lnworker import LNWallet
    from .lnchannel import AbstractChannel


class LNWatcher(Logger, EventListener):

    LOGGING_SHORTCUT = 'W'

    def __init__(self, lnworker: 'LNWallet'):
        self.lnworker = lnworker
        Logger.__init__(self)
        self.adb = lnworker.wallet.adb
        self.config = lnworker.config
        self.callbacks = {}  # address -> lambda function
        self.network = None
        self.register_callbacks()
        # status gets populated when we run
        self.channel_status = {}

    def start_network(self, network: 'Network'):
        self.network = network

    def stop(self):
        self.unregister_callbacks()

    def get_channel_status(self, outpoint):
        return self.channel_status.get(outpoint, 'unknown')

    def remove_callback(self, address):
        self.callbacks.pop(address, None)

    def add_callback(self, address, callback):
        self.adb.add_address(address)
        self.callbacks[address] = callback

    def trigger_callbacks(self):
        if not self.adb.synchronizer:
            self.logger.info("synchronizer not set yet")
            return
        for address, callback in list(self.callbacks.items()):
            callback()

    @event_listener
    async def on_event_blockchain_updated(self, *args):
        # we invalidate the cache on each new block because
        # some processes affect the list of sweep transactions
        # (hold invoice preimage revealed, MPP completed, etc)
        for chan in self.lnworker.channels.values():
            chan._sweep_info.clear()
        self.trigger_callbacks()

    @event_listener
    def on_event_wallet_updated(self, wallet):
        # called if we add local tx
        if wallet.adb != self.adb:
            return
        self.trigger_callbacks()

    @event_listener
    def on_event_adb_added_verified_tx(self, adb, tx_hash):
        if adb != self.adb:
            return
        self.trigger_callbacks()

    @event_listener
    def on_event_adb_set_up_to_date(self, adb):
        if adb != self.adb:
            return
        self.trigger_callbacks()

    def add_channel(self, chan: 'AbstractChannel') -> None:
        outpoint = chan.funding_outpoint.to_str()
        address = chan.get_funding_address()
        callback = lambda: self.check_onchain_situation(address, outpoint)
        callback()  # run once, for side effects
        if chan.need_to_subscribe():
            self.add_callback(address, callback)

    def unwatch_channel(self, address, funding_outpoint):
        self.logger.info(f'unwatching {funding_outpoint}')
        self.remove_callback(address)

    def check_onchain_situation(self, address, funding_outpoint):
        # early return if address has not been added yet
        if not self.adb.is_mine(address):
            return
        # inspect_tx_candidate might have added new addresses, in which case we return early
        funding_txid = funding_outpoint.split(':')[0]
        funding_height = self.adb.get_tx_height(funding_txid)
        closing_txid = self.adb.get_spender(funding_outpoint)
        closing_height = self.adb.get_tx_height(closing_txid)
        if closing_txid:
            closing_tx = self.adb.get_transaction(closing_txid)
            if closing_tx:
                keep_watching = self.sweep_commitment_transaction(funding_outpoint, closing_tx)
            else:
                self.logger.info(f"channel {funding_outpoint} closed by {closing_txid}. still waiting for tx itself...")
                keep_watching = True
        else:
            keep_watching = True
        self.update_channel_state(
            funding_outpoint=funding_outpoint,
            funding_txid=funding_txid,
            funding_height=funding_height,
            closing_txid=closing_txid,
            closing_height=closing_height,
            keep_watching=keep_watching)
        if not keep_watching:
            self.unwatch_channel(address, funding_outpoint)

    def diagnostic_name(self):
        return f"{self.lnworker.wallet.diagnostic_name()}-LNW"

    def update_channel_state(self, *, funding_outpoint: str, funding_txid: str,
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
        self.lnworker.handle_onchain_state(chan)

    def sweep_commitment_transaction(self, funding_outpoint, closing_tx) -> bool:
        """This function is called when a channel was closed. In this case
        we need to check for redeemable outputs of the commitment transaction
        or spenders down the line (HTLC-timeout/success transactions).

        Returns whether we should continue to monitor.

        Side-effécts:
          - sets defaults labels
        """
        chan = self.lnworker.channel_by_txo(funding_outpoint)
        if not chan:
            return False
        # detect who closed and get information about how to claim outputs
        sweep_info_dict = chan.sweep_ctx(closing_tx)
        keep_watching = False if sweep_info_dict else not self.adb.is_deeply_mined(closing_tx.txid())
        # create and broadcast transactions
        for prevout, sweep_info in sweep_info_dict.items():
            prev_txid, prev_index = prevout.split(':')
            name = sweep_info.name + ' ' + chan.get_id_for_log()
            self.lnworker.wallet.set_default_label(prevout, name)
            if not self.adb.get_transaction(prev_txid):
                # do not keep watching if prevout does not exist
                self.logger.info(f'prevout does not exist for {name}: {prevout}')
                continue
            spender_txid = self.adb.get_spender(prevout)
            spender_tx = self.adb.get_transaction(spender_txid) if spender_txid else None
            if spender_tx:
                # the spender might be the remote, revoked or not
                htlc_sweepinfo = chan.maybe_sweep_htlcs(closing_tx, spender_tx)
                for prevout2, htlc_sweep_info in htlc_sweepinfo.items():
                    htlc_tx_spender = self.adb.get_spender(prevout2)
                    self.lnworker.wallet.set_default_label(prevout2, htlc_sweep_info.name)
                    if htlc_tx_spender:
                        keep_watching |= not self.adb.is_deeply_mined(htlc_tx_spender)
                    else:
                        keep_watching |= self.maybe_redeem(htlc_sweep_info)
                keep_watching |= not self.adb.is_deeply_mined(spender_txid)
                self.maybe_extract_preimage(chan, spender_tx, prevout)
            else:
                keep_watching |= self.maybe_redeem(sweep_info)
        return keep_watching

    def maybe_redeem(self, sweep_info: 'SweepInfo') -> bool:
        """ returns False if it was dust """
        try:
            self.lnworker.wallet.txbatcher.add_sweep_input('lnwatcher', sweep_info, self.config.FEE_POLICY_LIGHTNING)
        except BelowDustLimit:
            return False
        return True

    def maybe_extract_preimage(self, chan: 'AbstractChannel', spender_tx: Transaction, prevout: str):
        txin_idx = spender_tx.get_input_idx_that_spent_prevout(TxOutpoint.from_str(prevout))
        assert txin_idx is not None
        spender_txin = spender_tx.inputs()[txin_idx]
        chan.extract_preimage_from_htlc_txin(
            spender_txin,
            is_deeply_mined=self.adb.is_deeply_mined(spender_tx.txid()),
        )
