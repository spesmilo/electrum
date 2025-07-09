# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import TYPE_CHECKING, Optional

from . import util
from .util import TxMinedInfo, BelowDustLimit, NoDynamicFeeEstimates
from .util import EventListener, event_listener, log_exceptions, ignore_exceptions
from .transaction import Transaction, TxOutpoint
from .logging import Logger
from .address_synchronizer import TX_HEIGHT_LOCAL
from .lnutil import REDEEM_AFTER_DOUBLE_SPENT_DELAY


if TYPE_CHECKING:
    from .network import Network
    from .lnsweep import SweepInfo
    from .lnworker import LNWallet
    from .lnchannel import AbstractChannel


class LNWatcher(Logger, EventListener):

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
        self._pending_force_closes = set()

    def start_network(self, network: 'Network'):
        self.network = network

    def stop(self):
        self.unregister_callbacks()

    def get_channel_status(self, outpoint):
        return self.channel_status.get(outpoint, 'unknown')

    def remove_callback(self, address):
        self.callbacks.pop(address, None)

    def add_callback(self, address, callback, *, subscribe=True):
        if subscribe:
            self.adb.add_address(address)
        self.callbacks[address] = callback

    async def trigger_callbacks(self, *, requires_synchronizer=True):
        if requires_synchronizer and not self.adb.synchronizer:
            self.logger.info("synchronizer not set yet")
            return
        for address, callback in list(self.callbacks.items()):
            await callback()
        # send callback to GUI
        util.trigger_callback('wallet_updated', self.lnworker.wallet)

    @event_listener
    async def on_event_blockchain_updated(self, *args):
        await self.trigger_callbacks()

    @event_listener
    async def on_event_adb_added_tx(self, adb, tx_hash, tx):
        # called if we add local tx
        if adb != self.adb:
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

    def add_channel(self, chan: 'AbstractChannel') -> None:
        outpoint = chan.funding_outpoint.to_str()
        address = chan.get_funding_address()
        callback = lambda: self.check_onchain_situation(address, outpoint)
        self.add_callback(address, callback, subscribe=chan.need_to_subscribe())

    @ignore_exceptions
    @log_exceptions
    async def check_onchain_situation(self, address: str, funding_outpoint: str) -> None:
        # early return if address has not been added yet
        if not self.adb.is_mine(address):
            return
        # inspect_tx_candidate might have added new addresses, in which case we return early
        # note: maybe we should wait until adb.is_up_to_date... (?)
        funding_txid = funding_outpoint.split(':')[0]
        funding_height = self.adb.get_tx_height(funding_txid)
        closing_txid = self.adb.get_spender(funding_outpoint)
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

    def diagnostic_name(self):
        return f"{self.lnworker.wallet.diagnostic_name()}-LNW"

    async def update_channel_state(
            self, *, funding_outpoint: str, funding_txid: str,
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
        if closing_height.conf > 0:
            self._pending_force_closes.discard(chan)
        await self.lnworker.handle_onchain_state(chan)

    async def sweep_commitment_transaction(self, funding_outpoint: str, closing_tx: Transaction) -> bool:
        """This function is called when a channel was closed. In this case
        we need to check for redeemable outputs of the commitment transaction
        or spenders down the line (HTLC-timeout/success transactions).

        Returns whether we should continue to monitor.

        Side-effects:
          - sets defaults labels
          - populates wallet._accounting_addresses
        """
        assert closing_tx
        chan = self.lnworker.channel_by_txo(funding_outpoint)
        if not chan:
            return False
        # detect who closed and get information about how to claim outputs
        is_local_ctx, sweep_info_dict = chan.get_ctx_sweep_info(closing_tx)
        # note: we need to keep watching *at least* until the closing tx is deeply mined,
        #       possibly longer if there are TXOs to sweep
        keep_watching = not self.adb.is_deeply_mined(closing_tx.txid())
        # create and broadcast transactions
        for prevout, sweep_info in sweep_info_dict.items():
            prev_txid, prev_index = prevout.split(':')
            name = sweep_info.name + ' ' + chan.get_id_for_log()
            self.lnworker.wallet.set_default_label(prevout, name)
            if not self.adb.get_transaction(prev_txid):
                # do not keep watching if prevout does not exist
                self.logger.info(f'prevout does not exist for {name}: {prevout}')
                continue
            watch_sweep_info = self.maybe_redeem(sweep_info)
            spender_txid = self.adb.get_spender(prevout)  # note: LOCAL spenders don't count
            spender_tx = self.adb.get_transaction(spender_txid) if spender_txid else None
            if spender_tx:
                # the spender might be the remote, revoked or not
                htlc_sweepinfo = chan.maybe_sweep_htlcs(closing_tx, spender_tx)
                for prevout2, htlc_sweep_info in htlc_sweepinfo.items():
                    watch_htlc_sweep_info = self.maybe_redeem(htlc_sweep_info)
                    htlc_tx_spender = self.adb.get_spender(prevout2)
                    self.lnworker.wallet.set_default_label(prevout2, htlc_sweep_info.name)
                    if htlc_tx_spender:
                        keep_watching |= not self.adb.is_deeply_mined(htlc_tx_spender)
                        self.maybe_add_accounting_address(htlc_tx_spender, htlc_sweep_info)
                    else:
                        keep_watching |= watch_htlc_sweep_info
                keep_watching |= not self.adb.is_deeply_mined(spender_txid)
                self.maybe_extract_preimage(chan, spender_tx, prevout)
                self.maybe_add_accounting_address(spender_txid, sweep_info)
            else:
                keep_watching |= watch_sweep_info
            self.maybe_add_pending_forceclose(
                chan=chan,
                spender_txid=spender_txid,
                is_local_ctx=is_local_ctx,
                sweep_info=sweep_info,
            )
        return keep_watching

    def get_pending_force_closes(self):
        return self._pending_force_closes

    def maybe_redeem(self, sweep_info: 'SweepInfo') -> bool:
        """ returns 'keep_watching' """
        try:
            self.lnworker.wallet.txbatcher.add_sweep_input('lnwatcher', sweep_info)
        except BelowDustLimit:
            # utxo is considered dust at *current* fee estimates.
            # but maybe the fees atm are very high? We will retry later.
            pass
        except NoDynamicFeeEstimates:
            pass  # will retry later
        if sweep_info.is_anchor():
            return False
        return True

    def maybe_extract_preimage(self, chan: 'AbstractChannel', spender_tx: Transaction, prevout: str):
        if not spender_tx.is_complete():
            self.logger.info('spender tx is unsigned')
            return
        txin_idx = spender_tx.get_input_idx_that_spent_prevout(TxOutpoint.from_str(prevout))
        assert txin_idx is not None
        spender_txin = spender_tx.inputs()[txin_idx]
        chan.extract_preimage_from_htlc_txin(
            spender_txin,
            is_deeply_mined=self.adb.is_deeply_mined(spender_tx.txid()),
        )

    def maybe_add_accounting_address(self, spender_txid: str, sweep_info: 'SweepInfo'):
        spender_tx = self.adb.get_transaction(spender_txid) if spender_txid else None
        if not spender_tx:
            return
        for i, txin in enumerate(spender_tx.inputs()):
            if txin.prevout == sweep_info.txin.prevout:
                break
        else:
            return
        if sweep_info.name in ['offered-htlc', 'received-htlc']:
            # always consider ours
            pass
        else:
            witness = txin.witness_elements()
            for sig in witness:
                # fixme: verify sig is ours
                witness2 = sweep_info.txin.make_witness(sig)
                if txin.witness == witness2:
                    break
            else:
                self.logger.info(f"signature not found {sweep_info.name}, {txin.prevout.to_str()}")
                return
        self.logger.info(f'adding txin address {sweep_info.name}, {txin.prevout.to_str()}')
        prev_txid, prev_index = txin.prevout.to_str().split(':')
        prev_tx = self.adb.get_transaction(prev_txid)
        txout = prev_tx.outputs()[int(prev_index)]
        self.lnworker.wallet._accounting_addresses.add(txout.address)

    def maybe_add_pending_forceclose(
        self,
        *,
        chan: 'AbstractChannel',
        spender_txid: Optional[str],
        is_local_ctx: bool,
        sweep_info: 'SweepInfo',
    ) -> None:
        """Adds chan into set of ongoing force-closures if the user should keep the wallet open, waiting for it.
        (we are waiting for ctx to be confirmed and there are received htlcs)
        """
        if is_local_ctx and sweep_info.name == 'received-htlc':
            cltv = sweep_info.cltv_abs
            assert cltv is not None, f"missing cltv for {sweep_info}"
            if self.adb.get_local_height() > cltv + REDEEM_AFTER_DOUBLE_SPENT_DELAY:
                # We had plenty of time to sweep. The remote also had time to time out the htlc.
                # Maybe its value has been ~dust at current and past fee levels (every time we checked).
                # We should not keep warning the user forever.
                return
            tx_mined_status = self.adb.get_tx_height(spender_txid)
            if tx_mined_status.height == TX_HEIGHT_LOCAL:
                self._pending_force_closes.add(chan)
