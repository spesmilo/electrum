import asyncio
import os
from typing import Optional, Sequence
from unittest import mock

from electrum_ecc import ECPrivkey

from electrum import bitcoin
from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.bitcoin import COIN, DUST_LIMIT_P2WSH
from electrum.util import bfh, now
from electrum.crypto import sha256
from electrum.lnonion import OnionRoutingFailure
from electrum.simple_config import SimpleConfig
from electrum.submarine_swaps import (
    SwapManager, SwapData, SwapServerTransport, LOCKTIME_DELTA_REFUND,
    MIN_LOCKTIME_DELTA_FOR_CLAIM, SPENDER_FINALITY_DELAY, _construct_swap_scriptcode)
from electrum.transaction import (
    PartialTransaction, PartialTxOutput, Transaction, TxOutput, TxOutpoint)
from electrum.txbatcher import TxBatcher
from electrum.wallet import Standard_Wallet, Wallet

from .toyserver.testcase import ToyServerTestCase


def random_address() -> str:
    """an address that does not belong to any wallet of the test"""
    return bitcoin.pubkey_to_address('p2wpkh', ECPrivkey(os.urandom(32)).get_public_key_hex(compressed=True))


class MockSwapServerTransport(SwapServerTransport):
    def __init__(self, *, config: SimpleConfig, sm: SwapManager):
        super().__init__(config=config, sm=sm)
        self.requests = []  # type: list[tuple[str, Optional[dict]]]
        self.is_connected.set()

    async def send_request_to_server(self, method: str, request_data: Optional[dict]) -> dict:
        self.requests.append((method, request_data))
        return {}


class SwapTestWallet(Standard_Wallet):
    def _start_network_lightning(self):
        # start only the lightning parts the swap manager needs
        self.lnworker.lnwatcher.start_network(self.network)
        self.lnworker.swap_manager.start_network(self.network)


class SwapTestWalletFactory(Wallet):
    @staticmethod
    def wallet_class(wallet_type):
        return SwapTestWallet


class TestSwapClaim(ToyServerTestCase):
    """The counterparty ("the server") is simulated: we keep its privkey and the preimage in the
    test, and build its claim tx with the same code the server would use.
    """

    def create_config(self, name: str = None) -> SimpleConfig:
        config = super().create_config(name)
        config.FEE_POLICY_SWAPS = 'feerate:5000'
        return config

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice = await self.create_instance("alice")
        self.wallet = self.create_wallet("alice", instance=self.alice, wallet_factory=SwapTestWalletFactory)
        self.sm = self.wallet.lnworker.swap_manager
        self.adb = self.wallet.adb
        await self.pay_to_address(self.wallet.get_receiving_address(), 1 * COIN)
        await self.mine_blocks(1)

    # --- swap helpers ---

    async def mine_until_swap_expires(self, swap: SwapData) -> None:
        await self.mine_blocks(swap.locktime - self.server.cur_height)

    async def restart_txbatcher(self) -> None:
        """Restart the txbatcher, the way a wallet restart would: TxBatcher.__init__ rebuilds
        its batches from the wallet db, which persists only the txids and the prevout of the
        current batch tx. The sweep info is not persisted, so whoever added a sweep input has
        to add it again, otherwise add_sweep_info_to_tx() cannot sign a replacement of the
        tx we already broadcast.
        """
        await self.wallet.txbatcher.taskgroup.cancel_remaining()
        self.wallet.txbatcher = TxBatcher(self.wallet)
        self.wallet.txbatcher.SLEEP_INTERVAL *= self.TIME_STEP
        await self.wallet.taskgroup.spawn(self.wallet.txbatcher.run())
        await self.sync()

    def utxos_at_lockup_address(self, swap: SwapData) -> Sequence[TxOutpoint]:
        return list(self.adb.get_addr_outputs(swap.lockup_address).keys())

    def create_forward_swap(self, *, onchain_amount: int = 100_000) -> SwapData:
        """Client side of a forward swap: we send on-chain, we receive on lightning.
        Same as request_normal_swap() would create after an honest server response.
        """
        self.preimage = os.urandom(32)
        self.server_privkey = os.urandom(32)
        server_pubkey = ECPrivkey(self.server_privkey).get_public_key_bytes(compressed=True)
        refund_privkey = os.urandom(32)
        refund_pubkey = ECPrivkey(refund_privkey).get_public_key_bytes(compressed=True)
        payment_hash = sha256(self.preimage)
        locktime = self.server.cur_height + LOCKTIME_DELTA_REFUND
        redeem_script = _construct_swap_scriptcode(
            payment_hash=payment_hash,
            locktime=locktime,
            refund_pubkey=refund_pubkey,
            claim_pubkey=server_pubkey,
        )
        swap, invoice, _prepay = self.sm.add_normal_swap(
            redeem_script=redeem_script,
            locktime=locktime,
            onchain_amount_sat=onchain_amount,
            lightning_amount_sat=onchain_amount + 1000,
            payment_hash=payment_hash,
            our_privkey=refund_privkey,
            prepay=False,
        )
        self.invoice = invoice  # the hold invoice we hand to the server
        # the client holds the incoming htlcs until it learns the preimage from the claim tx
        self.sm.lnworker.register_hold_invoice(payment_hash, self.sm.hold_invoice_callback)
        return swap

    def create_reverse_swap(
            self, *,
            onchain_amount: int = 100_000,
            claim_to_output: Optional[TxOutput] = None,
    ) -> SwapData:
        """Client side of a reverse swap: we send on lightning, we receive on-chain.
        With claim_to_output set this is a submarine payment: we claim to a third party.
        """
        self.preimage = os.urandom(32)
        self.server_privkey = os.urandom(32)
        server_pubkey = ECPrivkey(self.server_privkey).get_public_key_bytes(compressed=True)
        claim_privkey = os.urandom(32)
        claim_pubkey = ECPrivkey(claim_privkey).get_public_key_bytes(compressed=True)
        payment_hash = sha256(self.preimage)
        locktime = self.server.cur_height + LOCKTIME_DELTA_REFUND
        redeem_script = _construct_swap_scriptcode(
            payment_hash=payment_hash,
            locktime=locktime,
            refund_pubkey=server_pubkey,
            claim_pubkey=claim_pubkey,
        )
        return self.sm.add_reverse_swap(
            redeem_script=redeem_script,
            locktime=locktime,
            privkey=claim_privkey,
            preimage=self.preimage,
            payment_hash=payment_hash,
            onchain_amount_sat=onchain_amount,
            lightning_amount_sat=onchain_amount + 1000,
            claim_to_output=claim_to_output,
        )

    async def client_funds_swap(self, swap: SwapData) -> Transaction:
        """what the client does when the server's htlcs arrive (see wait_for_htlcs_and_broadcast)"""
        tx = self.sm.create_funding_tx(swap, None, password=None)
        await self.broadcast(tx)
        swap.funding_txid = tx.txid()
        return tx

    async def server_claims_utxo(self, swap: SwapData, prevout: TxOutpoint) -> Transaction:
        """the server spends a lockup utxo, revealing the preimage in the witness"""
        return await self.broadcast(self.server_claim_tx(swap, prevout))

    def server_claim_tx(self, swap: SwapData, prevout: TxOutpoint) -> Transaction:
        """the tx with which the server spends a lockup utxo, revealing the preimage"""
        server_swap = SwapData(
            is_reverse=True,  # the server's point of view of our forward swap
            locktime=swap.locktime,
            onchain_amount=swap.onchain_amount,
            lightning_amount=swap.lightning_amount,
            redeem_script=swap.redeem_script,
            preimage=self.preimage,
            prepay_hash=None,
            privkey=self.server_privkey,
            lockup_address=swap.lockup_address,
            claim_to_output=None,
            funding_txid=prevout.txid.hex(),
            spending_txid=None,
            is_redeemed=False,
        )
        txin = self.adb.get_addr_outputs(swap.lockup_address)[prevout]
        txin, _locktime = SwapManager.create_claim_txin(txin=txin, swap=server_swap)
        tx = PartialTransaction.from_io(
            [txin],
            [PartialTxOutput.from_address_and_value(random_address(), txin.value_sats() - 1000)],
            version=2,
        )
        txin.witness = txin.make_witness(tx.sign_txin(0, server_swap.privkey))
        assert tx.is_complete(), tx
        return tx

    def server_refund_tx(self, swap: SwapData, prevout: TxOutpoint, *, fee: int) -> Transaction:
        """the server takes back the utxo it locked up for us, using the timeout branch.
        This is only valid in a block of height > swap.locktime.
        """
        server_swap = SwapData(
            is_reverse=False,  # the server's point of view of our reverse swap
            locktime=swap.locktime,
            onchain_amount=swap.onchain_amount,
            lightning_amount=swap.lightning_amount,
            redeem_script=swap.redeem_script,
            preimage=None,  # not known by the server
            prepay_hash=None,
            privkey=self.server_privkey,
            lockup_address=swap.lockup_address,
            claim_to_output=None,
            funding_txid=prevout.txid.hex(),
            spending_txid=None,
            is_redeemed=False,
        )
        txin = self.adb.get_addr_outputs(swap.lockup_address)[prevout]
        txin, locktime = SwapManager.create_claim_txin(txin=txin, swap=server_swap)
        self.assertEqual(swap.locktime, locktime)
        tx = PartialTransaction.from_io(
            [txin],
            [PartialTxOutput.from_address_and_value(random_address(), txin.value_sats() - fee)],
            locktime=locktime,
            version=2,
        )
        txin.witness = txin.make_witness(tx.sign_txin(0, server_swap.privkey))
        assert tx.is_complete(), tx
        return tx

    async def server_wins_race_for_lockup_utxo(self, swap: SwapData, claim_tx: Transaction) -> Transaction:
        """The server saw our claim tx (and the preimage in it) in the mempool. Since the
        locktime has passed, its refund tx is final, so it can simply outbid our claim tx.
        """
        self.assertLessEqual(swap.locktime, self.server.cur_height)
        self.assertEqual(self.preimage, SwapManager.extract_preimage(swap, claim_tx))
        claim_fee = self.server._get_fee_sat_paid_by_tx(claim_tx)
        refund_tx = self.server_refund_tx(swap, swap._funding_prevout, fee=claim_fee + 10_000)
        await self.broadcast(refund_tx)
        await self.mine_blocks(1)
        return refund_tx

    # --- tests ---

    async def test_forward_swap_ignores_undervalued_lockup_utxos(self):
        """A malicious server knows the lockup address before we fund it. If it pays dust
        into it, we must not mistake those utxos for our funding utxo: the preimage can
        only ever be extracted from the utxo that pays the full swap amount.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        self.assertIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)
        for _ in range(3):
            await self.pay_to_address(swap.lockup_address, DUST_LIMIT_P2WSH)
        await self.mine_blocks(1)
        # the decoys are in our history, but the swap is not funded
        self.assertEqual(3, len(self.utxos_at_lockup_address(swap)))
        await self.sm._claim_swap(swap)
        self.assertIsNone(swap.funding_txid)
        self.assertFalse(swap.is_funded())
        self.assertFalse(self.wallet.txbatcher.tx_batches)

    async def test_forward_swap_fails_swap_when_only_undervalued_utxos_at_expiry(self):
        """Nothing was locked up for us, so the held htlcs must be failed at expiry
        instead of being stuck waiting for a preimage we can never learn.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        payment_hash = swap.payment_hash
        await self.pay_to_address(swap.lockup_address, swap.onchain_amount - 1)
        with self.assertLogs(self.sm.logger.name, level='INFO') as logs:
            await self.mine_until_swap_expires(swap)
            await self.sm._claim_swap(swap)
        self.assertIn(f'failing swap {payment_hash.hex()}: expired: remaining_time=0 blocks', [record.getMessage() for record in logs.records])
        self.assertNotIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        self.assertNotIn(payment_hash.hex(), self.wallet.db.get_dict('submarine_swaps'))
        self.assertNotIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)

    async def test_forward_swap_extracts_preimage_from_funding_utxo(self):
        """The preimage must be extracted from the utxo we funded, even if the lockup
        address also holds decoy utxos of the malicious server.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        for i in range(1, 4):
            await self.pay_to_address(swap.lockup_address, DUST_LIMIT_P2WSH)
        funding_tx = await self.client_funds_swap(swap)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        # the funding utxo was selected, not one of the decoys
        self.assertEqual(funding_tx.txid(), swap._funding_prevout.txid.hex())
        self.assertEqual(funding_tx.txid(), swap.funding_txid)
        self.assertIsNone(swap.preimage)
        # the server claims our funding utxo, revealing the preimage
        claim_tx = await self.server_claims_utxo(swap, swap._funding_prevout)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        self.assertEqual(self.preimage, swap.preimage)
        self.assertEqual(self.preimage, self.wallet.lnworker.get_preimage(swap.payment_hash))
        self.assertEqual(claim_tx.txid(), swap.spending_txid)

    async def test_forward_swap_funds_lockup_address_when_htlcs_arrive(self):
        """The server's htlcs arrived, so we must lock up exactly the swap amount. From
        then on the swap must not be cancellable anymore: the funding output is queued,
        and cancelling would fail the htlcs while we still pay on-chain.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        self.assertFalse(swap.is_funded())
        await self.sm.hold_invoice_callback(swap.payment_hash)
        self.assertTrue(swap.is_funded())
        with self.assertLogs(self.sm.logger.name, level='INFO') as logs:
            self.sm.cancel_normal_swap(swap)
        self.assertIn(
            f'cannot cancel swap {swap.payment_hash.hex()}: already funded',
            [record.getMessage() for record in logs.records])
        self.assertIn(swap.payment_hash.hex(), self.wallet.db.get_dict('submarine_swaps'))
        self.assertIn(swap.payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        # the txbatcher pays the lockup address
        await self.wait_until(lambda: len(self.utxos_at_lockup_address(swap)) == 1)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        txin = self.adb.get_addr_outputs(swap.lockup_address)[swap._funding_prevout]
        self.assertEqual(swap.onchain_amount, txin.value_sats())
        self.assertEqual(swap.funding_txid, swap._funding_prevout.txid.hex())

    async def test_forward_swap_stops_watching_after_claim_tx_is_deeply_confirmed(self):
        """Once the server's claim tx is confirmed deeply, the swap is done: we stop watching the
        lockup address and release the hold invoice, instead of watching it forever.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        await self.client_funds_swap(swap)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        await self.server_claims_utxo(swap, swap._funding_prevout)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        self.assertEqual(self.preimage, swap.preimage)
        self.assertFalse(swap.is_redeemed)
        self.assertIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)
        # one block short of finality we keep watching
        await self.mine_blocks(SPENDER_FINALITY_DELAY - 1)
        await self.sm._claim_swap(swap)
        self.assertFalse(swap.is_redeemed)
        self.assertIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)
        # now the claim tx can no longer be reorged out
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        self.assertTrue(swap.is_redeemed)
        self.assertNotIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)
        self.assertNotIn(swap.payment_hash, self.wallet.lnworker.hold_invoice_callbacks)

    async def test_forward_swap_does_not_refund_after_learning_the_preimage(self):
        """The server's claim tx revealed the preimage but then fell out of the mempool.
        We must not try to refund: we can settle the htlcs, so the coins are the server's.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        await self.client_funds_swap(swap)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        claim_tx = await self.server_claims_utxo(swap, swap._funding_prevout)
        await self.sm._claim_swap(swap)
        self.assertEqual(self.preimage, swap.preimage)
        # the claim tx is evicted, so the lockup utxo looks unspent again
        await self.server.mempool_rm_tx(claim_tx)
        await self.wait_until(
            lambda: self.adb.get_tx_height(claim_tx.txid()).height() == TX_HEIGHT_LOCAL)
        await self.mine_until_swap_expires(swap)
        await self.sm._claim_swap(swap)
        self.assertFalse(self.wallet.txbatcher.tx_batches)
        self.assertIsNone(self.spender_of(swap._funding_prevout))

    async def test_forward_swap_refunds_funding_utxo_after_expiry(self):
        """If the server never claims, we refund our funding utxo. A decoy utxo must not
        take its place: it would be dropped as dust and we would refund nothing.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        decoy_tx = await self.pay_to_address(swap.lockup_address, DUST_LIMIT_P2WSH)
        funding_tx = await self.client_funds_swap(swap)
        await self.mine_until_swap_expires(swap)
        await self.sm._claim_swap(swap)
        self.assertEqual(funding_tx.txid(), swap._funding_prevout.txid.hex())
        refund_tx = await self.wait_for_spender_of(swap._funding_prevout)
        self.assertIsNone(SwapManager.extract_preimage(swap, refund_tx))
        self.assertTrue(self.wallet.adb.is_mine(refund_tx.outputs()[0].address))
        self.assertIsNone(self.spender_of(TxOutpoint(bfh(decoy_tx.txid()), 0)))

    async def test_forward_swap_keeps_htlcs_until_refund_tx_is_deeply_confirmed(self):
        """A refund tx with a single confirmation can still be reorged out and replaced by
        the server's claim tx. Failing the held htlcs is irreversible, so until the refund
        is confirmed deeply we must keep holding them: otherwise we give the ln payment back while
        the server can still take our on-chain coins.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        payment_hash = swap.payment_hash
        await self.client_funds_swap(swap)
        await self.mine_until_swap_expires(swap)
        await self.sm._claim_swap(swap)
        refund_tx = await self.wait_for_spender_of(swap._funding_prevout)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        self.assertEqual(refund_tx.txid(), swap.spending_txid)
        self.assertIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        self.assertIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)

        # the reorg replaces our refund tx with the claim tx of the server
        claim_tx = self.server_claim_tx(swap, swap._funding_prevout)
        await self.reorg_replace_tip_tx(refund_tx, claim_tx)
        await self.sm._claim_swap(swap)
        # we still hold the htlcs, so the preimage is worth something to us
        self.assertEqual(claim_tx.txid(), swap.spending_txid)
        self.assertEqual(self.preimage, swap.preimage)
        self.assertEqual(self.preimage, self.wallet.lnworker.get_preimage(payment_hash))
        self.assertIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)

    async def test_forward_swap_fails_swap_when_refund_tx_confirms(self):
        """Once our refund is confirmed deeply we can never learn the preimage, so the held htlcs
        must be failed. Otherwise they stay pending until the server force-closes on us.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        payment_hash = swap.payment_hash
        await self.client_funds_swap(swap)
        await self.mine_until_swap_expires(swap)
        await self.sm._claim_swap(swap)
        refund_tx = await self.wait_for_spender_of(swap._funding_prevout)
        # one block short of finality we must still hold the htlcs
        await self.mine_blocks(SPENDER_FINALITY_DELAY)
        await self.sm._claim_swap(swap)
        self.assertIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        # now the refund tx can no longer be reorged out
        await self.mine_blocks(1)
        with self.assertLogs(self.sm.logger.name, level='INFO') as logs:
            await self.sm._claim_swap(swap)
        self.assertIn(
            f'failing swap {payment_hash.hex()}: refund tx confirmed',
            [record.getMessage() for record in logs.records])
        self.assertEqual(refund_tx.txid(), swap.spending_txid)
        self.assertNotIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        self.assertNotIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)
        # the swap was funded, so we keep it: the history groups funding and refund tx
        self.assertIn(payment_hash.hex(), self.wallet.db.get_dict('submarine_swaps'))

    async def test_forward_swap_fails_swap_when_htlcs_never_arrive(self):
        """The server took our hold invoice and never paid it. When the invoice expires the
        swap must be failed, so that no caller can go on to broadcast the funding tx anyway.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        payment_hash = swap.payment_hash
        tx = self.sm.create_funding_tx(swap, None, password=None)
        transport = MockSwapServerTransport(config=self.alice.config, sm=self.sm)
        # the hold invoice is created with a 300s expiry, so this is one second past it
        expired_clock = now() + 301
        with mock.patch('electrum.submarine_swaps.now', lambda: expired_clock):
            funding_txid = await self.sm.wait_for_htlcs_and_broadcast(
                transport=transport, swap=swap, invoice=self.invoice, tx=tx)
        # we sent the request to the server
        self.assertEqual(['addswapinvoice'], [method for method, _data in transport.requests])
        self.assertIsNone(funding_txid)
        self.assertIsNone(swap.funding_txid)
        # nothing was locked up
        self.assertNotIn(tx.txid(), self.server.txs)
        # the swap is gone
        self.assertNotIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        self.assertNotIn(payment_hash.hex(), self.wallet.db.get_dict('submarine_swaps'))
        self.assertNotIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)

    async def test_forward_swap_cancel_does_not_race_dispatched_hold_invoice_callback(self):
        """lnpeer dispatches the hold-invoice callback as an independent task, so a cancel
        can land after the callback is scheduled but before it runs. The callback must then
        not broadcast the funding tx, and must fail the htlcs rather than leave them hanging.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        payment_hash = swap.payment_hash
        tx = self.sm.create_funding_tx(swap, None, password=None)
        transport = MockSwapServerTransport(config=self.alice.config, sm=self.sm)
        fut = asyncio.create_task(self.sm.wait_for_htlcs_and_broadcast(
            transport=transport, swap=swap, invoice=self.invoice, tx=tx))
        # the callback is registered just before the invoice is sent to the server
        await self.wait_until(lambda: bool(transport.requests))
        # the server's htlcs arrived: lnpeer looked up the callback and scheduled it,
        # but the user cancels before it gets to run
        callback = self.wallet.lnworker.hold_invoice_callbacks[payment_hash]
        self.assertTrue(self.sm.cancel_normal_swap(swap))
        with self.assertRaises(OnionRoutingFailure):
            await callback(payment_hash)
        self.assertIsNone(await fut)
        self.assertIsNone(swap.funding_txid)
        # nothing was locked up, and the swap is gone
        self.assertNotIn(tx.txid(), self.server.txs)
        self.assertNotIn(payment_hash, self.wallet.lnworker.hold_invoice_callbacks)
        self.assertNotIn(payment_hash.hex(), self.wallet.db.get_dict('submarine_swaps'))
        self.assertNotIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)

    async def test_forward_swap_cannot_be_cancelled_once_funding_is_broadcast(self):
        """Once the callback has claimed the swap the cancel must be refused, and it must
        leave the refund key and the lnwatcher callback intact.
        """
        swap = self.create_forward_swap(onchain_amount=100_000)
        payment_hash = swap.payment_hash
        tx = self.sm.create_funding_tx(swap, None, password=None)
        transport = MockSwapServerTransport(config=self.alice.config, sm=self.sm)
        fut = asyncio.create_task(self.sm.wait_for_htlcs_and_broadcast(
            transport=transport, swap=swap, invoice=self.invoice, tx=tx))
        await self.wait_until(lambda: bool(transport.requests))
        # the htlcs arrived and the callback ran: we are committed to the swap
        await self.wallet.lnworker.hold_invoice_callbacks[payment_hash](payment_hash)
        self.assertEqual(tx.txid(), await fut)
        self.assertFalse(self.sm.cancel_normal_swap(swap))
        self.assertIn(tx.txid(), self.server.txs)
        self.assertIn(payment_hash.hex(), self.wallet.db.get_dict('submarine_swaps'))
        self.assertIn(swap.lockup_address, self.wallet.lnworker.lnwatcher.callbacks)

    async def test_reverse_swap_does_not_claim_underpaid_lockup_utxo(self):
        """As the client of a reverse swap we know the preimage, and we must
        not reveal it on-chain unless the lockup utxo pays us the full swap amount.
        """
        swap = self.create_reverse_swap(onchain_amount=100_000)
        underpaid_tx = await self.pay_to_address(swap.lockup_address, swap.onchain_amount - 1)
        await self.mine_blocks(2)
        await self.sm._claim_swap(swap)
        self.assertFalse(self.wallet.txbatcher.tx_batches)
        self.assertIsNone(self.spender_of(TxOutpoint(bfh(underpaid_tx.txid()), 0)))
        self.assertIsNone(swap.funding_txid)
        # now the server funds the swap properly
        funding_tx = await self.pay_to_address(swap.lockup_address, swap.onchain_amount)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        self.assertEqual(funding_tx.txid(), swap.funding_txid)
        claim_tx = await self.wait_for_spender_of(swap._funding_prevout)
        self.assertEqual(self.preimage, SwapManager.extract_preimage(swap, claim_tx))

    async def test_reverse_swap_does_not_reveal_preimage_when_funding_confirms_at_locktime(self):
        """A malicious server can withhold the funding tx until the tip has almost reached the
        locktime. We must not reveal the preimage then: in the next
        block the server's refund tx is final too. So the server can replace our claim tx,
        read the preimage from it, and settle the ln htlc.
        Not claiming at all is strictly better for us: then the server
        never learns the preimage and our ln payment is refunded when the htlc expires.
        """
        swap = self.create_reverse_swap(onchain_amount=100_000)
        # the server funds only once the tip is one block below the locktime
        await self.mine_blocks(swap.locktime - 1 - self.server.cur_height)
        await self.pay_to_address(swap.lockup_address, swap.onchain_amount)
        await self.mine_blocks(1)
        # the funding tx got its first confirmation in the block at swap.locktime
        self.assertEqual(swap.locktime, self.server.cur_height)
        await self.wait_until(lambda: swap.funding_txid is not None)
        self.assertEqual(swap.locktime, self.adb.get_tx_height(swap.funding_txid).height())

        await self.sm._claim_swap(swap)
        claim_tx = await self.spender_of_within(swap._funding_prevout, timeout=2)
        self.assertIsNone(claim_tx, 'preimage revealed while the server can already refund')

    async def test_reverse_swap_does_not_reveal_preimage_when_funding_confirms_late(self):
        """Same hazard as above, but the server funds early with a tx that does not get mined.
        We queue the claim while it is still safe, and the txbatcher holds it back until the
        funding tx has a confirmation. By the time that happens the locktime may have passed,
        so whether we reveal the preimage is decided by the txbatcher, not by _claim_swap.
        """
        swap = self.create_reverse_swap(onchain_amount=100_000)
        await self.pay_to_address(swap.lockup_address, swap.onchain_amount)
        await self.sm._claim_swap(swap)
        # the funding tx is unconfirmed, so nothing can be claimed yet
        self.assertIsNone(await self.spender_of_within(swap._funding_prevout, timeout=1))
        # blocks go by without the funding tx being mined
        await self.mine_blocks(swap.locktime - self.server.cur_height, include_mempool=False)
        await self.sm._claim_swap(swap)
        # now it confirms, and the server's refund tx is final from the next block on
        await self.mine_blocks(1)
        self.assertLess(swap.locktime, self.server.cur_height)
        self.assertEqual(1, self.adb.get_tx_height(swap.funding_txid).conf)

        claim_tx = await self.spender_of_within(swap._funding_prevout, timeout=2)
        self.assertIsNone(claim_tx, 'preimage revealed while the server can already refund')

    async def test_reverse_swap_keeps_claiming_after_the_preimage_became_public(self):
        """Our claim tx is in the mempool, so the server can read the preimage from it and
        settle the ln htlc whenever it wants. Dropping the claim now would leave it with
        both the ln payment and its coins, so once the preimage is out we must keep the
        claim alive, even past the point where we would not have started claiming anymore.
        """
        swap = self.create_reverse_swap(onchain_amount=100_000)
        await self.pay_to_address(swap.lockup_address, swap.onchain_amount)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        claim_tx = await self.wait_for_spender_of(swap._funding_prevout)
        self.assertEqual(self.preimage, SwapManager.extract_preimage(swap, claim_tx))

        # the claim tx does not get mined, until we are past the expiry of the sweep
        expiry_height = swap.locktime - MIN_LOCKTIME_DELTA_FOR_CLAIM
        await self.mine_blocks(expiry_height - self.server.cur_height, include_mempool=False)
        self.assertEqual(expiry_height, self.server.cur_height)
        self.assertEqual(claim_tx.txid(), self.spender_of(swap._funding_prevout))

        await self.restart_txbatcher()
        await self.sm._claim_swap(swap)
        batch = self.wallet.txbatcher.tx_batches['swaps']
        self.assertIn(swap._funding_prevout, batch.batch_inputs)

        # with the sweep info back, the claim tx can still be replaced, e.g. to bump its fee
        self.alice.config.FEE_POLICY_SWAPS = 'feerate:20000'
        await self.wait_until(lambda: self.spender_of(swap._funding_prevout) != claim_tx.txid())
        replacement_tx = Transaction(self.server.txs[self.spender_of(swap._funding_prevout)])
        self.assertEqual(self.preimage, SwapManager.extract_preimage(swap, replacement_tx))

    async def test_reverse_swap_does_not_claim_against_an_unconfirmed_refund_tx(self):
        """Companion of the test above: the lockup utxo is spent, but by the server's
        refund tx, which reveals no preimage. Ours is still secret, so revealing it now
        would only let the server settle the ln htlc while it outbids our claim tx.
        """
        swap = self.create_reverse_swap(onchain_amount=100_000)
        await self.mine_until_swap_expires(swap)
        await self.pay_to_address(swap.lockup_address, swap.onchain_amount)
        await self.mine_blocks(1)
        prevout = self.utxos_at_lockup_address(swap)[0]
        refund_tx = await self.broadcast(self.server_refund_tx(swap, prevout, fee=1000))

        await self.sm._claim_swap(swap)
        self.assertFalse(self.wallet.txbatcher.tx_batches)
        self.assertEqual(refund_tx.txid(), self.spender_of(prevout))

    async def test_reverse_swap_claims_to_external_output(self):
        """Submarine payment: the claim tx pays the payee directly, so it must pay exactly
        the amount we promised them, and only once the funding tx cannot be double spent.
        """
        payee_address = random_address()
        swap = self.create_reverse_swap(
            onchain_amount=100_000,
            claim_to_output=TxOutput.from_address_and_value(payee_address, 99_000))
        funding_tx = await self.pay_to_address(swap.lockup_address, swap.onchain_amount)
        await self.sm._claim_swap(swap)
        # the funding tx is unconfirmed, so the claim tx is only kept as a future tx
        await self.wait_until(lambda: bool(self.adb.future_tx))
        self.assertIsNone(self.spender_of(swap._funding_prevout))
        self.assertEqual(funding_tx.txid(), swap.funding_txid)
        await self.mine_blocks(1)
        await self.sm._claim_swap(swap)
        claim_tx = await self.wait_for_spender_of(swap._funding_prevout)
        self.assertEqual(self.preimage, SwapManager.extract_preimage(swap, claim_tx))
        self.assertEqual(1, len(claim_tx.outputs()))
        self.assertEqual(payee_address, claim_tx.outputs()[0].address)
        self.assertEqual(99_000, claim_tx.outputs()[0].value)
