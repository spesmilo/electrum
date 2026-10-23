import asyncio
import gc
import weakref

from electrum import keystore, SimpleConfig, util
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.fee_policy import FixedFeePolicy
from electrum.commands import Commands
from electrum.transaction import Transaction, PartialTxOutput, tx_from_any
from electrum.util import NotEnoughFunds, UserFacingException

from . import ElectrumTestCase
from .test_wallet_vertical import WalletIntegrityHelper


async def fast_sleep():
    # sleep a few event loop iterations, so queued callbacks get to run
    for i in range(5):
        await asyncio.sleep(0)


# same fixtures as TestWalletSending.test_get_spendable_coins
SEED = 'frost repair depend effort salon ring foam oak cancel receive save usage'
FUNDING_TX1 = '01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400'
FUNDING_TX2 = '01000000000101c0ec8b6cdcb6638fa117ead71a8edebc189b30e6e5415bdfb3c8260aa269e6520000000017160014ba9ca815474a674ff1efb3fc82cf0f3460de8c57fdffffff0230390f000000000017a9148b59abaca8215c0d4b18cbbf715550aa2b50c85b87404b4c000000000016001483c3bc7234f17a209cc5dcce14903b54ee4dab9002473044022038a05f7d38bcf810dfebb39f1feda5cc187da4cf5d6e56986957ddcccedc75d302203ab67ccf15431b4e2aeeab1582b9a5a7821e7ac4be8ebf512505dbfdc7e094fd0121032168234e0ba465b8cedc10173ea9391725c0f6d9fa517641af87926626a5144abd391400'

UTXO1 = 'c36a6e1cd54df108e69574f70bc9b88dc13beddc70cfad9feb7f8f6593255d4a:1'  # 5_000_000 sat
UTXO2 = '52e669a20a26c8b3df5b41e5e6309b18bcde8e1ad7ea17a18f63b6dc6c8becc0:1'  # 10_000_000 sat
UTXO2_ADDR = 'tb1q6n99dl96mx8mfh90m3tn5awk5mllkzdh25dw7z'

OTHER_ADDR = 'tb1q0ezagv55krljkz9973fryeyczhj3dnlsgr02g7'


class TestCoinFilter(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def create_wallet(self):
        ks = keystore.from_seed(SEED, passphrase='', for_multisig=False)
        wallet = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=2, config=self.config)
        for raw in (FUNDING_TX1, FUNDING_TX2):
            wallet.adb.receive_tx_callback(Transaction(raw), tx_height=TX_HEIGHT_UNCONFIRMED)
        return wallet

    @staticmethod
    def outpoints(coins):
        return {txi.prevout.to_str() for txi in coins}

    async def test_fixture_sanity(self):
        wallet = self.create_wallet()
        self.assertEqual((0, 15_000_000, 0), wallet.get_balance())
        self.assertEqual({UTXO1, UTXO2}, self.outpoints(wallet.get_spendable_coins()))
        self.assertFalse(wallet.coinfilter.is_coin_control_active())

    # composition with the policy filters

    async def test_selection_narrows_spendable_coins(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        self.assertEqual({UTXO1}, coinfilter.select_coins([UTXO1]))
        self.assertTrue(coinfilter.is_coin_control_active())
        self.assertEqual({UTXO1}, self.outpoints(wallet.get_spendable_coins()))
        # ...but the raw utxo set is untouched
        self.assertEqual({UTXO1, UTXO2}, self.outpoints(wallet.get_utxos()))

    async def test_selection_composes_with_frozen_coin(self):
        """Freezing a coin *after* selecting it must remove it from the spend set.
        """
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1, UTXO2])
        self.assertEqual({UTXO1, UTXO2}, self.outpoints(wallet.get_spendable_coins()))
        wallet.set_frozen_state_of_coins([UTXO1], True)
        self.assertEqual({UTXO2}, self.outpoints(wallet.get_spendable_coins()))
        status = coinfilter.get_coin_control_status()
        self.assertTrue(status.is_active)
        self.assertEqual(2, status.num_selected)
        self.assertEqual(1, status.num_usable)  # honest about the discrepancy
        self.assertEqual(10_000_000, status.value_sat)

    async def test_selection_composes_with_frozen_address(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1, UTXO2])
        wallet.set_frozen_state_of_addresses([UTXO2_ADDR], True)
        self.assertEqual({UTXO1}, self.outpoints(wallet.get_spendable_coins()))

    async def test_selection_composes_with_confirmed_only(self):
        """confirmed_only must still be honoured while coin control is active.
        """
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1])
        # both fixtures are unconfirmed
        self.assertEqual(set(), self.outpoints(wallet.get_spendable_coins(confirmed_only=True)))
        self.assertEqual({UTXO1}, self.outpoints(wallet.get_spendable_coins(confirmed_only=False)))

    async def test_selection_composes_with_nonlocal_only(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        tx = self._spend_utxo(wallet, UTXO1)
        change = [txo for txo in tx.outputs() if wallet.is_mine(txo.address)]
        self.assertTrue(change, "expected a change output funded by a local tx")
        local_op = f'{tx.txid()}:{tx.outputs().index(change[0])}'
        coinfilter.select_coins([local_op])
        self.assertEqual({local_op}, self.outpoints(wallet.get_spendable_coins()))
        self.assertEqual(set(), self.outpoints(wallet.get_spendable_coins(nonlocal_only=True)))

    async def test_selection_composes_with_domain(self):
        wallet = self.create_wallet()
        wallet.coinfilter.select_coins([UTXO1, UTXO2])
        self.assertEqual({UTXO2}, self.outpoints(wallet.get_spendable_coins([UTXO2_ADDR])))

    # pruning

    def _spend_utxo(self, wallet, outpoint: str, *, height=None):
        """Build+sign a tx spending `outpoint` and register it with the adb.

        height=None adds it as a local (unbroadcast) tx, which is enough to mark
        the input spent; pass a height to also give it a mined status.
        """
        coin = [c for c in wallet.get_utxos() if c.prevout.to_str() == outpoint]
        assert coin, f"{outpoint} not in wallet"
        tx = wallet.make_unsigned_transaction(
            coins=coin,
            outputs=[PartialTxOutput.from_address_and_value(OTHER_ADDR, 1_000_000)],
            fee_policy=FixedFeePolicy(5000),
        )
        wallet.sign_transaction(tx, password=None)
        if height is None:
            wallet.adb.add_transaction(tx)
        else:
            wallet.adb.receive_tx_callback(tx, tx_height=height)
        return tx

    async def test_selection_pruned_on_spend_keeps_the_rest(self):
        """Spending one selected coin must not silently disable coin control."""
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1, UTXO2])
        self._spend_utxo(wallet, UTXO1)
        await fast_sleep()
        self.assertEqual({UTXO2}, coinfilter.get_selection())
        self.assertTrue(coinfilter.is_coin_control_active())

    async def test_selection_inactive_when_all_selected_coins_spent(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1])
        self._spend_utxo(wallet, UTXO1)
        await fast_sleep()
        self.assertEqual(set(), coinfilter.get_selection())
        self.assertFalse(coinfilter.is_coin_control_active())
        # falls back to the whole wallet (UTXO2, plus the change of the spend)
        spendable = self.outpoints(wallet.get_spendable_coins())
        self.assertIn(UTXO2, spendable)
        self.assertNotIn(UTXO1, spendable)
        self.assertGreater(len(spendable), 1)

    async def test_selection_pruned_when_funding_tx_removed(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1, UTXO2])
        wallet.adb.remove_transaction(UTXO1.split(':')[0])
        await fast_sleep()
        self.assertEqual({UTXO2}, coinfilter.get_selection())

    async def test_events_dont_leak_across_wallets(self):
        wallet1 = self.create_wallet()
        wallet2 = self.create_wallet()
        wallet2.coinfilter.select_coins([UTXO1, UTXO2])
        self._spend_utxo(wallet1, UTXO1)
        await fast_sleep()
        # wallet2 has its own adb; its selection must be untouched
        self.assertEqual({UTXO1, UTXO2}, wallet2.coinfilter.get_selection())

    # integration with tx building

    async def test_make_unsigned_transaction_honours_selection(self):
        wallet = self.create_wallet()
        wallet.coinfilter.select_coins([UTXO2])
        tx = wallet.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(OTHER_ADDR, 1_000_000)],
            fee_policy=FixedFeePolicy(5000),
        )
        self.assertEqual({UTXO2}, {txin.prevout.to_str() for txin in tx.inputs()})

    async def test_make_unsigned_transaction_raises_when_selection_too_small(self):
        wallet = self.create_wallet()
        wallet.coinfilter.select_coins([UTXO1])  # 5_000_000 sat
        with self.assertRaises(NotEnoughFunds):
            wallet.make_unsigned_transaction(
                outputs=[PartialTxOutput.from_address_and_value(OTHER_ADDR, 12_000_000)],
                fee_policy=FixedFeePolicy(5000),
            )

    async def test_background_paths_ignore_selection(self):
        """The ignore_coin_control audit, locked in."""
        wallet = self.create_wallet()
        wallet.coinfilter.select_coins([UTXO1])
        self.assertEqual(
            {UTXO1, UTXO2},
            self.outpoints(wallet.get_spendable_coins(ignore_coin_control=True)))
        self.assertEqual(
            15_000_000,
            wallet.get_spendable_balance_sat(ignore_coin_control=True))
        # ...while the user-facing balance does reflect the selection
        self.assertEqual(5_000_000, wallet.get_spendable_balance_sat())

    # write-time validation

    async def test_get_coins_for_outpoints_deduplicates(self):
        """Returning a coin twice would build a tx that spends it twice."""
        wallet = self.create_wallet()
        coins = wallet.coinfilter.get_coins_for_outpoints([UTXO1, UTXO2, UTXO1])
        self.assertEqual([UTXO1, UTXO2], [c.prevout.to_str() for c in coins])

    async def test_get_coins_for_outpoints_keeps_first_seen_order(self):
        wallet = self.create_wallet()
        coins = wallet.coinfilter.get_coins_for_outpoints([UTXO2, UTXO1, UTXO2])
        self.assertEqual([UTXO2, UTXO1], [c.prevout.to_str() for c in coins])

    async def test_get_coins_for_outpoints_still_validates_duplicates(self):
        wallet = self.create_wallet()
        bogus = '00' * 32 + ':7'
        with self.assertRaises(UserFacingException):
            wallet.coinfilter.get_coins_for_outpoints([bogus, bogus])

    async def test_duplicate_from_coins_does_not_double_spend(self):
        """End to end: a repeated outpoint must not appear twice in the tx."""
        wallet = self.create_wallet()
        coins = wallet.coinfilter.get_coins_for_outpoints([UTXO1, UTXO1])
        tx = wallet.make_unsigned_transaction(
            coins=coins,
            outputs=[PartialTxOutput.from_address_and_value(OTHER_ADDR, 1_000_000)],
            fee_policy=FixedFeePolicy(5000),
        )
        prevouts = [txin.prevout.to_str() for txin in tx.inputs()]
        self.assertEqual(len(prevouts), len(set(prevouts)))
        self.assertEqual([UTXO1], prevouts)

    async def test_select_skips_unknown_outpoint(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        bogus = '00' * 32 + ':7'
        self.assertEqual({UTXO1}, coinfilter.select_coins([UTXO1, bogus]))
        self.assertEqual({UTXO1}, coinfilter.get_selection())

    async def test_select_strict_raises_on_unknown_outpoint(self):
        wallet = self.create_wallet()
        with self.assertRaises(UserFacingException):
            wallet.coinfilter.select_coins(['00' * 32 + ':7'], strict=True)

    async def test_select_skips_frozen_coin(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        wallet.set_frozen_state_of_coins([UTXO1], True)
        self.assertEqual({UTXO2}, coinfilter.select_coins([UTXO1, UTXO2]))

    async def test_toggle_selection(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.toggle_selection([UTXO1])
        self.assertEqual({UTXO1}, coinfilter.get_selection())
        coinfilter.toggle_selection([UTXO2])  # active -> clears instead of adding
        self.assertEqual(set(), coinfilter.get_selection())

    async def test_select_and_deselect_addresses(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        self.assertEqual({UTXO2}, coinfilter.select_addresses([UTXO2_ADDR]))
        self.assertEqual({UTXO2}, coinfilter.deselect_addresses([UTXO2_ADDR]))
        self.assertFalse(coinfilter.is_coin_control_active())

    async def test_status_when_inactive(self):
        wallet = self.create_wallet()
        status = wallet.coinfilter.get_coin_control_status()
        self.assertFalse(status.is_active)
        self.assertEqual(2, status.num_total)
        self.assertEqual(0, status.value_sat)

    # messaging

    async def test_not_enough_funds_text_mentions_coin_control(self):
        wallet = self.create_wallet()
        wallet.coinfilter.select_coins([UTXO1])
        text = wallet.get_text_not_enough_funds_mentioning_frozen(for_amount=12_000_000)
        self.assertIn('coin control', text.lower())

    async def test_not_enough_funds_text_silent_when_coin_control_inactive(self):
        wallet = self.create_wallet()
        text = wallet.get_text_not_enough_funds_mentioning_frozen(for_amount=99_000_000)
        self.assertNotIn('coin control', text.lower())

    # lifecycle

    async def test_stop_unregisters_callbacks(self):
        """A stopped wallet must stop reacting to adb events, which are process-global."""
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        coinfilter.select_coins([UTXO1, UTXO2])
        before = util.callback_mgr.count_all_callbacks()
        coinfilter.stop()
        self.assertLess(util.callback_mgr.count_all_callbacks(), before)
        coinfilter.stop()  # idempotent

        # the selection is no longer pruned, because we are not listening anymore
        self._spend_utxo(wallet, UTXO1)
        await fast_sleep()
        self.assertEqual({UTXO1, UTXO2}, coinfilter.get_selection())
        # ...but reads stay correct, since filtering happens at read time
        self.assertNotIn(UTXO1, self.outpoints(wallet.get_spendable_coins()))

    async def test_wallet_backref_is_weak(self):
        """The manager must not keep its wallet alive: wallet -> coinfilter -> wallet would
        be a cycle that refcounting cannot break, which is also what stops __del__
        from ever running."""
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        self.assertIs(coinfilter.wallet, wallet)  # still resolves normally
        held = [id(o) for o in gc.get_referents(coinfilter.__dict__)]
        self.assertNotIn(id(wallet), held)

    async def test_dead_wallet_ref_is_handled(self):
        """Once the wallet is gone, logging must still work and events must no-op."""
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter

        class Gone:
            pass
        tmp = Gone()
        dead = weakref.ref(tmp)
        del tmp
        coinfilter._wallet = dead

        self.assertEqual('', coinfilter.diagnostic_name())  # must not raise
        with self.assertRaises(RuntimeError):
            coinfilter.wallet
        coinfilter.on_event_adb_added_tx(object(), 'deadbeef', None)  # no-op, must not raise
        coinfilter.on_event_adb_removed_tx(object(), 'deadbeef', None)
        coinfilter.stop()  # teardown must not need the wallet

    # events

    async def test_coin_control_changed_event_fired(self):
        wallet = self.create_wallet()
        coinfilter = wallet.coinfilter
        seen = []

        def cb(w, added, removed, reason):
            seen.append((set(added), set(removed), reason))

        util.register_callback(cb, ['coin_control_changed'])
        try:
            coinfilter.select_coins([UTXO1])
            await fast_sleep()
            self.assertEqual([({UTXO1}, set(), 'user')], seen)
            seen.clear()

            coinfilter.clear_selection()
            await fast_sleep()
            self.assertEqual([(set(), {UTXO1}, 'cleared')], seen)
            seen.clear()

            coinfilter.select_coins([UTXO1])
            await fast_sleep()
            seen.clear()
            self._spend_utxo(wallet, UTXO1)
            await fast_sleep()
            self.assertEqual([(set(), {UTXO1}, 'spent')], seen)
        finally:
            util.unregister_callback(cb)

    async def test_frozen_state_changed_event_fired(self):
        wallet = self.create_wallet()
        seen = []

        def cb(w, addresses, outpoints):
            seen.append((set(addresses), set(outpoints)))

        util.register_callback(cb, ['frozen_state_changed'])
        try:
            wallet.set_frozen_state_of_coins([UTXO1], True)
            await fast_sleep()
            self.assertEqual([(set(), {UTXO1})], seen)
        finally:
            util.unregister_callback(cb)


class TestCoinControlCommands(ElectrumTestCase):
    """The CLI/RPC surface. This is what coin control gains beyond the Qt client."""
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def create_wallet(self):
        ks = keystore.from_seed(SEED, passphrase='', for_multisig=False)
        wallet = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=2, config=self.config)
        for raw in (FUNDING_TX1, FUNDING_TX2):
            wallet.adb.receive_tx_callback(Transaction(raw), tx_height=TX_HEIGHT_UNCONFIRMED)
        return wallet

    async def test_select_utxo_then_payto_restricts_inputs(self):
        wallet = self.create_wallet()
        cmds = Commands(config=self.config)
        self.assertEqual([UTXO2], await cmds.select_utxo([UTXO2], wallet=wallet))
        status = await cmds.list_selected_utxos(wallet=wallet)
        self.assertTrue(status['active'])
        self.assertEqual([UTXO2], status['selected'])

        raw = await cmds.payto(
            OTHER_ADDR, '0.001', feerate=1, unsigned=True, password=None, wallet=wallet)
        tx = tx_from_any(raw)
        self.assertEqual({UTXO2}, {txin.prevout.to_str() for txin in tx.inputs()})

        await cmds.unselect_utxo(wallet=wallet)
        self.assertFalse((await cmds.list_selected_utxos(wallet=wallet))['active'])

    async def test_select_utxo_rejects_unknown_outpoint(self):
        wallet = self.create_wallet()
        cmds = Commands(config=self.config)
        with self.assertRaises(UserFacingException):
            await cmds.select_utxo(['00' * 32 + ':7'], wallet=wallet)

    async def test_payto_from_coins_rejects_unknown_outpoint(self):
        """Previously a typo'd outpoint just yielded a confusing NotEnoughFunds."""
        wallet = self.create_wallet()
        cmds = Commands(config=self.config)
        with self.assertRaises(UserFacingException):
            await cmds.payto(
                OTHER_ADDR, '0.001', feerate=1, unsigned=True, password=None,
                from_coins='00' * 32 + ':7', wallet=wallet)

    async def test_payto_from_coins_overrides_stored_selection(self):
        wallet = self.create_wallet()
        cmds = Commands(config=self.config)
        await cmds.select_utxo([UTXO1], wallet=wallet)
        raw = await cmds.payto(
            OTHER_ADDR, '0.001', feerate=1, unsigned=True, password=None,
            from_coins=UTXO2, wallet=wallet)
        tx = tx_from_any(raw)
        self.assertEqual({UTXO2}, {txin.prevout.to_str() for txin in tx.inputs()})

    async def test_listunspent_reports_frozen_and_selected(self):
        wallet = self.create_wallet()
        cmds = Commands(config=self.config)
        await cmds.select_utxo([UTXO1], wallet=wallet)
        await cmds.freeze_utxo(UTXO2, wallet=wallet)
        by_outpoint = {c['prevout_hash'] + ':' + str(c['prevout_n']): c
                       for c in await cmds.listunspent(wallet=wallet)}
        self.assertTrue(by_outpoint[UTXO1]['selected'])
        self.assertFalse(by_outpoint[UTXO1]['frozen'])
        self.assertFalse(by_outpoint[UTXO2]['selected'])
        self.assertTrue(by_outpoint[UTXO2]['frozen'])
