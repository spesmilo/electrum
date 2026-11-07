from typing import Sequence, Tuple
from unittest import mock

from electrum import SimpleConfig
from electrum.address_synchronizer import AddressSynchronizer, TX_HEIGHT_UNCONFIRMED
from electrum.bitcoin import construct_witness, hash_to_segwit_addr
from electrum.transaction import Transaction, PartialTransaction, PartialTxInput, PartialTxOutput, TxOutpoint
from electrum.util import InvalidTxSignature, TxMinedInfo
from electrum.synchronizer import Synchronizer
from electrum.wallet_db import WalletDB

from . import ElectrumTestCase


ADDR_MINE = hash_to_segwit_addr(bytes(20), witver=0)
ADDR_OTHER = hash_to_segwit_addr(bytes([1]) * 20, witver=0)


def make_tx(prevouts: Sequence[str], outputs: Sequence[Tuple[str, int]], *, witness: bytes = b'good') -> Transaction:
    """Returns a complete tx. Its txid does not depend on witness."""
    txins = []
    for prevout in prevouts:
        txin = PartialTxInput(prevout=TxOutpoint.from_str(prevout))
        txin.script_sig = b''
        txin.witness = construct_witness([witness])
        txins.append(txin)
    txouts = [PartialTxOutput.from_address_and_value(addr, value) for addr, value in outputs]
    return Transaction(PartialTransaction.from_io(txins, txouts, locktime=0).serialize_to_network())


class TestAddressSynchronizerSignatures(ElectrumTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        config = SimpleConfig({'electrum_path': self.electrum_path})
        self.verify_calls = []
        self.adb = AddressSynchronizer(
            WalletDB('', storage=None, upgrade=False), config, verify_txins=self._verify_txins)
        self.adb.add_address(ADDR_MINE)
        self.funding_tx = make_tx(['00' * 32 + ':0'], [(ADDR_MINE, 100_000)])
        self.funding_outpoint = self.funding_tx.txid() + ':0'

    def _verify_txins(self, tx, prev_txs) -> bool:
        self.verify_calls.append((tx.txid(), sorted(prev_txs)))
        return all(tx.inputs()[txin_idx].witness_elements() == [b'good'] for txin_idx in prev_txs)

    def _receive(self, tx):
        self.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)

    async def test_invalid_tx_is_rejected(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self._receive(tx)
        conflicting_tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 80_000)], witness=b'bad')
        with self.assertRaises(InvalidTxSignature):
            self._receive(conflicting_tx)
        self.assertIsNone(self.adb.db.get_transaction(conflicting_tx.txid()))
        # the conflicting tx was not removed
        self.assertIsNotNone(self.adb.db.get_transaction(tx.txid()))

    async def test_invalid_tx_before_parent(self):
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self._receive(tx)
        self.assertIsNotNone(self.adb.db.get_transaction(tx.txid()))
        self._receive(self.funding_tx)
        self.assertIsNone(self.adb.db.get_transaction(tx.txid()))

    async def test_valid_tx_before_parent(self):
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self._receive(tx)
        self._receive(self.funding_tx)
        self.assertIsNotNone(self.adb.db.get_transaction(tx.txid()))
        self.assertEqual([ADDR_MINE], self.adb.db.get_txi_addresses(tx.txid()))
        self.assertEqual([(tx.txid(), [0])], self.verify_calls)

    async def test_linked_inputs_are_checked_once(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self._receive(tx)
        self.adb.add_transaction(tx, allow_unrelated=True, is_new=False)
        self.assertEqual([(tx.txid(), [0])], self.verify_calls)

    async def test_add_parent_with_stale_spent_outpoint(self):
        missing_txid = 'ab' * 32
        self.adb.db.set_spent_outpoint(self.funding_tx.txid(), 0, missing_txid)
        self.adb.db.add_txi_addr(missing_txid, ADDR_MINE, self.funding_outpoint, 100_000)
        self._receive(self.funding_tx)

    async def test_invalid_copy_of_stored_tx(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self._receive(tx)
        bad_copy = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self.assertEqual(tx.txid(), bad_copy.txid())
        self._receive(bad_copy)
        self.assertEqual(tx.wtxid(), self.adb.db.get_transaction(tx.txid()).wtxid())
        self.assertEqual([(tx.txid(), [0])], self.verify_calls)

    async def test_invalid_copy_of_stored_unlinked_tx(self):
        addr = hash_to_segwit_addr(bytes([2]) * 20, witver=0)
        funding_tx = make_tx(['00' * 32 + ':1'], [(addr, 100_000)])
        tx = make_tx([funding_tx.txid() + ':0'], [(ADDR_OTHER, 90_000)])
        for t in (funding_tx, tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(addr)
        bad_copy = make_tx([funding_tx.txid() + ':0'], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self._receive(bad_copy)
        self.assertEqual(tx.wtxid(), self.adb.db.get_transaction(tx.txid()).wtxid())

    async def test_signed_copy_of_stored_unsigned_tx(self):
        self._receive(self.funding_tx)
        txin = PartialTxInput(prevout=TxOutpoint.from_str(self.funding_outpoint))
        txin.witness_utxo = self.funding_tx.outputs()[0]
        unsigned_tx = PartialTransaction.from_io(
            [txin], [PartialTxOutput.from_address_and_value(ADDR_OTHER, 90_000)], locktime=0)
        bad_copy = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        signed_tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self.assertFalse(unsigned_tx.is_complete())
        self.assertEqual(unsigned_tx.txid(), bad_copy.txid())
        self.assertEqual(unsigned_tx.txid(), signed_tx.txid())
        self.adb.add_transaction(unsigned_tx)
        with self.assertRaises(InvalidTxSignature):
            self._receive(bad_copy)
        self.assertFalse(self.adb.db.get_transaction(unsigned_tx.txid()).is_complete())
        self._receive(signed_tx)
        self.assertEqual(signed_tx.wtxid(), self.adb.db.get_transaction(unsigned_tx.txid()).wtxid())

    async def test_history_update_with_invalid_tx(self):
        addr = hash_to_segwit_addr(bytes([2]) * 20, witver=0)
        funding_tx = make_tx(['00' * 32 + ':1'], [(addr, 100_000)])
        tx = make_tx([funding_tx.txid() + ':0'], [(ADDR_OTHER, 90_000)], witness=b'bad')
        other_funding_tx = make_tx(['00' * 32 + ':2'], [(addr, 50_000)])
        for t in (funding_tx, tx, other_funding_tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(addr)
        hist = [(t.txid(), TX_HEIGHT_UNCONFIRMED) for t in (tx, funding_tx, other_funding_tx)]
        self.adb.receive_history_callback(addr, hist, {})
        self.assertIsNone(self.adb.db.get_transaction(tx.txid()))
        self.assertEqual([addr], self.adb.db.get_txo_addresses(funding_tx.txid()))
        self.assertEqual([addr], self.adb.db.get_txo_addresses(other_funding_tx.txid()))

    async def test_verified_tx_is_not_checked(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=100, timestamp=0, txpos=1, header_hash='00' * 32))
        self.adb.receive_tx_callback(tx, tx_height=100)
        self.assertIsNotNone(self.adb.db.get_transaction(tx.txid()))
        self.assertEqual([], self.verify_calls)

    async def test_tx_claimed_mined_is_added_once_verified(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), 100)
        self.adb.receive_tx_callback(tx)
        self.assertIsNone(self.adb.db.get_transaction(tx.txid()))
        self.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=100, timestamp=0, txpos=1, header_hash='00' * 32))
        self.assertIsNotNone(self.adb.db.get_transaction(tx.txid()))
        self.assertEqual([], self.verify_calls)

    async def test_tx_claimed_mined_is_checked_if_not_at_height(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), 100)
        self.adb.receive_tx_callback(tx)
        with self.assertRaises(InvalidTxSignature):
            self.adb.remove_unverified_tx(tx.txid(), 100)
        self.assertIsNone(self.adb.db.get_transaction(tx.txid()))
        self.assertEqual([(tx.txid(), [0])], self.verify_calls)

    async def test_tx_claimed_mined_then_unconfirmed_is_checked(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)], witness=b'bad')
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), 100)
        self.adb.receive_tx_callback(tx)
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), TX_HEIGHT_UNCONFIRMED)
        with self.assertRaises(InvalidTxSignature):
            self.adb.receive_tx_callback(tx)
        self.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=100, timestamp=0, txpos=1, header_hash='00' * 32))
        self.assertIsNone(self.adb.db.get_transaction(tx.txid()))

    def _make_synchronizer(self) -> Synchronizer:
        sync = Synchronizer.__new__(Synchronizer)
        sync.adb = self.adb
        Synchronizer._reset(sync)
        return sync

    async def test_held_tx_is_not_requested_again(self):
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), 100)
        sync = self._make_synchronizer()
        self.adb.receive_tx_callback(tx)
        await sync._request_missing_txs([(tx.txid(), 100)])
        self.assertEqual(set(), sync.requested_tx)

    async def test_held_tx_is_requested_again_if_unconfirmed(self):
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), 100)
        sync = self._make_synchronizer()
        sync._get_transaction = mock.AsyncMock()
        self.adb.receive_tx_callback(tx)
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), TX_HEIGHT_UNCONFIRMED)
        await sync._request_missing_txs([(tx.txid(), TX_HEIGHT_UNCONFIRMED)])
        sync._get_transaction.assert_called_once_with(tx.txid(), allow_server_not_finding_tx=False)

    async def test_held_txs_are_dropped_on_server_switch(self):
        self._receive(self.funding_tx)
        tx = make_tx([self.funding_outpoint], [(ADDR_OTHER, 90_000)])
        self.adb.add_unverified_or_unconfirmed_tx(tx.txid(), 100)
        sync = self._make_synchronizer()
        self.adb.receive_tx_callback(tx)
        Synchronizer._reset(sync)
        self.assertFalse(self.adb.is_held_tx(tx.txid()))
        self.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=100, timestamp=0, txpos=1, header_hash='00' * 32))
        self.assertIsNone(self.adb.db.get_transaction(tx.txid()))
