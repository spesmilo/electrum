from typing import Sequence, Tuple
from unittest import mock

import electrum_ecc as ecc

from electrum import SimpleConfig, bitcoin, descriptor, keystore
from electrum.address_synchronizer import AddressSynchronizer, TX_HEIGHT_UNCONFIRMED
from electrum.bitcoin import construct_witness, hash_to_segwit_addr
from electrum.fee_policy import FixedFeePolicy
from electrum.transaction import (
    Transaction, PartialTransaction, PartialTxInput, PartialTxOutput, TxInput, TxOutpoint, tx_from_any,
)
from electrum.util import InvalidTxSignature, TxMinedInfo
from electrum.synchronizer import Synchronizer
from electrum.wallet_db import WalletDB

from . import ElectrumTestCase
from .test_wallet_vertical import WalletIntegrityHelper


KEY_MINE = ecc.ECPrivkey(bytes(31) + b'\x01')
KEY_MINE_2 = ecc.ECPrivkey(bytes(31) + b'\x02')
ADDR_MINE = bitcoin.pubkey_to_address('p2wpkh', KEY_MINE.get_public_key_hex())
ADDR_MINE_2 = bitcoin.pubkey_to_address('p2wpkh', KEY_MINE_2.get_public_key_hex())
ADDR_OTHER = hash_to_segwit_addr(bytes([1]) * 20, witver=0)


def make_tx(txins: Sequence[TxInput], outputs: Sequence[Tuple[str, int]], *, locktime: int = 0) -> Transaction:
    """Returns a tx with the given inputs, including their scriptSig and witness, and outputs."""
    txins = [PartialTxInput(prevout=txin.prevout, script_sig=txin.script_sig, nsequence=txin.nsequence,
                            witness=txin.witness) for txin in txins]
    txouts = [PartialTxOutput.from_address_and_value(addr, value) for addr, value in outputs]
    return Transaction(PartialTransaction.from_io(txins, txouts, locktime=locktime, BIP69_sort=False).serialize_to_network())


def fund(addr: str, value: int, *, n: int = 0) -> Transaction:
    """Returns a tx paying value to addr. Its input is a coinbase input."""
    txin = TxInput(prevout=TxOutpoint(txid=bytes(32), out_idx=n), script_sig=b'', witness=construct_witness([b'cb']))
    return make_tx([txin], [(addr, value)])


def spending_psbt(parent: Transaction, outputs: Sequence[Tuple[str, int]], *, key=KEY_MINE) -> PartialTransaction:
    """Returns an unsigned tx spending output 0 (p2wpkh) of parent."""
    txin = PartialTxInput(prevout=TxOutpoint(txid=bytes.fromhex(parent.txid()), out_idx=0))
    txin.witness_utxo = parent.outputs()[0]
    txin.script_descriptor = descriptor.get_singlesig_descriptor_from_legacy_leaf(
        pubkey=key.get_public_key_hex(), script_type='p2wpkh')
    txouts = [PartialTxOutput.from_address_and_value(addr, value) for addr, value in outputs]
    return PartialTransaction.from_io([txin], txouts, locktime=0)


def spend(parent: Transaction, outputs: Sequence[Tuple[str, int]], *, key=KEY_MINE) -> Transaction:
    """Returns a tx signed by key, spending output 0 (p2wpkh) of parent."""
    tx = spending_psbt(parent, outputs, key=key)
    tx.sign({key.get_public_key_bytes(): key.get_secret_bytes()})
    assert tx.is_complete()
    return Transaction(tx.serialize())


def with_witness(tx: Transaction, witness: Sequence[bytes]) -> Transaction:
    """Returns tx with another witness: same txid."""
    txins = [TxInput(prevout=txin.prevout, script_sig=txin.script_sig, nsequence=txin.nsequence,
                     witness=construct_witness(witness)) for txin in tx.inputs()]
    return make_tx(txins, [(txout.address, txout.value) for txout in tx.outputs()], locktime=tx.locktime)


def with_outputs(tx: Transaction, outputs: Sequence[Tuple[str, int]]) -> Transaction:
    """The fake-tx attack: the inputs and witnesses of tx, with other outputs."""
    return make_tx(tx.inputs(), outputs, locktime=tx.locktime)


def mined_info(height: int) -> TxMinedInfo:
    return TxMinedInfo(_height=height, timestamp=0, txpos=1, header_hash='00' * 32)


class TestAddressSynchronizerScripts(ElectrumTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.adb = AddressSynchronizer(WalletDB('', storage=None, upgrade=False), self.config)
        self.adb.add_address(ADDR_MINE)
        self.funding_tx = fund(ADDR_MINE, 100_000)
        self.funding_outpoint = self.funding_tx.txid() + ':0'
        self.tx = spend(self.funding_tx, [(ADDR_OTHER, 90_000)])
        self.fake_tx = with_outputs(self.tx, [(ADDR_OTHER, 99_000)])

    def _receive(self, tx):
        self.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)

    def _has(self, tx) -> bool:
        return self.adb.db.get_transaction(tx.txid()) is not None

    async def test_invalid_tx_is_rejected(self):
        self._receive(self.funding_tx)
        self._receive(self.tx)
        with self.assertRaises(InvalidTxSignature):
            self._receive(self.fake_tx)
        self.assertFalse(self._has(self.fake_tx))
        # the conflicting tx was not removed
        self.assertTrue(self._has(self.tx))

    async def test_invalid_tx_before_parent(self):
        self._receive(self.fake_tx)
        self.assertTrue(self._has(self.fake_tx))
        self._receive(self.funding_tx)
        self.assertFalse(self._has(self.fake_tx))

    async def test_valid_tx_before_parent(self):
        self._receive(self.tx)
        self._receive(self.funding_tx)
        self.assertTrue(self._has(self.tx))
        self.assertEqual([ADDR_MINE], self.adb.db.get_txi_addresses(self.tx.txid()))

    async def test_linked_inputs_are_verified_once(self):
        self._receive(self.funding_tx)
        with mock.patch.object(AddressSynchronizer, '_verify_txin_scripts', autospec=True,
                               side_effect=AddressSynchronizer._verify_txin_scripts) as verify:
            self._receive(self.tx)
            self.adb.add_transaction(self.tx, allow_unrelated=True, is_new=False)
        self.assertEqual(1, verify.call_count)

    async def test_input_with_unknown_parent(self):
        # our input is verified without the output spent by the other input (not taproot)
        foreign_txin = TxInput(prevout=TxOutpoint(txid=bytes(range(32)), out_idx=0), script_sig=b'',
                               witness=construct_witness([b'foreign']))
        psbt = spending_psbt(self.funding_tx, [(ADDR_OTHER, 150_000)])
        psbt.add_inputs([PartialTxInput(prevout=foreign_txin.prevout)], BIP69_sort=False)
        sig = psbt.sign_txin(0, KEY_MINE.get_secret_bytes())
        our_txin = TxInput(prevout=psbt.inputs()[0].prevout, script_sig=b'', nsequence=psbt.inputs()[0].nsequence,
                           witness=construct_witness([sig, KEY_MINE.get_public_key_bytes()]))
        foreign_txin.nsequence = psbt.inputs()[1].nsequence
        tx = make_tx([our_txin, foreign_txin], [(ADDR_OTHER, 150_000)])
        self._receive(self.funding_tx)
        with self.assertRaises(InvalidTxSignature):
            self._receive(with_outputs(tx, [(ADDR_OTHER, 160_000)]))
        self._receive(tx)
        self.assertTrue(self._has(tx))

    async def test_add_parent_with_stale_spent_outpoint(self):
        missing_txid = 'ab' * 32
        self.adb.db.set_spent_outpoint(self.funding_tx.txid(), 0, missing_txid)
        self.adb.db.add_txi_addr(missing_txid, ADDR_MINE, self.funding_outpoint, 100_000)
        self._receive(self.funding_tx)

    async def test_invalid_copy_of_stored_tx(self):
        self._receive(self.funding_tx)
        self._receive(self.tx)
        bad_copy = with_witness(self.tx, [b'bad'])
        self.assertEqual(self.tx.txid(), bad_copy.txid())
        self._receive(bad_copy)
        self.assertEqual(self.tx.wtxid(), self.adb.db.get_transaction(self.tx.txid()).wtxid())

    async def test_invalid_copy_of_stored_unlinked_tx(self):
        funding_tx = fund(ADDR_MINE_2, 100_000, n=1)
        tx = spend(funding_tx, [(ADDR_OTHER, 90_000)], key=KEY_MINE_2)
        for t in (funding_tx, tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(ADDR_MINE_2)
        self._receive(with_witness(tx, [b'bad']))
        self.assertEqual(tx.wtxid(), self.adb.db.get_transaction(tx.txid()).wtxid())

    async def test_signed_copy_of_stored_unsigned_tx(self):
        self._receive(self.funding_tx)
        unsigned_tx = spending_psbt(self.funding_tx, [(ADDR_OTHER, 90_000)])
        bad_copy = with_witness(self.tx, [b'bad'])
        self.assertFalse(unsigned_tx.is_complete())
        self.assertEqual(unsigned_tx.txid(), bad_copy.txid())
        self.assertEqual(unsigned_tx.txid(), self.tx.txid())
        self.adb.add_transaction(unsigned_tx)
        with self.assertRaises(InvalidTxSignature):
            self._receive(bad_copy)
        self.assertFalse(self.adb.db.get_transaction(unsigned_tx.txid()).is_complete())
        self._receive(self.tx)
        self.assertEqual(self.tx.wtxid(), self.adb.db.get_transaction(unsigned_tx.txid()).wtxid())

    async def test_history_update_with_invalid_tx(self):
        funding_tx = fund(ADDR_MINE_2, 100_000, n=1)
        tx = with_witness(spend(funding_tx, [(ADDR_OTHER, 90_000)], key=KEY_MINE_2), [b'bad'])
        other_funding_tx = fund(ADDR_MINE_2, 50_000, n=2)
        for t in (funding_tx, tx, other_funding_tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(ADDR_MINE_2)
        hist = [(t.txid(), TX_HEIGHT_UNCONFIRMED) for t in (tx, funding_tx, other_funding_tx)]
        self.adb.receive_history_callback(ADDR_MINE_2, hist, {})
        self.assertFalse(self._has(tx))
        self.assertEqual([ADDR_MINE_2], self.adb.db.get_txo_addresses(funding_tx.txid()))
        self.assertEqual([ADDR_MINE_2], self.adb.db.get_txo_addresses(other_funding_tx.txid()))

    async def test_invalid_stored_tx_on_load(self):
        # stored before the history of ADDR_MINE, e.g. by an older version
        adb = AddressSynchronizer(WalletDB('', storage=None, upgrade=False), self.config)
        for tx in (self.funding_tx, self.fake_tx):
            adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        adb.db.set_addr_history(ADDR_MINE, [(self.fake_tx.txid(), 0), (self.funding_tx.txid(), 0)])
        adb = AddressSynchronizer(adb.db, self.config)  # check_history links them to our coins
        self.assertEqual([ADDR_MINE], adb.db.get_txo_addresses(self.funding_tx.txid()))
        self.assertIsNone(adb.db.get_transaction(self.fake_tx.txid()))

    async def test_verified_tx_is_not_checked(self):
        self._receive(self.funding_tx)
        self.adb.add_verified_tx(self.fake_tx.txid(), mined_info(100))
        self.adb.receive_tx_callback(self.fake_tx, tx_height=100)
        self.assertTrue(self._has(self.fake_tx))

    async def test_tx_claimed_mined_is_added_once_verified(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), 100)
        self.adb.receive_tx_callback(self.fake_tx)
        self.assertFalse(self._has(self.fake_tx))
        self.adb.add_verified_tx(self.fake_tx.txid(), mined_info(100))
        self.assertTrue(self._has(self.fake_tx))

    async def test_tx_claimed_mined_is_checked_if_not_at_height(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), 100)
        self.adb.receive_tx_callback(self.fake_tx)
        with self.assertRaises(InvalidTxSignature):
            self.adb.remove_unverified_tx(self.fake_tx.txid(), 100)
        self.assertFalse(self._has(self.fake_tx))

    async def test_tx_claimed_mined_then_unconfirmed_is_checked(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), 100)
        self.adb.receive_tx_callback(self.fake_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), TX_HEIGHT_UNCONFIRMED)
        with self.assertRaises(InvalidTxSignature):
            self.adb.receive_tx_callback(self.fake_tx)
        self.adb.add_verified_tx(self.fake_tx.txid(), mined_info(100))
        self.assertFalse(self._has(self.fake_tx))

    def _make_synchronizer(self) -> Synchronizer:
        sync = Synchronizer.__new__(Synchronizer)
        sync.adb = self.adb
        Synchronizer._reset(sync)
        return sync

    async def test_held_tx_is_not_requested_again(self):
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), 100)
        sync = self._make_synchronizer()
        self.adb.receive_tx_callback(self.tx)
        await sync._request_missing_txs([(self.tx.txid(), 100)])
        self.assertEqual(set(), sync.requested_tx)

    async def test_held_tx_is_requested_again_if_unconfirmed(self):
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), 100)
        sync = self._make_synchronizer()
        sync._get_transaction = mock.AsyncMock()
        self.adb.receive_tx_callback(self.tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), TX_HEIGHT_UNCONFIRMED)
        await sync._request_missing_txs([(self.tx.txid(), TX_HEIGHT_UNCONFIRMED)])
        sync._get_transaction.assert_called_once_with(self.tx.txid(), allow_server_not_finding_tx=False)

    async def test_held_txs_are_dropped_on_server_switch(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), 100)
        sync = self._make_synchronizer()
        self.adb.receive_tx_callback(self.tx)
        Synchronizer._reset(sync)
        self.assertFalse(self.adb.is_held_tx(self.tx.txid()))
        self.adb.add_verified_tx(self.tx.txid(), mined_info(100))
        self.assertFalse(self._has(self.tx))


class TestFakeTxAttack(ElectrumTestCase):
    TESTNET = True

    async def test_fake_mempool_tx_is_rejected(self):
        # 2026-10-18 incident: the server replaced a mempool payment by a tx with the same inputs and
        # witnesses but paying the attacker at fee 0, which the user then fee-bumped.
        config = SimpleConfig({'electrum_path': self.electrum_path})
        ks = keystore.from_seed('frost repair depend effort salon ring foam oak cancel receive save usage',
                                passphrase='', for_multisig=False)
        wallet = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=2, config=config)
        funding_tx = Transaction('01000000000102acd6459dec7c3c51048eb112630da756f5d4cb4752b8d39aa325407ae0885cba020000001716001455c7f5e0631d8e6f5f05dddb9f676cec48845532fdffffffd146691ef6a207b682b13da5f2388b1f0d2a2022c8cfb8dc27b65434ec9ec8f701000000171600147b3be8a7ceaf15f57d7df2a3d216bc3c259e3225fdffffff02a9875b000000000017a914ea5a99f83e71d1c1dfc5d0370e9755567fe4a141878096980000000000160014d4ca56fcbad98fb4dcafdc573a75d6a6fffb09b702483045022100dde1ba0c9a2862a65791b8d91295a6603207fb79635935a67890506c214dd96d022046c6616642ef5971103c1db07ac014e63fa3b0e15c5729eacdd3e77fcb7d2086012103a72410f185401bb5b10aaa30989c272b554dc6d53bda6da85a76f662723421af024730440220033d0be8f74e782fbcec2b396647c7715d2356076b442423f23552b617062312022063c95cafdc6d52ccf55c8ee0f9ceb0f57afb41ea9076eb74fe633f59c50c6377012103b96a4954d834fbcfb2bbf8cf7de7dc2b28bc3d661c1557d1fd1db1bfc123a94abb391400')
        wallet.adb.receive_tx_callback(funding_tx, tx_height=1000)
        dest = '2N1VTMMFb91SH9SNRAkT7z8otP5eZEct4KL'
        genuine = wallet.make_unsigned_transaction(
            coins=wallet.get_spendable_coins(domain=None),
            outputs=[PartialTxOutput.from_address_and_value(dest, 2_500_000)],
            fee_policy=FixedFeePolicy(150))
        genuine.set_rbf(True)
        wallet.sign_transaction(genuine, password=None)
        genuine = tx_from_any(genuine.serialize())
        outputs = [(o.address, o.value) for o in genuine.outputs()]
        i = [addr for addr, _ in outputs].index(dest)
        outputs[i] = (bitcoin.hash160_to_p2sh(bytes(20)), 2_500_000 + 150)
        fake = with_outputs(genuine, outputs)

        wallet.adb.receive_tx_callback(genuine, tx_height=TX_HEIGHT_UNCONFIRMED)
        with self.assertRaises(InvalidTxSignature):
            wallet.adb.receive_tx_callback(fake, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.assertIsNone(wallet.db.get_transaction(fake.txid()))
        self.assertIsNotNone(wallet.db.get_transaction(genuine.txid()))
        self.assertNotIn(fake.txid(), [item['txid'] for item in wallet.get_full_history().values()])
