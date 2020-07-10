from collections import namedtuple
from typing import List
from unittest import TestCase

from electrum import Transaction
from electrum.three_keys.multikey_generator import MultiKeyScriptGenerator
from electrum.three_keys.transaction import ThreeKeysTransaction, TxType

TX = '0200000001eaa85f4446a8d48b345592b7bc540678ef1e0f4a80b4893e9bedbf9aae636d9400000000280000255121023765a77db702ab87d5cf6431d81a4734d9a636eb95446ffe01fa06ac190ce56c51aefdffffff02008c86470000000017a9142664929e5ed5356477dad1404f51bb507e89f9aa87b0398ecb0300000017a914a2703755a1b5e5aa06e742f3db127628d6ed40cd876c030000'


class DummyGenerator(MultiKeyScriptGenerator):

    def get_redeem_script(self, public_keys: List[str]) -> str:
        pass

    def get_script_sig(self, signatures: List[str], public_keys: List[str]) -> str:
        pass


class Test3KeysTransaction(TestCase):
    def test_setting_multisig_generator(self):
        tr = Transaction(None)
        generator = DummyGenerator()
        tr.multisig_script_generator = generator
        self.assertTrue(generator is tr.multisig_script_generator)

    def test_failed_multisig_setting(self):
        Gen = namedtuple('Gen', ['a', 'b'])
        generator = Gen(1, 1)
        tr = Transaction(None)
        with self.assertRaises(TypeError) as error:
            tr.multisig_script_generator = generator

        self.assertEqual(
            'Cannot set multisig_script_generator. It has to be MultisigScriptGenerator',
            str(error.exception)
        )

    def test_tx_type_setting(self):
        tx = ThreeKeysTransaction(None, TxType.ALERT_PENDING)
        self.assertEqual(tx.tx_type, TxType.ALERT_PENDING)
        with self.assertRaises(ValueError) as err:
            ThreeKeysTransaction(None, 'unknown type')

        self.assertTrue('tx_type has to be TxType' in str(err.exception))

    def test_creating_3key_tx_from_transaction(self):
        tx = Transaction(TX)
        # assert correct serialization
        self.assertEqual(TX, tx.serialize())
        # wrong type passed
        class WrongTxType: pass
        with self.assertRaises(ValueError) as err:
            ThreeKeysTransaction.from_tx(WrongTxType())
        self.assertEqual('Wrong transaction type WrongTxType', str(err.exception))

        three_key_tx = ThreeKeysTransaction.from_tx(tx)
        self.assertEqual(TX, three_key_tx.serialize())
        self.assertEqual(TxType.NONVAULT, three_key_tx.tx_type)
        self.assertTrue(isinstance(three_key_tx, Transaction))


class TestTxType(TestCase):
    def setUp(self):
        self.inputs = [(item.name, item) for item in TxType]

    def test_creating_from_string(self):
        for str_, type_ in self.inputs:
            with self.subTest((str_, type_)):
                tx_type = TxType.from_str(str_)
                self.assertEqual(type_, tx_type)

    def test_creating_error(self):
        inp = 'wrong key'
        with self.assertRaises(ValueError) as err:
            TxType.from_str(inp)
        self.assertEqual(f"Cannot get TxType for '{inp}'", str(err.exception))

    def test_identity(self):
        type1 = TxType.INSTANT
        type2 = TxType.from_str(str(type1.value))
        self.assertEqual(type1, type2)
