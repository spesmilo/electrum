# -*- coding: utf-8 -*-

from electrum.bitcoin import hash_encode
from electrum.transaction import Transaction
from electrum.util import bfh
from electrum.verifier import SPV, InnerNodeOfSpvProofIsValidTx

from . import TestCaseForTestnet


TST_MBRANCH = [
    'f2994fd4546086b21b4916b76cf901afb5c4db1c3ecbfc91d6f4cae1186dfe12',
    '6b65935528311901c7acda7db817bd6e3ce2f05d1c62c385b7caadb65fac7520']

TST_R = '11dbac015b6969ea75509dd1250f33c04ec4d562c2d895de139a65f62f808254'

TEST_T_TX_RAW = ('0200000001cb659c5528311901a7aada'
                 '7db817bd6e3ce2f05d1c62c385b7caad'
                 'b65fac75201234000000fabcdefa01ab'
                 'cd1234010000000405060708fabcdefa')

ORIG_RAISE_IF_VALID_TX = SPV._raise_if_valid_tx


class VerifierTestCase(TestCaseForTestnet):

    def test_verify_ok_t_tx(self):
        '''test vefify ok forged T tx'''
        assert len(TEST_T_TX_RAW) == 128
        t_tx = Transaction(TEST_T_TX_RAW)
        t_tx_hash = t_tx.txid()
        assert SPV.hash_merkle_root(TST_MBRANCH, t_tx_hash, 3) == TST_R

    def test_verify_ok_f_tx(self):
        '''test verify ok forged F tx (fake)'''
        SPV._raise_if_valid_tx = lambda raw_tx: None
        t_tx = Transaction(TEST_T_TX_RAW)
        # first 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(TEST_T_TX_RAW[:64]))
        fake_mbranch = [fake_branch_node] + TST_MBRANCH
        # last 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(TEST_T_TX_RAW[64:]))
        assert SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 7) == TST_R
        SPV._raise_if_valid_tx = ORIG_RAISE_IF_VALID_TX

    def test_verify_fail_f_tx(self):
        '''test verify fail forged F tx (fake)'''
        t_tx = Transaction(TEST_T_TX_RAW)
        # first 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(TEST_T_TX_RAW[:64]))
        fake_mbranch = [fake_branch_node] + TST_MBRANCH
        # last 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(TEST_T_TX_RAW[64:]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            assert SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 7) == TST_R

    def test_verify_ok_f_tx_even(self):
        '''test verify ok forged F tx (fake) with even fake txpos'''
        SPV._raise_if_valid_tx = lambda raw_tx: None
        t_tx = Transaction(TEST_T_TX_RAW)
        # last 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(TEST_T_TX_RAW[64:]))
        fake_mbranch = [fake_branch_node] + TST_MBRANCH
        # first 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(TEST_T_TX_RAW[:64]))
        assert SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 6) == TST_R
        SPV._raise_if_valid_tx = ORIG_RAISE_IF_VALID_TX

    def test_verify_fail_f_tx_even(self):
        '''test verify fail forged F tx (fake) with even fake txpos'''
        t_tx = Transaction(TEST_T_TX_RAW)
        # last 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(TEST_T_TX_RAW[64:]))
        fake_mbranch = [fake_branch_node] + TST_MBRANCH
        # first 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(TEST_T_TX_RAW[:64]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            assert SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 6) == TST_R
