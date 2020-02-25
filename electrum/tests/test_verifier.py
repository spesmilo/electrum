# -*- coding: utf-8 -*-

from electrum.bitcoin import hash_encode
from electrum.transaction import Transaction
from electrum.util import bfh
from electrum.verifier import SPV, InnerNodeOfSpvProofIsValidTx

from . import TestCaseForTestnet


MERKLE_BRANCH = [
    'f2994fd4546086b21b4916b76cf901afb5c4db1c3ecbfc91d6f4cae1186dfe12',
    '6b65935528311901c7acda7db817bd6e3ce2f05d1c62c385b7caadb65fac7520']

MERKLE_ROOT = '11dbac015b6969ea75509dd1250f33c04ec4d562c2d895de139a65f62f808254'

VALID_64_BYTE_TX = ('0200000001cb659c5528311901a7aada7db817bd6e3ce2f05d1c62c385b7caad'
                    'b65fac75201234000000fabcdefa01abcd1234010000000405060708fabcdefa')
assert len(VALID_64_BYTE_TX) == 128


class VerifierTestCase(TestCaseForTestnet):
    # these tests are regarding the attack described in
    # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-June/016105.html

    def test_verify_ok_t_tx(self):
        """Actually mined 64 byte tx should not raise."""
        t_tx = Transaction(VALID_64_BYTE_TX)
        t_tx_hash = t_tx.txid()
        self.assertEqual(MERKLE_ROOT, SPV.hash_merkle_root(MERKLE_BRANCH, t_tx_hash, 3))

    def test_verify_fail_f_tx_odd(self):
        """Raise if inner node of merkle branch is valid tx. ('odd' fake leaf position)"""
        # first 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(VALID_64_BYTE_TX[:64]))
        fake_mbranch = [fake_branch_node] + MERKLE_BRANCH
        # last 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(VALID_64_BYTE_TX[64:]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 7)

    def test_verify_fail_f_tx_even(self):
        """Raise if inner node of merkle branch is valid tx. ('even' fake leaf position)"""
        # last 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(VALID_64_BYTE_TX[64:]))
        fake_mbranch = [fake_branch_node] + MERKLE_BRANCH
        # first 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(VALID_64_BYTE_TX[:64]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 6)
