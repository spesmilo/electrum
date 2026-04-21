# -*- coding: utf-8 -*-

from electrum.bitcoin import hash_encode
from electrum.transaction import Transaction
from electrum.util import bfh
from electrum.verifier import SPV, InnerNodeOfSpvProofIsValidTx, LeftSiblingDuplicate

from . import ElectrumTestCase


class TestVerifier_CVE_2017_12842(ElectrumTestCase):
    # these tests are regarding CVE-2017-12842, the attack described in
    # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-June/016105.html
    TESTNET = True

    MERKLE_BRANCH = [
        'f2994fd4546086b21b4916b76cf901afb5c4db1c3ecbfc91d6f4cae1186dfe12',
        '6b65935528311901c7acda7db817bd6e3ce2f05d1c62c385b7caadb65fac7520',
    ]
    MERKLE_ROOT = '11dbac015b6969ea75509dd1250f33c04ec4d562c2d895de139a65f62f808254'
    VALID_64_BYTE_TX = ('0200000001cb659c5528311901a7aada7db817bd6e3ce2f05d1c62c385b7caad'
                        'b65fac75201234000000fabcdefa01abcd1234010000000405060708fabcdefa')
    assert len(VALID_64_BYTE_TX) == 128

    def test_verify_ok_t_tx(self):
        """Actually mined 64 byte tx should not raise."""
        t_tx = Transaction(self.VALID_64_BYTE_TX)
        t_tx_hash = t_tx.txid()
        self.assertEqual(self.MERKLE_ROOT, SPV.hash_merkle_root(self.MERKLE_BRANCH, t_tx_hash, 3))

    def test_verify_fail_f_tx_odd(self):
        """Raise if inner node of merkle branch is valid tx. ('odd' fake leaf position)"""
        # first 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(self.VALID_64_BYTE_TX[:64]))
        fake_mbranch = [fake_branch_node] + self.MERKLE_BRANCH
        # last 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(self.VALID_64_BYTE_TX[64:]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 7)

    def test_verify_fail_f_tx_even(self):
        """Raise if inner node of merkle branch is valid tx. ('even' fake leaf position)"""
        # last 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(self.VALID_64_BYTE_TX[64:]))
        fake_mbranch = [fake_branch_node] + self.MERKLE_BRANCH
        # first 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(self.VALID_64_BYTE_TX[:64]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 6)


class TestVerifier_CVE_2012_2459(ElectrumTestCase):
    # These tests are regarding CVE-2012-2459.
    # Bitcoin's Merkle tree duplicates odd nodes to balance the tree. An attacker can
    # exploit this by constructing a tree where a duplicated subtree is treated
    # as containing real leaves, allowing forged proofs for phantom leaf positions.
    #
    # Example with 11 real leaves and forged 16-leaf claim:
    #
    # Real tree (11 leaves):
    #
    #                           **root**
    #                   __________/  \_________
    #                  /                       \
    #                 14                        c       Height 3
    #             _ /   \ _                    / \
    #           /           \                 /   \
    #          6             13              b     b'   Height 2
    #        /    \        /    \         /     \
    #       2      5      9      12      17      a      Height 1
    #      / \    / \    / \    /  \    /  \    /  \
    #     0   1  3   4  7   8  10  11  15  16  18  18'  Height 0
    #     --------------------------------------------------------
    #     0   1  2   3  4   5   6   7   8   9  10       Leaf index
    #
    #     Nodes marked with ' are duplicates to balance the tree.
    #
    # Forged tree (attacker claims 16 leaves):
    #
    #                           **root**
    #                   __________/  \________________
    #                  /                              \
    #                 14                              c                   Height 3
    #             _ /   \ _                    _____/   \_____
    #           /           \                 /               \
    #          6             13              b                 b'         Height 2
    #        /    \        /    \         /     \           /     \
    #       2      5      9      12      17      a        17'      a'     Height 1
    #      / \    / \    / \    /  \    /  \    /  \     /  \     /  \
    #     0   1  3   4  7   8  10  11  15  16  18  18'  15' 16'  18' 18'  Height 0
    #     --------------------------------------------------------------------------
    #     0   1  2   3  4   5   6   7   8   9  10  11!  12! 13!  14! 15!  Leaf index
    #
    #     Nodes with ! are phantom leaves. The attacker duplicated the entire
    #     subtree under 'b' to create fake leaves 11-15.
    #
    # The attack works because:
    #   - Real proof for leaf 10:   [18', 17 , b', 14] with b' as RIGHT sibling
    #   - Forged proof for leaf 14: [18', 17', b , 14] with b as LEFT sibling
    #
    # We can guard against this: in forged proofs, a duplicate will appear as a LEFT sibling
    # (sibling == current when index bit is 1).
    # Legitimate duplicates for balancing only appear as RIGHT siblings.
    TESTNET = True

    # from testnet3 block 4909055 (https://blockstream.info/testnet/block/00000000c4a54b073c224bbf1f7c40cc85498a823e1dd5d20be51e6464a3dab9)
    # but even if it gets reorged, point is:
    # - block has 3 txns total, so valid indices [0,1,2]
    # - next power of 2 is 4, so merkle tree leaves will be [t0,t1,t2,t2']
    # - TXID is for t2, so its real index is 2, but index 3 could be "forged" for it as well
    MERKLE_BRANCH = [
        '9b2c7e407188465594832cfbe84c9758029084527c855ea29a16603e5d1c51b6',
        'a8484ccbaa74ffa060d0a500f7ce3ea4953beace18df8384024dfa9290385b1c',
    ]
    MERKLE_ROOT = '3465af659f6438b133c6d980accbb61b7be43f8ad899e40054e33b37aecba28e'
    TXID = '9b2c7e407188465594832cfbe84c9758029084527c855ea29a16603e5d1c51b6'

    def test_valid_right_sibling_duplicate(self):
        leaf_pos_in_tree = 2
        self.assertEqual(self.MERKLE_ROOT, SPV.hash_merkle_root(self.MERKLE_BRANCH, self.TXID, leaf_pos_in_tree))

    def test_malicious_left_sibling_duplicate(self):
        leaf_pos_in_tree = 3
        with self.assertRaises(LeftSiblingDuplicate):
            SPV.hash_merkle_root(self.MERKLE_BRANCH, self.TXID, leaf_pos_in_tree)
