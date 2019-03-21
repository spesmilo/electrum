from pprint import pprint
import unittest
from electrum.lnutil import RECEIVED, LOCAL, REMOTE, SENT, HTLCOwner
from electrum.lnhtlc import HTLCManager
from typing import NamedTuple

class H(NamedTuple):
    owner : str
    htlc_id : int

class TestHTLCManager(unittest.TestCase):
    def test_adding_htlcs_race(self):
        A = HTLCManager()
        B = HTLCManager()
        ah0, bh0 = H('A', 0), H('B', 0)
        B.recv_htlc(A.send_htlc(ah0))
        self.assertTrue(B.expect_sig[RECEIVED])
        self.assertTrue(A.expect_sig[SENT])
        self.assertFalse(B.expect_sig[SENT])
        self.assertFalse(A.expect_sig[RECEIVED])
        self.assertEqual(B.log[REMOTE]['locked_in'][0][LOCAL], 1)
        A.recv_htlc(B.send_htlc(bh0))
        self.assertTrue(B.expect_sig[RECEIVED])
        self.assertTrue(A.expect_sig[SENT])
        self.assertTrue(A.expect_sig[SENT])
        self.assertTrue(B.expect_sig[RECEIVED])
        self.assertEqual(B.current_htlcs(LOCAL), [])
        self.assertEqual(A.current_htlcs(LOCAL), [])
        self.assertEqual(B.pending_htlcs(LOCAL), [(RECEIVED, ah0)])
        self.assertEqual(A.pending_htlcs(LOCAL), [(RECEIVED, bh0)])
        A.send_ctx()
        B.recv_ctx()
        B.send_ctx()
        A.recv_ctx()
        self.assertEqual(B.pending_htlcs(LOCAL), [(RECEIVED, ah0), (SENT, bh0)][::-1])
        self.assertEqual(A.pending_htlcs(LOCAL), [(RECEIVED, bh0), (SENT, ah0)][::-1])
        B.send_rev()
        A.recv_rev()
        A.send_rev()
        B.recv_rev()
        self.assertEqual(B.current_htlcs(LOCAL), [(RECEIVED, ah0), (SENT, bh0)][::-1])
        self.assertEqual(A.current_htlcs(LOCAL), [(RECEIVED, bh0), (SENT, ah0)][::-1])

    def test_single_htlc_full_lifecycle(self):
        def htlc_lifecycle(htlc_success: bool):
            A = HTLCManager()
            B = HTLCManager()
            B.recv_htlc(A.send_htlc(H('A', 0)))
            self.assertEqual(len(B.pending_htlcs(REMOTE)), 0)
            self.assertEqual(len(A.pending_htlcs(REMOTE)), 1)
            self.assertEqual(len(B.pending_htlcs(LOCAL)), 1)
            self.assertEqual(len(A.pending_htlcs(LOCAL)), 0)
            A.send_ctx()
            B.recv_ctx()
            B.send_rev()
            A.recv_rev()
            B.send_ctx()
            A.recv_ctx()
            A.send_rev()
            B.recv_rev()
            self.assertEqual(len(A.current_htlcs(LOCAL)), 1)
            self.assertEqual(len(B.current_htlcs(LOCAL)), 1)
            if htlc_success:
                B.send_settle(0)
                A.recv_settle(0)
            else:
                B.send_fail(0)
                A.recv_fail(0)
            self.assertEqual(A.htlcs_by_direction(REMOTE, RECEIVED), [H('A', 0)])
            self.assertNotEqual(A.current_htlcs(LOCAL), [])
            self.assertNotEqual(B.current_htlcs(REMOTE), [])

            self.assertEqual(A.pending_htlcs(LOCAL), [])
            self.assertNotEqual(A.pending_htlcs(REMOTE), [])
            self.assertEqual(A.pending_htlcs(REMOTE), A.current_htlcs(REMOTE))

            self.assertEqual(B.pending_htlcs(REMOTE), [])
            B.send_ctx()
            A.recv_ctx()
            A.send_rev() # here pending_htlcs(REMOTE) should become empty
            self.assertEqual(A.pending_htlcs(REMOTE), [])

            B.recv_rev()
            A.send_ctx()
            B.recv_ctx()
            B.send_rev()
            A.recv_rev()
            self.assertEqual(B.current_htlcs(LOCAL), [])
            self.assertEqual(A.current_htlcs(LOCAL), [])
            self.assertEqual(A.current_htlcs(REMOTE), [])
            self.assertEqual(B.current_htlcs(REMOTE), [])
            self.assertEqual(len(A.all_settled_htlcs_ever(LOCAL)), int(htlc_success))
            self.assertEqual(len(A.sent_in_ctn(2)), int(htlc_success))
            self.assertEqual(len(B.received_in_ctn(2)), int(htlc_success))

            A.recv_htlc(B.send_htlc(H('B', 0)))
            self.assertEqual(A.pending_htlcs(REMOTE), [])
            self.assertNotEqual(A.pending_htlcs(LOCAL), [])
            self.assertNotEqual(B.pending_htlcs(REMOTE), [])
            self.assertEqual(B.pending_htlcs(LOCAL), [])

            B.send_ctx()
            A.recv_ctx()
            A.send_rev()
            B.recv_rev()

            self.assertNotEqual(A.pending_htlcs(REMOTE), A.current_htlcs(REMOTE))
            self.assertEqual(A.pending_htlcs(LOCAL), A.current_htlcs(LOCAL))
            self.assertEqual(B.pending_htlcs(REMOTE), B.current_htlcs(REMOTE))
            self.assertNotEqual(B.pending_htlcs(LOCAL), B.pending_htlcs(REMOTE))

        htlc_lifecycle(htlc_success=True)
        htlc_lifecycle(htlc_success=False)

    def test_remove_htlc_while_owing_commitment(self):
        def htlc_lifecycle(htlc_success: bool):
            A = HTLCManager()
            B = HTLCManager()
            B.recv_htlc(A.send_htlc(H('A', 0)))
            A.send_ctx()
            B.recv_ctx()
            B.send_rev()
            A.recv_rev()
            if htlc_success:
                B.send_settle(0)
                A.recv_settle(0)
            else:
                B.send_fail(0)
                A.recv_fail(0)
            self.assertEqual(B.pending_htlcs(REMOTE), [])
            B.send_ctx()
            A.recv_ctx()
            A.send_rev()
            B.recv_rev()

        htlc_lifecycle(htlc_success=True)
        htlc_lifecycle(htlc_success=False)
