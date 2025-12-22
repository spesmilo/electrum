import asyncio
import logging
import shutil
import os

from . import ElectrumTestCase
from .test_lnpeer import MockLNWallet, keypair

from electrum.lnutil import RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED
from electrum.logging import console_stderr_handler
from electrum.invoices import LN_EXPIRY_NEVER, PR_UNPAID


class TestLNWallet(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    async def asyncSetUp(self):
        k1, q1 = keypair(), asyncio.Queue()
        w1 = MockLNWallet(local_keypair=k1, chans=[], tx_queue=q1, name="test_lnwallet", has_anchors=self.TEST_ANCHOR_CHANNELS)
        self.lnwallet = w1
        await super().asyncSetUp()

    async def asyncTearDown(self):
        await self.lnwallet.stop()
        shutil.rmtree(self.lnwallet._user_dir)
        await super().asyncTearDown()

    def test_create_payment_info(self):
        tests = (
            (100_000, 200, 100),
            (0, 200, 100),
            (None, 200, 100),
            (None, None, LN_EXPIRY_NEVER),
            (100_000, None, 0),
        )
        for amount_msat, min_final_cltv_delta, exp_delay in tests:
            payment_hash = self.lnwallet.create_payment_info(
                amount_msat=amount_msat,
                min_final_cltv_delta=min_final_cltv_delta,
                exp_delay=exp_delay,
            )
            self.assertIsNotNone(self.lnwallet.get_preimage(payment_hash))
            pi = self.lnwallet.get_payment_info(payment_hash, direction=RECEIVED)
            self.assertEqual(pi.amount_msat, amount_msat)
            self.assertEqual(pi.min_final_cltv_delta, min_final_cltv_delta or MIN_FINAL_CLTV_DELTA_ACCEPTED)
            self.assertEqual(pi.expiry_delay, exp_delay or LN_EXPIRY_NEVER)
            self.assertEqual(pi.db_key, f"{payment_hash.hex()}:{int(pi.direction)}")
            self.assertEqual(pi.status, PR_UNPAID)
        self.assertIsNone(self.lnwallet.get_payment_info(os.urandom(32), direction=RECEIVED))
