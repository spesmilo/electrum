import os
import sys
import unittest
import subprocess


class TestLightning(unittest.TestCase):
    TEST_ANCHOR_CHANNELS = False

    def run_shell(self, args, timeout=30):
        process = subprocess.Popen(
            ['electrum/tests/regtest/regtest.sh'] + args,
            stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
            universal_newlines=True,
            env=os.environ.update({'TEST_ANCHOR_CHANNELS': str(self.TEST_ANCHOR_CHANNELS)}),
        )
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(line)
            sys.stdout.flush()
        process.wait(timeout=timeout)
        process.stdout.close()
        assert process.returncode == 0

    def setUp(self):
        test_name = self.id().split('.')[-1]
        sys.stdout.write("***** %s ******\n" % test_name)
        # initialize and get funds
        for agent in self.agents:
            self.run_shell(['init', agent])
        # mine a block so that funds are confirmed
        self.run_shell(['new_block'])
        # extra configuration (optional)
        self.run_shell(['configure_' + test_name])
        # start daemons
        for agent in self.agents:
            self.run_shell(['start', agent])

    def tearDown(self):
        for agent in self.agents:
            self.run_shell(['stop', agent])


class TestUnixSockets(TestLightning):
    agents = []

    def test_unixsockets(self):
        self.run_shell(['unixsockets'])


class TestLightningAB(TestLightning):
    agents = ['alice', 'bob']

    def test_backup(self):
        self.run_shell(['backup'])

    def test_breach(self):
        self.run_shell(['breach'])

    def test_extract_preimage(self):
        self.run_shell(['extract_preimage'])

    def test_redeem_htlcs(self):
        self.run_shell(['redeem_htlcs'])

    def test_breach_with_unspent_htlc(self):
        self.run_shell(['breach_with_unspent_htlc'])

    def test_breach_with_spent_htlc(self):
        self.run_shell(['breach_with_spent_htlc'])


class TestLightningABAnchors(TestLightningAB):
    TEST_ANCHOR_CHANNELS = True


class TestLightningABC(TestLightning):
    agents = ['alice', 'bob', 'carol']

    def test_watchtower(self):
        self.run_shell(['watchtower'])


class TestLightningABCAnchors(TestLightningABC):
    TEST_ANCHOR_CHANNELS = True
