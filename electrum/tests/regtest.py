import os
import sys
import unittest
import subprocess

class TestLightning(unittest.TestCase):

    @staticmethod
    def run_shell(args, timeout=30):
        process = subprocess.Popen(['electrum/tests/regtest/regtest.sh'] + args, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):
            sys.stdout.write(line.decode(sys.stdout.encoding))
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


class TestLightningAB(TestLightning):
    agents = ['alice', 'bob']

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


class TestLightningABC(TestLightning):
    agents = ['alice', 'bob', 'carol']

    def test_forwarding(self):
        self.run_shell(['forwarding'])

    def test_watchtower(self):
        self.run_shell(['watchtower'])
