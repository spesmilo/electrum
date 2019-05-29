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
        self.run_shell(['stop'])
        self.run_shell(['init'])
        self.run_shell(['start'])

    def tearDown(self):
        self.run_shell(['stop'])

    def test_breach(self):
        self.run_shell(['breach'])

    def test_forwarding(self):
        self.run_shell(['open'])
        self.run_shell(['alice_pays_carol'])
        self.run_shell(['close'])

    def test_redeem_htlcs(self):
        self.run_shell(['redeem_htlcs'])

    def test_breach_with_htlc(self):
        self.run_shell(['breach_with_htlc'])
