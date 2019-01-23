import base64
import os
import sys
import unittest
import subprocess
from electrum.crypto import sha256
from electrum.util import bh2u
import itertools
import pathlib

def split_seq(iterable, size):
    it = iter(iterable)
    item = list(itertools.islice(it, size))
    while item:
        yield item
        item = list(itertools.islice(it, size))

not_travis_text = 'breach test takes a long time, installs things, requires certain ports to be available, assumes x86 and doesn\'t clean up after itself'

@unittest.skipUnless(os.getlogin() == 'travis', not_travis_text)
class TestLNWatcher(unittest.TestCase):
    maxDiff = None # unlimited

    @staticmethod
    def run_shell(cmd, timeout=60):
        process = subprocess.Popen(['electrum/tests/test_lnwatcher/' + cmd[0]] + ([] if len(cmd) == 1 else cmd[1:]), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):
            sys.stdout.write(line.decode(sys.stdout.encoding))
        process.wait(timeout=timeout)
        assert process.returncode == 0

    @classmethod
    def setUpClass(cls):
        cls.run_shell(['setup.sh'])

    def test_redeem_stuck_htlcs(self):
        self.run_shell(['start_dependencies.sh', 'do_not_settle_elec2'])
        self.run_shell(['redeem_htlcs.sh'])

    def test_funder_publishes_initial_commitment_and_fundee_takes_all(self):
        self.run_shell(['start_dependencies.sh'])
        self.run_shell(['breach.sh'])
