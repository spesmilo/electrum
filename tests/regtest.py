import os
import sys
import unittest
import subprocess
from typing import Mapping, Any

from electrum.simple_config import SimpleConfig


class TestLightning(unittest.TestCase):
    agents: Mapping[str, Mapping[str, Any]]

    @staticmethod
    def run_shell(args, timeout=30):
        process = subprocess.Popen(['tests/regtest/regtest.sh'] + args, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
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
        for agent, config_options in self.agents.items():
            self.run_shell(['init', agent])
            for k, v in config_options.items():
                self.run_shell(['setconfig', agent, k, v])
        # mine a block so that funds are confirmed
        self.run_shell(['new_block'])
        # start daemons
        for agent in self.agents:
            self.run_shell(['start', agent])

    def tearDown(self):
        for agent in self.agents:
            self.run_shell(['stop', agent])


class TestUnixSockets(TestLightning):
    agents = {}

    def test_unixsockets(self):
        self.run_shell(['unixsockets'])


class TestLightningAB(TestLightning):
    agents = {
        'alice': {
        },
        'bob': {
            SimpleConfig.LIGHTNING_LISTEN.key(): 'localhost:9735',
        }
    }

    def test_collaborative_close(self):
        self.run_shell(['collaborative_close'])

    def test_backup(self):
        self.run_shell(['backup'])

    def test_backup_local_forceclose(self):
        self.run_shell(['backup_local_forceclose'])

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


class TestLightningSwapserver(TestLightning):
    agents = {
        'alice': {
            SimpleConfig.LIGHTNING_USE_GOSSIP.key(): 'false',
            SimpleConfig.SWAPSERVER_URL.key(): 'http://localhost:5455',
            SimpleConfig.NOSTR_RELAYS.key(): "''",
        },
        'bob': {
            SimpleConfig.LIGHTNING_LISTEN.key(): 'localhost:9735',
            'enable_plugin_swapserver': 'true',
            SimpleConfig.SWAPSERVER_PORT.key(): '5455',
            SimpleConfig.NOSTR_RELAYS.key(): "''",
        }
    }

    def test_swapserver_success(self):
        self.run_shell(['swapserver_success'])

    def test_swapserver_forceclose(self):
        self.run_shell(['swapserver_forceclose'])

    def test_swapserver_refund(self):
        self.run_shell(['swapserver_refund'])



class TestLightningWatchtower(TestLightning):
    agents = {
        'alice': {
        },
        'bob': {
            SimpleConfig.LIGHTNING_LISTEN.key(): 'localhost:9735',
            SimpleConfig.WATCHTOWER_CLIENT_URL.key(): 'http://wtuser:wtpassword@127.0.0.1:12345',
        },
        'carol': {
            'enable_plugin_watchtower': 'true',
            SimpleConfig.WATCHTOWER_SERVER_USER.key(): 'wtuser',
            SimpleConfig.WATCHTOWER_SERVER_PASSWORD.key(): 'wtpassword',
            SimpleConfig.WATCHTOWER_SERVER_PORT.key(): '12345',
        }
    }

    def test_watchtower(self):
        self.run_shell(['watchtower'])


class TestLightningJIT(TestLightning):
    agents = {
        'alice': {
            SimpleConfig.ACCEPT_ZEROCONF_CHANNELS.key(): 'true',
        },
        'bob': {
            SimpleConfig.LIGHTNING_LISTEN.key(): 'localhost:9735',
            SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS.key(): 'true',
            SimpleConfig.ACCEPT_ZEROCONF_CHANNELS.key(): 'true',
        },
        'carol': {
        }
    }

    def test_just_in_time(self):
        self.run_shell(['just_in_time'])


class TestLightningJITTrampoline(TestLightningJIT):
    agents = {
        'alice': {
            SimpleConfig.LIGHTNING_USE_GOSSIP.key(): 'false',
            SimpleConfig.ACCEPT_ZEROCONF_CHANNELS.key(): 'true',
        },
        'bob': {
            SimpleConfig.LIGHTNING_LISTEN.key(): 'localhost:9735',
            SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS.key(): 'true',
            SimpleConfig.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS.key(): 'true',
            SimpleConfig.ACCEPT_ZEROCONF_CHANNELS.key(): 'true',
        },
        'carol': {
            SimpleConfig.LIGHTNING_USE_GOSSIP.key(): 'false',
        }
    }
