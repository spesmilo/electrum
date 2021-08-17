import asyncio
import json
import shutil
import subprocess
import time
from threading import Event
from typing import List, Dict, TYPE_CHECKING, Union
import unittest

from electrum.commands import Commands
from electrum import constants
from electrum.daemon import Daemon
from electrum.logging import get_logger, configure_logging  # import logging submodule first
from electrum.lnwatcher import LNWalletWatcher
from electrum.simple_config import SimpleConfig
from electrum.util import create_and_start_event_loop, log_exceptions
from electrum.wallet import create_new_wallet, Abstract_Wallet
from electrum.util import register_callback, unregister_callback

if TYPE_CHECKING:
    from electrum.lnworker import LNWorker

constants.set_regtest()

import logging.config
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.handlers[0].setLevel(logging.DEBUG)


def decode_byte_string_to_dict_or_str(out: Union[bytes, str]) -> Union[Dict, str]:
    """Takes output from Process and converts it to a dict."""
    try:
        json_data = json.loads(out)
        return json_data
    except json.decoder.JSONDecodeError:
        if isinstance(out, str):
            return out.strip()
        if isinstance(out, bytes):
            return out.decode().strip()


class TestLightningIntegration(unittest.TestCase):
    agent_names = []  # type: List[str]
    agent_configs = {}  # type: Dict[str, SimpleConfig]
    agents = {}  # type: Dict[str, Abstract_Wallet]

    def setUp(self):
        try:
            shutil.rmtree('/tmp/electrum')
        except FileNotFoundError:
            pass

        self.loop, self.stopping_fut, self.loop_thread = create_and_start_event_loop()
        base_config = {
            'regtest': True,
            'verbosity': '*',
            'daemon': True,
            'cwd': '/tmp/electrum',
            'electrum_path': '/tmp/electrum',
            'server': 'localhost:51001:t',
            'lightning_to_self_delay': 144,
            'log_to_file': True,
            'ligthning_listen': 'localhost:9735',
            'path': '/tmp/electrum'
        }
        # give time to start event loop
        time.sleep(0.1)

        self.daemon = Daemon(SimpleConfig(base_config), listen_jsonrpc=False)
        self.network = self.daemon.network
        self.simple_base_config = SimpleConfig(base_config)
        configure_logging(self.simple_base_config)

        for agent in self.agent_names:
            config = base_config.copy()
            if agent == 'alice':
                config['path'] = '/tmp/electrum/wallet_alice'
            elif agent == 'bob':
                config['lightning_listen'] = 'localhost:9736'
                config['path'] = '/tmp/electrum/wallet_bob'
            elif agent == 'carlie':
                config['lightning_listen'] = 'localhost:9737'
                config['path'] = '/tmp/electrum/wallet_carlie'

            simple_config = SimpleConfig(config)
            self.agent_configs[agent] = simple_config
            self.network.config = simple_config  # replace configs to put correct lightning_listen
            create_new_wallet(path=config['path'], config=simple_config)
            self.agents[agent] = self.daemon.load_wallet(config['path'], password=None, manual_upgrades=False)

        # at this point we assume that bitcoin-cli has funds available
        # addr = self.bitcoincli(['getnewaddress'])
        # self.bitcoincli(['generatetoaddress', 1, addr])
        # self.mine_blocks(100)

        # fill agents' wallets
        for agent, wallet in self.agents.items():
            addr = wallet.get_receiving_address()
            self.bitcoincli(['sendtoaddress', addr, 1])
        self.wait_for_callback('wallet_updated')
        self.confirm()

    def wait_for_callback(self, callback_str: str, instance=None):
        logger.debug(f'>>> waiting for {callback_str}, instance: {instance}')
        event = Event()

        def callback(*args, **kwargs):
            logger.debug(f">>> args {args} kwargs {kwargs}")
            if instance and isinstance(args[1], LNWalletWatcher):
                if args[1] is instance:
                    event.set()
                else:
                    return
            event.set()

        register_callback(callback, [callback_str])
        event.wait()
        unregister_callback(callback)

    def confirm(self, number_blocks=3):
        self.mine_blocks(number_blocks)
        self.wait_for_callback('blockchain_updated')

    def tearDown(self) -> None:
        shutil.rmtree('/tmp/electrum')

    @staticmethod
    def bitcoincli(args, timeout=30):
        bitcoin_cli = "bitcoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"
        args = list(map(str, args))
        logger.debug(f"BTC: {' '.join(args)}")
        process = subprocess.Popen(bitcoin_cli.split() + args, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        process.wait(timeout=timeout)
        result = decode_byte_string_to_dict_or_str(process.stdout.read().strip())
        process.stdout.close()
        logger.debug(f"BTC: {result}")
        assert process.returncode == 0
        return result

    def mine_blocks(self, number_blocks=3):
        self.bitcoincli(['generatetoaddress', number_blocks, 'bcrt1q35jr8lys6tlxyye9dk3pxxumr4wtnydpzpl6s7'])


class TestLightningAB(TestLightningIntegration):
    agent_names = ['alice', 'bob']

    def test_breach(self):
        @log_exceptions
        async def run_test():
            try:
                cmd = Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)
                # 1: alice opens channel to bob
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = self.network.run_from_another_thread(cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice']))
                self.mine_blocks(3)
                # 2: wait until the channel to be open from both partners
                self.wait_for_callback('channel')
                self.wait_for_callback('channel')
                # 3: alice pays bob
                payment_request = self.network.run_from_another_thread(cmd.add_lightning_request(0.01, 'blah', wallet=self.agents['bob']))['invoice']
                self.network.run_from_another_thread(cmd.lnpay(payment_request, wallet=self.agents['alice']))
                # 4: alice saves old ctx
                ctx = self.network.run_from_another_thread(cmd.get_channel_ctx(channel, iknowwhatimdoing=True, wallet=self.agents['alice']))
                # 5: alice pays again
                payment_request = self.network.run_from_another_thread(cmd.add_lightning_request(0.01, 'blah2', wallet=self.agents['bob']))['invoice']
                self.network.run_from_another_thread(cmd.lnpay(payment_request, wallet=self.agents['alice']))
                balance_before = self.network.run_from_another_thread(cmd.getbalance(wallet=self.agents['bob']))
                # 6: alice broadcasts old ctx
                self.bitcoincli(['sendrawtransaction', ctx])
                # 7: ctx gets confirmed
                self.mine_blocks(1)
                # 8: wait for channel to get closed
                self.wait_for_callback('channel')
                self.wait_for_callback('wallet_updated', self.agents['bob'].lnworker.lnwatcher)
                # 9: mine penalty transaction
                self.mine_blocks(1)
                self.wait_for_callback('blockchain_updated')
                self.wait_for_callback('wallet_updated')
                # 10: compare balance
                balance_after = self.network.run_from_another_thread(cmd.getbalance(wallet=self.agents['bob']))
                balance_before = float(balance_before.get('confirmed', 0)) + float(balance_before.get('unconfirmed', 0))
                balance_after = float(balance_after.get('confirmed', 0)) + float(balance_after.get('unconfirmed', 0))
                self.assertAlmostEqual(0.14945639, balance_after - balance_before, places=8)
            finally:
                self.stopping_fut.set_result(1)
        asyncio.run(run_test())

