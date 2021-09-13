import asyncio
import json
import shutil
import subprocess
import time
from threading import Event
from typing import List, Dict, Union
import os
import unittest
import tempfile
import importlib

# alias electrum modules to be able to reload and to undo side effects
from electrum import daemon as electrum_daemon
from electrum import commands as electrum_commands
from electrum import constants as electrum_constants
from electrum import network as electrum_network
from electrum import lnwatcher as electrum_lnwatcher
from electrum import logging as electrum_logging
from electrum import simple_config as electrum_simple_config
from electrum import util as electrum_util
from electrum import wallet as electrum_wallet

import logging

# set log level of all subsystems
loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
for logger in loggers:
    logger.setLevel(logging.DEBUG)

# configure test logger
logger = logging.getLogger(__name__)
logger.propagate = False  # do not repeat in main logging
logger.setLevel(logging.INFO)
formatter = logging.Formatter(">>> %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

PORT = 9375
electrum_constants.set_regtest()

TEST_ANCHOR_CHANNELS = False


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=asyncio.get_event_loop()).result()


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


def extract_balance(balance, include_unconfirmed=False) -> float:
    total_balance = float(balance.get('confirmed', 0))
    if include_unconfirmed:
        total_balance += float(balance.get('unconfirmed', 0))
    return total_balance


class TestLightningIntegration(unittest.TestCase):
    watchtower = False  # there's only one network instance that can run the watchtower
    agent_names = []  # type: List[str]

    def setUp(self):
        # tests are decoupled by using temporary folders, which gets deleted in tearDown
        self.tmpdir = tempfile.TemporaryDirectory()
        global PORT  # this is a hack because transports are not getting closed properly

        # undo some side effects - order is important
        importlib.reload(logging)
        importlib.reload(electrum_logging)
        importlib.reload(electrum_simple_config)
        importlib.reload(electrum_network)
        importlib.reload(electrum_util)

        self.agent_configs = {}  # type: Dict[str, electrum_simple_config.SimpleConfig]
        self.agents = {}  # type: Dict[str, electrum_wallet.Abstract_Wallet]

        self.loop, self.stopping_fut, self.loop_thread = electrum_util.create_and_start_event_loop()
        base_config = {
            'regtest': True,
            'verbosity': '*',
            'daemon': True,
            'cwd': self.tmpdir.name,
            'electrum_path': self.tmpdir.name,
            'server': 'localhost:51001:t',
            'lightning_to_self_delay': 144,
            'log_to_file': True,
            'path': self.tmpdir.name,
            'use_gossip': True,
            'enable_anchor_channels': TEST_ANCHOR_CHANNELS,
        }
        if self.watchtower:
            base_config.update({
                'run_watchtower': True,
                'watchtower_user': 'wtuser',
                'watchtower_password': 'wtpassword',
                'watchtower_address': '127.0.0.1:12345',
            })
        # give time to start event loop
        time.sleep(0.1)
        # start the daemon that handles the wallets and the network instance
        self.daemon = electrum_daemon.Daemon(electrum_simple_config.SimpleConfig(base_config), listen_jsonrpc=False)
        self.network = self.daemon.network

        self.simple_base_config = electrum_simple_config.SimpleConfig(base_config)
        electrum_logging.configure_logging(self.simple_base_config)

        PORT += 1
        for agent in self.agent_names:
            config = base_config.copy()
            if agent == 'alice':
                config['path'] = os.path.join(self.tmpdir.name, "wallet_alice")
            elif agent == 'bob':
                config['lightning_listen'] = f'localhost:{PORT}'
                config['path'] = os.path.join(self.tmpdir.name, "wallet_bob")
                if self.watchtower:
                    config['watchtower_url'] = 'http://wtuser:wtpassword@127.0.0.1:12345'

            simple_config = electrum_simple_config.SimpleConfig(config)
            self.agent_configs[agent] = simple_config
            self.network.config = simple_config  # replace configs to put correct lightning_listen
            electrum_wallet.create_new_wallet(path=config['path'], config=simple_config)
            self.agents[agent] = self.daemon.load_wallet(config['path'], password=None, manual_upgrades=False)

        # fill agents' wallets
        for agent, wallet in self.agents.items():
            addr = wallet.get_receiving_address()
            self.bitcoincli(['sendtoaddress', addr, 1])
        self.wait_for_callback('wallet_updated')
        self.confirm()

        self.cmd = electrum_commands.Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)

    def tearDown(self) -> None:
        self.daemon.stop()
        del self.tmpdir

    def wait_for_callback(self, callback_str: str, instance=None):
        logger.debug(f'waiting for {callback_str}, instance: {instance}')
        event = Event()

        def callback(*args, **kwargs):
            logger.debug(f"args {args} kwargs {kwargs}")
            if instance and isinstance(args[1], electrum_lnwatcher.LNWalletWatcher):
                if args[1] is instance:
                    event.set()
                else:
                    return
            event.set()

        electrum_util.register_callback(callback, [callback_str])
        event.wait(timeout=10)
        electrum_util.unregister_callback(callback)

    def confirm(self, number_blocks=3):
        self.mine_blocks(number_blocks)
        self.wait_for_callback('blockchain_updated')

    async def wait_for_channel_change(self, wallet):
        logger.debug(f'waiting for channel state change of {wallet.diagnostic_name()}')
        initial_channels = await self.cmd.list_channels(wallet=wallet)
        initial_states = [c['state'] for c in initial_channels]
        while True:
            channels = await self.cmd.list_channels(wallet=wallet)
            states = [c['state'] for c in channels]
            await asyncio.sleep(1)
            if states != initial_states:
                break
        logger.debug('channel changed')

    async def wait_for_balance(self, wallet, threshold, include_unconfirmed=False, return_on_change=False, timeout_sec=15):
        """Will immediately return if threshold is met."""
        initial_balance_dict = await self.cmd.getbalance(wallet=wallet)
        logger.info(f'waiting for balance change or threshold of {threshold} of {wallet.diagnostic_name()}')
        logger.info(f'initial balance: {initial_balance_dict}')
        start_time = time.time()

        def balance_to_sum(balance_dict):
            balance = float(balance_dict['confirmed'])
            if include_unconfirmed:
                unconfirmed = balance_dict.get('unconfirmed')
                balance += float(unconfirmed) if unconfirmed else 0
            return balance
        initial_balance = balance_to_sum(initial_balance_dict)

        while True:
            elapsed_time = time.time() - start_time
            next_balance_dict = await self.cmd.getbalance(wallet=wallet)
            if elapsed_time > timeout_sec:
                raise TimeoutError
            next_balance = balance_to_sum(next_balance_dict)
            logger.info(f'new balance: {next_balance_dict}')
            if next_balance >= threshold:
                break
            if next_balance != initial_balance and return_on_change:
                break
            await asyncio.sleep(1)
        logger.info(f'final balance: {next_balance_dict}')

    @staticmethod
    def bitcoincli(args, timeout=30):
        bitcoin_cli = "bitcoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"
        args = list(map(str, args))
        logger.info(f"BTC: {' '.join(args)}")
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

    def test_close_collaborative(self):
        async def run_test():
            payment_amount = 0.01
            try:
                balance_alice_before = extract_balance(await self.cmd.getbalance(wallet=self.agents['alice']))
                balance_bob_before = extract_balance(await self.cmd.getbalance(wallet=self.agents['bob']))
                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = await self.cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)
                logger.info("2: wait until the channel is open")
                await self.wait_for_channel_change(self.agents['alice'])
                logger.info("3: alice pays bob")
                payment_request = (await self.cmd.add_lightning_request(0.01, 'blah', wallet=self.agents['bob']))['invoice']
                await self.cmd.lnpay(payment_request, wallet=self.agents['alice'])
                logger.info("4: alice closes channel")
                await self.cmd.close_channel(channel, wallet=self.agents['alice'])
                self.mine_blocks(1)
                await self.wait_for_channel_change(self.agents['alice'])
                logger.info("5: confirm funds")
                self.mine_blocks(3)
                await self.wait_for_balance(self.agents['alice'], threshold=0.98)
                await self.wait_for_balance(self.agents['bob'], threshold=1.01)
                time.sleep(5)
                logger.info("6: compare balance")
                balance_alice_after = extract_balance(await self.cmd.getbalance(wallet=self.agents['alice']))
                balance_bob_after = extract_balance(await self.cmd.getbalance(wallet=self.agents['bob']))
                # bob has payment_amount more
                self.assertAlmostEqual(payment_amount, balance_bob_after - balance_bob_before, places=8)
                # alice has payment_amount + miner fees less
                self.assertLess(payment_amount, balance_alice_before - balance_alice_after)
            finally:
                self.stopping_fut.set_result(1)
        run(run_test())

    @unittest.skip
    def test_close_force(self):
        payment_amount = 0.01
        async def run_test():
            try:
                cmd = electrum_commands.Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)
                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = await cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)
                logger.info("2: wait until the channel is open")
                await self.wait_for_channel_change(self.agents['alice'])
                logger.info("3: alice pays bob")
                payment_request = (await cmd.add_lightning_request(payment_amount, 'blah', wallet=self.agents['bob']))['invoice']
                await cmd.lnpay(payment_request, wallet=self.agents['alice'])
                logger.info("4: alice closes channel")
                await cmd.close_channel(channel, force=True, wallet=self.agents['alice'])
                self.mine_blocks(1)
                await self.wait_for_channel_change(self.agents['alice'])
                logger.info("5: both peers prepare to sweep")
                self.mine_blocks(1)
                logger.info("6: bob can now sweep his to_remote output")
                await self.wait_for_balance(self.agents['bob'], include_unconfirmed=True, threshold=1.009)
                self.mine_blocks(143)
                await asyncio.sleep(10)  # wait for alice to publish the to_local sweep
                logger.info("7: alice can now sweep her to_local output")
                await self.wait_for_balance(self.agents['alice'], include_unconfirmed=True, threshold=0.98)
                self.mine_blocks(1)
                logger.info("8: alice's funds get confirmed")
                await self.wait_for_balance(self.agents['alice'], threshold=0.98, timeout_sec=30)
            finally:
                self.stopping_fut.set_result(1)
        run(run_test())

    @unittest.skip
    def test_close_with_htlc_success(self):
        payment_amount = 0.04
        async def run_test():
            try:
                cmd = electrum_commands.Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)
                extract_balance(await cmd.getbalance(wallet=self.agents['alice']))
                extract_balance(await cmd.getbalance(wallet=self.agents['bob']))

                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = await cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)

                logger.info("2: wait until the channel is open")
                await self.wait_for_channel_change(self.agents['alice'])

                logger.info("3: alice pays bob, but bob holds on to the htlc, while alice closes")
                self.agents['bob'].lnworker.enable_htlc_settle = False
                payment_request = (await cmd.add_lightning_request(payment_amount, 'blah', wallet=self.agents['bob']))['invoice']
                async def pay():
                    await cmd.lnpay(payment_request, wallet=self.agents['alice'])
                async def close():
                    await asyncio.sleep(1)
                    await cmd.close_channel(channel, force=True, wallet=self.agents['bob'])
                    await asyncio.sleep(1)
                    gathered.cancel()  # payment fails
                gathered = asyncio.gather(pay(), close())
                try:
                    await gathered
                except asyncio.CancelledError:
                    pass
                # set if htlc gets settled onchain or not
                self.agents['bob'].lnworker.enable_htlc_settle_onchain = True

                logger.info("5: ctx gets mined, alice publishes to_remote sweep, bob publishes htlc_success tx")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['bob'], include_unconfirmed=True, threshold=1.03)

                logger.info("6: to_remote sweep gets mined, htlc success gets mined")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['alice'], threshold=0.95)

                logger.info("7: bob's htlc-success output matures, publishes htlc_success sweep")
                self.mine_blocks(143)
                await asyncio.sleep(10)  # wait for blockchain to be synced

                logger.info("7: htlc success sweep gets mined")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['bob'], threshold=1.03)

                balance_alice = extract_balance(await cmd.getbalance(wallet=self.agents['alice']))
                balance_bob = extract_balance(await cmd.getbalance(wallet=self.agents['bob']))
                self.assertAlmostEqual(1-payment_amount, balance_alice, places=1)
                self.assertAlmostEqual(1+payment_amount, balance_bob, places=1)
            finally:
                self.stopping_fut.set_result(1)
        run(run_test())

    def test_breach(self):
        async def run_test():
            try:
                cmd = electrum_commands.Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)
                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = await cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)

                logger.info("2: wait until the channel is open")
                await self.wait_for_channel_change(self.agents['alice'])

                logger.info("3: alice pays bob")
                payment_request = (await cmd.add_lightning_request(0.01, 'blah', wallet=self.agents['bob']))['invoice']
                await cmd.lnpay(payment_request, wallet=self.agents['alice'])

                logger.info("4: alice saves old ctx bob")
                ctx = await cmd.get_channel_ctx(channel, iknowwhatimdoing=True, wallet=self.agents['alice'])

                logger.info("5: alice pays bob again")
                payment_request = (await cmd.add_lightning_request(0.01, 'blah2', wallet=self.agents['bob']))['invoice']
                await cmd.lnpay(payment_request, wallet=self.agents['alice'])

                logger.info("6: alice broadcasts old ctx")
                self.bitcoincli(['sendrawtransaction', ctx])

                logger.info("7: ctx gets confirmed")
                self.mine_blocks(1)

                logger.info("8: wait for channel to get closed")
                await self.wait_for_channel_change(self.agents['alice'])

                logger.info("9: mine penalty transaction")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['bob'], threshold=1.14)

            finally:
                self.stopping_fut.set_result(1)
        run(run_test())

    def test_breach_with_htlc(self):
        async def run_test():
            try:
                cmd = electrum_commands.Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)
                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = await cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)

                logger.info("2: wait until the channel to be open from both partners")
                await self.wait_for_channel_change(self.agents['alice'])

                logger.info("3: alice pays bob, without settling the htlc")
                payment_request = (await cmd.add_lightning_request(0.03, 'blah', wallet=self.agents['bob']))['invoice']
                self.agents['bob'].lnworker.enable_htlc_settle = False

                async def pay():
                    await cmd.lnpay(payment_request, wallet=self.agents['alice'])

                async def save_ctx_and_settle():
                    await asyncio.sleep(2)
                    ctx_alice = await cmd.get_channel_ctx(channel, iknowwhatimdoing=True, wallet=self.agents['alice'])
                    ctx_bob = await cmd.get_channel_ctx(channel, iknowwhatimdoing=True, wallet=self.agents['bob'])
                    logger.info("4: bob settles the htlc offchain")
                    self.agents['bob'].lnworker.enable_htlc_settle = True
                    return ctx_alice, ctx_bob
                gathered = asyncio.gather(pay(), save_ctx_and_settle())
                ctx_alice, ctx_bob = (await gathered)[1]

                logger.info("5: alice broadcasts old ctx")
                self.bitcoincli(['sendrawtransaction', ctx_alice])
                await self.wait_for_balance(self.agents['bob'], threshold=1.14, include_unconfirmed=True)

                logger.info("6: old ctx gets mined")
                self.mine_blocks(1)

                logger.info("7: bob publishes to_local justice transactions")

                logger.info("8: to_local justice transaction gets confirmed, "
                    "bob publishes htlc justice transaction")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['bob'], threshold=1.11)

                logger.info("9: htlc justice transaction gets mined")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['bob'], threshold=1.14, timeout_sec=30)

            finally:
                self.stopping_fut.set_result(1)
        run(run_test())

    @unittest.skip
    def test_channel_backup(self):
        imported_backup = True
        onchain_backup = True
        async def run_test():
            try:
                channel1 = None
                channel2 = None
                backup = None
                cmd = electrum_commands.Commands(config=self.simple_base_config, daemon=self.daemon, network=self.network)

                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"

                logger.info("2: chose backup type of channels")
                if onchain_backup:
                    channel1 = await cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                await cmd.setconfig('use_recoverable_channels', False)
                if imported_backup:
                    channel2 = await cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)

                logger.info("3: wait until the channels are open")
                await self.wait_for_channel_change(self.agents['alice'])

                if imported_backup:
                    backup = await cmd.export_channel_backup(channel2, wallet=self.agents['alice'])
                seed = await cmd.getseed(wallet=self.agents['alice'])

                logger.info("4: alice closes and renames wallet")
                alice_wallet_path = self.agent_configs['alice'].cmdline_options['path']
                await cmd.close_wallet(wallet_path=alice_wallet_path)
                shutil.move(
                    alice_wallet_path,
                    alice_wallet_path + '.old'
                )

                logger.info("5: alice restores from seed")
                electrum_wallet.restore_wallet_from_text(seed, config=self.agent_configs['alice'], path=alice_wallet_path)
                self.agents['alice'] = self.daemon.load_wallet(alice_wallet_path, password=None, manual_upgrades=False)

                logger.info("5: alice restores backups and requests force closures")
                await asyncio.sleep(2)
                if imported_backup:
                    await cmd.import_channel_backup(backup, wallet=self.agents['alice'])
                if onchain_backup:
                    await cmd.request_force_close(channel_point=channel1, wallet=self.agents['alice'])
                await asyncio.sleep(2)  # needed otherwise racy
                if imported_backup:
                    await cmd.request_force_close(channel_point=channel2, wallet=self.agents['alice'])

                logger.info("6: mine force closure ctx transactions")
                self.mine_blocks(1)

                logger.info("7: alice sees ctx and prepare sweep txns")
                await self.wait_for_balance(self.agents['alice'], include_unconfirmed=True, threshold=0.99)
                self.mine_blocks(1)

                logger.info("8: alice publishes sweep transactions")
                await self.wait_for_balance(self.agents['alice'], return_on_change=True, threshold=0.99)

                logger.info("9: mine sweep transactions")
                self.mine_blocks(1)
                await self.wait_for_balance(self.agents['alice'], return_on_change=True, threshold=0.99)

            finally:
                self.stopping_fut.set_result(1)
        run(run_test())


class TestLightningABC(TestLightningIntegration):
    # daemon plays the role of watchtower
    agent_names = ['alice', 'bob']
    watchtower = True

    @unittest.skip
    def test_watchtower_htlc(self):
        async def run_test():
            try:
                logger.info("0: configure external watchtower")
                await self.cmd.setconfig('watchtower_url', 'http://wtuser:wtpassword@127.0.0.1:12345')

                logger.info("1: alice opens channel to bob")
                bob_nodeid = self.agents['bob'].lnworker.node_keypair.pubkey.hex()
                bob_connect_string = f"{bob_nodeid}@{self.agent_configs['bob'].get('lightning_listen')}"
                channel = await self.cmd.open_channel(bob_connect_string, 0.15, wallet=self.agents['alice'])
                self.mine_blocks(3)

                logger.info("2: wait until the channel to be open from both partners")
                self.wait_for_callback('channel')
                self.wait_for_callback('verified')
                await asyncio.sleep(5) # test seems to depend on this

                logger.info("3: alice pays bob, without first settling the htlc")
                payment_request = (await self.cmd.add_lightning_request(0.03, 'blah', wallet=self.agents['bob']))['invoice']
                self.agents['bob'].lnworker.enable_htlc_settle = False
                async def pay():
                    await self.cmd.lnpay(payment_request, wallet=self.agents['alice'])
                async def save_ctx_and_settle():
                    await asyncio.sleep(2)
                    # alice saves ctx with htlc attached to it
                    ctx_alice = await self.cmd.get_channel_ctx(channel, iknowwhatimdoing=True, wallet=self.agents['alice'])
                    ctx_bob = await self.cmd.get_channel_ctx(channel, iknowwhatimdoing=True, wallet=self.agents['bob'])
                    logger.info("4: bob settles the htlc offchain")
                    self.agents['bob'].lnworker.enable_htlc_settle = True
                    return ctx_alice, ctx_bob
                gathered = asyncio.gather(pay(), save_ctx_and_settle())
                ctx_alice, ctx_bob = (await gathered)[1]

                logger.info("5: alice pays again")
                payment_request = (await self.cmd.add_lightning_request(0.01, 'blah2', wallet=self.agents['bob']))['invoice']
                await self.cmd.lnpay(payment_request, wallet=self.agents['alice'])

                logger.info("6: bob syncs newest state with watchtower")
                for _ in range(30):
                    ctn = await self.cmd.get_watchtower_ctn(channel_point=channel, wallet=self.agents['bob'])
                    if ctn == 3:
                        break
                    await asyncio.sleep(1)
                else:
                    raise TimeoutError

                logger.info("7: alice and bob go offline")
                await self.agents['bob'].stop()
                await self.agents['alice'].stop()

                logger.info("8: alice broadcasts old ctx")
                ctxid = self.bitcoincli(['sendrawtransaction', ctx_alice])
                await asyncio.sleep(2)
                self.assertTrue(bool(self.bitcoincli(['gettxout', ctxid, 2])))  # htlc
                self.assertTrue(bool(self.bitcoincli(['gettxout', ctxid, 3])))  # to_local

                logger.info("9: ctx gets confirmed")
                self.mine_blocks(1)
                await asyncio.sleep(3)

                logger.info("10: watchtower sweeps")
                await asyncio.sleep(10)
                self.assertFalse(bool(self.bitcoincli(['gettxout', ctxid, 2])))
                self.assertFalse(bool(self.bitcoincli(['gettxout', ctxid, 3])))

            finally:
                self.stopping_fut.set_result(1)
        run(run_test())
