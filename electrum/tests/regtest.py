import asyncio
import queue
import subprocess
import sys
import unittest
from decimal import Decimal

from electrum import util
from electrum.commands import Commands
from electrum.constants import set_regtest
from electrum.daemon import Daemon
from electrum.simple_config import SimpleConfig
from electrum.storage import WalletStorage
from electrum.wallet import Wallet
from electrum.wallet_db import WalletDB


class TestLightning(unittest.TestCase):

    @staticmethod
    def run_shell(args, timeout=30):
        process = subprocess.Popen(
            ['electrum/tests/regtest/regtest.sh'] + args,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        output = ''
        for line in iter(process.stdout.readline, ''):
            output += line + '\n'
            sys.stdout.write(line)
            sys.stdout.flush()
        process.wait(timeout=timeout)
        process.stdout.close()
        assert process.returncode == 0
        return output.strip()

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

    def test_collaborative_close(self):
        self.run_shell(['collaborative_close'])

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


class TestLightningABC(TestLightning):
    agents = ['alice', 'bob', 'carol']

    def test_watchtower(self):
        self.run_shell(['watchtower'])


class TestPaymentRequests(TestLightning):
    agents = ['wallet']
    INVOICE_AMOUNT = '0.01'

    def setUp(self):
        super().setUp()
        set_regtest()
        (
            self.asyncio_loop,
            self._stop_loop,
            self._loop_thread,
        ) = util.create_and_start_event_loop()
        self.config = SimpleConfig(
            {'electrum_path': '/tmp/wallet', 'server': '127.0.0.1:51001:t'}
        )
        self.daemon = Daemon(self.config, listen_jsonrpc=False)
        self.network = self.daemon.network
        self.queue = queue.Queue()

    def tearDown(self):
        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)
        super().tearDown()

    def test_payment_requests(self):

        commands = Commands(
            config=self.config, network=self.network, daemon=self.daemon
        )
        storage = WalletStorage('/tmp/wallet/regtest/wallets/default_wallet')
        db = WalletDB(storage.read(), manual_upgrades=False)
        wallet = Wallet(db=db, storage=storage, config=self.config)
        util.register_callback(self.process_callbacks, ['request_status'])
        wallet.start_network(self.network)
        self.daemon.add_wallet(wallet)

        async def main_test():
            await commands.add_request(
                self.INVOICE_AMOUNT, wallet=wallet
            )  # skip first one as it gets paid via init function
            req = await commands.add_request(self.INVOICE_AMOUNT, wallet=wallet)
            address = req['address']
            tx_hash = self.run_shell(['sendtoaddress', address, self.INVOICE_AMOUNT])
            while True:
                balance = (await commands.getaddressbalance(address))['unconfirmed']
                if Decimal(balance) >= Decimal(self.INVOICE_AMOUNT):
                    break
                await asyncio.sleep(1)
            # wait a bit more for electrum to sync state
            await asyncio.sleep(1)
            assert self.queue.qsize() > 0
            matched_data = None
            while not self.queue.empty():
                data = self.queue.get()
                if data[1] == req['request_id']:
                    matched_data = data
                    break
            assert matched_data is not None
            assert matched_data == (wallet, req['request_id'], 7)
            req = await commands.get_request(req['request_id'], wallet=wallet)
            assert req['status'] == 7
            assert req['tx_hashes'] == [tx_hash]

        asyncio.run_coroutine_threadsafe(
            main_test(), loop=util.get_asyncio_loop()
        ).result()

    async def process_callbacks(self, *args):
        self.queue.put(args)
