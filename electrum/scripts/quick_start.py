#!/usr/bin/env python3

import os
import asyncio

from electrum.simple_config import SimpleConfig
from electrum import constants
from electrum.daemon import Daemon
from electrum.storage import WalletStorage
from electrum.wallet import Wallet, create_new_wallet
from electrum.wallet_db import WalletDB
from electrum.commands import Commands
from electrum.util import create_and_start_event_loop, log_exceptions


loop, stopping_fut, loop_thread = create_and_start_event_loop()

config = SimpleConfig({"testnet": True})  # to use ~/.electrum/testnet as datadir
constants.BitcoinTestnet.set_as_network()  # to set testnet magic bytes
daemon = Daemon(config, listen_jsonrpc=False)
network = daemon.network
assert network.asyncio_loop.is_running()

# get wallet on disk
wallet_dir = os.path.dirname(config.get_wallet_path())
wallet_path = os.path.join(wallet_dir, "test_wallet")
if not os.path.exists(wallet_path):
    create_new_wallet(path=wallet_path, config=config)

# open wallet
wallet = daemon.load_wallet(wallet_path, password=None, upgrade=True)

# you can use ~CLI commands by accessing command_runner
command_runner = Commands(config=config, daemon=daemon, network=network)
print("balance", network.run_from_another_thread(command_runner.getbalance(wallet=wallet)))
print("addr",    network.run_from_another_thread(command_runner.getunusedaddress(wallet=wallet)))
print("gettx",   network.run_from_another_thread(
    command_runner.gettransaction("bd3a700b2822e10a034d110c11a596ee7481732533eb6aca7f9ca02911c70a4f")))


# but you might as well interact with the underlying methods directly
print("balance", wallet.get_balance())
print("addr",    wallet.get_unused_address())
print("gettx",   network.run_from_another_thread(network.get_transaction("bd3a700b2822e10a034d110c11a596ee7481732533eb6aca7f9ca02911c70a4f")))

stopping_fut.set_result(1)  # to stop event loop
