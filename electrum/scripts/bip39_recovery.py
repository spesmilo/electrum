#!/usr/bin/env python3

import sys
import asyncio

from electrum.util import json_encode, print_msg, create_and_start_event_loop, log_exceptions
from electrum.simple_config import SimpleConfig
from electrum.network import Network
from electrum.keystore import bip39_to_seed
from electrum.bip32 import BIP32Node
from electrum.bip39_recovery import account_discovery

try:
    mnemonic = sys.argv[1]
    passphrase = sys.argv[2] if len(sys.argv) > 2 else ""
except Exception:
    print("usage: bip39_recovery <mnemonic> [<passphrase>]")
    sys.exit(1)

loop, stopping_fut, loop_thread = create_and_start_event_loop()

config = SimpleConfig()
network = Network(config)
network.start()

@log_exceptions
async def f():
    try:
        def get_account_xpub(account_path):
            root_seed = bip39_to_seed(mnemonic, passphrase)
            root_node = BIP32Node.from_rootseed(root_seed, xtype="standard")
            account_node = root_node.subkey_at_private_derivation(account_path)
            account_xpub = account_node.to_xpub()
            return account_xpub
        active_accounts = await account_discovery(network, get_account_xpub)
        print_msg(json_encode(active_accounts))
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
