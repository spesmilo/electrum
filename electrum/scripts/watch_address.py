#!/usr/bin/env python3

import sys
import asyncio

import electrum
from electrum.bitcoin import script_to_address
from electrum.network import Network
from electrum.util import print_msg, create_and_start_event_loop
from electrum.synchronizer import SynchronizerBase
from electrum.simple_config import SimpleConfig


try:
    addr = sys.argv[1]
except Exception:
    print("usage: watch_address <bitcoin_address>")
    sys.exit(1)

config = SimpleConfig()

# start network
loop = create_and_start_event_loop()[0]
network = Network(config)
network.start()


class Notifier(electrum.synchronizer.Notifier):
    def __init__(self, network):
        super().__init__(network)

    async def _on_spk_status(self, spk, status):
        addr = script_to_address(spk)
        print_msg(f"spk {spk}, addr {addr}, status {status}")


notifier = Notifier(network)
asyncio.run_coroutine_threadsafe(notifier.start_watching_addr(addr, url=""), loop)
