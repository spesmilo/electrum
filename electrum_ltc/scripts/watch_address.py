#!/usr/bin/env python3

import sys
import asyncio

from electrum_ltc.network import Network
from electrum_ltc.util import print_msg, create_and_start_event_loop
from electrum_ltc.synchronizer import SynchronizerBase


try:
    addr = sys.argv[1]
except Exception:
    print("usage: watch_address <litecoin_address>")
    sys.exit(1)

# start network
loop = create_and_start_event_loop()[0]
network = Network()
network.start()


class Notifier(SynchronizerBase):
    def __init__(self, network):
        SynchronizerBase.__init__(self, network)
        self.watched_addresses = set()
        self.watch_queue = asyncio.Queue()

    async def main(self):
        # resend existing subscriptions if we were restarted
        for addr in self.watched_addresses:
            await self._add_address(addr)
        # main loop
        while True:
            addr = await self.watch_queue.get()
            self.watched_addresses.add(addr)
            await self._add_address(addr)

    async def _on_address_status(self, addr, status):
        print_msg(f"addr {addr}, status {status}")


notifier = Notifier(network)
asyncio.run_coroutine_threadsafe(notifier.watch_queue.put(addr), loop)
