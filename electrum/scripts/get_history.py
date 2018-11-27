#!/usr/bin/env python3

import sys
import asyncio

from electrum import bitcoin
from electrum.network import Network
from electrum.util import json_encode, print_msg, create_and_start_event_loop, log_exceptions


try:
    addr = sys.argv[1]
except Exception:
    print("usage: get_history <bitcoin_address>")
    sys.exit(1)

loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network()
network.start()

@log_exceptions
async def f():
    try:
        sh = bitcoin.address_to_scripthash(addr)
        hist = await network.get_history_for_scripthash(sh)
        print_msg(json_encode(hist))
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
