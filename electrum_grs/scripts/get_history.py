#!/usr/bin/env python3

import sys
import asyncio

from electrum_grs import bitcoin
from electrum_grs.network import Network
from electrum_grs.util import json_encode, print_msg, create_and_start_event_loop, log_exceptions
from electrum_grs.simple_config import SimpleConfig


try:
    addr = sys.argv[1]
except Exception:
    print("usage: get_history <groestlcoin_address>")
    sys.exit(1)

config = SimpleConfig()

loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network(config)
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
