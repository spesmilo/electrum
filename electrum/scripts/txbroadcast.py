#!/usr/bin/env python3
#
# Connect to lots of servers and broadcast a given tx to each.

import sys
import asyncio

from electrum.network import filter_protocol, Network
from electrum.util import create_and_start_event_loop, log_exceptions
from electrum.simple_config import SimpleConfig


try:
    rawtx = sys.argv[1]
except:
    print("usage: txbroadcast rawtx")
    sys.exit(1)

config = SimpleConfig()

loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network(config)
network.start()

@log_exceptions
async def f():
    try:
        peers = await network.get_peers()
        peers = filter_protocol(peers)
        results = await network.send_multiple_requests(peers, 'blockchain.transaction.broadcast', [rawtx])
        for server, resp in results.items():
            print(f"result: server={server}, response={resp}")
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
