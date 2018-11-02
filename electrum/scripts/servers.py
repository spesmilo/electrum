#!/usr/bin/env python3
import json
import asyncio

from electrum.network import filter_version, Network
from electrum.util import create_and_start_event_loop, log_exceptions
from electrum import constants

import util


#constants.set_testnet()

loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network()
network.start()

@log_exceptions
async def f():
    try:
        peers = await util.get_peers(network)
        peers = filter_version(peers)
        print(json.dumps(peers, sort_keys=True, indent=4))
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
