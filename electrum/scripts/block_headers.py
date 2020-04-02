#!/usr/bin/env python3

# A simple script that connects to a server and displays block headers

import time
import asyncio

from electrumsys.network import Network
from electrumsys.util import print_msg, json_encode, create_and_start_event_loop, log_exceptions
from electrumsys.simple_config import SimpleConfig

config = SimpleConfig()

# start network
loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network(config)
network.start()

# wait until connected
while not network.is_connected():
    time.sleep(1)
    print_msg("waiting for network to get connected...")

header_queue = asyncio.Queue()

@log_exceptions
async def f():
    try:
        await network.interface.session.subscribe('blockchain.headers.subscribe', [], header_queue)
        # 3. wait for results
        while network.is_connected():
            header = await header_queue.get()
            print_msg(json_encode(header))
    finally:
        stopping_fut.set_result(1)

# 2. send the subscription
asyncio.run_coroutine_threadsafe(f(), loop)
