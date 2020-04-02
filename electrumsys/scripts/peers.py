#!/usr/bin/env python3
import asyncio

from electrumsys.network import filter_protocol, Network
from electrumsys.util import create_and_start_event_loop, log_exceptions
from electrumsys.blockchain import hash_raw_header
from electrumsys.simple_config import SimpleConfig


config = SimpleConfig()

loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network(config)
network.start()

@log_exceptions
async def f():
    try:
        peers = await network.get_peers()
        peers = filter_protocol(peers, 's')
        results = await network.send_multiple_requests(peers, 'blockchain.headers.subscribe', [])
        for server, header in sorted(results.items(), key=lambda x: x[1].get('height')):
            height = header.get('height')
            blockhash = hash_raw_header(header.get('hex'))
            print(server, height, blockhash)
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
