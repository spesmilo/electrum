#!/usr/bin/env python3
import json
import asyncio
from statistics import median
from numbers import Number

from electrum.network import filter_protocol, Network
from electrum.util import create_and_start_event_loop, log_exceptions


loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network()
network.start()

@log_exceptions
async def f():
    try:
        peers = await network.get_peers()
        peers = filter_protocol(peers)
        results = await network.send_multiple_requests(peers, 'blockchain.estimatefee', [2])
        print(json.dumps(results, indent=4))
        feerate_estimates = filter(lambda x: isinstance(x, Number), results.values())
        print(f"median feerate: {median(feerate_estimates)}")
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
