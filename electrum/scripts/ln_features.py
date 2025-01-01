#!/usr/bin/env python3
"""
Script to analyze the graph for Lightning features.

https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
"""

import asyncio
import os
import time

from electrum.logging import get_logger, configure_logging
from electrum.simple_config import SimpleConfig
from electrum import constants, util
from electrum.daemon import Daemon
from electrum.wallet import create_new_wallet
from electrum.util import create_and_start_event_loop, log_exceptions, bfh
from electrum.lnutil import LnFeatures

logger = get_logger(__name__)


# Configuration parameters
IS_TESTNET = False
TIMEOUT = 5  # for Lightning peer connections
WORKERS = 30  # number of workers that concurrently fetch results for feature comparison
NODES_PER_WORKER = 50
VERBOSITY = ''  # for debugging set '*', otherwise ''
FLAG = LnFeatures.OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT  # chose the 'opt' flag
PRESYNC = False  # should we sync the graph or take it from an already synced database?


config = SimpleConfig({"testnet": IS_TESTNET, "verbosity": VERBOSITY})
configure_logging(config)

loop, stopping_fut, loop_thread = create_and_start_event_loop()
# avoid race condition when starting network, in debug starting the asyncio loop
# takes some time
time.sleep(2)

if IS_TESTNET:
    constants.BitcoinTestnet.set_as_network()
daemon = Daemon(config, listen_jsonrpc=False)
network = daemon.network
assert network.asyncio_loop.is_running()

# create empty wallet
wallet_dir = os.path.dirname(config.get_wallet_path())
wallet_path = os.path.join(wallet_dir, "ln_features_wallet_main")
if not os.path.exists(wallet_path):
    create_new_wallet(path=wallet_path, config=config)

# open wallet
wallet = daemon.load_wallet(wallet_path, password=None, upgrade=True)
wallet.start_network(network)


async def worker(work_queue: asyncio.Queue, results_queue: asyncio.Queue, flag):
    """Connects to a Lightning peer and checks whether the announced feature
    from the gossip is equal to the feature in the init message.

    Returns None if no connection could be made, True or False otherwise."""
    count = 0
    while not work_queue.empty():
        if count > NODES_PER_WORKER:
            return
        work = await work_queue.get()

        # only check non-onion addresses
        addr = None
        for a in work['addrs']:
            if "onion" not in a[0]:
                addr = a
        if not addr:
            await results_queue.put(None)
            continue

        # handle ipv4/ipv6
        if ':' in addr[0]:
            connect_str = f"{work['pk'].hex()}@[{addr.host}]:{addr.port}"
        else:
            connect_str = f"{work['pk'].hex()}@{addr.host}:{addr.port}"

        print(f"worker connecting to {connect_str}")
        try:
            peer = await wallet.lnworker.add_peer(connect_str)
            res = await util.wait_for2(peer.initialized, TIMEOUT)
            if res:
                if peer.features & flag == work['features'] & flag:
                    await results_queue.put(True)
                else:
                    await results_queue.put(False)
            else:
                await results_queue.put(None)
        except Exception as e:
            await results_queue.put(None)


@log_exceptions
async def node_flag_stats(opt_flag: LnFeatures, presync: False):
    """Determines statistics for feature advertisements by nodes on the Lighting
    network by evaluation of the public graph.

    opt_flag: The optional-flag for a feature.
    presync: Sync the graph. Can take a long time and depends on the quality
        of the peers. Better to use presynced graph from regular wallet use for
        now.
    """
    try:
        await wallet.lnworker.channel_db.data_loaded.wait()

        # optionally presync graph (not reliable)
        if presync:
            network.start_gossip()

            # wait for the graph to be synchronized
            while True:
                await asyncio.sleep(5)

                # logger.info(wallet.network.lngossip.get_sync_progress_estimate())
                cur, tot, pct = wallet.network.lngossip.get_sync_progress_estimate()
                print(f"graph sync progress {cur}/{tot} ({pct}%) channels")
                if pct >= 100:
                    break

        with wallet.lnworker.channel_db.lock:
            nodes = wallet.lnworker.channel_db._nodes.copy()

        # check how many nodes advertise opt/req flag in the gossip
        n_opt = 0
        n_req = 0
        print(f"analyzing {len(nodes.keys())} nodes")

        # 1. statistics on graph
        req_flag = LnFeatures(opt_flag >> 1)
        for n, nv in nodes.items():
            features = LnFeatures(nv.features)
            if features & opt_flag:
                n_opt += 1
            if features & req_flag:
                n_req += 1

        # analyze numbers
        print(
            f"opt: {n_opt} ({100 * n_opt/len(nodes)}%) "
            f"req: {n_req} ({100 * n_req/len(nodes)}%)")

        # 2. compare announced and actual feature set
        # put nodes into a work queue
        work_queue = asyncio.Queue()
        results_queue = asyncio.Queue()

        # fill up work
        for n, nv in nodes.items():
            addrs = wallet.lnworker.channel_db._addresses[n]
            await work_queue.put({'pk': n, 'addrs': addrs, 'features': nv.features})
        tasks = [asyncio.create_task(worker(work_queue, results_queue, opt_flag)) for i in range(WORKERS)]
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            print(e)
        # analyze results
        n_true = 0
        n_false = 0
        n_tot = 0
        while not results_queue.empty():
            i = results_queue.get_nowait()
            n_tot += 1
            if i is True:
                n_true += 1
            elif i is False:
                n_false += 1
        print(f"feature comparison - equal: {n_true} unequal: {n_false} total:{n_tot}")

    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(
    node_flag_stats(FLAG, presync=PRESYNC), loop)
