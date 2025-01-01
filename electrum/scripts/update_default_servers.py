#!/usr/bin/env python3
# This script prints a new "servers.json" to stdout.
# It prunes the offline servers from the existing list (note: run with Tor proxy to keep .onions),
# and adds new servers from provided file(s) of candidate servers.
# A file of new candidate servers can be created via e.g.:
# $ ./electrum/scripts/servers.py > reply.txt

import asyncio
import sys
import json

from electrum.network import Network
from electrum.util import create_and_start_event_loop, log_exceptions
from electrum.simple_config import SimpleConfig
from electrum import constants

try:
    fname1 = sys.argv[1]
    fname2 = sys.argv[2] if len(sys.argv) > 2 else None
except Exception:
    print("usage: update_default_servers.py <file1> [<file2>]")
    print("       - the file(s) should contain json hostmaps for new servers to be added")
    print("       - if two files are provided, their intersection is used (peers found in both).\n"
          "         file1 should have the newer data.")
    sys.exit(1)


def get_newly_added_servers(fname1, fname2=None):
    with open(fname1) as f:
        res_hostmap = json.loads(f.read())
    if fname2 is not None:
        with open(fname2) as f:
            dict2 = json.loads(f.read())
        common_set = set.intersection(set(res_hostmap), set(dict2))
        res_hostmap = {k: v for k, v in res_hostmap.items() if k in common_set}
    return res_hostmap


# testnet?
#constants.BitcoinTestnet.set_as_network()
config = SimpleConfig({'testnet': False})

loop, stopping_fut, loop_thread = create_and_start_event_loop()
network = Network(config)
network.start()

@log_exceptions
async def f():
    try:
        # prune existing servers
        old_servers_all = constants.net.DEFAULT_SERVERS
        old_servers_online = await network.prune_offline_servers(constants.net.DEFAULT_SERVERS)
        # add new servers
        newly_added_servers = get_newly_added_servers(fname1, fname2)
        res_servers = {**old_servers_online, **newly_added_servers}

        print(json.dumps(res_servers, indent=4, sort_keys=True))
        print(f"got reply from {len(old_servers_online)}/{len(old_servers_all)} old servers", file=sys.stderr)
        print(f"len(newly_added_servers)={len(newly_added_servers)}. total: {len(res_servers)}", file=sys.stderr)
    finally:
        stopping_fut.set_result(1)

asyncio.run_coroutine_threadsafe(f(), loop)
