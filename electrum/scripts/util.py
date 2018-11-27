import asyncio
from typing import List, Sequence

from aiorpcx import TaskGroup

from electrum.network import parse_servers, Network
from electrum.interface import Interface


#electrum.util.set_verbosity(True)

async def get_peers(network: Network):
    while not network.is_connected():
        await asyncio.sleep(1)
        print("waiting for network to get connected...")
    interface = network.interface
    session = interface.session
    print(f"asking server {interface.server} for its peers")
    peers = parse_servers(await session.send_request('server.peers.subscribe'))
    print(f"got {len(peers)} servers")
    return peers


async def send_request(network: Network, servers: List[str], method: str, params: Sequence):
    print(f"contacting {len(servers)} servers")
    num_connecting = len(network.connecting)
    for server in servers:
        network._start_interface(server)
    # sleep a bit
    for _ in range(10):
        if len(network.connecting) < num_connecting:
            break
        await asyncio.sleep(1)
    print(f"connected to {len(network.interfaces)} servers. sending request to all.")
    responses = dict()
    async def get_response(iface: Interface):
        try:
            res = await iface.session.send_request(method, params, timeout=10)
        except Exception as e:
            print(f"server {iface.server} errored or timed out: ({repr(e)})")
            res = e
        responses[iface.server] = res
    async with TaskGroup() as group:
        for interface in network.interfaces.values():
            await group.spawn(get_response(interface))
    print("%d answers" % len(responses))
    return responses
