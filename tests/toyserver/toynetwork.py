# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio

from electrum import blockchain, util
from electrum.blockchain import Blockchain
from electrum.fee_policy import FeeTimeEstimates, FEE_ETA_TARGETS
from electrum.interface import Interface, ServerAddr
from electrum.simple_config import SimpleConfig
from electrum.transaction import Transaction
from electrum.util import OldTaskGroup
from electrum.wallet import Abstract_Wallet

from .toyserver import ToyServer


class MockDaemon:

    def get_wallets(self) -> dict[str, Abstract_Wallet]:
        return {}


class ToyNetwork:
    """Client-side stand-in for Network, driving a single Interface against a ToyServer.

    Unlike the other MockNetworks in the test suite (tests/lnhelpers.py,
    tests/test_txbatcher.py), this one has a real chain behind it: the local height,
    the wallet history and the mempool all come from the server.
    """

    def __init__(self, *, config: SimpleConfig):
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.taskgroup = OldTaskGroup()
        self.bc_mgr = blockchain.BlockchainManager.from_config(self.config)
        self.proxy = None
        self.debug = True
        self.bhi_lock = asyncio.Lock()
        self.interface = None  # type: Interface | None

        self.relay_fee = None  # type: int | None  # sat/kbyte, set from the server on connect
        self.fee_estimates = FeeTimeEstimates()
        for target in FEE_ETA_TARGETS[:-1]:
            self.fee_estimates.set_data(target, 50_000 // target)

        self.daemon = MockDaemon()
        self.channel_db = None
        self.path_finder = None
        self.lngossip = None
        self.is_proxy_tor = False

    async def connect(self, server: ToyServer, *, client_name: str | None = None) -> Interface:
        """connect to server, and wait until we have synced its headers"""
        assert self.interface is None, "already connected"
        interface = Interface(network=self, server=ServerAddr(host="127.0.0.1", port=server.server_port, protocol="t"))
        if client_name is not None:  # so that the server can identify this session
            interface.client_name = lambda: client_name
        self.interface = interface
        async with util.async_timeout(5):
            await interface.ready
            await interface._blockchain_updated.wait()
            self.relay_fee = await interface.get_relay_fee()
        return interface

    async def stop(self) -> None:
        if self.interface:
            await self.interface.close()

    async def connection_down(self, interface: Interface):
        pass
    def get_network_timeout_seconds(self, request_type) -> int:
        return 10
    def check_interface_against_healthy_spread_of_connected_servers(self, iface_to_check: Interface) -> bool:
        return True
    def update_fee_estimates(self, *, fee_est: dict[int, int] = None):
        pass
    async def switch_unwanted_fork_interface(self):
        pass
    async def switch_lagging_interface(self):
        pass
    def start_gossip(self):
        pass
    def blockchain(self) -> Blockchain:
        return self.interface.blockchain
    def get_local_height(self) -> int:
        return self.blockchain().height()
    def is_connected(self) -> bool:
        return True

    # the wallet and the txbatcher broadcast through the network:

    async def broadcast_transaction(self, tx: Transaction) -> None:
        await self.interface.broadcast_transaction(tx)

    async def try_broadcasting(self, tx: Transaction, name: str) -> bool:
        try:
            await self.broadcast_transaction(tx)
        except Exception:
            return False
        return True
