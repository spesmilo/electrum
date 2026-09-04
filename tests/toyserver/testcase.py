# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import os
from dataclasses import dataclass, field
from typing import Callable, Optional
from unittest import mock

from electrum import util
from electrum.interface import PaddedRSTransport
from electrum.simple_config import SimpleConfig
from electrum.transaction import Transaction, TxOutput, TxOutpoint
from electrum.util import wait_for2
from electrum.wallet import Abstract_Wallet

from .. import ElectrumTestCase, restore_wallet_from_text__for_unittest
from .toynetwork import ToyNetwork
from .toyserver import ToyServer


SEED = "9dk"


@dataclass
class ToyInstance:
    """Electrum instance with its own config, network and wallets"""
    name: str
    config: SimpleConfig
    network: ToyNetwork
    wallets: list[Abstract_Wallet] = field(default_factory=list)


class ToyServerTestCase(ElectrumTestCase):
    """
    Base class for tests that need a chain: a ToyServer, one or more ToyInstances connected to it,
    and wallets that sync from it.
    """
    REGTEST = True
    TIME_STEP = 0.01

    def setUp(self):
        super().setUp()
        self._orig_wait_for_buffer_growth = PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS
        PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS *= self.TIME_STEP

    def tearDown(self):
        PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS = self._orig_wait_for_buffer_growth
        super().tearDown()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.instances = {}  # type: dict[str, ToyInstance]
        self.server = ToyServer()
        await self.server.start()
        await self.server.set_up_faucet(config=self.create_config("faucet"))

    async def asyncTearDown(self):
        for wallet in self.wallets:
            await self.stop_wallet(wallet)
        for instance in self.instances.values():
            await instance.network.stop()
        await self.server.stop()
        await super().asyncTearDown()

    @property
    def wallets(self) -> list[Abstract_Wallet]:
        """the wallets of all instances. the chain helpers below wait on all of them."""
        return [wallet for instance in self.instances.values() for wallet in instance.wallets]

    # --- setup helpers ---

    def create_config(self, name: Optional[str] = None) -> SimpleConfig:
        """A config with its own data dir. Subclasses can override this to set custom config vars."""
        path = os.path.join(self.unittest_base_path, name) if name else self.electrum_path
        util.make_dir(path)
        config = SimpleConfig({'electrum_path': path})
        config.NETWORK_SKIPMERKLECHECK = True
        config.FEE_POLICY = 'feerate:5000'
        return config

    async def create_instance(self, name: str) -> ToyInstance:
        """An instance is similar to a separate Electrum process, they own independent configs and wallets, they share the server"""
        assert name not in self.instances, f"instance {name!r} already exists"
        config = self.create_config(name)
        network = ToyNetwork(config=config)
        instance = ToyInstance(name=name, config=config, network=network)
        self.instances[name] = instance
        await network.connect(self.server, client_name=name)
        return instance

    def create_wallet(self, name: str, *, instance: ToyInstance, text: str = SEED, **kwargs) -> Abstract_Wallet:
        """Add an in-memory wallet to given instance and put it online. Calling it twice with the same name returns
        the same wallet but without the previous wallets data (simulating data loss)."""
        with mock.patch.object(Abstract_Wallet, 'basename', lambda w: name):  # mock basename so name is shown in logs
            wallet = restore_wallet_from_text__for_unittest(
                text,
                passphrase=name,
                path=None,
                config=instance.config,
                **kwargs,
            )['wallet']  # type: Abstract_Wallet
            wallet.start_network(instance.network)
        wallet.basename = lambda: name  # for objects created later on, e.g. peers
        wallet.txbatcher.SLEEP_INTERVAL *= self.TIME_STEP
        instance.wallets.append(wallet)
        return wallet

    async def stop_wallet(self, wallet: Abstract_Wallet) -> None:
        owners = [instance for instance in self.instances.values() if wallet in instance.wallets]
        assert len(owners) == 1, f"wallet {wallet.basename()} is owned by {len(owners)} instances"
        owners[0].wallets.remove(wallet)
        await wallet.stop()

    # --- chain and wallet helpers ---

    async def wait_until(self, predicate: Callable[[], bool], *, timeout: int = 20) -> None:
        async with util.async_timeout(timeout):
            while not predicate():
                await asyncio.sleep(self.TIME_STEP)

    async def sync(self) -> None:
        """wait until all wallets have caught up with the server"""
        def is_synced() -> bool:
            return all(
                wallet.adb.get_local_height() == self.server.cur_height
                and wallet.adb.is_up_to_date()
                and wallet.is_up_to_date()
                for wallet in self.wallets
            )
        while True:
            await self.wait_until(is_synced)
            # the adb_set_up_to_date callback might unsync a wallet again when syncing new addresses
            new_addresses = sum(wallet.synchronize() for wallet in self.wallets)
            if new_addresses == 0:
                return

    async def mine_blocks(self, count: int, *, include_mempool: bool = True) -> None:
        for _ in range(count):
            await self.server.mine_block(include_mempool=include_mempool)
        await self.sync()

    async def wait_for_tx(self, tx: Transaction) -> Transaction:
        """wait until the wallets tx concerns have it, and are up to date"""
        await self.wait_until(lambda: any(w.adb.get_transaction(tx.txid()) is not None for w in self.wallets))
        await self.sync()
        return tx

    async def broadcast(self, tx: Transaction) -> Transaction:
        """put tx into the server mempool, as if one of the instances had broadcast it"""
        await self.server.mempool_add_tx(tx)
        return await self.wait_for_tx(tx)

    async def pay_to_address(self, address: str, value: int) -> Transaction:
        """a third party (the faucet) sends coins to address, leaving the tx in the mempool"""
        tx = await self.server.ask_faucet([TxOutput.from_address_and_value(address, value)])
        return await self.wait_for_tx(tx)

    def spender_of(self, prevout: TxOutpoint) -> Optional[str]:
        """txid of the tx spending prevout, as seen by the server"""
        return self.server.txo_to_spender_txid[prevout]

    async def wait_for_spender_of(self, prevout: TxOutpoint) -> Transaction:
        """wait for a tx spending prevout to be broadcast, e.g. by the txbatcher"""
        await self.wait_until(lambda: self.spender_of(prevout) is not None)
        return Transaction(self.server.txs[self.spender_of(prevout)])

    async def spender_of_within(self, prevout: TxOutpoint, *, timeout: float = 2) -> Optional[Transaction]:
        """like wait_for_spender_of, but returns None if we did not broadcast anything"""
        try:
            return await wait_for2(self.wait_for_spender_of(prevout), timeout)
        except asyncio.TimeoutError:
            return None

    async def reorg_replace_tip_tx(self, tx: Transaction, replacement: Transaction) -> None:
        """The block at the tip is reorged out and mined again at the same height, but now
        it contains replacement, which conflicts with tx. tx is evicted along the way.
        """
        self.assertEqual(self.server.cur_height, self.server.block_height_from_txid(tx.txid()))
        await self.server.unmine_block()
        await self.server.mempool_rm_tx(tx)
        await self.server.mempool_add_tx(replacement)
        await self.server.mine_block()
        await self.wait_until(lambda: any(w.adb.get_tx_height(replacement.txid()).conf > 0 for w in self.wallets))
        await self.sync()
