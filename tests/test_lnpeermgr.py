import logging
import os
import socket
import asyncio
import time
from unittest import mock

from . import ElectrumTestCase

from electrum.lnpeer import Peer
from electrum.lntransport import ConnStringFormatError, LNPeerAddr, LNResponderTransport, LNTransport
from electrum.logging import console_stderr_handler


class TestLNPeerManager(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    async def asyncSetUp(self):
        lnwallet = self.create_mock_lnwallet(name='mock_lnwallet_anchors')
        self.lnpeermgr = lnwallet.lnpeermgr
        await super().asyncSetUp()

    async def test_add_peer_conn_string_errors(self):
        unknown_node_id = os.urandom(33)
        peermgr = self.lnpeermgr
        peermgr._add_peer = mock.Mock(side_effect=NotImplementedError)

        # Trampoline enabled, unknown node (no address in trampolines)
        channel_db = peermgr.network.channel_db
        peermgr.network.channel_db = None
        try:
            with self.assertRaises(ConnStringFormatError) as cm:
                await peermgr.add_peer(unknown_node_id.hex())
            self.assertIn("Address unknown for node", str(cm.exception))
        finally:
            peermgr.network.channel_db = channel_db  # re-set channel db

        # Trampoline disabled, unknown node (no address in channel_db)
        with mock.patch.object(peermgr.network.channel_db, 'get_node_addresses', return_value=[]):
            with self.assertRaises(ConnStringFormatError) as cm:
                await peermgr.add_peer(unknown_node_id.hex())
            self.assertIn("Don't know any addresses for node", str(cm.exception))

        # .onion address, but no proxy configured
        onion_conn_str = unknown_node_id.hex() + "@somewhere.onion:9735"
        self.assertFalse(peermgr.network.proxy.enabled)
        with self.assertRaises(ConnStringFormatError) as cm:
            await peermgr.add_peer(onion_conn_str)
        self.assertIn(".onion address, but no proxy configured", str(cm.exception))

        # Hostname does not resolve (getaddrinfo failed)
        bad_host_conn_str = unknown_node_id.hex() + "@badhost:9735"
        loop = asyncio.get_running_loop()
        with mock.patch.object(loop, 'getaddrinfo', side_effect=socket.gaierror):
            with self.assertRaises(ConnStringFormatError) as cm:
                await peermgr.add_peer(bad_host_conn_str)
            self.assertIn("Hostname does not resolve", str(cm.exception))

    def _add_channelless_peer(self, *, incoming: bool, initialization_time: float) -> Peer:
        peermgr = self.lnpeermgr
        pubkey = os.urandom(33)
        if incoming:
            transport = LNResponderTransport(peermgr.node_keypair.privkey, None, None)
            transport._pubkey = pubkey  # normally set during the handshake
        else:
            peer_addr = LNPeerAddr('127.0.0.1', 9735, pubkey)
            transport = LNTransport(peermgr.node_keypair.privkey, peer_addr, e_proxy=None)
        peer = Peer(peermgr._lnwallet_or_lngossip, pubkey, transport)
        peer.initialization_time = initialization_time
        peermgr._peers[pubkey] = peer
        return peer

    async def _run_single_cleanup_iteration(self):
        num_sleeps = 0

        async def limited_sleep(delay):
            nonlocal num_sleeps
            num_sleeps += 1
            if num_sleeps > 1:  # run exactly one iteration of the cleanup loop
                raise asyncio.CancelledError

        with mock.patch.object(asyncio, 'sleep', limited_sleep):
            with self.assertRaises(asyncio.CancelledError):
                await self.lnpeermgr._cleanup_unused_peers()

    async def test_cleanup_unused_peers_evicts_per_direction(self):
        """Incoming connection pressure must not cause eviction of outgoing connections,
        as we opened those for a purpose (e.g. an onion message session)."""
        peermgr = self.lnpeermgr
        now = time.monotonic()
        outgoing = [self._add_channelless_peer(incoming=False, initialization_time=now - 7200) for _ in range(2)]
        incoming = [self._add_channelless_peer(incoming=True, initialization_time=now - 3600 - i)
                    for i in range(peermgr.MAX_CHANNELLESS_PEERS_PER_DIRECTION + 3)]
        num_excess_incoming = len(incoming) - peermgr.MAX_CHANNELLESS_PEERS_PER_DIRECTION
        await self._run_single_cleanup_iteration()
        for peer in outgoing:  # outgoing peers survive even though they are the oldest
            self.assertIn(peer.pubkey, peermgr.peers)
        self.assertEqual(peermgr.MAX_CHANNELLESS_PEERS_PER_DIRECTION + len(outgoing), len(peermgr.peers))
        # the incoming excess got evicted from the incoming peers, oldest first
        evicted = [peer for peer in incoming if peer.pubkey not in peermgr.peers]
        oldest_incoming = sorted(incoming, key=lambda p: p.initialization_time)[:num_excess_incoming]
        self.assertEqual({p.pubkey for p in oldest_incoming}, {p.pubkey for p in evicted})

    async def test_cleanup_unused_peers_keeps_young_outgoing_peers(self):
        """Outgoing connections younger than the minimum lifetime are not evicted, even above the cap."""
        peermgr = self.lnpeermgr
        now = time.monotonic()
        old = [self._add_channelless_peer(incoming=False, initialization_time=now - 3600) for _ in range(2)]
        young = [self._add_channelless_peer(incoming=False, initialization_time=now - 5)
                 for _ in range(peermgr.MAX_CHANNELLESS_PEERS_PER_DIRECTION + 2)]
        await self._run_single_cleanup_iteration()
        self.assertEqual(len(young), len(peermgr.peers))
        for peer in old:
            self.assertNotIn(peer.pubkey, peermgr.peers)
        for peer in young:
            self.assertIn(peer.pubkey, peermgr.peers)

    def test_choose_preferred_address(self):
        peermgr = self.lnpeermgr

        # prefer most recent IP address
        addr_list = [
            ("192.168.1.1", 9735, 100),
            ("host.onion", 9735, 200),
            ("10.0.0.1", 9735, 150),
            ("host.com", 9735, 250)
        ]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertEqual(result, ("10.0.0.1", 9735, 150))  # Most recent IP

        # no IP, proxy disabled, filter .onion and choose random
        self.assertFalse(peermgr.network.is_proxy_tor)
        addr_list = [("host.com", 9735, 100), ("host.onion", 9735, 200)]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertEqual(result, ("host.com", 9735, 100))

        # empty list after filtering
        addr_list = [("host.onion", 9735, 100)]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertIsNone(result)

        # return onion if proxy enabled
        peermgr.network.is_proxy_tor = True
        addr_list = [("host.onion", 9735, 100)]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertEqual(result, ("host.onion", 9735, 100))
