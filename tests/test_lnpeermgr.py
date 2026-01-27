import logging
import os
import socket
import asyncio
from unittest import mock

from . import ElectrumTestCase

from electrum.lntransport import ConnStringFormatError
from electrum.logging import console_stderr_handler


class TestLNPeerManager(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    async def asyncSetUp(self):
        lnwallet = self.create_mock_lnwallet(name='mock_lnwallet_anchors', has_anchors=True)
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
        self.assertFalse(peermgr.network.proxy.enabled)
        addr_list = [("host.com", 9735, 100), ("host.onion", 9735, 200)]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertEqual(result, ("host.com", 9735, 100))

        # empty list after filtering
        addr_list = [("host.onion", 9735, 100)]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertIsNone(result)

        # return onion if proxy enabled
        peermgr.network.proxy.enabled = True
        addr_list = [("host.onion", 9735, 100)]
        result = peermgr.choose_preferred_address(addr_list)
        self.assertEqual(result, ("host.onion", 9735, 100))
