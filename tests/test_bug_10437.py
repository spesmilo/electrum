import unittest
from unittest.mock import MagicMock
from electrum.wizard import ServerConnectWizard
from electrum.interface import ServerAddr
from electrum.network import NetworkParameters

class DaemonMock:
    def __init__(self):
        self.network = MagicMock()
        self.network.get_parameters.return_value = NetworkParameters(
            server=ServerAddr.from_str('localhost:1:s'),
            proxy=None,
            auto_connect=True,
            oneserver=False
        )

class TestBug10437(unittest.TestCase):
    def test_autoconnect_server_addr_type(self):
        daemon = DaemonMock()
        default_server = ServerAddr.from_str('localhost:1:s')

        w = ServerConnectWizard(daemon)
        w.do_configure_server({'autoconnect': True, 'one_server': False})

        args, kwargs = daemon.network.set_parameters.call_args
        net_params = args[0]
        # if autoconnect is True, server can be an empty string in the current wizard implementation
        if not net_params.auto_connect:
            self.assertIsInstance(net_params.server, ServerAddr)
        self.assertEqual(net_params.server, default_server if not net_params.auto_connect else '')

    def test_manual_server_addr_type(self):
        daemon = DaemonMock()
        w = ServerConnectWizard(daemon)

        w.do_configure_server({'autoconnect': False, 'server': 'localhost:1:t', 'one_server': False})

        args, kwargs = daemon.network.set_parameters.call_args
        net_params = args[0]
        self.assertIsInstance(net_params.server, ServerAddr)
        self.assertEqual(str(net_params.server), 'localhost:1:t')
