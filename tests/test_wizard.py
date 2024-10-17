import os

from electrum import SimpleConfig
from electrum.interface import ServerAddr
from electrum.network import NetworkParameters
from electrum.plugin import Plugins
from electrum.wizard import ServerConnectWizard, NewWalletWizard
from tests import ElectrumTestCase


class NetworkMock:
    def __init__(self):
        self.reset()

    def reset(self):
        self.run_called = False
        self.parameters = NetworkParameters(server=None, proxy=None, auto_connect=None, oneserver=None)

    def run_from_another_thread(self, *args, **kwargs):
        self.run_called = True

    def set_parameters(self, parameters):
        self.parameters = parameters

    def get_parameters(self):
        return self.parameters


class DaemonMock:
    def __init__(self, config):
        self.config = config
        self.network = NetworkMock()


class WizardTestCase(ElectrumTestCase):

    def setUp(self):
        super().setUp()

        self.config = SimpleConfig({
            'electrum_path': self.electrum_path,
            'enable_plugin_trustedcoin': True,
        })
        self.wallet_path = os.path.join(self.electrum_path, "somewallet")
        self.plugins = Plugins(self.config, gui_name='cmdline')
        self.plugins.load_internal_plugin('trustedcoin')

    def tearDown(self):
        super().tearDown()
        self.plugins.stop()
        self.plugins.stopped_event.wait()


class ServerConnectWizardTestCase(WizardTestCase):

    async def test_no_advanced(self):
        w = ServerConnectWizard(DaemonMock(self.config))
        v_init = w.start()

        d = {'autoconnect': True, 'want_proxy': False}
        self.assertTrue(w.is_last_view(v_init.view, d))
        w.resolve_next(v_init.view, d)
        self.assertEqual(True, self.config.NETWORK_AUTO_CONNECT)

    async def test_server(self):
        w = ServerConnectWizard(DaemonMock(self.config))
        v_init = w.start()

        d = {'autoconnect': False, 'want_proxy': False}
        self.assertFalse(w.is_last_view(v_init.view, d))
        v = w.resolve_next(v_init.view, d)
        self.assertEqual('server_config', v.view)
        self.assertEqual(False, self.config.NETWORK_AUTO_CONNECT)

    async def test_proxy(self):
        w = ServerConnectWizard(DaemonMock(self.config))
        v_init = w.start()
        w._daemon.network.reset()

        d = {'autoconnect': True, 'want_proxy': True}
        self.assertFalse(w.is_last_view(v_init.view, d))
        v = w.resolve_next(v_init.view, d)
        self.assertEqual('proxy_config', v.view)
        self.assertEqual(True, self.config.NETWORK_AUTO_CONNECT)
        d_proxy = {'enabled': True, 'mode': 'socks5', 'host': 'localhost', 'port': '1'}
        d.update({'proxy': d_proxy})
        v = w.resolve_next(v.view, d)
        self.assertTrue(w.is_last_view(v.view, d))

        self.assertTrue(w._daemon.network.run_called)
        self.assertEqual(NetworkParameters(server=None, proxy=d_proxy, auto_connect=True, oneserver=None), w._daemon.network.parameters)

    async def test_proxy_and_server(self):
        w = ServerConnectWizard(DaemonMock(self.config))
        v_init = w.start()
        w._daemon.network.reset()

        d = {'autoconnect': False, 'want_proxy': True}
        self.assertFalse(w.is_last_view(v_init.view, d))
        v = w.resolve_next(v_init.view, d)
        self.assertEqual('proxy_config', v.view)
        self.assertEqual(False, self.config.NETWORK_AUTO_CONNECT)
        d_proxy = {'enabled': False}
        d.update({'proxy': d_proxy})
        v = w.resolve_next(v.view, d)

        w._daemon.network.reset()
        self.assertEqual('server_config', v.view)
        d.update({'server': 'localhost:1:t'})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        serverobj = ServerAddr.from_str_with_inference('localhost:1:t')
        self.assertTrue(w._daemon.network.run_called)
        self.assertEqual(NetworkParameters(server=serverobj, proxy=None, auto_connect=False, oneserver=None), w._daemon.network.parameters)


class WalletWizardTestCase(WizardTestCase):

    def wizard_for(self, *, name, wallet_type):
        w = NewWalletWizard(DaemonMock(self.config), self.plugins)
        if wallet_type == '2fa':
            w.plugins.get_plugin('trustedcoin').extend_wizard(w)
        v_init = w.start()
        self.assertEqual('wallet_name', v_init.view)
        d = {'wallet_name': name}
        self.assertFalse(w.is_last_view(v_init.view, d))
        v = w.resolve_next(v_init.view, d)
        self.assertEqual('wallet_type', v.view)

        d.update({'wallet_type': wallet_type})
        w.resolve_next(v.view, d)

        return w

    async def test_create_standard_wallet_newseed(self):
        w = self.wizard_for(name='test_standard_wallet', wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'createseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('create_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum',
                  'seed_extra_words': False})
        v = w.resolve_next(v.view, d)
        self.assertEqual('confirm_seed', v.view)

        v = w.resolve_next(v.view, d)
        self.assertEqual('wallet_password', v.view)

        d.update({'password': None, 'encrypt': False})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        wallet_path = os.path.join(w._daemon.config.get_datadir_wallet_path(), d['wallet_name'])
        w.create_storage(wallet_path, d)

        self.assertTrue(os.path.exists(wallet_path))

    async def test_create_standard_wallet_haveseed_electrum(self):
        w = self.wizard_for(name='test_standard_wallet', wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum',
                  'seed_extra_words': False})
        v = w.resolve_next(v.view, d)
        self.assertEqual('wallet_password', v.view)

        d.update({'password': None, 'encrypt': False})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        wallet_path = os.path.join(w._daemon.config.get_datadir_wallet_path(), d['wallet_name'])
        w.create_storage(wallet_path, d)

        self.assertTrue(os.path.exists(wallet_path))

    async def test_create_standard_wallet_haveseed_bip39(self):
        w = self.wizard_for(name='test_standard_wallet', wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'bip39', 'seed_extend': False, 'seed_variant': 'bip39',
                  'seed_extra_words': False})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({'script_type': 'p2wsh', 'derivation_path': 'm'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('wallet_password', v.view)

        d.update({'password': None, 'encrypt': False})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        wallet_path = os.path.join(w._daemon.config.get_datadir_wallet_path(), d['wallet_name'])
        w.create_storage(wallet_path, d)

        self.assertTrue(os.path.exists(wallet_path))

    async def test_2fa(self):
        self.assertTrue(self.config.get('enable_plugin_trustedcoin'))
        w = self.wizard_for(name='test_2fa_wallet', wallet_type='2fa')
        v = w._current
        d = v.wizard_data
        self.assertEqual('trustedcoin_start', v.view)

        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_choose_seed', v.view)
        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_have_seed', v.view)
        d.update({
            'seed': 'oblige basket safe educate whale bacon celery demand novel slice various awkward',
            'seed_type': '2fa', 'seed_extend': False, 'seed_variant': 'electrum',
            'seed_extra_words': False
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_keep_disable', v.view)
        d.update({'trustedcoin_keepordisable': 'keep'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_tos', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_show_confirm_otp', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('wallet_password', v.view)

        d.update({'password': None, 'encrypt': False})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        wallet_path = os.path.join(w._daemon.config.get_datadir_wallet_path(), d['wallet_name'])
        w.create_storage(wallet_path, d)

        self.assertTrue(os.path.exists(wallet_path))
