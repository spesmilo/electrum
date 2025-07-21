import os

from electrum import SimpleConfig
from electrum.interface import ServerAddr
from electrum.network import NetworkParameters, ProxySettings
from electrum.plugin import Plugins, DeviceInfo, Device
from electrum.wizard import ServerConnectWizard, NewWalletWizard, WizardViewState
from electrum.daemon import Daemon
from electrum.wallet import Abstract_Wallet
from electrum import util

from . import ElectrumTestCase
from .test_wallet_vertical import UNICODE_HORROR


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
    def __init__(self, config: SimpleConfig):
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
        self.plugins.load_plugin_by_name('trustedcoin')
        # note: hw plugins are loaded on-demand

    def tearDown(self):
        self.plugins.stop()
        self.plugins.stopped_event.wait()
        super().tearDown()


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
        self.assertEqual(NetworkParameters(server=None, proxy=ProxySettings.from_dict(d_proxy), auto_connect=True, oneserver=None), w._daemon.network.parameters)

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
        self.assertEqual(NetworkParameters(server=serverobj, proxy=None, auto_connect=False, oneserver=False), w._daemon.network.parameters)

# TODO KeystoreWizard ("enable keystore")

class WalletWizardTestCase(WizardTestCase):

    # TODO imported addresses
    # TODO imported WIF keys
    # TODO multisig
    # TODO slip39

    def _wizard_for(
        self,
        *,
        name: str = "mywallet",
        wallet_type: str,
    ) -> NewWalletWizard:
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

    def _set_password_and_check_address(
        self,
        *,
        v: WizardViewState,
        w: NewWalletWizard,
        recv_addr: str,
        password: str | None = None,
        encrypt_file: bool = False,
    ) -> Abstract_Wallet:
        d = v.wizard_data
        self.assertEqual('wallet_password', v.view)

        d.update({'password': password, 'encrypt': encrypt_file})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        wallet_path = os.path.join(w._daemon.config.get_datadir_wallet_path(), d['wallet_name'])
        w.create_storage(wallet_path, d)

        self.assertTrue(os.path.exists(wallet_path))
        wallet = Daemon._load_wallet(wallet_path, password=password, config=self.config)
        self.assertEqual(recv_addr, wallet.get_receiving_addresses()[0])
        self.assertEqual(bool(password), wallet.has_password())
        self.assertEqual(encrypt_file, wallet.has_storage_encryption())
        return wallet

    async def test_set_password_and_encrypt_file(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)
        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)
        d.update({'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)

        wallet = self._set_password_and_check_address(
            v=v, w=w, recv_addr="bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0",
            password="1234", encrypt_file=True,
        )
        self.assertTrue(wallet.has_password())
        with self.assertRaises(util.InvalidPassword):
            wallet.check_password("0000")
        wallet.check_password("1234")
        self.assertTrue(wallet.has_keystore_encryption())
        self.assertTrue(wallet.has_storage_encryption())

    async def test_set_password_but_dont_encrypt_file(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)
        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)
        d.update({'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)

        wallet = self._set_password_and_check_address(
            v=v, w=w, recv_addr="bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0",
            password="1234", encrypt_file=False,
        )
        self.assertTrue(wallet.has_password())
        with self.assertRaises(util.InvalidPassword):
            wallet.check_password("0000")
        wallet.check_password("1234")
        self.assertTrue(wallet.has_keystore_encryption())
        self.assertFalse(wallet.has_storage_encryption())

    async def test_create_standard_wallet_createseed(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'createseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('create_seed', v.view)

        d.update({
            'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum',
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('confirm_seed', v.view)

        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0")

    async def test_create_standard_wallet_createseed_passphrase(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'createseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('create_seed', v.view)

        d.update({
            'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': True, 'seed_variant': 'electrum',
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('create_ext', v.view)

        d.update({'seed_extra_words': UNICODE_HORROR})
        v = w.resolve_next(v.view, d)
        self.assertEqual('confirm_seed', v.view)

        v = w.resolve_next(v.view, d)
        self.assertEqual('confirm_ext', v.view)

        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qgvx24uzdv4mapfmtlu8azty5fxdcw9ghxu4pr4")

    async def test_create_standard_wallet_haveseed_electrum_oldseed(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({
            'seed': 'powerful random nobody notice nothing important anyway look away hidden message over',
            'seed_type': 'old', 'seed_extend': False, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo")

    async def test_create_standard_wallet_haveseed_electrum_oldseed_passphrase(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({
            'seed': 'powerful random nobody notice nothing important anyway look away hidden message over',
            'seed_type': 'old', 'seed_extend': True, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)
        # FIXME this diverges from the actual GUIs :(
        #  the GUIs do validation using wizard.validate_seed() and don't go to 'have_ext' for next view.
        #  the validation should be moved to the base impl!
        self.assertEqual('have_ext', v.view)

        d.update({'seed_extra_words': UNICODE_HORROR})
        with self.assertRaises(Exception) as ctx:
            v = w.resolve_next(v.view, d)
        self.assertTrue("cannot have passphrase" in ctx.exception.args[0])

    async def test_create_standard_wallet_haveseed_electrum(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0")

    async def test_create_standard_wallet_haveseed_electrum_passphrase(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'segwit', 'seed_extend': True, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_ext', v.view)

        d.update({'seed_extra_words': UNICODE_HORROR})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qgvx24uzdv4mapfmtlu8azty5fxdcw9ghxu4pr4")

    async def test_create_standard_wallet_haveseed_bip39(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'bip39', 'seed_extend': False, 'seed_variant': 'bip39'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qrjr8qn4669jgr3s34f2pyj9awhz02eyvk5eh8g")

    async def test_create_standard_wallet_haveseed_bip39_passphrase(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': '9dk', 'seed_type': 'bip39', 'seed_extend': True, 'seed_variant': 'bip39'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_ext', v.view)

        d.update({'seed_extra_words': UNICODE_HORROR})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qjexrunguxz8rlfuul8h4apafyh3sq5yp9kg98j")

    async def test_2fa_createseed(self):
        self.assertTrue(self.config.get('enable_plugin_trustedcoin'))
        w = self._wizard_for(wallet_type='2fa')
        v = w._current
        d = v.wizard_data
        self.assertEqual('trustedcoin_start', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_choose_seed', v.view)
        d.update({'keystore_type': 'createseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_create_seed', v.view)
        d.update({
            'seed': 'oblige basket safe educate whale bacon celery demand novel slice various awkward',
            'seed_type': '2fa', 'seed_extend': False, 'seed_variant': 'electrum',
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_confirm_seed', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_tos', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_show_confirm_otp', v.view)
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qnf5qafvpx0afk47433j3tt30pqkxp5wa263m77wt0pvyqq67rmfs522m94")

    async def test_2fa_haveseed_keep2FAenabled(self):
        self.assertTrue(self.config.get('enable_plugin_trustedcoin'))
        w = self._wizard_for(wallet_type='2fa')
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
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_keep_disable', v.view)
        d.update({'trustedcoin_keepordisable': 'keep'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_tos', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_show_confirm_otp', v.view)
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qnf5qafvpx0afk47433j3tt30pqkxp5wa263m77wt0pvyqq67rmfs522m94")

    async def test_2fa_haveseed_disable2FA(self):
        self.assertTrue(self.config.get('enable_plugin_trustedcoin'))
        w = self._wizard_for(wallet_type='2fa')
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
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_keep_disable', v.view)
        d.update({'trustedcoin_keepordisable': 'disable'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qnf5qafvpx0afk47433j3tt30pqkxp5wa263m77wt0pvyqq67rmfs522m94")

    async def test_2fa_haveseed_passphrase(self):
        self.assertTrue(self.config.get('enable_plugin_trustedcoin'))
        w = self._wizard_for(wallet_type='2fa')
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
            'seed_type': '2fa', 'seed_extend': True, 'seed_variant': 'electrum',
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_have_ext', v.view)
        d.update({'seed_extra_words': UNICODE_HORROR})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_keep_disable', v.view)
        d.update({'trustedcoin_keepordisable': 'keep'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_tos', v.view)
        v = w.resolve_next(v.view, d)
        self.assertEqual('trustedcoin_show_confirm_otp', v.view)
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qcnu9ay4v3w0tawuxe6wlh6mh33rrpauqnufdgkxx7we8vpx3e6wqa25qud")

    async def test_create_standard_wallet_trezor(self):
        # bip39 seed for trezor: "history six okay anchor sheriff flock atom tomorrow foster aerobic eternal foam"
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'hardware'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('choose_hardware_device', v.view)

        d.update({
            'hardware_device': (
                'trezor',
                DeviceInfo(
                    device=Device(path='webusb:002:1', interface_number=-1, id_='webusb:002:1', product_key='Trezor', usage_page=0, transport_ui_string='webusb:002:1'),
                    label='trezor_unittests', initialized=True, exception=None, plugin_name='trezor', soft_device_id='088C3F260B66F60E15DE0FA5', model_name='Trezor T'))})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_start', v.view)

        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_xpub', v.view)

        d.update({
            'hw_type': 'trezor', 'master_key': 'zpub6qqp9XwsVMsovwzayXhFDJTpoc8VFoNy6mjkJHygou9NPRPDNR7MXVp9DM7qpacWwoePFWg7Gt5L5xnKNLmZYH8AFoTm2AAZA7LasycHu3n',
            'root_fingerprint': '6306ee35', 'label': 'trezor_unittests', 'soft_device_id': '088C3F260B66F60E15DE0FA5',
            'multisig_master_pubkey': 'zpub6qqp9XwsVMsovwzayXhFDJTpoc8VFoNy6mjkJHygou9NPRPDNR7MXVp9DM7qpacWwoePFWg7Gt5L5xnKNLmZYH8AFoTm2AAZA7LasycHu3n'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('wallet_password_hardware', v.view)

        d.update({'password': '03a580deb85ef85654ed177fc049867ce915a8b392a34a524123870925e48a5b9e', 'encrypt': True, 'xpub_encrypt': True})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        wallet_path = os.path.join(w._daemon.config.get_datadir_wallet_path(), d['wallet_name'])
        w.create_storage(wallet_path, d)

        self.assertTrue(os.path.exists(wallet_path))
        wallet = Daemon._load_wallet(wallet_path, password=d['password'], config=self.config)
        self.assertEqual("bc1q7ltf4aq95rj695fu5aaa5mx5m9p55xyr2fy6y0", wallet.get_receiving_addresses()[0])
        self.assertTrue(wallet.has_password())
        self.assertTrue(wallet.has_storage_encryption())

    async def test_unlock_hw_trezor(self):
        # bip39 seed for trezor: "history six okay anchor sheriff flock atom tomorrow foster aerobic eternal foam"
        w = NewWalletWizard(DaemonMock(self.config), self.plugins)
        v = w.start()
        self.assertEqual('wallet_name', v.view)
        d = {
            'wallet_name': 'mywallet',
            'wallet_exists': True, 'wallet_is_open': False, 'wallet_needs_hw_unlock': True,}
        self.assertFalse(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)
        self.assertEqual('hw_unlock', v.view)

        d.update({
            'hardware_device': (
                'trezor',
                DeviceInfo(
                    device=Device(path='webusb:002:1', interface_number=-1, id_='webusb:002:1', product_key='Trezor', usage_page=0, transport_ui_string='webusb:002:1'),
                    label='trezor_unittests', initialized=True, exception=None, plugin_name='trezor', soft_device_id='088C3F260B66F60E15DE0FA5', model_name='Trezor T'))})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_unlock', v.view)

        d.update({'password': '03a580deb85ef85654ed177fc049867ce915a8b392a34a524123870925e48a5b9e'})
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)
