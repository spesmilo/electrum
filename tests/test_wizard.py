import os

from electrum import SimpleConfig
from electrum.interface import ServerAddr
from electrum.keystore import bip44_derivation, Hardware_KeyStore, KeyStore, BIP32_KeyStore
from electrum.network import NetworkParameters, ProxySettings
from electrum.plugin import Plugins, DeviceInfo, Device
from electrum.wizard import ServerConnectWizard, NewWalletWizard, WizardViewState, KeystoreWizard
from electrum.daemon import Daemon
from electrum.wallet import Abstract_Wallet, Deterministic_Wallet
from electrum import util
from electrum import slip39
from electrum.bip32 import KeyOriginInfo
from electrum import keystore
from electrum.storage import WalletStorage

from . import ElectrumTestCase
from .test_wallet_vertical import UNICODE_HORROR, WalletIntegrityHelper


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
        self.assertFalse(self.config.cv.NETWORK_AUTO_CONNECT.is_set())

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
        self.assertFalse(self.config.cv.NETWORK_AUTO_CONNECT.is_set())
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


class KeystoreWizardTestCase(WizardTestCase):

    class TKeystoreWizard(KeystoreWizard):
        def is_single_password(self):
            """impl abstract reqd"""
            return True

    class TNewWalletWizard(NewWalletWizard):
        def is_single_password(self):
            """impl abstract reqd"""
            return True

    def _wizard_for(self, *, wallet_type: str = 'standard', hww: bool = False) -> tuple[KeystoreWizard, WizardViewState]:
        w = KeystoreWizardTestCase.TKeystoreWizard(self.plugins)
        start_viewstate = WizardViewState('keystore_type', {'wallet_type': wallet_type}, {})
        v = w.start(start_viewstate=start_viewstate)
        self.assertEqual('keystore_type', v.view)
        d = v.wizard_data
        if hww:
            d.update({'keystore_type': 'hardware'})
            v = w.resolve_next(v.view, d)
            self.assertEqual('choose_hardware_device', v.view)
        else:
            d.update({'keystore_type': 'haveseed'})
            v = w.resolve_next(v.view, d)
            self.assertEqual('enter_seed', v.view)

        return w, v

    def _create_xpub_keystore_wallet(self, *, wallet_type: str = 'standard', xpub):
        w = KeystoreWizardTestCase.TNewWalletWizard(DaemonMock(self.config), self.plugins)
        wallet_path = self.wallet_path
        d = {
            'wallet_type': wallet_type,
            'keystore_type': 'masterkey',
            'master_key': xpub,
            'password': None,
            'encrypt': False,
        }
        w.create_storage(wallet_path, d)
        self.assertTrue(os.path.exists(wallet_path))
        wallet = Daemon._load_wallet(wallet_path, password=None, config=self.config)
        return wallet

    def _sanity_checks_after_disabling_keystore(
        self,
        *,
        ks: 'KeyStore',
        xpub: str,
        key_origin_info: KeyOriginInfo,
    ) -> None:
        self.assertTrue(ks.is_watching_only())
        self.assertTrue(ks.type in ('bip32', 'old'))
        self.assertFalse(ks.has_seed())
        self.assertEqual(ks.get_master_public_key(), xpub)
        if isinstance(ks, BIP32_KeyStore):
            self.assertEqual(ks.xprv, None)
        self.assertEqual(ks.get_key_origin_info(), key_origin_info)

    async def test_haveseed_electrum(self):
        w, v = self._wizard_for()
        d = v.wizard_data
        myseed = '9dk'
        mypassphrase = ''
        myxpub = 'zpub6nAZodjgiMNf9zzX1pTqd6ZVX61ax8azhUDnWRumKVUr1VYATVoqAuqv3qKsb8WJXjxei4wei2p4vnMG9RnpKnen2kmgdhvZUmug2NnHNsr'
        d.update({
            'seed': myseed, 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum',
        })
        self.assertTrue(w.is_last_view(v.view, d))
        w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)
        self.assertEqual(ks.xpub, myxpub)

        wallet = self._create_xpub_keystore_wallet(xpub=myxpub)
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystore().is_watching_only())
        self.assertEqual(myseed, wallet.get_keystore().get_seed(None))
        self.assertEqual(mypassphrase, wallet.get_keystore().get_passphrase(None))

        my_keyorigininfo = wallet.get_keystore().get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystore())
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystore(), xpub=myxpub, key_origin_info=my_keyorigininfo)

    async def test_haveseed_ext_electrum(self):
        w, v = self._wizard_for()
        d = v.wizard_data
        myseed = '9dk'
        mypassphrase = 'abc'
        myxpub = 'zpub6oLFCUpqxT8BUzy8g5miUuRofPZ46ZjjvZfcfH7qJanRM7aRYGpNX4uBGtcJRbgcKbi7dYkiiPw1GB2sc3SufyDcZskuQEWp5jBwbNcj1VL'
        d.update({
            'seed': myseed, 'seed_type': 'segwit', 'seed_extend': True, 'seed_variant': 'electrum',
        })
        self.assertFalse(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)
        self.assertEqual('enter_ext', v.view)
        d.update({'seed_extra_words': mypassphrase})
        self.assertTrue(w.is_last_view(v.view, d))
        w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)
        self.assertEqual(ks.xpub, myxpub)

        wallet = self._create_xpub_keystore_wallet(xpub=myxpub)
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystore().is_watching_only())
        self.assertEqual(myseed, wallet.get_keystore().get_seed(None))
        self.assertEqual(mypassphrase, wallet.get_keystore().get_passphrase(None))

        my_keyorigininfo = wallet.get_keystore().get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystore())
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystore(), xpub=myxpub, key_origin_info=my_keyorigininfo)

    async def test_haveseed_electrum__mismatching_seed(self):
        """adding an unrelated seed to an xpub-only keystore should raise"""
        w, v = self._wizard_for()
        d = v.wizard_data
        d.update({
            'seed': 'abandon bike', 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum',
        })
        self.assertTrue(w.is_last_view(v.view, d))
        w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)

        wallet = self._create_xpub_keystore_wallet(xpub='zpub6nAZodjgiMNf9zzX1pTqd6ZVX61ax8azhUDnWRumKVUr1VYATVoqAuqv3qKsb8WJXjxei4wei2p4vnMG9RnpKnen2kmgdhvZUmug2NnHNsr')
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        with self.assertRaises(Exception) as ctx:
            wallet.enable_keystore(ks, ishww, None)
        self.assertTrue("mismatching xpubs" in ctx.exception.args[0])

    async def test_haveseed_electrum_oldseed(self):
        w, v = self._wizard_for()
        d = v.wizard_data
        myseed = 'powerful random nobody notice nothing important anyway look away hidden message over'
        mypassphrase = ''
        myxpub = 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3'
        d.update({
            'seed': myseed,
            'seed_type': 'old', 'seed_extend': False, 'seed_variant': 'electrum',
        })
        self.assertTrue(w.is_last_view(v.view, d))
        w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)
        self.assertEqual(ks.get_master_public_key(), myxpub)

        wallet = self._create_xpub_keystore_wallet(xpub=myxpub)
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystore().is_watching_only())
        self.assertEqual(myseed, wallet.get_keystore().get_seed(None))
        self.assertEqual(mypassphrase, wallet.get_keystore().get_passphrase(None))

        my_keyorigininfo = wallet.get_keystore().get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystore())
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystore(), xpub=myxpub, key_origin_info=my_keyorigininfo)

    async def test_haveseed_bip39(self):
        w, v = self._wizard_for()
        d = v.wizard_data
        myxpub = 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs'
        d.update({
            'seed': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
            'seed_type': 'bip39', 'seed_extend': False, 'seed_variant': 'bip39',
        })
        self.assertFalse(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)
        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h'})
        v = w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)
        self.assertEqual(ks.xpub, myxpub)

        wallet = self._create_xpub_keystore_wallet(xpub=myxpub)
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystore().is_watching_only())

        my_keyorigininfo = wallet.get_keystore().get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystore())
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystore(), xpub=myxpub, key_origin_info=my_keyorigininfo)

    async def test_haveseed_ext_bip39(self):
        w, v = self._wizard_for()
        d = v.wizard_data
        myxpub = 'zpub6qaQ1V7UyjNRXR5u8QzTi1ibaWQkskUsfpi7na4oqwkXrZWzVqqohSKG8g2sL5m8CJju2E8GFRkZBxKKq5iEqS167CLLDK2jNz4vpNAea7X'
        d.update({
            'seed': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
            'seed_type': 'bip39', 'seed_extend': True, 'seed_variant': 'bip39',
        })
        self.assertFalse(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)
        self.assertEqual('enter_ext', v.view)
        d.update({'seed_extra_words': 'abc'})
        v = w.resolve_next(v.view, d)

        self.assertEqual('script_and_derivation', v.view)
        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h'})
        v = w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)
        self.assertEqual(ks.xpub, myxpub)

        wallet = self._create_xpub_keystore_wallet(xpub=myxpub)
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystore().is_watching_only())

        my_keyorigininfo = wallet.get_keystore().get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystore())
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystore(), xpub=myxpub, key_origin_info=my_keyorigininfo)

    async def test_hww(self):
        w, v = self._wizard_for(hww=True)
        d = v.wizard_data
        myxpub = 'zpub6rakEaM5ps5UiQ2yhbWiEkd6ceJfmuzegwc62G4itMz8L7rRFRqh6y8bTCScXV6NfTMUhANYQnfqfBd9dYfBRKf4LD1Yyfc8UvwY1MtNKWs'
        d.update({
            'hardware_device': (
                'trezor',
                DeviceInfo(
                    device=Device(path='webusb:002:1', interface_number=-1, id_='webusb:002:1', product_key='Trezor', usage_page=0, transport_ui_string='webusb:002:1'),
                    label='trezor_unittests', initialized=True, exception=None, plugin_name='trezor', soft_device_id='088C3F260B66F60E15DE0FA5', model_name='Trezor T'))})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_start', v.view)
        d.update({
            'script_type': 'p2wpkh',
            'derivation_path': bip44_derivation(0, bip43_purpose=84)
        })
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_xpub', v.view)
        d.update({
            'hw_type': 'trezor',
            'master_key': myxpub,
            'root_fingerprint': 'b3569ff0',
            'label': 'trezor_unittests',
            'soft_device_id': '088C3F260B66F60E15DE0FA5',
        })
        self.assertTrue(w.is_last_view(v.view, d))
        v = w.resolve_next(v.view, d)

        ks, ishww = w._result
        self.assertTrue(ishww)

        wallet = self._create_xpub_keystore_wallet(xpub=myxpub)
        self.assertTrue(wallet.get_keystore().is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystore().is_watching_only())
        self.assertTrue(isinstance(wallet.get_keystore(), Hardware_KeyStore))

        my_keyorigininfo = wallet.get_keystore().get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystore())
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystore(), xpub=myxpub, key_origin_info=my_keyorigininfo)

    async def test_multisig(self):
        seed1 = "bitter grass shiver impose acquire brush forget axis eager alone wine silver"
        xpub1 = "Zpub6ymNkfdyhypEoqQNNGAUz9gXeiWJsW8AWx8Aa6PnDdeL76UC9b1UPGmEvwWzzkVVghVQuDBry7CK7wCBBdysRQgFFmdDSqi5kWoZ3A4cBuA"
        seed2 = "snow nest raise royal more walk demise rotate smooth spirit canyon gun"
        xpub2 = "Zpub6xwgqLvc42wXB1wEELTdALD9iXwStMUkGqBgxkJFYumaL2dWgNvUkjEDWyDFZD3fZuDWDzd1KQJ4NwVHS7hs6H6QkpNYSShfNiUZsgMdtNg"

        wallet = WalletIntegrityHelper.create_multisig_wallet(
            [
                keystore.from_seed(seed1, passphrase='', for_multisig=True),
                keystore.from_xpub(xpub2),
            ],
            '2of2',
            config=self.config,
            storage=WalletStorage(self.wallet_path),
        )

        w, v = self._wizard_for(wallet_type=wallet.wallet_type)
        d = v.wizard_data
        d.update({
            'seed': seed2, 'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum',
        })
        self.assertTrue(w.is_last_view(v.view, d))
        w.resolve_next(v.view, d)
        ks, ishww = w._result
        self.assertFalse(ishww)
        self.assertEqual(ks.xpub, xpub2)

        self.assertFalse(wallet.get_keystores()[0].is_watching_only())
        self.assertTrue(wallet.get_keystores()[1].is_watching_only())
        self.assertTrue(wallet.can_enable_disable_keystore(ks))
        wallet.enable_keystore(ks, ishww, None)
        self.assertFalse(wallet.get_keystores()[0].is_watching_only())
        self.assertFalse(wallet.get_keystores()[1].is_watching_only())
        self.assertEqual(seed1, wallet.get_keystores()[0].get_seed(None))
        self.assertEqual(seed2, wallet.get_keystores()[1].get_seed(None))

        keyorigininfo1 = wallet.get_keystores()[0].get_key_origin_info()
        wallet.disable_keystore(wallet.get_keystores()[0])
        self._sanity_checks_after_disabling_keystore(ks=wallet.get_keystores()[0], xpub=xpub1, key_origin_info=keyorigininfo1)


class WalletWizardTestCase(WizardTestCase):

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
        recv_addr: str | None,  # "first addr" only makes sense for HD wallets
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
        if recv_addr is not None:
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
        wallet = self._set_password_and_check_address(v=v, w=w, recv_addr="1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo")

        self.assertIsInstance(wallet, Deterministic_Wallet)
        self.assertEqual(wallet.get_seed(password=None), 'powerful random nobody notice nothing important anyway look away hidden message over')

    async def test_create_standard_wallet_haveseed_electrum_oldseed_in_hex_format(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({
            'seed': 'acb740e454c3134901d7c8f16497cc1c',
            'seed_type': 'old', 'seed_extend': False, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)
        wallet = self._set_password_and_check_address(v=v, w=w, recv_addr="1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo")

        self.assertIsInstance(wallet, Deterministic_Wallet)
        self.assertEqual(wallet.get_seed(password=None), 'powerful random nobody notice nothing important anyway look away hidden message over')

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

    async def test_create_standard_wallet_have_master_key(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'masterkey'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_master_key', v.view)

        d.update({
            'master_key': 'zpub6nAZodjgiMNf9zzX1pTqd6ZVX61ax8azhUDnWRumKVUr1VYATVoqAuqv3qKsb8WJXjxei4wei2p4vnMG9RnpKnen2kmgdhvZUmug2NnHNsr',
            'multisig_master_pubkey': 'zpub6nAZodjgiMNf9zzX1pTqd6ZVX61ax8azhUDnWRumKVUr1VYATVoqAuqv3qKsb8WJXjxei4wei2p4vnMG9RnpKnen2kmgdhvZUmug2NnHNsr'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0")

    async def test_create_standard_wallet_haveseed_bip39(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
                  'seed_type': 'bip39', 'seed_extend': False, 'seed_variant': 'bip39'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

    async def test_create_standard_wallet_haveseed_bip39_passphrase(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({'seed': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
                  'seed_type': 'bip39', 'seed_extend': True, 'seed_variant': 'bip39'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_ext', v.view)

        d.update({'seed_extra_words': UNICODE_HORROR})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qjc3dsy5wxaksae6zqmr3nwjsmuckwqca8flql3")

    async def test_create_standard_wallet_haveseed_slip39(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        # SLIP39 shares (128 bits, 2 groups from 1 of 1, 1 of 1, 3 of 5, 2 of 6)
        mnemonics = [
            "fact else acrobat romp analysis usher havoc vitamins analysis garden prevent romantic silent dramatic adjust priority mailman plains vintage else",
            "fact else ceramic round craft lips snake faint adorn square bucket deadline violence guitar greatest academic stadium snake frequent memory",
            "fact else ceramic scatter counter remove club forbid busy cause taxi forecast prayer uncover living type training forward software pumps",
            "fact else ceramic shaft clock crowd detect cleanup wildlife depict include trip profile isolate express category wealthy advance garden mixture",
        ]
        encrypted_seed = slip39.recover_ems(mnemonics)

        d.update({'seed': encrypted_seed, 'seed_variant': 'slip39', 'seed_type': 'slip39', 'seed_extend': False})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({
            'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h',
            'multisig_master_pubkey': 'zpub6riQosasrLdM1rmmohyUHtseLYeCBKP55Xe1LTT7jyKFM6dMMZPYVx5ug6zH2gZ6XFGcUYubjbm43vXHecTzNmoMS3yfp6oeZT3GetsGFt4'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1q40ksvkl7wvc2l999ppl48swgt3rsl45ykyyrjn")

    async def test_create_standard_wallet_haveseed_slip39_passphrase(self):
        w = self._wizard_for(wallet_type='standard')
        v = w._current
        d = v.wizard_data
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        # SLIP39 shares (128 bits, 2 groups from 1 of 1, 1 of 1, 3 of 5, 2 of 6)
        mnemonics = [
            "fact else acrobat romp analysis usher havoc vitamins analysis garden prevent romantic silent dramatic adjust priority mailman plains vintage else",
            "fact else ceramic round craft lips snake faint adorn square bucket deadline violence guitar greatest academic stadium snake frequent memory",
            "fact else ceramic scatter counter remove club forbid busy cause taxi forecast prayer uncover living type training forward software pumps",
            "fact else ceramic shaft clock crowd detect cleanup wildlife depict include trip profile isolate express category wealthy advance garden mixture",
        ]
        encrypted_seed = slip39.recover_ems(mnemonics)

        d.update({'seed': encrypted_seed, 'seed_variant': 'slip39', 'seed_type': 'slip39', 'seed_extend': True})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_ext', v.view)

        d.update({'seed_extra_words': 'TREZOR'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('script_and_derivation', v.view)

        d.update({
            'script_type': 'p2wpkh', 'derivation_path': 'm/84h/0h/0h',
            'multisig_master_pubkey': 'zpub6s6A9ynh7TT1sPXmQyu8S6g7kxMF6iSZkM3NmgF4w7CtpsGgg56aouYSWHgAoMy186a8FRT8zkmhcwV5SWKFFQfMpvV8C9Ft4woWSzD5sXz'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qs2svwhfz47qv9qju2waa6prxzv5f522fc4p06t")

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
        wallet = self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qnf5qafvpx0afk47433j3tt30pqkxp5wa263m77wt0pvyqq67rmfs522m94")

        with self.subTest(msg="2fa wallet cannot enable/disable keystore"):
            for ks in wallet.get_keystores():
                self.assertFalse(wallet.can_enable_disable_keystore(ks))
                with self.assertRaises(Exception) as ctx:
                    wallet.enable_keystore(ks, False, None)
                self.assertTrue("2fa wallet cannot" in ctx.exception.args[0])
                with self.assertRaises(Exception) as ctx:
                    wallet.enable_keystore(ks, False, None)
                self.assertTrue("2fa wallet cannot" in ctx.exception.args[0])

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

    async def test_create_multisig_wallet_2of2_createseed_cosigner2hasmasterkey(self):
        w = self._wizard_for(wallet_type='multisig')
        v = w._current
        d = v.wizard_data
        self.assertEqual('multisig', v.view)

        d.update({'multisig_participants': 2, 'multisig_signatures': 2, 'multisig_cosigner_data': {}})
        v = w.resolve_next(v.view, d)
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'createseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('create_seed', v.view)

        d.update({
            'seed': 'eager divert pigeon dentist punch festival manage smart globe regular adult cash',
            'seed_type': 'segwit', 'seed_extend': False, 'seed_variant': 'electrum'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('confirm_seed', v.view)

        d.update({'multisig_master_pubkey': 'Zpub6y7YR1dmZZV4f5rRm6dJCKSqqxZhKUxc8PkssXm84k2bzbGYkL22ugC4aZxVxC1qz4yo53Zwz1c1kiSHmybB4JjCsjCPjzygSsN1UcdCcvB'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_keystore', v.view)

        # 2nd cosigner uses Zpub from "9dk" seed
        d['multisig_cosigner_data']['2'] = {'keystore_type': 'masterkey'}
        d.update({
            'multisig_current_cosigner': 2, 'cosigner_keystore_type': 'masterkey'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_key', v.view)

        d['multisig_cosigner_data']['2'].update({'master_key': 'Zpub6y4evsU8HJw2d7ZH8QNyC6UKWHyxinAuQKkD6btsEZMbamy96UnefnM4sZp2K38rdiUssEhNq9TBpJ8Bh1GZCGTFpnYz8jM9pAdS6vk5VQs'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qg39tkymxwq4tn2ly6c3lmnyvsy94jyw52rdvfqkzdv2slvlj9xcsfy63vc")

    async def test_create_multisig_wallet_3of6_haveseed_passphrase__cs2hasbip39__cs3zpub__cs4trezor__cs5seedandpassphrase__cs6zprv(self):
        w = self._wizard_for(wallet_type='multisig')
        v = w._current
        d = v.wizard_data
        self.assertEqual('multisig', v.view)

        d.update({'multisig_participants': 6, 'multisig_signatures': 3, 'multisig_cosigner_data': {}})
        v = w.resolve_next(v.view, d)
        self.assertEqual('keystore_type', v.view)

        d.update({'keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_seed', v.view)

        d.update({
            'seed': '9dk',
            'seed_variant': 'electrum', 'seed_type': 'segwit', 'seed_extend': True})
        v = w.resolve_next(v.view, d)
        self.assertEqual('have_ext', v.view)

        d.update({
            'seed_extra_words': UNICODE_HORROR,
            'multisig_master_pubkey': 'Zpub6zAYrXzLbLwWFCkahiB3fQz4KMUm68RsoGVHkM5aBjzHBGnQ9orvy7PKuFvMj4gyJXhFW5uFzHBgDDYFEPS75b3ADq3yvtuEJF86ZgLLyeL'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_keystore', v.view)

        # 2nd cosigner
        d['multisig_cosigner_data']['2'] = {'keystore_type': 'haveseed'}
        d.update({
            'multisig_current_cosigner': 2, 'cosigner_keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_seed', v.view)

        d['multisig_cosigner_data']['2'].update({
            'seed': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
            'seed_variant': 'bip39', 'seed_type': 'bip39', 'seed_extend': False})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_script_and_derivation', v.view)

        d['multisig_cosigner_data']['2'].update({
            'script_type': 'p2wsh', 'derivation_path': 'm/48h/0h/0h/2h'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_keystore', v.view)

        # 3rd cosigner uses Zpub from "9dk" seed
        d['multisig_cosigner_data']['3'] = {'keystore_type': 'masterkey'}
        d.update({
            'multisig_current_cosigner': 3, 'cosigner_keystore_type': 'masterkey'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_key', v.view)

        d['multisig_cosigner_data']['3'].update({
            'master_key': 'Zpub6y4evsU8HJw2d7ZH8QNyC6UKWHyxinAuQKkD6btsEZMbamy96UnefnM4sZp2K38rdiUssEhNq9TBpJ8Bh1GZCGTFpnYz8jM9pAdS6vk5VQs'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_keystore', v.view)

        # 4th cosigner
        d['multisig_cosigner_data']['4'] = {'keystore_type': 'hardware'}
        d.update({
            'multisig_current_cosigner': 4, 'cosigner_keystore_type': 'hardware'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_hardware', v.view)

        d['multisig_cosigner_data']['4'].update({
            'hardware_device': (
                'trezor',
                DeviceInfo(
                    device=Device(path='webusb:002:1', interface_number=-1, id_='webusb:002:1', product_key='Trezor', usage_page=0, transport_ui_string='webusb:002:1'),
                    label='trezor_unittests', initialized=True, exception=None, plugin_name='trezor', soft_device_id='088C3F260B66F60E15DE0FA5', model_name='Trezor T'))})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_start', v.view)

        d['multisig_cosigner_data']['4'].update({
            'script_type': 'p2wsh', 'derivation_path': 'm/48h/0h/0h/2h'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('trezor_xpub', v.view)

        d['multisig_cosigner_data']['4'].update({
            'hw_type': 'trezor', 'master_key': 'Zpub75t8XsK4GVa2EyQtjvT9auayKwonGaQJ149qB9r11o5iikugxJ99hYgbcaTdCGjd4DUdz4z2bqAtmDv2s8UihG1AnbzBufSG82GxjMDfVUn',
            'root_fingerprint': '6306ee35', 'label': 'trezor_unittests', 'soft_device_id': '088C3F260B66F60E15DE0FA5'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_keystore', v.view)

        # 5th cosigner
        d['multisig_cosigner_data']['5'] = {'keystore_type': 'haveseed'}
        d.update({
            'multisig_current_cosigner': 5, 'cosigner_keystore_type': 'haveseed'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_seed', v.view)

        d['multisig_cosigner_data']['5'].update({
            'seed': 'abandon bike',
            'seed_variant': 'electrum', 'seed_type': 'segwit', 'seed_extend': True})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_have_ext', v.view)

        d['multisig_cosigner_data']['5'].update({
            'seed_extra_words': UNICODE_HORROR})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_keystore', v.view)

        # 6th cosigner uses Zprv from "abandon bike" seed
        d['multisig_cosigner_data']['6'] = {'keystore_type': 'masterkey'}
        d.update({
            'multisig_current_cosigner': 6, 'cosigner_keystore_type': 'masterkey'})
        v = w.resolve_next(v.view, d)
        self.assertEqual('multisig_cosigner_key', v.view)

        d['multisig_cosigner_data']['6'].update({
            'master_key': 'ZprvAjWENdvYc1Ctvppxm4Z67U4EoiDy5VXKNvWmVAZshy7UjgKggu1UcAH7MqRqTaHVunuEPZ7o51wCrsZnJXPJtzHnAoxNmMLWFMHC7uvUN5P'})
        v = w.resolve_next(v.view, d)
        self._set_password_and_check_address(v=v, w=w, recv_addr="bc1qtuzp7rectyjquax5c3p80eletswhp6cxslye749l47h4m9x92hzs6cmymy")

    async def test_create_imported_wallet_from_addresses(self):
        w = self._wizard_for(wallet_type='imported')
        v = w._current
        d = v.wizard_data
        self.assertEqual('imported', v.view)

        d.update({
            'address_list':
                '14gcRovpkCoGkCNBivQBvw7eso7eiNAbxG\n'
                '35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUCQMJbT\n'
                'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4\n'
                'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y\n'})
        v = w.resolve_next(v.view, d)
        wallet = self._set_password_and_check_address(v=v, w=w, recv_addr=None)
        self.assertEqual(
            set(wallet.get_receiving_addresses()),
            {
                "14gcRovpkCoGkCNBivQBvw7eso7eiNAbxG",
                "35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUCQMJbT",
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",  # TODO normalize to lowercase?
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            },
        )

    async def test_create_imported_wallet_from_addresses__invalid_input(self):
        w = self._wizard_for(wallet_type='imported')
        v = w._current
        d = v.wizard_data
        self.assertEqual('imported', v.view)

        d.update({
            'address_list':
                'garbagegarbage\n'
                '35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUCQMJbT\n'
        })
        v = w.resolve_next(v.view, d)
        with self.assertRaises(AssertionError) as ctx:
            wallet = self._set_password_and_check_address(v=v, w=w, recv_addr=None)
        self.assertTrue("expected bitcoin addr" in ctx.exception.args[0])

    async def test_create_imported_wallet_from_wif_keys(self):
        w = self._wizard_for(wallet_type='imported')
        v = w._current
        d = v.wizard_data
        self.assertEqual('imported', v.view)

        d.update({
            'private_key_list':
                'p2wpkh:L1cgMEnShp73r9iCukoPE3MogLeueNYRD9JVsfT1zVHyPBR3KqBY\n'
                'p2pkh:KyQ2voUQj71P6E9KyDFqQoYMMm3yKKAPMKbfqZccib6xWxbWHCex\n'
                'p2pkh:5JuecQZ1nH4VCQRQJTQjB4yu93BU6NmnAkDoGRdHX2PyH2E8QVX\n'})
        v = w.resolve_next(v.view, d)
        wallet = self._set_password_and_check_address(v=v, w=w, recv_addr=None)
        self.assertEqual(
            set(wallet.get_receiving_addresses()),
            {"bc1qq2tmmcngng78nllq2pvrkchcdukemtj56uyue0", "1LNvv5h6QHoYv1nJcqrp13T2TBkD2sUGn1", "1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo"},
        )
        self.assertFalse(wallet.can_enable_disable_keystore(wallet.keystore))
