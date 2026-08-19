import os
import sys

from unittest import mock

from electrum import util
from electrum import plugin as plugin_module
from electrum.crypto import sha256
from electrum.plugin import Plugins, IncorrectPluginHash
from electrum.zip_importer import MemoryZipImporter
from electrum.simple_config import SimpleConfig

from electrum_ecc import ECPrivkey

from . import ElectrumTestCase
from .test_zip_importer import PLUGIN_NAME, make_plugin_zip


class PluginLoaderTestCase(ElectrumTestCase):
    """Tests that an authorized plugin is loaded from the bytes whose signature
    was verified, and not from whatever happens to be on disk at import time."""

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.privkey = ECPrivkey(sha256(b'plugin zip unit test key'))
        self.plugins_dir = os.path.join(self.electrum_path, 'plugins')
        util.make_dir(self.plugins_dir)
        self.zip_path = os.path.join(self.plugins_dir, f'{PLUGIN_NAME}.zip')
        self._patcher = mock.patch.object(
            Plugins, 'get_pubkey_bytes',
            lambda _self: (self.privkey.get_public_key_bytes(), bytes(32)))
        self._patcher.start()
        self.plugins = None

    def tearDown(self):
        self._patcher.stop()
        self._stop_plugins()
        super().tearDown()

    def _stop_plugins(self) -> None:
        if self.plugins is not None:
            self.plugins.stop()
            self.plugins.stopped_event.wait()
            self.plugins = None
        # the import system is global state; undo what the test did to it
        for modname in [m for m in sys.modules if m.startswith('electrum_external_plugins')]:
            del sys.modules[modname]
        for finder in [f for f in sys.meta_path if isinstance(f, MemoryZipImporter)]:
            sys.meta_path.remove(finder)
        plugin_module._zip_importers.clear()

    def _start_plugins(self) -> Plugins:
        self.plugins = Plugins(self.config, gui_name='cmdline')
        return self.plugins

    def _authorize(self, plugins: Plugins) -> None:
        plugins.authorize_plugin(PLUGIN_NAME, self.privkey)

    def _replace_zip_on_disk(self, secret: str = 'evil') -> None:
        evil = os.path.join(self.electrum_path, 'evil.zip')
        make_plugin_zip(evil, secret=secret)
        os.replace(evil, self.zip_path)

    # --- the regression this guards against ---

    def test_import_raises_after_file_replaced(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        self.assertTrue(plugins.is_authorized(PLUGIN_NAME))
        self._replace_zip_on_disk('evil')
        with self.assertRaises(IncorrectPluginHash):
            plugin = plugins.load_plugin_by_name(PLUGIN_NAME)

    def test_read_file_raises_after_file_replaced(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        self._replace_zip_on_disk('evil')
        with self.assertRaises(IncorrectPluginHash):
            plugins.read_file(PLUGIN_NAME, 'icon.txt')

    def test_tampered_plugin_is_not_authorized(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        # replace on disk
        self._replace_zip_on_disk('evil')
        self.assertTrue(plugins.is_authorized(PLUGIN_NAME))
        # as if electrum had been restarted
        plugins.stop()
        plugins = self._start_plugins()
        self.assertFalse(plugins.is_authorized(PLUGIN_NAME))
        self.assertIsNone(plugins.load_plugin_by_name(PLUGIN_NAME))

    def test_unsigned_plugin_is_not_authorized(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self.assertFalse(plugins.is_authorized(PLUGIN_NAME))
        self.assertIsNone(plugins.load_plugin_by_name(PLUGIN_NAME))

    def test_manifest_hash_describes_the_bytes_it_was_read_from(self):
        blob = make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        manifest = plugins.read_manifest(self.zip_path)
        self.assertEqual(sha256(blob).hex(), manifest['zip_hash_sha256'])
