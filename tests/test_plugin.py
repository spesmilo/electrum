import importlib
import importlib.util
import json
import os
import sys
import zipfile

from unittest import mock

from electrum import util
from electrum.crypto import sha256
from electrum.plugin import Plugins
from electrum.zip_importer import MemoryZipImporter
from electrum.simple_config import SimpleConfig

from electrum_ecc import ECPrivkey

from . import ElectrumTestCase


PLUGIN_NAME = 'toctou_test'


def make_plugin_zip(path: str, *, secret: str = 'benign', name: str = PLUGIN_NAME) -> bytes:
    """Writes a minimal, loadable cmdline plugin to `path`, and returns its bytes."""
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr(f'{name}/manifest.json', json.dumps({
            'name': name,
            'fullname': 'TOCTOU test plugin',
            'description': 'test fixture',
            'available_for': ['cmdline'],
        }))
        z.writestr(f'{name}/__init__.py', f'SECRET = {secret!r}\n')
        z.writestr(f'{name}/cmdline.py', '\n'.join([
            'from electrum.plugin import BasePlugin',
            f'SECRET = {secret!r}',
            'class Plugin(BasePlugin):',
            '    pass',
            '',
        ]))
        z.writestr(f'{name}/icon.txt', secret)
        z.writestr(f'{name}/sub/__init__.py', '')
        z.writestr(f'{name}/sub/deep.py', f'DEEP = {secret!r}\n')
    with open(path, 'rb') as f:
        return f.read()


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
        if self.plugins is not None:
            self.plugins.stop()
            self.plugins.stopped_event.wait()
        # the import system is global state; undo what the test did to it
        for modname in [m for m in sys.modules if m.startswith('electrum_external_plugins')]:
            del sys.modules[modname]
        for finder in [f for f in sys.meta_path if isinstance(f, MemoryZipImporter)]:
            sys.meta_path.remove(finder)
        super().tearDown()

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

    def test_import_uses_verified_bytes_after_file_replaced(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        self.assertTrue(plugins.is_authorized(PLUGIN_NAME))
        self._replace_zip_on_disk('evil')
        plugin = plugins.load_plugin_by_name(PLUGIN_NAME)
        self.assertIsNotNone(plugin)
        init_mod = sys.modules[f'electrum_external_plugins.{PLUGIN_NAME}']
        gui_mod = sys.modules[f'electrum_external_plugins.{PLUGIN_NAME}.cmdline']
        self.assertEqual('benign', init_mod.SECRET)
        self.assertEqual('benign', gui_mod.SECRET)
        # a submodule imported only now still comes from the verified bytes
        import importlib
        deep = importlib.import_module(f'electrum_external_plugins.{PLUGIN_NAME}.sub.deep')
        self.assertEqual('benign', deep.DEEP)

    def test_read_file_uses_verified_bytes_after_file_replaced(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        self.assertEqual(b'benign', plugins.read_file(PLUGIN_NAME, 'icon.txt'))
        self._replace_zip_on_disk('evil')
        self.assertEqual(b'benign', plugins.read_file(PLUGIN_NAME, 'icon.txt'))

    def test_tampered_plugin_is_not_authorized(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        # replace on disk
        self._replace_zip_on_disk('evil')
        self.assertTrue(plugins.is_authorized(PLUGIN_NAME))
        # as if electrum had been restarted
        plugins._drop_zip_bundle(PLUGIN_NAME)
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

    def test_uninstall_drops_the_cached_archive(self):
        make_plugin_zip(self.zip_path, secret='benign')
        plugins = self._start_plugins()
        self._authorize(plugins)
        self.assertTrue(plugins.is_authorized(PLUGIN_NAME))
        plugins.uninstall(PLUGIN_NAME)
        self.assertFalse(any(isinstance(f, MemoryZipImporter) for f in sys.meta_path))
        self.assertFalse(plugins.is_authorized(PLUGIN_NAME))


class MemoryZipImporterTestCase(ElectrumTestCase):
    """Tests for the in-memory archive itself, independent of the Plugins object."""

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.electrum_path, 'p.zip')
        self.blob = make_plugin_zip(self.path, secret='benign')

    def _bundle(self, blob=None) -> MemoryZipImporter:
        return MemoryZipImporter(blob if blob is not None else self.blob,
                         root_name='test_pkg_for_pluginzip', prefix=PLUGIN_NAME,
                         archive_path=self.path)

    def test_sha256_is_of_the_bytes_held(self):
        self.assertEqual(sha256(self.blob), self._bundle().sha256)

    def test_module_map(self):
        b = self._bundle()
        self.assertTrue(b.is_package('test_pkg_for_pluginzip'))
        self.assertFalse(b.is_package('test_pkg_for_pluginzip.cmdline'))
        self.assertTrue(b.is_package('test_pkg_for_pluginzip.sub'))
        self.assertIsNotNone(b.find_spec('test_pkg_for_pluginzip.sub.deep'))
        self.assertIsNone(b.find_spec('test_pkg_for_pluginzip.nope'))
        self.assertIsNone(b.find_spec('os'))  # never claims foreign names

    def test_submodule_search_locations_is_empty(self):
        # a non-empty entry would be a path, and PathFinder resolves a relative
        # one against the process CWD, so there is no safe sentinel string
        spec = self._bundle().find_spec('test_pkg_for_pluginzip')
        self.assertEqual([], spec.submodule_search_locations)

    def test_bypassed_finder_cannot_resolve_submodule_from_disk(self):
        # plant a directory named after each search location in the CWD, as an
        # attacker who can write next to where electrum was started would
        spec = self._bundle().find_spec('test_pkg_for_pluginzip')
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.electrum_path)
        for location in spec.submodule_search_locations:
            os.makedirs(location, exist_ok=True)
            with open(os.path.join(location, 'sub.py'), 'w') as f:
                f.write("raise AssertionError('imported from disk')\n")
        # the finder is deliberately not installed: only __path__ is in play
        module = importlib.util.module_from_spec(spec)
        sys.modules['test_pkg_for_pluginzip'] = module
        self.addCleanup(sys.modules.pop, 'test_pkg_for_pluginzip', None)
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('test_pkg_for_pluginzip.sub')

    def test_read_resource(self):
        self.assertEqual(b'benign', self._bundle().read('icon.txt'))
        with self.assertRaises(FileNotFoundError):
            self._bundle().read('no-such-file')

    def test_corrupted_member_is_rejected(self):
        blob = bytearray(self.blob)
        with zipfile.ZipFile(self.path) as z:
            offset = z.getinfo(f'{PLUGIN_NAME}/cmdline.py').header_offset
        blob[offset + 60] ^= 0xff  # flip a bit inside the member payload
        with self.assertRaises(zipfile.BadZipFile):
            self._bundle(bytes(blob)).read('cmdline.py')
