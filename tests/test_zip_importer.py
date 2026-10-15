import importlib
import importlib.util
import json
import os
import sys
import zipfile

from electrum.zip_importer import MemoryZipImporter

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


class MemoryZipImporterTestCase(ElectrumTestCase):
    """Tests for the in-memory archive itself, independent of the Plugins object."""

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.electrum_path, 'p.zip')
        self.blob = make_plugin_zip(self.path, secret='benign')

    def _importer(self, blob=None) -> MemoryZipImporter:
        return MemoryZipImporter(blob if blob is not None else self.blob,
                         root_name='test_pkg_for_pluginzip', prefix=PLUGIN_NAME,
                         archive_path=self.path)

    def test_module_map(self):
        b = self._importer()
        self.assertTrue(b.is_package('test_pkg_for_pluginzip'))
        self.assertFalse(b.is_package('test_pkg_for_pluginzip.cmdline'))
        self.assertTrue(b.is_package('test_pkg_for_pluginzip.sub'))
        self.assertIsNotNone(b.find_spec('test_pkg_for_pluginzip.sub.deep'))
        self.assertIsNone(b.find_spec('test_pkg_for_pluginzip.nope'))
        self.assertIsNone(b.find_spec('os'))  # never claims foreign names

    def test_submodule_search_locations_is_empty(self):
        # a non-empty entry would be a path, and PathFinder resolves a relative
        # one against the process CWD, so there is no safe sentinel string
        spec = self._importer().find_spec('test_pkg_for_pluginzip')
        self.assertEqual([], spec.submodule_search_locations)

    def test_importlib_cannot_resolve_submodule(self):
        # check that importlib, which would read from disk,
        # is disabled because search_locations is empty
        importer = self._importer()
        spec = importer.find_spec('test_pkg_for_pluginzip')
        module = importlib.util.module_from_spec(spec)
        sys.modules['test_pkg_for_pluginzip'] = module
        self.addCleanup(sys.modules.pop, 'test_pkg_for_pluginzip', None)
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('test_pkg_for_pluginzip.sub')
        # find_spec works
        spec2 = importer.find_spec('test_pkg_for_pluginzip.sub')
        module2 = importlib.util.module_from_spec(spec2)

    def test_read_resource(self):
        self.assertEqual(b'benign', self._importer().read('icon.txt'))
        with self.assertRaises(FileNotFoundError):
            self._importer().read('no-such-file')

    def test_corrupted_member_is_rejected(self):
        blob = bytearray(self.blob)
        with zipfile.ZipFile(self.path) as z:
            offset = z.getinfo(f'{PLUGIN_NAME}/cmdline.py').header_offset
        blob[offset + 60] ^= 0xff  # flip a bit inside the member payload
        with self.assertRaises(zipfile.BadZipFile):
            self._importer(bytes(blob)).read('cmdline.py')
