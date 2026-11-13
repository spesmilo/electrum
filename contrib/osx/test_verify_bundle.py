"""Integration checks using real arm64 and x86_64 Mach-O object files."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from verify_bundle import verify_bundle


@unittest.skipUnless(sys.platform == 'darwin', 'requires macOS clang and lipo')
class VerifyBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'Electrum.app'
        self.bundle.mkdir()
        self.source = self.root / 'fixture.c'
        self.source.write_text('int fixture(void) { return 0; }\n')

    def compile(self, arch, name):
        path = self.bundle / name
        subprocess.run(['clang', '-arch', arch, '-c', str(self.source), '-o', str(path)], check=True)
        return path

    def test_native_and_universal_dependencies(self):
        arm = self.compile('arm64', 'arm.o')
        intel = self.compile('x86_64', 'intel.o')
        universal = self.bundle / 'universal.o'
        subprocess.run(['lipo', '-create', str(arm), str(intel), '-output', str(universal)], check=True)
        intel.unlink()
        (self.bundle / 'resource.txt').write_text('ordinary app data')
        (self.bundle / 'alias.o').symlink_to(arm.name)
        self.assertEqual(verify_bundle(self.bundle, 'arm64'), 2)
        arm.unlink()
        self.assertEqual(verify_bundle(self.bundle, 'x86_64'), 1)

    def test_wrong_architecture_dependency(self):
        self.compile('arm64', 'executable.o')
        self.compile('x86_64', 'dependency.o')
        with self.assertRaisesRegex(RuntimeError, 'dependency.o: expected arm64'):
            verify_bundle(self.bundle, 'arm64')

    def test_empty_or_missing_bundle(self):
        for path in (self.bundle, self.root / 'missing.app'):
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'No Mach-O'):
                verify_bundle(path, 'arm64')


if __name__ == '__main__':
    unittest.main()
