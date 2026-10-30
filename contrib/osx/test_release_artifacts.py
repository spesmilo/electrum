"""Exercise website artifact/signature selection without publishing anything."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class ReleaseArtifactsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'contrib').mkdir()
        source_root = Path(__file__).resolve().parents[2]
        self.script = self.root / 'contrib/make_download'
        shutil.copyfile(source_root / 'contrib/make_download', self.script)
        (self.root / 'electrum').mkdir()
        (self.root / 'electrum/version.py').write_text("ELECTRUM_VERSION = '0.0.1'\n")
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        names = (
            'Electrum-0.0.1.tar.gz', 'Electrum-sourceonly-0.0.1.tar.gz',
            'electrum-0.0.1-x86_64.AppImage', 'electrum-0.0.1.dmg',
            'electrum-0.0.1.exe', 'electrum-0.0.1-setup.exe',
            'electrum-0.0.1-portable.exe',
            'Electrum-0.0.1-arm64-v8a-release.apk',
            'Electrum-0.0.1-armeabi-v7a-release.apk',
            'Electrum-0.0.1-x86_64-release.apk',
        )
        for name in names:
            (self.dist / name).touch()
            (self.dist / (name + '.fixture_signer.asc')).touch()
        self.website = self.root / 'website'
        self.website.mkdir()
        (self.website / 'index.html.template').write_text('##DOWNLOAD_PAGE##')
        (self.website / 'panel-download.html.template').write_text(
            '##link_mac## ##link_mac_arm64## ##sigs_mac_arm64## ##signers_list##'
        )

    def generate(self, include_arm):
        env = dict(os.environ, INCLUDE_MACOS_ARM64=str(int(include_arm)))
        return subprocess.run(
            [sys.executable, str(self.script), str(self.website)],
            env=env, capture_output=True, text=True,
        )

    def test_default_does_not_require_arm(self):
        result = self.generate(False)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = (self.website / 'index.html').read_text()
        self.assertIn('https://download.electrum.org/0.0.1/electrum-0.0.1.dmg', html)
        self.assertIn('fixture_signer', html)

    def test_opt_in_requires_arm_and_matching_signatures(self):
        self.assertNotEqual(self.generate(True).returncode, 0)
        arm_name = 'electrum-0.0.1-arm64.dmg'
        (self.dist / arm_name).touch()
        result = self.generate(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('fixture_signer', (self.website / 'index.html').read_text())
        (self.dist / (arm_name + '.fixture_signer.asc')).touch()
        result = self.generate(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = (self.website / 'index.html').read_text()
        self.assertIn('fixture_signer', html)
        self.assertIn('https://download.electrum.org/0.0.1/' + arm_name + '.asc', html)
        self.assertNotIn('##link_mac_arm64##', html)


if __name__ == '__main__':
    unittest.main()
