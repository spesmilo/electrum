import hashlib
import hmac
import pathlib
import tempfile
import threading
import unittest

from electrum import SimpleConfig
from electrum.logging import get_logger
from electrum.gui.qml import qeapp

NODE = '03' + 'ab' * 32


class _Signal:
    def __init__(self):
        self.calls = []
        self.event = threading.Event()

    def emit(self, *args):
        self.calls.append(args)
        self.event.set()


class _App:
    MAX_SHARED_LOG_SIZE = 1_000_000

    def __init__(self, config):
        self.config = config
        self._log_file_busy = False
        self.logger = get_logger('test_qml_share_log')
        self.userNotify = _Signal()
        self._logFileReady = _Signal()

    def isAndroid(self):
        return True


class TestShareLogFile(unittest.TestCase):
    """What the Share button produces, through the app's own slot."""

    def _share(self, path) -> str:
        app = self._app = _App(SimpleConfig({'electrum_path': path}))
        qeapp.QEAppController.shareLogFile(app)
        self.assertTrue(app._logFileReady.event.wait(30))
        text, error = app._logFileReady.calls[0]
        self.assertEqual('', error)
        return text

    def test_the_same_labels_in_every_share_also_after_a_restart(self):
        with tempfile.TemporaryDirectory() as path:
            logs = pathlib.Path(path) / 'logs'
            logs.mkdir(parents=True)
            (logs / 'electrum_log_20261116T000000Z_1.log').write_text(
                f'20261116T015645.543541Z |     INFO | lnworker.LNWallet.[w] | error reported by {NODE}. '
                'htlc failed at edge 3 of 4 (channel 700123x456x7)\n'
                '20261116T015645.543542Z |     INFO | gui.qml.qeinvoice | paying the rent\n', encoding='utf-8')
            first = self._share(path)
            self.assertNotIn(NODE[:10], first)
            self.assertNotIn('rent', first)
            # labelled with the key of this installation, kept in its config
            key = bytes.fromhex(self._app.config.LOGS_SHARING_KEY)
            node_label = hmac.new(key, f'node:{NODE[:10]}'.encode(), hashlib.sha256).hexdigest()[:8]
            self.assertIn(f'error reported by <node {node_label}>', first)
            self.assertEqual(first, self._share(path))  # a new config object, as after a restart
            with tempfile.TemporaryDirectory() as other:  # another installation: another key
                (pathlib.Path(other) / 'logs').mkdir(parents=True)
                (pathlib.Path(other) / 'logs' / logs.joinpath('electrum_log_20261116T000000Z_1.log').name).write_text(
                    (logs / 'electrum_log_20261116T000000Z_1.log').read_text(encoding='utf-8'), encoding='utf-8')
                self.assertNotEqual(first, self._share(other))
