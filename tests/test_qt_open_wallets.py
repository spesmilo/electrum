import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QDialog, QWidget
except ImportError:
    # Desktop Qt is optional in Electrum's core test environment.
    raise unittest.SkipTest('PyQt6 is required for desktop GUI tests')

from electrum.gui.qt import ElectrumGui
from electrum.gui.qt.main_window import ElectrumWindow
from electrum.gui.qt.wizard.wallet import WCWalletName
from electrum.daemon import Daemon
from electrum.simple_config import SimpleConfig
from electrum.util import InvalidPassword
from electrum.wallet import create_new_wallet
from electrum.wallet_db import WalletRequiresUpgrade
from tests import ElectrumTestCase


class TestOpenWallets(unittest.TestCase):
    gui: ElectrumGui
    parent: Mock

    def setUp(self) -> None:
        self.gui = object.__new__(ElectrumGui)
        self.gui.daemon = Mock()
        self.gui.daemon.get_wallet.return_value = None
        self.gui.start_new_window = Mock()
        self.gui.logger = Mock()
        self.parent = Mock()

    def test_reuses_password_across_wallets(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password != 'shared':
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.return_value = 'shared'
        self.gui.open_wallets(['/wallets/one', '/wallets/two'], parent=self.parent)
        self.parent.password_dialog.assert_called_once()
        self.assertEqual(self.gui.daemon.load_wallet.call_args_list[3].args,
                         ('/wallets/two', 'shared'))
        self.assertEqual(self.gui.start_new_window.call_count, 2)

    def test_bad_cached_password_prompts_again(self) -> None:
        passwords = {'/wallets/one': 'first', '/wallets/two': 'second'}

        def load(path: str, password: str | None) -> object:
            if password != passwords[path]:
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['first', 'second']
        self.gui.open_wallets(list(passwords), parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)
        self.assertEqual(self.gui.start_new_window.call_count, 2)

    def test_each_selection_has_separate_password_cache(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password != 'shared':
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.return_value = 'shared'
        self.gui.open_wallets(['/wallets/one'], parent=self.parent)
        self.gui.open_wallets(['/wallets/two'], parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)

    def test_tries_all_cached_passwords_before_prompting(self) -> None:
        passwords = {'/wallets/one': 'first', '/wallets/two': 'second',
                     '/wallets/three': 'first'}

        def load(path: str, password: str | None) -> object:
            if password != passwords[path]:
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['first', 'second']
        self.gui.open_wallets(list(passwords), parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)
        self.assertEqual(self.gui.start_new_window.call_count, 3)

    def test_cancel_stops_batch(self) -> None:
        def load(path: str, password: str | None) -> object:
            if path.endswith('one'):
                raise InvalidPassword('No password given')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.return_value = None
        self.gui.open_wallets(['/wallets/one', '/wallets/two'], parent=self.parent)
        self.gui.start_new_window.assert_not_called()
        self.parent.password_dialog.assert_called_once()
        self.gui.daemon.get_wallet.assert_called_once_with('/wallets/one')
        self.gui.daemon.load_wallet.assert_called_once_with('/wallets/one', None)

    def test_wrong_password_then_correct_is_only_prompted_twice(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password != 'correct':
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['wrong', 'correct']
        paths = ['/wallets/one', '/wallets/two', '/wallets/three']
        self.gui.open_wallets(paths, parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)
        self.parent.show_error.assert_called_once()
        self.assertEqual(self.gui.start_new_window.call_count, 3)
        for path in paths[1:]:
            self.gui.daemon.load_wallet.assert_any_call(path, 'correct')

    def test_rejected_password_is_tried_on_later_wallets(self) -> None:
        passwords = {'/wallets/first': 'second-password',
                     '/wallets/next': 'first-password'}

        def load(path: str, password: str | None) -> object:
            if password != passwords[path]:
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['first-password', 'second-password']
        self.gui.open_wallets(list(passwords), parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)
        self.gui.daemon.load_wallet.assert_any_call('/wallets/next', 'first-password')
        self.assertEqual(self.gui.start_new_window.call_count, 2)

    def test_repeated_wrong_password_is_only_cached_once(self) -> None:
        passwords = {'/wallets/first': 'right', '/wallets/next': 'wrong'}

        def load(path: str, password: str | None) -> object:
            if password != passwords[path]:
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['wrong', 'wrong', 'right']
        self.gui.open_wallets(list(passwords), parent=self.parent)
        attempts = [call.args for call in self.gui.daemon.load_wallet.call_args_list
                    if call.args[0] == '/wallets/next']
        self.assertEqual(attempts, [('/wallets/next', None), ('/wallets/next', 'wrong')])
        self.assertEqual(self.parent.password_dialog.call_count, 3)

    def test_empty_password_is_rejected_without_loading_wallet(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password is None:
                raise InvalidPassword('No password given')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['', 'correct']
        self.gui.open_wallets(['/wallets/one'], parent=self.parent)
        self.assertEqual(self.gui.daemon.load_wallet.call_args_list[1].args,
                         ('/wallets/one', 'correct'))
        self.parent.show_error.assert_called_once()
        self.gui.start_new_window.assert_called_once()

    def test_error_after_cached_password_uses_wizard(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password is None:
                raise InvalidPassword('No password given')
            if path.endswith('second'):
                raise OSError('Cannot read wallet')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.return_value = 'shared'
        self.gui.open_wallets(['/wallets/first', '/wallets/second'], parent=self.parent)
        self.parent.password_dialog.assert_called_once()
        self.assertEqual(self.gui.start_new_window.call_count, 2)

    def test_upgrade_reuses_verified_password_in_wizard_and_next_wallet(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password != 'shared':
                raise InvalidPassword('Invalid password')
            if path.endswith('upgrade'):
                raise WalletRequiresUpgrade()
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['wrong', 'shared']
        self.gui.open_wallets(['/wallets/upgrade', '/wallets/next'], parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)
        self.parent.show_error.assert_called_once()
        self.gui.start_new_window.assert_any_call('/wallets/upgrade', uri=None,
                                                  wizard_password='shared')
        self.gui.start_new_window.assert_any_call('/wallets/next', uri=None)

    def test_cached_password_prefills_upgrade_wizard(self) -> None:
        def load(path: str, password: str | None) -> object:
            if password != 'shared':
                raise InvalidPassword('Invalid password')
            if path.endswith('upgrade'):
                raise WalletRequiresUpgrade()
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.return_value = 'shared'
        self.gui.open_wallets(['/wallets/first', '/wallets/upgrade'], parent=self.parent)
        self.parent.password_dialog.assert_called_once()
        self.gui.start_new_window.assert_any_call('/wallets/upgrade', uri=None,
                                                  wizard_password='shared')

    @patch('electrum.gui.qt.QENewWalletWizard')
    def test_wizard_receives_verified_password(self, mock_wizard: Mock) -> None:
        mock_wizard.return_value.exec.return_value = QDialog.DialogCode.Rejected
        self.gui.config = Mock()
        self.gui.app = Mock()
        self.gui.plugins = Mock()
        self.assertIsNone(self.gui._start_wizard_to_select_or_create_wallet(
            '/wallets/upgrade', initial_password='shared'))
        self.assertEqual(mock_wizard.return_value.initial_password, 'shared')

    @patch('electrum.gui.qt.wizard.wallet.WalletStorage')
    def test_wizard_prefills_password_only_for_original_wallet(self, mock_storage: Mock) -> None:
        # Keep QApplication alive while the Qt widgets are in use.
        app = QApplication.instance() or QApplication([])
        wizard = Mock()
        wizard._path = '/wallets/upgrade'
        wizard.path = '/wallets/upgrade'
        wizard.initial_password = 'shared'
        wizard.config.get_datadir_wallet_path.return_value = '/wallets'
        wizard._daemon.get_wallet.return_value = None
        mock_storage.return_value.file_exists.return_value = True
        mock_storage.return_value.is_encrypted_with_user_pw.return_value = True
        parent_widget = QWidget()
        widget = WCWalletName(parent_widget, wizard)
        self.assertEqual(widget.pw_e.text(), 'shared')
        widget.name_e.setText('other')
        self.assertEqual(widget.pw_e.text(), '')
        self.assertIsNone(wizard.initial_password)

    def test_cancel_keeps_opened_wallets(self) -> None:
        passwords = {'/wallets/first': 'shared', '/wallets/second': 'other',
                     '/wallets/third': 'shared'}

        def load(path: str, password: str | None) -> object:
            if password != passwords[path]:
                raise InvalidPassword('Invalid password')
            return object()

        self.gui.daemon.load_wallet.side_effect = load
        self.parent.password_dialog.side_effect = ['shared', None]
        self.gui.open_wallets(list(passwords), parent=self.parent)
        self.assertEqual(self.parent.password_dialog.call_count, 2)
        self.gui.start_new_window.assert_called_once_with('/wallets/first', uri=None)
        self.assertEqual(
            [call.args[0] for call in self.gui.daemon.get_wallet.call_args_list],
            ['/wallets/first', '/wallets/second'],
        )

    def test_hardware_encrypted_wallet_uses_wizard_without_password_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'hardware-wallet'
            path.write_bytes(base64.b64encode(b'BIE2not-a-real-wallet'))
            self.gui.daemon.load_wallet.side_effect = InvalidPassword('No password given')
            self.gui.open_wallets([str(path)], parent=self.parent)
            self.parent.password_dialog.assert_not_called()
            self.gui.start_new_window.assert_called_once_with(str(path), uri=None)

    @patch('electrum.gui.qt.main_window.QFileDialog.getOpenFileNames')
    def test_file_dialog_allows_multiple_selection(self, mock_dialog: Mock) -> None:
        mock_dialog.return_value = ['/wallets/one', '/wallets/two'], ''
        window = Mock()
        window.get_wallet_folder.return_value = '/wallets'
        ElectrumWindow.open_wallet(window)
        self.assertEqual(mock_dialog.call_count, 1)
        window.gui_object.open_wallets.assert_called_once_with(
            ['/wallets/one', '/wallets/two'], parent=window)


class TestOpenRealTestnetWallets(ElectrumTestCase):
    TESTNET = True

    async def test_rejected_password_opens_later_testnet_wallet(self) -> None:
        config = SimpleConfig({'testnet': True, 'electrum_path': self.electrum_path})
        paths = [str(Path(self.electrum_path) / name) for name in ('one', 'two', 'three')]
        for path, password in zip(paths, ('correct', 'correct', 'wrong')):
            create_new_wallet(path=path, config=config, password=password,
                              gap_limit=1, gap_limit_for_change=1)

        gui = object.__new__(ElectrumGui)
        gui.daemon = Mock()
        gui.daemon.get_wallet.return_value = None
        gui.daemon.load_wallet.side_effect = lambda path, password: Daemon._load_wallet(
            path, password, config=config)
        gui.start_new_window = Mock()
        parent = Mock()
        parent.password_dialog.side_effect = ['wrong', 'correct']

        gui.open_wallets(paths, parent=parent)

        self.assertEqual(parent.password_dialog.call_count, 2)
        parent.show_error.assert_called_once()
        self.assertEqual(gui.start_new_window.call_count, 3)
        gui.daemon.load_wallet.assert_any_call(paths[2], 'wrong')


if __name__ == '__main__':
    unittest.main()
