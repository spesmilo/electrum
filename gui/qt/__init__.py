#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys
import os.path
import signal

try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum.i18n import _, set_language
from electrum.plugins import run_hook
from electrum import SimpleConfig, Wallet, WalletStorage

try:
    import icons_rc
except Exception:
    sys.exit("Error: Could not import icons_rc.py, please generate it with: 'pyrcc4 icons.qrc -o gui/qt/icons_rc.py'")

from util import *   # * needed for plugins
from main_window import ElectrumWindow


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        self.windows = windows
        super(OpenFileEventFilter, self).__init__()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toEncoded())
                return True
        return False



class ElectrumGui:

    def __init__(self, config, network):
        set_language(config.get('language'))
        self.network = network
        self.config = config
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.timer = Timer()

        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Electrum')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.app.connect(self.app, QtCore.SIGNAL('new_window'), self.start_new_window)

    def build_tray_menu(self):
        # Avoid immediate GC of old menu when window closed via its action
        self.old_menu = self.tray.contextMenu()
        m = QMenu()
        for window in self.windows:
            submenu = m.addMenu(window.wallet.basename())
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            submenu.addAction(_("Close"), window.close)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electrum"), self.close)
        self.tray.setContextMenu(m)

    def tray_icon(self):
        if self.dark_icon:
            return QIcon(':icons/electrum_dark_icon.png')
        else:
            return QIcon(':icons/electrum_light_icon.png')

    def toggle_tray_icon(self):
        self.dark_icon = not self.dark_icon
        self.config.set_key("dark_icon", self.dark_icon, True)
        self.tray.setIcon(self.tray_icon())

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if all([w.is_hidden() for w in self.windows]):
                for w in self.windows:
                    w.bring_to_top()
            else:
                for w in self.windows:
                    w.hide()

    def close(self):
        for window in self.windows:
            window.close()

    def run_wizard(self, storage, action):
        import installwizard
        if storage.file_exists and action != 'new':
            msg = _("The file '%s' contains an incompletely created wallet.")%storage.path + '\n'\
                  + _("Do you want to complete its creation now?")
            if not self.question(msg):
                if self.question(_("Do you want to delete '%s'?")%storage.path):
                    os.remove(storage.path)
                    QMessageBox.information(self, _('Warning'), _('The file was removed'), _('OK'))
                    return
                return
        wizard = installwizard.InstallWizard(self.config, self.network, storage, self)
        wizard.show()
        if action == 'new':
            action, wallet_type = wizard.restore_or_create()
        else:
            wallet_type = None
        try:
            wallet = wizard.run(action, wallet_type)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            QMessageBox.information(None, _('Error'), str(e), _('OK'))
            return
        return wallet

    def load_wallet_file(self, filename):
        try:
            storage = WalletStorage(filename)
        except Exception as e:
            QMessageBox.information(None, _('Error'), str(e), _('OK'))
            return
        if not storage.file_exists:
            recent = self.config.get('recently_open', [])
            if filename in recent:
                recent.remove(filename)
                self.config.set_key('recently_open', recent)
            action = 'new'
        else:
            try:
                wallet = Wallet(storage)
            except BaseException as e:
                traceback.print_exc(file=sys.stdout)
                QMessageBox.warning(None, _('Warning'), str(e), _('OK'))
                return
            action = wallet.get_action()
        # run wizard
        if action is not None:
            wallet = self.run_wizard(storage, action)
            # keep current wallet
            if not wallet:
                return
        else:
            wallet.start_threads(self.network)

        return wallet

    def get_wallet_folder(self):
        #return os.path.dirname(os.path.abspath(self.wallet.storage.path if self.wallet else self.wallet.storage.path))
        return os.path.dirname(os.path.abspath(self.config.get_wallet_path()))

    def new_wallet(self):
        import installwizard
        wallet_folder = self.get_wallet_folder()
        i = 1
        while True:
            filename = "wallet_%d"%i
            if filename in os.listdir(wallet_folder):
                i += 1
            else:
                break
        filename = line_dialog(None, _('New Wallet'), _('Enter file name') + ':', _('OK'), filename)
        if not filename:
            return
        full_path = os.path.join(wallet_folder, filename)
        storage = WalletStorage(full_path)
        if storage.file_exists:
            QMessageBox.critical(None, "Error", _("File exists"))
            return
        wizard = installwizard.InstallWizard(self.config, self.network, storage, self.app)
        action, wallet_type = wizard.restore_or_create()
        if not action:
            return
        wallet = wizard.run(action, wallet_type)
        if wallet:
            self.start_new_window(self.config, full_path)

    def new_window(self, path):
        # Use a signal as can be called from daemon thread
        self.app.emit(SIGNAL('new_window'), self.config, path)

    def start_new_window(self, config, path=None):
        if path is None:
            path = config.get_wallet_path()
        for w in self.windows:
            if w.wallet.storage.path == path:
                w.bring_to_top()
                break
        else:
            wallet = self.load_wallet_file(path)
            if not wallet:
                return
            w = ElectrumWindow(config, self.network, self)
            run_hook('new_window', w)
            w.connect_slots(self.timer)

            # load new wallet in gui
            w.load_wallet(wallet)
            # save path
            if self.config.get('wallet_path') is None:
                self.config.set_key('gui_last_wallet', path)
            # add to recently visited
            w.update_recently_visited(path)
            w.show()
            self.windows.append(w)
            self.build_tray_menu()

        url = config.get('url')
        if url:
            w.pay_to_URI(url)
        return w

    def close_window(self, window):
        self.windows.remove(window)
        self.build_tray_menu()

    def main(self):
        self.timer.start()

        last_wallet = self.config.get('gui_last_wallet')
        if last_wallet is not None and self.config.get('wallet_path') is None:
            if os.path.exists(last_wallet):
                self.config.cmdline_options['default_wallet_path'] = last_wallet

        # main window
        self.main_window = self.start_new_window(self.config)
        if not self.main_window:
            return

        # plugins interact with main window
        run_hook('init_qt', self)

        # initial configuration
        if self.config.get('hide_gui') is True and self.tray.isVisible():
            self.main_window.hide()


        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        # main loop
        self.app.exec_()

        # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)

        if self.tray:
            self.tray.hide()
