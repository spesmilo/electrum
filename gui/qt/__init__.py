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
import os
import signal

try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum_ltc.i18n import _, set_language
from electrum_ltc.plugins import run_hook
from electrum_ltc import SimpleConfig, Wallet, WalletStorage
from electrum_ltc.paymentrequest import InvoiceStore
from electrum_ltc.contacts import Contacts
from electrum_ltc.synchronizer import Synchronizer
from electrum_ltc.verifier import SPV
from electrum_ltc.util import DebugMem
from electrum_ltc.wallet import Abstract_Wallet
from installwizard import InstallWizard


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

    def __init__(self, config, network, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        self.network = network
        self.config = config
        self.plugins = plugins
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.timer = Timer()
        # shared objects
        self.invoices = InvoiceStore(self.config)
        self.contacts = Contacts(self.config)
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Electrum-LTC')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.app.connect(self.app, QtCore.SIGNAL('new_window'), self.start_new_window)
        run_hook('init_qt', self)

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
        m.addAction(_("Exit Electrum-LTC"), self.close)
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
            wizard = InstallWizard(self.app, self.config, self.network, storage)
            wallet = wizard.run(action)
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
        wizard = InstallWizard(self.app, self.config, self.network, storage)
        wallet = wizard.run('new')
        if wallet:
            self.new_window(full_path)

    def new_window(self, path, uri=None):
        # Use a signal as can be called from daemon thread
        self.app.emit(SIGNAL('new_window'), path, uri)

    def start_new_window(self, path, uri):
        for w in self.windows:
            if w.wallet.storage.path == path:
                w.bring_to_top()
                break
        else:
            wallet = self.load_wallet_file(path)
            if not wallet:
                return
            w = ElectrumWindow(self, wallet)
            w.connect_slots(self.timer)
            # save path
            if self.config.get('wallet_path') is None:
                self.config.set_key('gui_last_wallet', path)
            # add to recently visited
            w.update_recently_visited(path)
            # initial configuration
            if self.config.get('hide_gui') is True and self.tray.isVisible():
                w.hide()
            else:
                w.show()
            self.windows.append(w)
            self.build_tray_menu()
            run_hook('on_new_window', w)

        if uri:
            w.pay_to_URI(uri)

        return w

    def close_window(self, window):
        self.windows.remove(window)
        self.build_tray_menu()
        run_hook('on_close_window', window)

    def main(self):
        self.timer.start()

        last_wallet = self.config.get('gui_last_wallet')
        if last_wallet is not None and self.config.get('wallet_path') is None:
            if os.path.exists(last_wallet):
                self.config.cmdline_options['default_wallet_path'] = last_wallet

        if not self.start_new_window(self.config.get_wallet_path(),
                                     self.config.get('url')):
            return

        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        # main loop
        self.app.exec_()

        # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)

        self.tray.hide()
