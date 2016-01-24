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

    def __init__(self, config, network, daemon, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        self.network = network
        self.config = config
        self.daemon = daemon
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

    def new_window(self, path, uri=None):
        # Use a signal as can be called from daemon thread
        self.app.emit(SIGNAL('new_window'), path, uri)

    def create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        self.build_tray_menu()
        # FIXME: Remove in favour of the load_wallet hook
        run_hook('on_new_window', w)
        return w

    def get_wizard(self):
        return InstallWizard(self.config, self.app, self.plugins)

    def start_new_window(self, path, uri):
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it.'''
        for w in self.windows:
            if w.wallet.storage.path == path:
                w.bring_to_top()
                break
        else:
            wallet = self.daemon.load_wallet(path, self.get_wizard)
            if not wallet:
                return
            w = self.create_window_for_wallet(wallet)

        if uri:
            w.pay_to_URI(uri)

        return w

    def close_window(self, window):
        self.windows.remove(window)
        self.build_tray_menu()
        # save wallet path of last open window
        if self.config.get('wallet_path') is None and not self.windows:
            path = window.wallet.storage.path
            self.config.set_key('gui_last_wallet', path)
        run_hook('on_close_window', window)

    def main(self):
        self.timer.start()
        # open last wallet
        if self.config.get('wallet_path') is None:
            last_wallet = self.config.get('gui_last_wallet')
            if last_wallet is not None and os.path.exists(last_wallet):
                self.config.cmdline_options['default_wallet_path'] = last_wallet

        if not self.start_new_window(self.config.get_wallet_path(),
                                     self.config.get('url')):
            return

        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        # main loop
        self.app.exec_()

        # Shut down the timer cleanly
        self.timer.stop()

        # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)

        self.tray.hide()
