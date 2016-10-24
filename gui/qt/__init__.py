#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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

from electrum.i18n import _, set_language
from electrum.plugins import run_hook
from electrum import SimpleConfig, Wallet, WalletStorage
from electrum.paymentrequest import InvoiceStore
from electrum.contacts import Contacts
from electrum.synchronizer import Synchronizer
from electrum.verifier import SPV
from electrum.util import DebugMem, UserCancelled
from electrum.wallet import Abstract_Wallet
from installwizard import InstallWizard, GoBack


try:
    import icons_rc
except Exception:
    print "Error: Could not find icons file."
    print "Please run 'pyrcc4 icons.qrc -o gui/qt/icons_rc.py', and reinstall Electrum"
    sys.exit(1)

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

    def __init__(self, config, daemon, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
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
        self.tray.setToolTip('Electrum')
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

    def start_new_window(self, path, uri):
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it.'''
        for w in self.windows:
            if w.wallet.storage.path == path:
                w.bring_to_top()
                break
        else:
            wallet = self.daemon.load_wallet(path)
            if not wallet:
                wizard = InstallWizard(self.config, self.app, self.plugins, path)
                wallet = wizard.run_and_get_wallet()
                if not wallet:
                    return
                wallet.start_threads(self.daemon.network)
                self.daemon.add_wallet(wallet)
            w = self.create_window_for_wallet(wallet)
        if uri:
            w.pay_to_URI(uri)
        return w

    def close_window(self, window):
        self.windows.remove(window)
        self.build_tray_menu()
        # save wallet path of last open window
        if not self.windows:
            self.config.save_last_wallet(window.wallet)
        run_hook('on_close_window', window)

    def init_network(self):
        # Show network dialog if config does not exist
        if self.daemon.network:
            if self.config.get('auto_connect') is None:
                wizard = InstallWizard(self.config, self.app, self.plugins, None)
                wizard.init_network(self.daemon.network)
                wizard.terminate()

    def main(self):
        try:
            self.init_network()
        except UserCancelled:
            return
        except GoBack:
            return
        except:
            traceback.print_exc(file=sys.stdout)
            return
        self.timer.start()
        self.config.open_last_wallet()
        path = self.config.get_wallet_path()
        if not self.start_new_window(path, self.config.get('url')):
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
