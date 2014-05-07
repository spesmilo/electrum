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

import sys, time, datetime, re, threading
from electrum.i18n import _, set_language
from electrum.util import print_error, print_msg, parse_url
from electrum.plugins import run_hook
import os.path, json, ast, traceback
import shutil


try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum import WalletStorage, Wallet
from electrum.i18n import _
from electrum.bitcoin import MIN_RELAY_TX_FEE

try:
    import icons_rc
except Exception:
    sys.exit("Error: Could not import icons_rc.py, please generate it with: 'pyrcc4 icons.qrc -o gui/qt/icons_rc.py'")

from util import *
from main_window import ElectrumWindow
from electrum.plugins import init_plugins


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        self.windows = windows
        super(OpenFileEventFilter, self).__init__()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].set_url(event.url().toEncoded())
                return True
        return False


class ElectrumGui:

    def __init__(self, config, network, app=None):
        self.network = network
        self.config = config
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        if app is None:
            self.app = QApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        init_plugins(self)


    def build_tray_menu(self):
        m = QMenu()
        m.addAction(_("Show/Hide"), self.show_or_hide)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electrum"), self.close)
        self.tray.setContextMenu(m)

    def toggle_tray_icon(self):
        self.dark_icon = not self.dark_icon
        self.config.set_key("dark_icon", self.dark_icon, True)
        icon = QIcon(":icons/electrum_dark_icon.png") if self.dark_icon else QIcon(':icons/electrum_light_icon.png')
        self.tray.setIcon(icon)

    def show_or_hide(self):
        self.tray_activated(QSystemTrayIcon.DoubleClick)

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.current_window.isMinimized() or self.current_window.isHidden():
                self.current_window.show()
                self.current_window.raise_()
            else:
                self.current_window.hide()

    def close(self):
        self.current_window.close()



    def go_full(self):
        self.config.set_key('lite_mode', False, True)
        self.lite_window.hide()
        self.main_window.show()
        self.main_window.raise_()
        self.current_window = self.main_window

    def go_lite(self):
        self.config.set_key('lite_mode', True, True)
        self.main_window.hide()
        self.lite_window.show()
        self.lite_window.raise_()
        self.current_window = self.lite_window


    def init_lite(self):
        import lite_window
        if not self.check_qt_version():
            if self.config.get('lite_mode') is True:
                msg = "Electrum was unable to load the 'Lite GUI' because it needs Qt version >= 4.7.\nChanging your config to use the 'Classic' GUI"
                QMessageBox.warning(None, "Could not start Lite GUI.", msg)
                self.config.set_key('lite_mode', False, True)
                sys.exit(0)
            self.lite_window = None
            self.main_window.show()
            self.main_window.raise_()
            return

        actuator = lite_window.MiniActuator(self.main_window)
        actuator.load_theme()
        self.lite_window = lite_window.MiniWindow(actuator, self.go_full, self.config)
        driver = lite_window.MiniDriver(self.main_window, self.lite_window)

        if self.config.get('lite_mode') is True:
            self.go_lite()
        else:
            self.go_full()


    def check_qt_version(self):
        qtVersion = qVersion()
        return int(qtVersion[0]) >= 4 and int(qtVersion[2]) >= 7


    def set_url(self, url):
        from electrum import util
        from decimal import Decimal

        try:
            address, amount, label, message, request_url, url = util.parse_url(url)
        except Exception:
            QMessageBox.warning(self.main_window, _('Error'), _('Invalid bitcoin URL'), _('OK'))
            return

        if amount:
            try:
                if self.main_window.base_unit() == 'mBTC': 
                    amount = str( 1000* Decimal(amount))
                else: 
                    amount = str(Decimal(amount))
            except Exception:
                amount = "0.0"
                QMessageBox.warning(self.main_window, _('Error'), _('Invalid Amount'), _('OK'))

        if request_url:
            try:
                from electrum import paymentrequest
            except:
                print "cannot import paymentrequest"
                return
            def payment_request():
                pr = paymentrequest.PaymentRequest(request_url)
                if pr.verify() or 1:
                    self.main_window.payment_request = pr
                    self.main_window.emit(SIGNAL('payment_request_ok'))
                else:
                    self.main_window.emit(SIGNAL('payment_request_failed'))

            threading.Thread(target=payment_request).start()
            
        self.main_window.set_send(address, amount, label, message)
        if self.lite_window:
            self.lite_window.set_payment_fields(address, amount)


    def main(self, url):

        storage = WalletStorage(self.config)
        if storage.file_exists:
            wallet = Wallet(storage)
            action = wallet.get_action()
        else:
            action = 'new'

        if action is not None:
            import installwizard
            wizard = installwizard.InstallWizard(self.config, self.network, storage)
            wallet = wizard.run(action)
            if not wallet: 
                exit()
        else:
            wallet.start_threads(self.network)

        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        icon = QIcon(":icons/electrum_dark_icon.png") if self.dark_icon else QIcon(':icons/electrum_light_icon.png')
        self.tray = QSystemTrayIcon(icon, None)
        self.tray.setToolTip('Electrum')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()

        # main window
        self.main_window = w = ElectrumWindow(self.config, self.network, self)
        self.current_window = self.main_window

        #lite window
        self.init_lite()

        # plugins that need to change the GUI do it here
        run_hook('init')

        w.load_wallet(wallet)

        s = Timer()
        s.start()

        self.windows.append(w)
        if url: 
            self.set_url(url)

        w.app = self.app
        w.connect_slots(s)
        w.update_wallet()

        self.app.exec_()

        wallet.stop_threads()


