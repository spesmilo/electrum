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
import time
import datetime
import re
import threading
import os.path, json, ast, traceback
import shutil
import signal

try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum_ltc.i18n import _, set_language
from electrum_ltc.util import print_error, print_msg
from electrum_ltc.plugins import run_hook, always_hook
from electrum_ltc import WalletStorage, Wallet
from electrum_ltc.bitcoin import MIN_RELAY_TX_FEE

try:
    import icons_rc
except Exception:
    sys.exit("Error: Could not import icons_rc.py, please generate it with: 'pyrcc4 icons.qrc -o gui/qt/icons_rc.py'")

from util import *
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

    def __init__(self, config, network, app=None):
        set_language(config.get('language'))
        self.network = network
        self.config = config
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        if app is None:
            self.app = QApplication(sys.argv)
        self.app.installEventFilter(self.efilter)

    def build_tray_menu(self):
        m = QMenu()
        m.addAction(_("Show/Hide"), self.show_or_hide)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electrum-LTC"), self.close)
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
            return

        actuator = lite_window.MiniActuator(self.main_window)
        actuator.load_theme()
        self.lite_window = lite_window.MiniWindow(actuator, self.go_full, self.config)
        driver = lite_window.MiniDriver(self.main_window, self.lite_window)



    def check_qt_version(self):
        qtVersion = qVersion()
        return int(qtVersion[0]) >= 4 and int(qtVersion[2]) >= 7

    def set_url(self, uri):
        self.current_window.pay_to_URI(uri)


    def main(self, url):

        last_wallet = self.config.get('gui_last_wallet')
        if last_wallet is not None and self.config.get('wallet_path') is None:
            if os.path.exists(last_wallet):
                self.config.cmdline_options['default_wallet_path'] = last_wallet

        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        icon = QIcon(":icons/electrum_dark_icon.png") if self.dark_icon else QIcon(':icons/electrum_light_icon.png')
        self.tray = QSystemTrayIcon(icon, None)
        self.tray.setToolTip('Electrum-LTC')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()

        # main window
        self.main_window = w = ElectrumWindow(self.config, self.network, self)
        self.current_window = self.main_window
        w.show()

        #lite window
        self.init_lite()

        w.load_wallet_file(self.config.get_wallet_path())

        # plugins interact with main window
        run_hook('init_qt', self)

        # initial configuration
        if self.config.get('hide_gui') is True and self.tray.isVisible():
            self.main_window.hide()
            self.lite_window.hide()
        else:
            if self.config.get('lite_mode') is True:
                self.go_lite()
            else:
                self.go_full()

        s = Timer()
        s.start()

        self.windows.append(w)
        if url:
            self.set_url(url)

        w.connect_slots(s)

        signal.signal(signal.SIGINT, lambda *args: self.app.quit())
        self.app.exec_()
        if self.tray:
            self.tray.hide()

        # clipboard persistence
        # see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)

        w.close_wallet()
