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

from electrum.i18n import _, set_language
from electrum.util import print_error, print_msg
from electrum.plugins import run_hook, always_hook
from electrum import WalletStorage, Wallet
from electrum.bitcoin import MIN_RELAY_TX_FEE

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

    def __init__(self, config, network):
        set_language(config.get('language'))
        self.network = network
        self.config = config
        self.windows = {}
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.timer = Timer()

        self.app.connect(self.app, QtCore.SIGNAL('new_window'), self.start_new_window)


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

    def new_window(self, config):
        self.app.emit(SIGNAL('new_window'), config)

    def start_new_window(self, config):
        path = config.get_wallet_path()
        if path not in self.windows:
            w = ElectrumWindow(config, self.network, self)
            w.connect_slots(self.timer)
            w.load_wallet_file(path)
            w.show()
            self.windows[path] = w

        w = self.windows[path]
        url = config.get('url')
        if url:
            w.pay_to_URI(url)
        return w


    def main(self):
        self.timer.start()

        last_wallet = self.config.get('gui_last_wallet')
        if last_wallet is not None and self.config.get('wallet_path') is None:
            if os.path.exists(last_wallet):
                self.config.cmdline_options['default_wallet_path'] = last_wallet

        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        icon = QIcon(":icons/electrum_dark_icon.png") if self.dark_icon else QIcon(':icons/electrum_light_icon.png')
        self.tray = QSystemTrayIcon(icon, None)
        self.tray.setToolTip('Electrum')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()

        # main window
        self.current_window = self.main_window = self.start_new_window(self.config)

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

        for window in self.windows.values():
            window.close_wallet()

        if self.tray:
            self.tray.hide()
