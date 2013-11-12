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

class Timer(QtCore.QThread):
    def run(self):
        while True:
            self.emit(QtCore.SIGNAL('timersignal'))
            time.sleep(0.5)

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


    def main(self, url):

        storage = WalletStorage(self.config)
        if not storage.file_exists:
            import installwizard
            wizard = installwizard.InstallWizard(self.config, self.network, storage)
            wallet = wizard.run()
            if not wallet: 
                exit()
        else:
            wallet = Wallet(storage)
            wallet.start_threads(self.network)
            
        self.main_window = w = ElectrumWindow(self.config, self.network)

        # plugins that need to change the GUI do it here
        run_hook('init')

        w.load_wallet(wallet)

        s = Timer()
        s.start()

        self.windows.append(w)
        if url: w.set_url(url)
        w.app = self.app
        w.connect_slots(s)
        w.update_wallet()

        self.app.exec_()

        wallet.stop_threads()


