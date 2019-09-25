#!/usr/bin/env python
#
# Electrum - lightweight Ocean client
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

import os
import signal
import sys
import traceback


try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import (QApplication, QSystemTrayIcon, QWidget, QMenu,
                             QMessageBox)
from PyQt5.QtCore import QObject, pyqtSignal, QTimer, QFile, QTextStream
import PyQt5.QtCore as QtCore

from electrum.i18n import _, set_language
from electrum.plugin import run_hook
from electrum.storage import WalletStorage
from electrum.base_wizard import GoBack
# from electrum.synchronizer import Synchronizer
# from electrum.verifier import SPV
# from electrum.util import DebugMem
from electrum.util import (UserCancelled, print_error,
                           WalletFileException, BitcoinException)
# from electrum.wallet import Abstract_Wallet

from .installwizard import InstallWizard
import breeze_resources


try:
    from . import icons_rc
except Exception as e:
    print(e)
    print("Error: Could not find icons file.")
    print("Please run 'pyrcc5 icons.qrc -o electrum/gui/qt/icons_rc.py'")
    sys.exit(1)

from .util import *   # * needed for plugins
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog


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


class QElectrumApplication(QApplication):
    new_window_signal = pyqtSignal(str, object)


class QNetworkUpdatedSignalObject(QObject):
    network_updated_signal = pyqtSignal(str, object)


class ElectrumGui:

    def __init__(self, config, daemon, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum.desktop')
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QElectrumApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.timer = Timer()
        self.nd = None
        self.network_updated_signal_obj = QNetworkUpdatedSignalObject()
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Ocean wallet')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.app.new_window_signal.connect(self.start_new_window)
        self.set_dark_theme_if_needed()
        run_hook('init_qt', self)

    def set_dark_theme_if_needed(self):
        use_dark_theme = self.config.get('qt_gui_color_theme', 'default') == 'dark'
        if use_dark_theme:
            try:
                file = QFile(":/dark.qss")
                file.open(QFile.ReadOnly | QFile.Text)
                stream = QTextStream(file)
                self.app.setStyleSheet(stream.readAll())
            except BaseException as e:
                use_dark_theme = False
                print_error('Error setting dark theme: {}'.format(e))
        else:
            try:
                file = QFile(":/light.qss")
                file.open(QFile.ReadOnly | QFile.Text)
                stream = QTextStream(file)
                self.app.setStyleSheet(stream.readAll())
            except BaseException as e:
                print_error('Error setting light theme: {}'.format(e))            
        # Even if we ourselves don't set the dark theme,
        # the OS/window manager/etc might set *a dark theme*.
        # Hence, try to choose colors accordingly:
        ColorScheme.update_from_widget(QWidget(), force_dark=use_dark_theme)

    def build_tray_menu(self):
        # Avoid immediate GC of old menu when window closed via its action
        if self.tray.contextMenu() is None:
            m = QMenu()
            self.tray.setContextMenu(m)
        else:
            m = self.tray.contextMenu()
            m.clear()
        for window in self.windows:
            submenu = m.addMenu(window.wallet.basename())
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            submenu.addAction(_("Close"), window.close)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electrum"), self.close)

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
        self.app.new_window_signal.emit(path, uri)

    def show_network_dialog(self, parent):
        if not self.daemon.network:
            parent.show_warning(_('You are using Electrum in offline mode; restart Electrum if you want to get connected'), title=_('Offline'))
            return
        if self.nd:
            self.nd.on_update()
            self.nd.show()
            self.nd.raise_()
            return
        self.nd = NetworkDialog(self.daemon.network, self.config,
                                self.network_updated_signal_obj)
        self.nd.show()

    def create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        self.build_tray_menu()
        # FIXME: Remove in favour of the load_wallet hook
        run_hook('on_new_window', w)
        return w

    def start_new_window(self, path, uri, app_is_starting=False):
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it'''
        try:
            wallet = self.daemon.load_wallet(path, None)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            d = QMessageBox(QMessageBox.Warning, _('Error'),
                            _('Cannot load wallet') + ' (1):\n' + str(e))
            d.exec_()
            if app_is_starting:
                # do not return so that the wizard can appear
                wallet = None
            else:
                return
        if not wallet:
            storage = WalletStorage(path, manual_upgrades=True)
            wizard = InstallWizard(self.config, self.app, self.plugins, storage)
            try:
                wallet = wizard.run_and_get_wallet(self.daemon.get_wallet)
            except UserCancelled:
                pass
            except GoBack as e:
                print_error('[start_new_window] Exception caught (GoBack)', e)
            except (WalletFileException, BitcoinException) as e:
                traceback.print_exc(file=sys.stderr)
                d = QMessageBox(QMessageBox.Warning, _('Error'),
                                _('Cannot load wallet') + ' (2):\n' + str(e))
                d.exec_()
                return
            finally:
                wizard.terminate()
            if not wallet:
                return

            if not self.daemon.get_wallet(wallet.storage.path):
                # wallet was not in memory
                wallet.start_threads(self.daemon.network)
                self.daemon.add_wallet(wallet)
        try:
            for w in self.windows:
                if w.wallet.storage.path == wallet.storage.path:
                    w.bring_to_top()
                    return
            w = self.create_window_for_wallet(wallet)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            d = QMessageBox(QMessageBox.Warning, _('Error'),
                            _('Cannot create window for wallet') + ':\n' + str(e))
            d.exec_()
            return
        if uri:
            w.pay_to_URI(uri)
        w.bring_to_top()
        w.setWindowState(w.windowState() & ~QtCore.Qt.WindowMinimized | QtCore.Qt.WindowActive)

        # this will activate the window
        w.activateWindow()
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
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            return
        self.timer.start()
        self.config.open_last_wallet()
        path = self.config.get_wallet_path()
        if not self.start_new_window(path, self.config.get('url'), app_is_starting=True):
            return
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        def quit_after_last_window():
            # on some platforms, not only does exec_ not return but not even
            # aboutToQuit is emitted (but following this, it should be emitted)
            if self.app.quitOnLastWindowClosed():
                self.app.quit()
        self.app.lastWindowClosed.connect(quit_after_last_window)

        def clean_up():
            # Shut down the timer cleanly
            self.timer.stop()
            # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
            event = QtCore.QEvent(QtCore.QEvent.Clipboard)
            self.app.sendEvent(self.app.clipboard(), event)
            self.tray.hide()
        self.app.aboutToQuit.connect(clean_up)

        # main loop
        self.app.exec_()
        # on some platforms the exec_ call may not return, so use clean_up()
