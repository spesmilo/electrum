#!/usr/bin/env python3
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

import signal, sys, traceback, gc

try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import PyQt5.QtCore as QtCore

from electroncash.i18n import _, set_language
from electroncash.plugins import run_hook
from electroncash import WalletStorage
from electroncash.util import UserCancelled, Weak, print_error
from electroncash.networks import NetworkConstants

from .installwizard import InstallWizard, GoBack

from . import icons # This needs to be imported once app-wide then the :icons/ namespace becomes available for Qt icon filenames.
from .util import *   # * needed for plugins
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog
from .exception_window import Exception_Hook


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        self.windows = windows
        super(OpenFileEventFilter, self).__init__()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toString())
                return True
        return False


class QElectrumApplication(QApplication):
    new_window_signal = pyqtSignal(str, object)


class ElectrumGui:

    def __init__(self, config, daemon, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #if daemon.network:
        #    from electroncash.util import DebugMem
        #    from electroncash.wallet import Abstract_Wallet
        #    from electroncash.verifier import SPV
        #    from electroncash.synchronizer import Synchronizer
        #    daemon.network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                                       ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electron-cash.desktop')
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.windows = []
        self.weak_windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QElectrumApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.timer = QTimer(self.app); self.timer.setSingleShot(False); self.timer.setInterval(500) #msec
        self.gc_timer = QTimer(self.app); self.gc_timer.setSingleShot(True); self.gc_timer.timeout.connect(ElectrumGui.gc); self.gc_timer.setInterval(333) #msec
        self.nd = None
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Electron Cash')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.app.new_window_signal.connect(self.start_new_window)
        run_hook('init_qt', self)
        ColorScheme.update_from_widget(QWidget())

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
        m.addAction(_("Exit Electron Cash"), self.close)
        self.tray.setContextMenu(m)

    def tray_icon(self):
        if self.dark_icon:
            return QIcon(':icons/electron_dark_icon.png')
        else:
            return QIcon(':icons/electron_light_icon.png')

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
            parent.show_warning(_('You are using Electron Cash in offline mode; restart Electron Cash if you want to get connected'), title=_('Offline'))
            return
        if self.nd:
            self.nd.on_update()
            self.nd.show()
            self.nd.raise_()
            return
        self.nd = NetworkDialog(self.daemon.network, self.config)
        self.nd.show()

    def create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        dname = w.diagnostic_name()
        def onFinalized(wr,dname=dname):
            print_error("[{}] finalized".format(dname))
            self.weak_windows.remove(wr)
        self.weak_windows.append(Weak.ref(w,onFinalized))
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
            try:
                wallet = self.daemon.load_wallet(path, None)
                if not wallet:
                    storage = WalletStorage(path, manual_upgrades=True)
                    wizard = InstallWizard(self.config, self.app, self.plugins, storage)
                    try:
                        wallet = wizard.run_and_get_wallet()
                    except UserCancelled:
                        pass
                    except GoBack as e:
                        print_error('[start_new_window] Exception caught (GoBack)', e)
                    finally:
                        wizard.terminate()
                        del wizard
                        gc.collect() # wizard sticks around in memory sometimes, otherwise :/
                    if not wallet:
                        return
                    wallet.start_threads(self.daemon.network)
                    self.daemon.add_wallet(wallet)
            except BaseException as e:
                traceback.print_exc(file=sys.stdout)
                if '2fa' in str(e):
                    d = QMessageBoxMixin(QMessageBox.Warning, _('Error'), '2FA wallets for Bitcoin Cash are currently unsupported by <a href="https://api.trustedcoin.com/#/">TrustedCoin</a>. Follow <a href="https://github.com/Electron-Cash/Electron-Cash/issues/41#issuecomment-357468208">this guide</a> in order to recover your funds.')
                    d.exec_()
                else:
                    d = QMessageBoxMixin(QMessageBox.Warning, _('Error'), 'Cannot load wallet:\n' + str(e))
                    d.exec_()
                return
            w = self.create_window_for_wallet(wallet)
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
        # GC on ElectrumWindows takes forever to actually happen due to the
        # circular reference zoo they create around them (they end up stuck in
        # generation 2 for a long time before being collected). The below
        # schedules a more comprehensive GC to happen in the very near future.
        # This mechanism takes on the order of 40-100ms to execute (depending
        # on hardware) but frees megabytes of memory after closing a window
        # (which itslef is a relatively infrequent UI event, so it's
        # an acceptable tradeoff).
        self.gc_schedule()

    def gc_schedule(self):
        ''' Schedule garbage collection to happen in the near future.
        Note that rapid-fire calls to this re-start the timer each time, thus
        only the last call takes effect (it's rate-limited). '''
        self.gc_timer.start() # start/re-start the timer to fire exactly once in timeInterval() msecs
        
    @staticmethod
    def gc():
        ''' self.gc_timer timeout() slot '''
        gc.collect()

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
        if not self.start_new_window(path, self.config.get('url')):
            return
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        def quit_after_last_window():
            # on some platforms, not only does exec_ not return but not even
            # aboutToQuit is emitted (but following this, it should be emitted)
            if self.app.quitOnLastWindowClosed():
                self.app.quit()
        self.app.lastWindowClosed.connect(quit_after_last_window)

        def clean_up():
            # Just in case we get an exception as we exit, uninstall the Exception_Hook
            Exception_Hook.uninstall()
            # Shut down the timer cleanly
            self.timer.stop()
            self.gc_timer.stop()
            # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
            event = QtCore.QEvent(QtCore.QEvent.Clipboard)
            self.app.sendEvent(self.app.clipboard(), event)
            self.tray.hide()
        self.app.aboutToQuit.connect(clean_up)

        Exception_Hook(self.config) # This wouldn't work anyway unless the app event loop is active, so we must install it once here and no earlier.
        # main loop
        self.app.exec_()
        # on some platforms the exec_ call may not return, so use clean_up()
