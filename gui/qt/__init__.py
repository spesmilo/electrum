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

from electroncash.i18n import _, set_language
from electroncash.plugins import run_hook
from electroncash import WalletStorage
from electroncash.util import (UserCancelled, Weak, PrintError, print_error,
                               standardize_path)

from .installwizard import InstallWizard, GoBack

from . import icons # This needs to be imported once app-wide then the :icons/ namespace becomes available for Qt icon filenames.
from .util import *   # * needed for plugins
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog
from .exception_window import Exception_Hook
from .update_checker import UpdateChecker


class ElectrumGui(QObject, PrintError):
    new_window_signal = pyqtSignal(str, object)

    def __init__(self, config, daemon, plugins):
        super(__class__, self).__init__() # QObject init
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
        QCoreApplication.setAttribute(Qt.AA_X11InitThreads)
        if hasattr(Qt, "AA_ShareOpenGLContexts"):
            QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electron-cash.desktop')
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.windows = []
        self.weak_windows = []
        self.app = QApplication(sys.argv)
        self.app.installEventFilter(self)
        self.timer = QTimer(self); self.timer.setSingleShot(False); self.timer.setInterval(500) #msec
        self.gc_timer = QTimer(self); self.gc_timer.setSingleShot(True); self.gc_timer.timeout.connect(ElectrumGui.gc); self.gc_timer.setInterval(333) #msec
        self.nd = None
        self.update_checker = UpdateChecker()
        self.update_checker_timer = QTimer(self); self.update_checker_timer.timeout.connect(self.on_auto_update_timeout); self.update_checker_timer.setSingleShot(False)
        self.update_checker.got_new_version.connect(lambda x: self.show_update_checker(parent=None, skip_check=True))
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Electron Cash')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.new_window_signal.connect(self.start_new_window)
        self.set_dark_theme_if_needed()
        if self.has_auto_update_check():
            self._start_auto_update_timer(first_run = True)
        run_hook('init_qt', self)
        ColorScheme.update_from_widget(QWidget())

    def is_dark_theme_available(self):
        try:
            import qdarkstyle
        except:
            return False
        return True

    def set_dark_theme_if_needed(self):
        use_dark_theme = self.config.get('qt_gui_color_theme', 'default') == 'dark'
        if use_dark_theme:
            try:
                import qdarkstyle
                self.app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
            except BaseException as e:
                use_dark_theme = False
                self.print_error('Error setting dark theme: {}'.format(repr(e)))
        # Even if we ourselves don't set the dark theme,
        # the OS/window manager/etc might set *a dark theme*.
        # Hence, try to choose colors accordingly:
        ColorScheme.update_from_widget(QWidget(), force_dark=use_dark_theme)

    def eventFilter(self, obj, event):
        ''' This event filter allows us to open bitcoincash: URIs on macOS '''
        if event.type() == QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toString())
                return True
        return False

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
        m.addAction(_("&Check for updates..."), lambda: self.show_update_checker(None))
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
        self.new_window_signal.emit(path, uri)

    def show_network_dialog(self, parent):
        if self.warn_if_no_network(parent):
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
        path = standardize_path(path)  # just make sure some plugin didn't give us a symlink
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
                        self.print_error('[start_new_window] Exception caught (GoBack)', e)
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
                    self.warning(title=_('Error'), message = '2FA wallets for Bitcoin Cash are currently unsupported by <a href="https://api.trustedcoin.com/#/">TrustedCoin</a>. Follow <a href="https://github.com/Electron-Cash/Electron-Cash/issues/41#issuecomment-357468208">this guide</a> in order to recover your funds.')
                else:
                    self.warning(title=_('Error'), message = 'Cannot load wallet:\n' + str(e))
                return
            w = self.create_window_for_wallet(wallet)
        if uri:
            w.pay_to_URI(uri)
        w.bring_to_top()
        w.setWindowState(w.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)

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

    def show_update_checker(self, parent, *, skip_check = False):
        if self.warn_if_no_network(parent):
            return
        self.update_checker.show()
        self.update_checker.raise_()
        if not skip_check:
            self.update_checker.do_check()

    def on_auto_update_timeout(self):
        if not self.daemon.network:
            # auto-update-checking never is done in offline mode
            self.print_error("Offline mode; update check skipped")
        elif not self.update_checker.did_check_recently():  # make sure auto-check doesn't happen right after a manual check.
            self.update_checker.do_check()
        if self.update_checker_timer.first_run:
            self._start_auto_update_timer(first_run = False)

    def _start_auto_update_timer(self, *, first_run = False):
        self.update_checker_timer.first_run = bool(first_run)
        if first_run:
            interval = 10.0*1e3 # do it very soon (in 10 seconds)
        else:
            interval = 3600.0*1e3 # once per hour (in ms)
        self.update_checker_timer.start(interval)
        self.print_error("Auto update check: interval set to {} seconds".format(interval//1e3))

    def _stop_auto_update_timer(self):
        self.update_checker_timer.stop()
        self.print_error("Auto update check: disabled")

    def warn_if_no_network(self, parent):
        if not self.daemon.network:
            self.warning(message=_('You are using Electron Cash in offline mode; restart Electron Cash if you want to get connected'), title=_('Offline'), parent=parent)
            return True
        return False

    def warning(self, title, message, icon = QMessageBox.Warning, parent = None):
        if isinstance(parent, MessageBoxMixin):
            parent.msg_box(title=title, text=message, icon=icon, parent=None)
        else:
            parent = parent if isinstance(parent, QWidget) else None
            d = QMessageBoxMixin(QMessageBox.Warning, title, message, QMessageBox.Ok, parent)
            d.setWindowModality(Qt.WindowModal if parent else Qt.ApplicationModal)
            d.exec_()
            d.setParent(None)

    def has_auto_update_check(self):
        return bool(self.config.get('auto_update_check', True))

    def set_auto_update_check(self, b):
        was, b = self.has_auto_update_check(), bool(b)
        if was != b:
            self.config.set_key('auto_update_check', b, save=True)
            if b:
                self._start_auto_update_timer()
            else:
                self._stop_auto_update_timer()

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
            self._stop_auto_update_timer()
            # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
            event = QEvent(QEvent.Clipboard)
            self.app.sendEvent(self.app.clipboard(), event)
            self.tray.hide()
        self.app.aboutToQuit.connect(clean_up)

        Exception_Hook(self.config) # This wouldn't work anyway unless the app event loop is active, so we must install it once here and no earlier.
        # main loop
        self.app.exec_()
        # on some platforms the exec_ call may not return, so use clean_up()
