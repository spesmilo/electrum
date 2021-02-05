#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

import gc
import os
import platform
import shutil
import signal
import sys
import traceback

try:
    import PyQt5
except Exception:
    if sys.platform.startswith('win'):
        msg = ("\n\nError: Could not import PyQt5.\n"
               "If you are running the release .exe, this is a bug (please"
               " contact the developers in that case).\n"
               "If you are running from source, then you may try this from the command-line:\n\n"
               "    python -m pip install pyqt5\n\n")
    elif sys.platform.startswith('darw'):
        msg = ("\n\nError: Could not import PyQt5.\n"
               "If you are running the release .app, this is a bug (please"
               " contact the developers in that case).\n"
               "If you are running from source, then you may try this from the command-line:\n\n"
               "    python3 -m pip install --user -I pyqt5\n\n")
    else:
        msg = ("\n\nError: Could not import PyQt5.\n"
               "You may try:\n\n"
               "    python3 -m pip install --user -I pyqt5\n\n"
               "Or, if on Linux Ubuntu, Debian, etc:\n\n"
               "    sudo apt-get install python3-pyqt5\n\n")
    sys.exit(msg)

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

from electroncash.i18n import _
from electroncash import i18n
from electroncash.plugins import run_hook
from electroncash import WalletStorage
from electroncash.util import (UserCancelled, PrintError, print_error,
                               standardize_path, finalization_print_error, Weak,
                               get_new_wallet_name, Handlers)
from electroncash import version
from electroncash.address import Address

from .installwizard import InstallWizard, GoBack

from . import icons # This needs to be imported once app-wide then the :icons/ namespace becomes available for Qt icon filenames.
from .util import *   # * needed for plugins
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog
from .exception_window import Exception_Hook
from .update_checker import UpdateChecker


class ElectrumGui(QObject, PrintError):
    new_window_signal = pyqtSignal(str, object)
    update_available_signal = pyqtSignal(bool)
    cashaddr_toggled_signal = pyqtSignal()  # app-wide signal for when cashaddr format is toggled. This used to live in each ElectrumWindow instance but it was recently refactored to here.
    cashaddr_status_button_hidden_signal = pyqtSignal(bool)  # app-wide signal for when cashaddr toggle button is hidden from the status bar
    shutdown_signal = pyqtSignal()  # signal for requesting an app-wide full shutdown
    do_in_main_thread_signal = pyqtSignal(object, object, object)

    instance = None

    def __init__(self, config, daemon, plugins):
        super(__class__, self).__init__() # QObject init
        assert __class__.instance is None, "ElectrumGui is a singleton, yet an instance appears to already exist! FIXME!"
        __class__.instance = self
        i18n.set_language(config.get('language'))

        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.windows = []

        self._setup_do_in_main_thread_handler()

        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #if daemon.network:
        #    from electroncash.util import DebugMem
        #    from electroncash.wallet import Abstract_Wallet
        #    from electroncash.verifier import SPV
        #    from electroncash.synchronizer import Synchronizer
        #    daemon.network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                                       ElectrumWindow], interval=5)])

        call_after_app = self._pre_and_post_app_setup()
        try:
            self.app = QApplication(sys.argv)
        finally:
            call_after_app()

        self._load_fonts()  # this needs to be done very early, before the font engine loads fonts.. out of paranoia
        self._exit_if_required_pyqt_is_missing()  # This may immediately exit the app if missing required PyQt5 modules, so it should also be done early.
        self.new_version_available = None
        self._set_icon()
        self.app.installEventFilter(self)
        self.timer = QTimer(self); self.timer.setSingleShot(False); self.timer.setInterval(500) #msec
        self.gc_timer = QTimer(self); self.gc_timer.setSingleShot(True); self.gc_timer.timeout.connect(ElectrumGui.gc); self.gc_timer.setInterval(500) #msec
        self.nd = None
        self._last_active_window = None  # we remember the last activated ElectrumWindow as a Weak.ref
        Address.show_cashaddr(self.is_cashaddr())
        # Dark Theme -- ideally set this before any widgets are created.
        self.set_dark_theme_if_needed()
        # /
        # Wallet Password Cache
        # wallet -> (password, QTimer) map for some plugins (like CashShuffle)
        # that need wallet passwords to operate, and we don't want to prompt
        # for pw twice right after the InstallWizard runs (see #106).
        # Entries in this map are deleted after 10 seconds by the QTimer (which
        # also deletes itself)
        self._wallet_password_cache = Weak.KeyDictionary()
        # /
        self.update_checker = UpdateChecker()
        self.update_checker_timer = QTimer(self); self.update_checker_timer.timeout.connect(self.on_auto_update_timeout); self.update_checker_timer.setSingleShot(False)
        self.update_checker.got_new_version.connect(self.on_new_version)
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), self)
        self.tray.setToolTip('Electron Cash')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.new_window_signal.connect(self.start_new_window)
        if self.has_auto_update_check():
            self._start_auto_update_timer(first_run = True)
        self.app.focusChanged.connect(self.on_focus_change)  # track last window the user interacted with
        self.shutdown_signal.connect(self.close, Qt.QueuedConnection)
        run_hook('init_qt', self)
        # We did this once already in the set_dark_theme call, but we do this
        # again here just in case some plugin modified the color scheme.
        ColorScheme.update_from_widget(QWidget())

        self._check_and_warn_qt_version()

    def __del__(self):
        stale = True
        if __class__.instance is self:
            stale = False
            __class__.instance = None
        print_error("[{}] finalized{}".format(__class__.__name__, ' (stale instance)' if stale else ''))
        if hasattr(super(), '__del__'):
            super().__del__()

    def _setup_do_in_main_thread_handler(self):
        ''' Sets up "do_in_main_thread" handler mechanism for Qt GUI. '''
        self.do_in_main_thread_signal.connect(self._do_in_main_thread_handler_slot)
        orig_handler = Handlers.do_in_main_thread
        weakSelf = Weak.ref(self)
        def my_do_in_main_thread_handler(func, *args, **kwargs):
            strongSelf = weakSelf()
            if strongSelf:
                # We are still alive, emit the signal which will be handled
                # in the main thread.
                strongSelf.do_in_main_thread_signal.emit(func, args, kwargs)
            else:
                # We died. Uninstall this handler, invoke original handler.
                Handlers.do_in_main_thread = orig_handler
                orig_handler(func, *args, **kwargs)
        Handlers.do_in_main_thread = my_do_in_main_thread_handler

    def _do_in_main_thread_handler_slot(self, func, args, kwargs):
        """
        Hooked in to util.Handlers.do_in_main_thread via the
        do_in_main_thread_signal. This ensures that there is an app-wide
        mechanism for posting invocations to the main thread.  Currently
        CashFusion uses this mechanism, but other code may as well.
        """
        func(*args, **kwargs)

    def _pre_and_post_app_setup(self):
        """
        Call this before instantiating the QApplication object.  It sets up
        some platform-specific miscellany that need to happen before the
        QApplication is constructed.

        A function is returned.  This function *must* be called after the
        QApplication is constructed.
        """
        callables = []
        def call_callables():
            for func in callables:
                func()
        ret = call_callables

        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electron-cash.desktop')

        if self.windows_qt_use_freetype:
            # Use FreeType for font rendering on Windows. This fixes rendering
            # of the Schnorr sigil and allows us to load the Noto Color Emoji
            # font if needed.
            os.environ['QT_QPA_PLATFORM'] = 'windows:fontengine=freetype'

        QCoreApplication.setAttribute(Qt.AA_X11InitThreads)
        if hasattr(Qt, "AA_ShareOpenGLContexts"):
            QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        if sys.platform not in ('darwin',) and hasattr(Qt, "AA_EnableHighDpiScaling"):
            # The below only applies to non-macOS. On macOS this setting is
            # never used (because it is implicitly auto-negotiated by the OS
            # in a differernt way).
            #
            # qt_disable_highdpi will be set to None by default, or True if
            # specified on command-line.  The command-line override is intended
            # to supporess high-dpi mode just for this run for testing.
            #
            # The more permanent setting is qt_enable_highdpi which is the GUI
            # preferences option, so we don't enable highdpi if it's explicitly
            # set to False in the GUI.
            #
            # The default on Linux, Windows, etc is to enable high dpi
            disable_scaling = self.config.get('qt_disable_highdpi', False)
            enable_scaling = self.config.get('qt_enable_highdpi', True)
            if not disable_scaling and enable_scaling:
                QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
        if hasattr(Qt, "AA_UseHighDpiPixmaps"):
            QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

        # Set mac_ver to the appropriate macOS version e.g.: (10,15,1) for Catalina, etc or None if not macOS
        mac_ver = None
        if sys.platform in ('darwin',):
            try:
                mac_ver = tuple(int(a) for a in platform.mac_ver()[0].split('.'))
                self.print_error("macOS version:", mac_ver)
            except (TypeError, ValueError) as e:
                self.print_error("WARNING: Cannot parse platform.mac_ver:", repr(e))

        # macOS Mojave "font rendering looks terrible on PyQt5.11" workaround.
        # See: https://old.reddit.com/r/apple/comments/9leavs/fix_mojave_font_rendering_issues_on_a_perapp_basis/
        # This affects PyQt 5.11 (which is what we ship in the macOS El Capitan
        # .dmg).  We apply the workaround and also warn the user to not use
        # the El Capitan compatibility .dmg.
        if mac_ver and mac_ver >= (10, 14) and self.qt_version() < (5, 12):
            # macOS hacks. On Mojave with PyQt <5.12 the font rendering is terrible.
            # As a workaround we need to temporarily set this 'defaults' keys
            # which we immediately disable after the QApplication is started.
            from electroncash.utils import macos
            self.print_error("Mojave+ with PyQt<5.12 detected; applying CGFontRenderingFontSmoothingDisabled workaround...")
            bundle = macos.get_bundle_identifier()
            os.system(f'defaults write {bundle} CGFontRenderingFontSmoothingDisabled -bool NO')
            def undo_hack():
                os.system(f'defaults delete {bundle} CGFontRenderingFontSmoothingDisabled')
                self.print_error("Mojave+ font rendering workaround applied.")

            callables.append(undo_hack)

        # macOS Big Sur workaround for Qt>=5.13.2 sometimes not working at all
        # See: https://bugreports.qt.io/browse/QTBUG-87014
        # See also: https://stackoverflow.com/questions/64818879/is-there-any-solution-regarding-to-pyqt-library-doesnt-work-in-mac-os-big-sur
        if mac_ver and mac_ver >= (10, 16) and self.qt_version() >= (5, 13, 2) and self.qt_version() < (5, 15, 2):
            # Setting this env var causes Qt to use some other macOS API that always works on Big Sur
            os.environ['QT_MAC_WANTS_LAYER'] = '1'
            self.print_error(f"macOS Big Sur Qt workaround applied")

        def setup_layout_direction():
            """Sets the app layout direction depending on language. To be called
            after self.app is created successfully. Note this *MUST* be called
            after set_language has been called."""
            assert i18n.set_language_called > 0
            lc = i18n.language.info().get('language')
            lc = '' if not isinstance(lc, str) else lc
            lc = lc.split('_')[0]
            layout_direction = Qt.LeftToRight
            blurb = "left-to-right"
            if lc in {'ar', 'fa', 'he', 'ps', 'ug', 'ur'}:  # Right-to-left languages
                layout_direction = Qt.RightToLeft
                blurb = "right-to-left"
            self.print_error("Setting layout direction:", blurb)
            self.app.setLayoutDirection(layout_direction)
        # callable will be called after self.app is set-up successfully
        callables.append(setup_layout_direction)

        return ret

    def _exit_if_required_pyqt_is_missing(self):
        ''' Will check if required PyQt5 modules are present and if not,
        display an error message box to the user and immediately quit the app.

        This is because some Linux systems break up PyQt5 into multiple
        subpackages, and for instance PyQt5 QtSvg is its own package, and it
        may be missing.
        '''
        try:
            from PyQt5 import QtSvg
        except ImportError:
            # Closes #1436 -- Some "Run from source" Linux users lack QtSvg
            # (partial PyQt5 install)
            msg = _("A required Qt module, QtSvg was not found. Please fully install all of PyQt5 5.12 or above to resolve this issue.")
            if sys.platform == 'linux':
                msg += "\n\n" + _("On Linux, you may try:\n\n    python3 -m pip install --user -I pyqt5")
                if shutil.which('apt'):
                    msg += "\n\n" + _("On Debian-based distros, you can run:\n\n    sudo apt install python3-pyqt5.qtsvg")

            QMessageBox.critical(None, _("QtSvg Missing"), msg)  # this works even if app is not exec_() yet.
            self.app.exit(1)
            sys.exit(msg)

    def is_dark_theme_available(self):
        if sys.platform in ('darwin',):
            # On OSX, qdarkstyle is kind of broken. We instead rely on Mojave
            # dark mode if (built in to the OS) for this facility, which the
            # user can set outside of this application.
            return False
        try:
            import qdarkstyle
        except:
            return False
        return True

    def set_dark_theme_if_needed(self):
        if sys.platform in ('darwin',):
            # On OSX, qdarkstyle is kind of broken. We instead rely on Mojave
            # dark mode if (built in to the OS) for this facility, which the
            # user can set outside of this application.
            use_dark_theme = False
        else:
            use_dark_theme = self.config.get('qt_gui_color_theme', 'default') == 'dark'
        darkstyle_ver = None
        if use_dark_theme:
            try:
                import qdarkstyle
                self.app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
                try:
                    darkstyle_ver = version.normalize_version(qdarkstyle.__version__)
                except (ValueError, IndexError, TypeError, NameError, AttributeError) as e:
                    self.print_error("Warning: Could not determine qdarkstyle version:", repr(e))
            except BaseException as e:
                use_dark_theme = False
                self.print_error('Error setting dark theme: {}'.format(repr(e)))
        # Apply any necessary stylesheet patches. For now this only does anything
        # if the version is < 2.6.8.
        # 2.6.8+ seems to have fixed all the issues (for now!)
        from . import style_patcher
        style_patcher.patch(dark=use_dark_theme, darkstyle_ver=darkstyle_ver)
        # Even if we ourselves don't set the dark theme,
        # the OS/window manager/etc might set *a dark theme*.
        # Hence, try to choose colors accordingly:
        ColorScheme.update_from_widget(QWidget(), force_dark=use_dark_theme)

    def get_cached_password(self, wallet):
        ''' Passwords in the cache only live for a very short while (10 seconds)
        after wallet window creation, and only if it's a new window. This
        mechanism is a convenience for plugins that need access to the wallet
        password and it would make for poor UX for the user to enter their
        password twice when opening a new window '''
        entry = self._wallet_password_cache.get(wallet)
        if entry:
            return entry[0]

    def _expire_cached_password(self, weakWallet):
        ''' Timer callback, called after 10 seconds. '''
        wallet = weakWallet() if isinstance(weakWallet, Weak.ref) else weakWallet
        if wallet:
            entry = self._wallet_password_cache.pop(wallet, None)
            if entry:
                timer = entry[1]
                timer.stop(); timer.deleteLater()

    def _cache_password(self, wallet, password):
        self._expire_cached_password(wallet)
        if password is None:
            return
        timer = QTimer()  # NB a top-level parentless QObject will get delete by Python when its Python refct goes to 0, which is what we want here. Future programmers: Do not give this timer a parent!
        self._wallet_password_cache[wallet] = (password, timer)
        weakWallet = Weak.ref(wallet)
        weakSelf = Weak.ref(self)
        def timeout():
            slf = weakSelf()
            slf and slf._expire_cached_password(weakWallet)
        timer.setSingleShot(True); timer.timeout.connect(timeout); timer.start(10000)  # 10 sec

    def cache_password(self, wallet, password):
        self._cache_password(wallet, password)

    def _set_icon(self):
        icon = None
        if sys.platform == 'darwin':
            # on macOS, in "running from source" mode, we want to set the app
            # icon, otherwise we get the generic Python icon.
            # In non-running-from-source mode, macOS will get the icon from
            # the .app bundle Info.plist spec (which ends up being
            # electron.icns).  However, in .app mode, Qt will not know about
            # this icon and won't be able to use it for e.g. the About dialog.
            # In the latter case the branch below will tell Qt to use
            # electron-cash.svg as the "window icon".
            icon = QIcon("electron.icns") if os.path.exists("electron.icns") else None
        if not icon:
            # Set this on all other platforms (and macOS built .app) as it can
            # only help and never harm, and is always available.
            icon = QIcon(":icons/electron-cash.svg")
        if icon:
            self.app.setWindowIcon(icon)

    @staticmethod
    def qt_version() -> tuple:
        ''' Returns a 3-tuple of the form (major, minor, revision) eg
        (5, 12, 4) for the current Qt version derived from the QT_VERSION
        global provided by Qt. '''
        return ( (QT_VERSION >> 16) & 0xff,  (QT_VERSION >> 8) & 0xff, QT_VERSION & 0xff )

    def _load_fonts(self):
        ''' All apologies for the contorted nature of this platform code.
        Fonts on Windows & Linux are .. a sensitive situation. :) '''
        # Only load the emoji font on Linux and Windows
        if sys.platform not in ('linux', 'win32', 'cygwin'):
            return

        # TODO: Check if we already have the needed emojis
        # TODO: Allow the user to download a full color emoji set

        linux_font_config_file = os.path.join(os.path.dirname(__file__), 'data', 'fonts.xml')
        emojis_ttf_name = 'ecsupplemental_lnx.ttf'
        emojis_ttf_path = os.path.join(os.path.dirname(__file__), 'data', emojis_ttf_name)
        did_set_custom_fontconfig = False

        if (sys.platform == 'linux'
                and self.linux_qt_use_custom_fontconfig  # method-backed property, checks config settings
                and not os.environ.get('FONTCONFIG_FILE')
                and os.path.exists('/etc/fonts/fonts.conf')
                and os.path.exists(linux_font_config_file)
                and os.path.exists(emojis_ttf_path)
                and self.qt_version() >= (5, 12)):  # doing this on Qt < 5.12 causes harm and makes the whole app render fonts badly
            # On Linux, we override some fontconfig rules by loading our own
            # font config XML file. This makes it so that our custom emojis and
            # other needed glyphs are guaranteed to get picked up first,
            # regardless of user font config.  Without this some Linux systems
            # had black and white or missing emoji glyphs.  We only do this if
            # the user doesn't have their own fontconfig file in env and
            # also as a sanity check, if they have the system
            # /etc/fonts/fonts.conf file in the right place.
            os.environ['FONTCONFIG_FILE'] = linux_font_config_file
            did_set_custom_fontconfig = True

        if sys.platform in ('win32', 'cygwin'):
            env_var = os.environ.get('QT_QPA_PLATFORM')
            if not env_var or 'windows:fontengine=freetype' not in env_var.lower():
                # not set up to use freetype, so loading the .ttf would fail.
                # abort early.
                return
            del env_var
            # use a different .ttf file on Windows
            emojis_ttf_name = 'ecsupplemental_win.ttf'
            emojis_ttf_path = os.path.join(os.path.dirname(__file__), 'data', emojis_ttf_name)

        if QFontDatabase.addApplicationFont(emojis_ttf_path) < 0:
            self.print_error('Failed to add unicode emoji font to application fonts:', emojis_ttf_path)
            if did_set_custom_fontconfig:
                self.print_error('Deleting custom (fonts.xml) FONTCONFIG_FILE env. var')
                del os.environ['FONTCONFIG_FILE']

    def _check_and_warn_qt_version(self):
        if sys.platform == 'linux' and self.qt_version() < (5, 12):
            msg = _("Electron Cash on Linux requires PyQt5 5.12+.\n\n"
                    "You have version {version_string} installed.\n\n"
                    "Please upgrade otherwise you may experience "
                    "font rendering issues with emojis and other unicode "
                    "characters used by Electron Cash.").format(version_string=QT_VERSION_STR)
            QMessageBox.warning(None, _("PyQt5 Upgrade Needed"), msg)  # this works even if app is not exec_() yet.


    def eventFilter(self, obj, event):
        ''' This event filter allows us to open bitcoincash: URIs on macOS '''
        if event.type() == QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toString())
                return True
        return False

    def build_tray_menu(self):
        ''' Rebuild the tray menu by tearing it down and building it new again '''
        m_old = self.tray.contextMenu()
        if m_old is not None:
            # Tray does NOT take ownership of menu, so we are tasked with
            # deleting the old one. Note that we must delete the old one rather
            # than just clearing it because otherwise the old sub-menus stick
            # around in Qt. You can try calling qApp.topLevelWidgets() to
            # convince yourself of this.  Doing it this way actually cleans-up
            # the menus and they do not leak.
            m_old.clear()
            m_old.deleteLater()  # C++ object and its children will be deleted later when we return to the event loop
        m = QMenu()
        m.setObjectName("SysTray.QMenu")
        self.tray.setContextMenu(m)
        destroyed_print_error(m)
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
            return QIcon(':icons/electron_dark_icon.svg')
        else:
            return QIcon(':icons/electron_light_icon.svg')

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
        for window in list(self.windows):
            window.close()

    def new_window(self, path, uri=None):
        # Use a signal as can be called from daemon thread
        self.new_window_signal.emit(path, uri)

    def show_network_dialog(self, parent, *, jumpto : str = ''):
        if self.warn_if_no_network(parent):
            return
        if self.nd:
            self.nd.on_update()
            run_hook("on_network_dialog", self.nd)
            self.nd.show()
            self.nd.raise_()
            if jumpto: self.nd.jumpto(jumpto)
            return
        self.nd = NetworkDialog(self.daemon.network, self.config)
        run_hook("on_network_dialog", self.nd)
        self.nd.show()
        if jumpto: self.nd.jumpto(jumpto)

    def create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        finalization_print_error(w, "[{}] finalized".format(w.diagnostic_name()))
        self.build_tray_menu()
        run_hook('on_new_window', w)
        return w

    def get_wallet_folder(self):
        ''' may raise FileNotFoundError '''
        return os.path.dirname(os.path.abspath(self.config.get_wallet_path()))

    def get_new_wallet_path(self):
        ''' may raise FileNotFoundError '''
        wallet_folder = self.get_wallet_folder()
        filename = get_new_wallet_name(wallet_folder)
        full_path = os.path.join(wallet_folder, filename)
        return full_path

    def on_focus_change(self, ignored, new_focus_widget):
        ''' Remember the last wallet window that was activated because
        start_new_window uses this information.  We store the ElectrumWindow
        in a weak reference so that we don't interfere with its gc when it is
        closed.'''
        if not new_focus_widget:
            return
        if isinstance(new_focus_widget, QWidget):
            window = QWidget.window(new_focus_widget)  # call base class because some widgets may actually override 'window' with Python attributes.
            if isinstance(window, ElectrumWindow):
                self._last_active_window = Weak.ref(window)

    def start_new_window(self, path, uri):
        '''Raises the window for the wallet if it is open. Otherwise
        opens the wallet and creates a new window for it.

        `path=None` is a special usage which will raise the last activated
        window or open the 'last wallet' if no windows are open.'''

        if not path:
            if not self.windows:
                # This branch is taken if nothing is currently open but
                # path == None, in which case set path=last wallet
                self.config.open_last_wallet()
                path = self.config.get_wallet_path()
            elif self._last_active_window:
                # This branch is taken if we have windows open and we have
                # _last_active_window defined, in which case we specify
                # that this window should be activated by setting path
                # so that the for loop below will trigger on this window.
                w = self._last_active_window()  # weak ref -> strong ref
                if w and w in self.windows:  # check ref still alive
                    # this will cause the last active window to be used in the
                    # for loop below
                    path = w.wallet.storage.path

        # NB: path may still be None here if it came in as None from args and
        # if the above logic couldn't select a window to use -- in which case
        # we'll end up picking self.windows[0]

        path = path and standardize_path(path) # just make sure some plugin didn't give us a symlink
        for w in self.windows:
            if not path or w.wallet.storage.path == path:
                path = w.wallet.storage.path  # remember path in case it was None
                w.bring_to_top()
                break
        else:
            try:

                if not self.windows:
                    self.warn_if_no_secp(relaxed=True)

                try:
                    wallet = self.daemon.load_wallet(path, None)
                except BaseException as e:
                    self.print_error(repr(e))
                    if self.windows:
                        # *Not* starting up. Propagate exception out to present
                        # error message box to user.
                        raise e
                    # We're just starting up, so we are tolerant of bad wallets
                    # and just want to proceed to the InstallWizard so the user
                    # can either specify a different wallet or create a new one.
                    # (See issue #1189 where before they would get stuck)
                    path = self.get_new_wallet_path()  # give up on this unknown wallet and try a new name.. note if things get really bad this will raise FileNotFoundError and the app aborts here.
                    wallet = None  # fall thru to wizard
                if not wallet:
                    storage = WalletStorage(path, manual_upgrades=True)
                    wizard = InstallWizard(self.config, self.app, self.plugins, storage)
                    try:
                        wallet, password = wizard.run_and_get_wallet() or (None, None)
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
                    self._cache_password(wallet, password)
            except BaseException as e:
                traceback.print_exc(file=sys.stdout)
                if '2fa' in str(e):
                    self.warning(title=_('Error'), message = '2FA wallets for Bitcoin Cash are currently unsupported by <a href="https://api.trustedcoin.com/#/">TrustedCoin</a>. Follow <a href="https://github.com/Electron-Cash/Electron-Cash/issues/41#issuecomment-357468208">this guide</a> in order to recover your funds.')
                else:
                    self.warning(title=_('Error'), message = 'Cannot load wallet:\n' + str(e), icon=QMessageBox.Critical)
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

        if not self.windows:
            self.config.save_last_wallet(window.wallet)
            # NB: We see if we should quit the app after the last wallet
            # window is closed, even if a network dialog or some other window is
            # open.  It was bizarre behavior to keep the app open when
            # things like a transaction dialog or the network dialog were still
            # up.
            self._quit_after_last_window()  # central point that checks if we should quit.

        #window.deleteLater()  # <--- This has the potential to cause bugs (esp. with misbehaving plugins), so commented-out. The object gets deleted anyway when Python GC kicks in. Forcing a delete may risk python to have a dangling reference to a deleted C++ object.

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

    def on_new_version(self, newver):
        ''' Called by the auto update check mechanism to notify
        that a new version is available.  We propagate the signal out
        using our own update_available_signal as well as post a message
        to the system tray. '''
        self.new_version_available = newver
        self.update_available_signal.emit(True)
        self.notify(_("A new version of Electron Cash is available: {}").format(newver))

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
            interval = 4.0*3600.0*1e3 # once every 4 hours (in ms)
        self.update_checker_timer.start(interval)
        self.print_error("Auto update check: interval set to {} seconds".format(interval//1e3))

    def _stop_auto_update_timer(self):
        self.update_checker_timer.stop()
        self.print_error("Auto update check: disabled")

    def warn_if_cant_import_qrreader(self, parent, show_warning=True):
        ''' Checks it QR reading from camera is possible.  It can fail on a
        system lacking QtMultimedia.  This can be removed in the future when
        we are unlikely to encounter Qt5 installations that are missing
        QtMultimedia '''
        try:
            from .qrreader import QrReaderCameraDialog
        except ImportError as e:
            if show_warning:
                self.warning(parent=parent,
                             title=_("QR Reader Error"),
                             message=_("QR reader failed to load. This may "
                                       "happen if you are using an older version "
                                       "of PyQt5.<br><br>Detailed error: ") + str(e),
                             rich_text=True)
            return True
        return False

    def warn_if_no_network(self, parent):
        if not self.daemon.network:
            self.warning(message=_('You are using Electron Cash in offline mode; restart Electron Cash if you want to get connected'), title=_('Offline'), parent=parent, rich_text=True)
            return True
        return False

    def warn_if_no_secp(self, parent=None, message=None, icon=QMessageBox.Warning, relaxed=False):
        ''' Returns True if it DID warn: ie if there's no secp and ecc operations
        are slow, otherwise returns False if we have secp.

        Pass message (rich text) to provide a custom message.

        Note that the URL link to the HOWTO will always be appended to the custom message.'''
        from electroncash import ecc_fast
        has_secp = ecc_fast.is_using_fast_ecc()
        if has_secp:
            return False

        # When relaxwarn is set return True without showing the warning
        from electroncash import get_config
        if relaxed and get_config().cmdline_options["relaxwarn"]:
            return True

        # else..
        howto_url='https://github.com/Electron-Cash/Electron-Cash/blob/master/contrib/secp_HOWTO.md#libsecp256k1-0-for-electron-cash'
        template = '''
        <html><body>
            <p>
            {message}
            <p>
            {url_blurb}
            </p>
            <p><a href="{url}">Electron Cash Secp Mini-HOWTO</a></p>
        </body></html>
        '''
        msg = template.format(
            message = message or _("Electron Cash was unable to find the secp256k1 library on this system. Elliptic curve cryptography operations will be performed in slow Python-only mode."),
            url=howto_url,
            url_blurb = _("Please visit this page for instructions on how to correct the situation:")
        )
        self.warning(parent=parent, title=_("Missing libsecp256k1"),
                     message=msg, rich_text=True)
        return True

    def warning(self, title, message, icon = QMessageBox.Warning, parent = None, rich_text=False):
        if not isinstance(icon, QMessageBox.Icon):
            icon = QMessageBox.Warning
        if isinstance(parent, MessageBoxMixin):
            parent.msg_box(title=title, text=message, icon=icon, parent=None, rich_text=rich_text)
        else:
            parent = parent if isinstance(parent, QWidget) else None
            d = QMessageBoxMixin(icon, title, message, QMessageBox.Ok, parent)
            if not rich_text:
                d.setTextFormat(Qt.PlainText)
                d.setTextInteractionFlags(Qt.TextSelectableByMouse)
            else:
                d.setTextFormat(Qt.AutoText)
                d.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.LinksAccessibleByMouse)
            d.setWindowModality(Qt.WindowModal if parent else Qt.ApplicationModal)
            d.exec_()
            d.setParent(None)

    def lin_win_maybe_show_highdpi_caveat_msg(self, parent):
        ''' Called from main_window.py -- tells user once and only once about
        the high DPI mode and its caveats on Linux only.  Is a no-op otherwise. '''
        is_win = sys.platform[:3] in ('win', 'cyg')
        is_lin = sys.platform in ('linux',)
        if not is_win and not is_lin:
            return
        if (hasattr(Qt, "AA_EnableHighDpiScaling")
                and self.app.testAttribute(Qt.AA_EnableHighDpiScaling)
                # first run check:
                and self.config.get('qt_enable_highdpi', None) is None
                and (is_lin # we can't check pixel ratio on linux as apparently it's unreliable, so always show this message on linux
                     # on some windows systems running in highdpi causes
                     # glitches to the QMessageBox windows, so we need
                     # to also warn Windows users that they can turn this off,
                     # but only if they actually are using a high dpi display
                     or (is_win and hasattr(QScreen, 'devicePixelRatio')
                         and any(s.devicePixelRatio() > 1.0  # do they have any screens that are high dpi?
                                 for s in self.app.screens()) ))):
            # write to the config key to immediately suppress this warning in
            # the future -- it only appears on first-run if key was None
            self.config.set_key('qt_enable_highdpi', True)
            if is_lin:
                msg = (_("Automatic high DPI scaling has been enabled for Electron Cash, which should result in improved graphics quality.")
                       + "\n\n" + _("However, on some esoteric Linux systems, this mode may cause disproportionately large status bar icons.")
                       + "\n\n" + _("If that is the case for you, then you may disable automatic DPI scaling in the preferences, under 'General'."))
            else: # is_win
                msg = (_("Automatic high DPI scaling has been enabled for Electron Cash, which should result in improved graphics quality.")
                       + "\n\n" + _("However, on some Windows systems, bugs in Qt may result in minor graphics glitches in system 'message box' dialogs.")
                       + "\n\n" + _("If that is the case for you, then you may disable automatic DPI scaling in the preferences, under 'General'."))
            parent.show_message( title = _('Automatic High DPI'), msg = msg)

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

    def _quit_after_last_window(self):
        if any(1 for w in self.windows
               if isinstance(w, ElectrumWindow) and not w.cleaned_up):
            # We can get here if we have some top-level ElectrumWindows that
            # are "minimized to tray" (hidden).  "lastWindowClosed "is emitted
            # if there are no *visible* windows.  If we actually have hidden
            # app windows (because the user hid them), then we want to *not*
            # quit the app. https://doc.qt.io/qt-5/qguiapplication.html#lastWindowClosed
            # This check and early return fixes issue #1727.
            return
        qApp.quit()

    def notify(self, message):
        ''' Display a message in the system tray popup notification. On macOS
        this is the GROWL thing. On Windows it's a balloon popup from the system
        tray. On Linux it's usually a banner in the top of the screen.'''
        if self.tray:
            try:
                # this requires Qt 5.9
                self.tray.showMessage("Electron Cash", message, QIcon(":icons/electron-cash.svg"), 20000)
            except TypeError:
                self.tray.showMessage("Electron Cash", message, QSystemTrayIcon.Information, 20000)

    def is_cashaddr(self):
        return bool(self.config.get('show_cashaddr', True))

    def toggle_cashaddr(self, on = None):
        was = self.is_cashaddr()
        if on is None:
            on = not was
        else:
            on = bool(on)
        self.config.set_key('show_cashaddr', on)
        Address.show_cashaddr(on)
        if was != on:
            self.cashaddr_toggled_signal.emit()

    def is_cashaddr_status_button_hidden(self):
        return bool(self.config.get('hide_cashaddr_button', False))

    def set_cashaddr_status_button_hidden(self, b):
        b = bool(b)
        was = self.is_cashaddr_status_button_hidden()
        if was != b:
            self.config.set_key('hide_cashaddr_button', bool(b))
            self.cashaddr_status_button_hidden_signal.emit(b)

    @property
    def windows_qt_use_freetype(self):
        ''' Returns True iff we are windows and we are set to use freetype as
        the font engine.  This will always return false on platforms where the
        question doesn't apply. This config setting defaults to True for
        Windows < Win10 and False otherwise. It is only relevant when
        using the Qt GUI, however. '''
        if sys.platform not in ('win32', 'cygwin'):
            return False
        try:
            winver = float(platform.win32_ver()[0])  # '7', '8', '8.1', '10', etc
        except (AttributeError, ValueError, IndexError):
            # We can get here if cygwin, which has an empty win32_ver tuple
            # in some cases.
            # In that case "assume windows 10" and just proceed.  Cygwin users
            # can always manually override this setting from GUI prefs.
            winver = 10
        # setting defaults to on for Windows < Win10
        return bool(self.config.get('windows_qt_use_freetype', winver < 10))

    @windows_qt_use_freetype.setter
    def windows_qt_use_freetype(self, b):
        if self.config.is_modifiable('windows_qt_use_freetype') and sys.platform in ('win32', 'cygwin'):
            self.config.set_key('windows_qt_use_freetype', bool(b))

    @property
    def linux_qt_use_custom_fontconfig(self):
        ''' Returns True iff we are Linux and we are set to use the fonts.xml
        fontconfig override, False otherwise.  This config setting defaults to
        True for all Linux, but only is relevant to Qt GUI. '''
        return bool(sys.platform in ('linux',) and self.config.get('linux_qt_use_custom_fontconfig', True))

    @linux_qt_use_custom_fontconfig.setter
    def linux_qt_use_custom_fontconfig(self, b):
        if self.config.is_modifiable('linux_qt_use_custom_fontconfig') and sys.platform in ('linux',):
            self.config.set_key('linux_qt_use_custom_fontconfig', bool(b))


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
        signal.signal(signal.SIGINT, lambda signum, frame: self.shutdown_signal.emit())

        self.app.setQuitOnLastWindowClosed(False)  # we want to control this in our slot (since we support non-visible, backgrounded windows via the systray show/hide facility)
        self.app.lastWindowClosed.connect(self._quit_after_last_window)

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
