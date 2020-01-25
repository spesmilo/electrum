#!/usr/bin/env python3
#
# Cash Shuffle - CoinJoin for Bitcoin Cash
# Copyright (C) 2018-2020 Electron Cash LLC
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
import weakref

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.i18n import _
from electroncash.plugins import hook
from electroncash_gui.qt.main_window import ElectrumWindow, StatusBarButton
from electroncash_gui.qt.popup_widget import ShowPopupLabel, KillPopupLabel
from electroncash_gui.qt.util import ColorScheme

class ShuffleStatusBarButtonMgr:
    ''' Apologies for how contorted this is.  All this code used to live inside
    the ElectrumWindow instance in Electron Cash 4.0.x, before CashFusion.
    We moved it out into a separate "manager" class, for managing the
    StatusBarButton state. '''

    def __init__(self, plugin : object, window : ElectrumWindow):
        from .qt import Plugin  # <--- we lazy-load this each time becasue the Plugin class may go away and come back as a different class for each plugin load/unload cycle
        assert isinstance(plugin, Plugin)
        assert isinstance(window, ElectrumWindow)
        self.weak_window = weakref.ref(window)
        self.weak_plugin = weakref.ref(plugin)
        self._create_button()

    @property
    def window(self):
        return self.weak_window()

    @property
    def plugin(self):
        return self.weak_plugin()

    def require_good_window_first_arg(func, *args, **kwargs):
        ''' Verifies that self.window is good, and then passes it as the first
        arg to func.  If it is not good, returns with no-op. '''
        def inner(self, *args, **kwargs):
            w = self.window
            if w:
                return func(self, w, *args, **kwargs)
        return inner

    @require_good_window_first_arg
    def remove(self, window):
        attrs2del = [ 'cashshuffle_set_flag', 'cashshuffle_get_flag' ]
        for attr in attrs2del:
            if hasattr(window, attr):
                delattr(window, attr)
        sb = window.statusBar()
        sb.removeWidget(self.cashshuffle_status_button)
        self.cashshuffle_status_button.setParent(None)
        self.cashshuffle_status_button.deleteLater()
        self.cashshuffle_status_button = None
        self.cashshuffle_toggle_action = None
        self.cashshuffle_settings_action = None
        self.cashshuffle_viewpools_action = None
        self.cashshuffle_separator_action = None


    @require_good_window_first_arg
    def _create_button(self, window):
        sb = window.statusBar()
        self.cashshuffle_status_button = StatusBarButton(
            self.cashshuffle_icon(),
            '', # ToolTip will be set in update_cashshuffle code
            self.cashshuffle_icon_leftclick
        )
        self.cashshuffle_toggle_action = QAction("", self.cashshuffle_status_button) # action text will get set in update_cashshuffle_icon()
        self.cashshuffle_toggle_action.triggered.connect(self.toggle_cashshuffle)
        self.cashshuffle_settings_action = QAction("", self.cashshuffle_status_button)
        self.cashshuffle_settings_action.triggered.connect(self.show_cashshuffle_settings)
        self.cashshuffle_viewpools_action = QAction(_("View pools..."), self.cashshuffle_status_button)
        self.cashshuffle_viewpools_action.triggered.connect(self.show_cashshuffle_pools)
        self.cashshuffle_status_button.addAction(self.cashshuffle_viewpools_action)
        self.cashshuffle_status_button.addAction(self.cashshuffle_settings_action)
        self.cashshuffle_separator_action = sep = QAction(self.cashshuffle_status_button); sep.setSeparator(True)
        self.cashshuffle_status_button.addAction(sep)
        self.cashshuffle_status_button.addAction(self.cashshuffle_toggle_action)
        self.cashshuffle_status_button.setContextMenuPolicy(Qt.ActionsContextMenu)

        # monkey patch window because client.py code expects these method
        window.cashshuffle_set_flag = self.cashshuffle_set_flag
        window.cashshuffle_get_flag = self.cashshuffle_get_flag

        sb.insertPermanentWidget(4, self.cashshuffle_status_button)

    @require_good_window_first_arg
    def is_cashshuffle_enabled(self, window):
        plugin = self.plugin
        return bool(plugin and plugin.is_enabled() and plugin.window_has_cashshuffle(window))

    def cashshuffle_icon(self):
        if self.is_cashshuffle_enabled():
            if self._cash_shuffle_flag == 1:
                return QIcon(":icons/cashshuffle_on_error.svg")
            else:
                return QIcon(":icons/cashshuffle_on.svg")
        else:
            self._cash_shuffle_flag = 0
            return QIcon(":icons/cashshuffle_off.svg")

    @require_good_window_first_arg
    def update_cashshuffle_icon(self, window):
        self.cashshuffle_status_button.setIcon(self.cashshuffle_icon())
        loaded = bool(self.plugin)
        en = self.is_cashshuffle_enabled()
        if self._cash_shuffle_flag == 0:
            self.cashshuffle_status_button.setStatusTip(_("CashShuffle") + " - " + _("ENABLED") if en else _("CashShuffle") + " - " + _("Disabled"))
            rcfcm = _("Right-click for context menu")
            self.cashshuffle_status_button.setToolTip(
                (_("Toggle CashShuffle") + "\n" + rcfcm)
            )
            self.cashshuffle_toggle_action.setText(_("Enable CashShuffle") if not en else _("Disable CashShuffle"))
            self.cashshuffle_settings_action.setText(_("CashShuffle Settings..."))
            self.cashshuffle_viewpools_action.setEnabled(True)
        elif self._cash_shuffle_flag == 1: # Network server error
            self.cashshuffle_status_button.setStatusTip(_('CashShuffle Error: Could not connect to server'))
            self.cashshuffle_status_button.setToolTip(_('Right-click to select a different CashShuffle server'))
            self.cashshuffle_settings_action.setText(_("Resolve Server Problem..."))
            self.cashshuffle_viewpools_action.setEnabled(False)
        self.cashshuffle_settings_action.setVisible(en or loaded)
        self.cashshuffle_viewpools_action.setVisible(en)
        if en:
            # ensure 'Disable CashShuffle' appears at the end of the context menu
            self.cashshuffle_status_button.removeAction(self.cashshuffle_separator_action)
            self.cashshuffle_status_button.removeAction(self.cashshuffle_toggle_action)
            self.cashshuffle_status_button.addAction(self.cashshuffle_separator_action)
            self.cashshuffle_status_button.addAction(self.cashshuffle_toggle_action)
        else:
            # ensure 'Enable CashShuffle' appears at the beginning of the context menu
            self.cashshuffle_status_button.removeAction(self.cashshuffle_separator_action)
            self.cashshuffle_status_button.removeAction(self.cashshuffle_toggle_action)
            actions = self.cashshuffle_status_button.actions()
            self.cashshuffle_status_button.insertAction(actions[0] if actions else None, self.cashshuffle_separator_action)
            self.cashshuffle_status_button.insertAction(self.cashshuffle_separator_action, self.cashshuffle_toggle_action)

    @require_good_window_first_arg
    def show_cashshuffle_settings(self, window, *args):
        p = self.plugin
        if p:
            msg = None
            if self._cash_shuffle_flag == 1:
                # had error
                msg = _("There was a problem connecting to this server.\nPlease choose a different CashShuffle server.")
            p.settings_dialog(window, msg)

    @require_good_window_first_arg
    def show_cashshuffle_pools(self, window, *args):
        p = self.plugin
        if p:
            p.view_pools(window)

    @require_good_window_first_arg
    def cashshuffle_icon_leftclick(self, window, *args):
        self.toggle_cashshuffle()

    @require_good_window_first_arg
    def toggle_cashshuffle(self, window, *args):
        from .qt import Plugin
        if not Plugin.is_wallet_cashshuffle_compatible(window):
            window.show_warning(_("This wallet type cannot be used with CashShuffle."), parent=window)
            return
        plugins = window.gui_object.plugins
        p0 = self.plugin
        p = p0 or plugins.enable_internal_plugin("shuffle")
        if not p:
            raise RuntimeError("Could not find CashShuffle plugin")
        was_enabled = p.window_has_cashshuffle(window)
        if was_enabled and not p.warn_if_shuffle_disable_not_ok(window):
            # user at nag screen said "no", so abort
            self.update_cashshuffle_icon()
            return
        enable_flag = not was_enabled
        self._cash_shuffle_flag = 0
        KillPopupLabel("CashShuffleError")
        if not p0:
            # plugin was not loaded -- so flag window as wanting cashshuffle and do init
            p.window_set_wants_cashshuffle(window, enable_flag)
            p.init_qt(window.gui_object)
        else:
            # plugin was already started -- just add the window to the plugin
            p.window_set_cashshuffle(window, enable_flag)
        self.update_cashshuffle_icon()
        window.statusBar().showMessage(self.cashshuffle_status_button.statusTip(), 3000)
        if enable_flag and window.config.get("show_utxo_tab") is None:
            window.toggle_tab(window.utxo_tab) # toggle utxo tab to 'on' if user never specified it should be off.

    _cash_shuffle_flag = 0
    @require_good_window_first_arg
    def cashshuffle_set_flag(self, window, flag):
        flag = int(flag)
        changed = flag != self._cash_shuffle_flag
        if not changed:
            return
        if flag:
            def onClick():
                KillPopupLabel("CashShuffleError")
                self.show_cashshuffle_settings()
            ShowPopupLabel(name = "CashShuffleError",
                           text="<center><b>{}</b><br><small>{}</small></center>".format(_("Server Error"),_("Click here to resolve")),
                           target=self.cashshuffle_status_button,
                           timeout=20000, onClick=onClick, onRightClick=onClick,
                           dark_mode = ColorScheme.dark_scheme)
        else:
            KillPopupLabel("CashShuffleError")
        window.print_error("Cash Shuffle flag is now {}".format(flag))
        oldTip = self.cashshuffle_status_button.statusTip()
        self._cash_shuffle_flag = flag
        window.update_status()  # ultimately leads to a call to self.update_cashshuffle_icon()
        newTip = self.cashshuffle_status_button.statusTip()
        if newTip != oldTip:
            window.statusBar().showMessage(newTip, 7500)

    def cashshuffle_get_flag(self):
        return self._cash_shuffle_flag
