#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2022 The Electrum Developers
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

from functools import partial
from typing import TYPE_CHECKING
from PyQt5 import QtWidgets

from electrum.i18n import _
from electrum.plugin import hook
from electrum.gui.qt.util import WindowModalDialog, OkButton, Buttons, EnterButton, webopen
from .payserver import PayServerPlugin

if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui


class Plugin(PayServerPlugin):

    _init_qt_received = False

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:  # only need/want the first signal
            return
        self._init_qt_received = True
        # If the user just enabled the plugin, the 'load_wallet' hook would not
        # get called for already loaded wallets, hence we call it manually for those:
        for window in gui.windows:
            self.daemon_wallet_loaded(gui.daemon, window.wallet)

    def requires_settings(self):
        return True

    def settings_widget(self, window: WindowModalDialog):
        return EnterButton(
            _('Settings'),
            partial(self.settings_dialog, window))

    def settings_dialog(self, window: WindowModalDialog):
        if self.config.NETWORK_OFFLINE:
            window.show_error(_("You are offline."))
            return
        d = WindowModalDialog(window, _("PayServer Settings"))
        form = QtWidgets.QFormLayout(None)
        addr = self.config.PAYSERVER_ADDRESS
        assert self.server
        url = self.server.base_url + self.server.root + '/create_invoice.html'
        self.help_button = QtWidgets.QPushButton('View sample invoice creation form')
        self.help_button.clicked.connect(lambda: webopen(url))
        address_e = QtWidgets.QLineEdit(addr)
        keyfile_e = QtWidgets.QLineEdit(self.config.SSL_KEYFILE_PATH)
        certfile_e = QtWidgets.QLineEdit(self.config.SSL_CERTFILE_PATH)
        form.addRow(QtWidgets.QLabel("Network address:"), address_e)
        form.addRow(QtWidgets.QLabel("SSL key file:"), keyfile_e)
        form.addRow(QtWidgets.QLabel("SSL cert file:"), certfile_e)
        vbox = QtWidgets.QVBoxLayout(d)
        vbox.addLayout(form)
        vbox.addSpacing(20)
        vbox.addWidget(self.help_button)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))
        if d.exec_():
            self.config.PAYSERVER_ADDRESS = str(address_e.text())
            self.config.SSL_KEYFILE_PATH = str(keyfile_e.text())
            self.config.SSL_CERTFILE_PATH = str(certfile_e.text())
            # fixme: restart the server
            window.show_message('Please restart Electrum to enable those changes')

    @hook
    def receive_list_menu(self, parent, menu, key):
        menu.addAction(_("View in payserver"), lambda: webopen(self.view_url(key)))
