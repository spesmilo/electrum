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
from PyQt5 import QtWidgets
from electrum.i18n import _
from electrum.gui.qt.util import WindowModalDialog, OkButton, Buttons, EnterButton
from .payserver import PayServerPlugin


class Plugin(PayServerPlugin):

    def requires_settings(self):
        return True

    def settings_widget(self, window: WindowModalDialog):
        return EnterButton(
            _('Settings'),
            partial(self.settings_dialog, window))

    def settings_dialog(self, window: WindowModalDialog):
        d = WindowModalDialog(window, _("PayServer Settings"))
        form = QtWidgets.QFormLayout(None)
        addr = self.config.get('payserver_address', 'localhost:8080')
        url = self.server.base_url + self.server.root + '/create_invoice.html'
        self.help_label = QtWidgets.QLabel('create invoice: <a href="%s">%s</a>'%(url, url))
        self.help_label.setOpenExternalLinks(True)
        address_e = QtWidgets.QLineEdit(addr)
        keyfile_e = QtWidgets.QLineEdit(self.config.get('ssl_keyfile', ''))
        certfile_e = QtWidgets.QLineEdit(self.config.get('ssl_certfile', ''))
        form.addRow(QtWidgets.QLabel("Network address:"), address_e)
        form.addRow(QtWidgets.QLabel("SSL key file:"), keyfile_e)
        form.addRow(QtWidgets.QLabel("SSL cert file:"), certfile_e)
        vbox = QtWidgets.QVBoxLayout(d)
        vbox.addLayout(form)
        vbox.addSpacing(20)
        vbox.addWidget(self.help_label)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))
        if d.exec_():
            self.config.set_key('payserver_address', str(address_e.text()))
            self.config.set_key('ssl_keyfile', str(keyfile_e.text()))
            self.config.set_key('ssl_certfile', str(certfile_e.text()))
