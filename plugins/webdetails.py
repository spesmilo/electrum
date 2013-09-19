# Webdetails plugin
# Copyright (C) 2013 vrde
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

import re
import webbrowser
from urlparse import urlparse

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum.i18n import _


from electrum.plugins import BasePlugin

class Plugin(BasePlugin):

    DEFAULT_ENDPOINT = "http://blockchain.info/tx/{}"

    def fullname(self):
        return 'Web transaction details'

    def description(self):
        return _('Open transaction details in the browser.')

    def requires_settings(self):
        return True

    def create_history_menu(self, menu, item):
        tx_hash = str(item.data(0, Qt.UserRole).toString())
        url = self.web_endpoint().replace("{}", "{0}").format(tx_hash)
        netloc = urlparse(url).netloc

        menu.addSeparator()

        menu.addAction(
            _("Open details on {0}".format(netloc)),
            lambda: webbrowser.open_new_tab(self.web_endpoint().format(tx_hash)))

    def web_endpoint(self):
        return self.config.get("plugin_webdetails_endpoint", self.DEFAULT_ENDPOINT)

    def settings_dialog(self):

        def save_endpoint(value):
            self.config.set_key("plugin_webdetails_endpoint", str(value))

        d = QDialog(self.gui)
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Endpoint: "), 0, 0)

        self.text_endpoint = QLineEdit(self.web_endpoint())
        self.text_endpoint.textChanged.connect(save_endpoint)
        layout.addWidget(self.text_endpoint, 0, 1, 1, 2)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(d.accept)
        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(d.accept)

        layout.addWidget(c,3,1)
        layout.addWidget(self.accept,3,2)

        if d.exec_():
          return True
        else:
          return False

