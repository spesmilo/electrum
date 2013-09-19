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
    TMPL_LABEL = '''<a href="{0}">{1}</a>'''

    def fullname(self):
        return 'Web transaction details'

    def description(self):
        return _('Open transaction details in the browser.')

    def requires_settings(self):
        return True

    def create_history_menu(self, menu, item):
        tx_hash = str(item.data(0, Qt.UserRole).toString())

        menu.addSeparator()

        menu.addAction(self.format_label(tx_hash),
            lambda: webbrowser.open_new_tab(self.web_endpoint(tx_hash)))

    def format_label(self, tx_hash):
        url = self.web_endpoint(tx_hash)
        netloc = urlparse(url).netloc
        return _("Open details on {0}".format(netloc))

    def web_endpoint(self, tx_hash=None):
        url = self.config.get("plugin_webdetails_endpoint", self.DEFAULT_ENDPOINT)

        if tx_hash:
            # be compatible w/ Python 2.6
            url = url.replace("{}", "{0}").format(tx_hash)

        return url

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

    def transaction_dialog_init(self, dialog, main_box, tx):
        tx_hash = tx.hash()

        label = self.TMPL_LABEL.format(self.web_endpoint(tx_hash), self.format_label(tx_hash))

        status_label = QLabel(label)
        status_label.setOpenExternalLinks(True)

        main_box.addWidget(status_label)

