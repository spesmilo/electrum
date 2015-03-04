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

import threading, httplib, re, socket
import webbrowser
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum_grs.i18n import _
from electrum_grs import ELECTRUM_VERSION, print_error

class VersionGetter(threading.Thread):

    def __init__(self, label):
        threading.Thread.__init__(self)
        self.label = label

    def run(self):
        try:
            con = httplib.HTTPSConnection('electrum.org', timeout=5)
            con.request("GET", "/version")
            res = con.getresponse()
        except socket.error as msg:
            print_error("Could not retrieve version information")
            return

        if res.status == 200:
            latest_version = res.read()
            latest_version = latest_version.replace("\n","")
            if(re.match('^\d+(\.\d+)*$', latest_version)):
                self.label.callback(latest_version)

class UpdateLabel(QLabel):
    def __init__(self, config, sb):
        QLabel.__init__(self)
        self.new_version = False
        self.sb = sb
        self.config = config
        self.current_version = ELECTRUM_VERSION
        self.connect(self, QtCore.SIGNAL('new_electrum_version'), self.new_electrum_version)
        # prevent HTTP leaks if a proxy is set
        if self.config.get('proxy'):
            return
        VersionGetter(self).start()

    def callback(self, version):
        self.latest_version = version
        if(self.compare_versions(self.latest_version, self.current_version) == 1):
            latest_seen = self.config.get("last_seen_version",ELECTRUM_VERSION)
            if(self.compare_versions(self.latest_version, latest_seen) == 1):
                self.new_version = True
                self.emit(QtCore.SIGNAL('new_electrum_version'))

    def new_electrum_version(self):
        if self.new_version:
            self.setText(_("New version available") + ": " + self.latest_version)
            self.sb.insertPermanentWidget(1, self)

    def compare_versions(self, version1, version2):
        def normalize(v):
            return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]
        try:
            return cmp(normalize(version1), normalize(version2))
        except:
            return 0

    def ignore_this_version(self):
        self.setText("")
        self.config.set_key("last_seen_version", self.latest_version, True)
        QMessageBox.information(self, _("Preference saved"), _("Notifications about this update will not be shown again."))
        self.dialog.done(0)

    def ignore_all_version(self):
        self.setText("")
        self.config.set_key("last_seen_version", "9.9.9", True)
        QMessageBox.information(self, _("Preference saved"), _("No more notifications about version updates will be shown."))
        self.dialog.done(0)

    def open_website(self):
        webbrowser.open("http://electrum.org/download.html")
        self.dialog.done(0)

    def mouseReleaseEvent(self, event):
        dialog = QDialog(self)
        dialog.setWindowTitle(_('Electrum update'))
        dialog.setModal(1)

        main_layout = QGridLayout()
        main_layout.addWidget(QLabel(_("A new version of Electrum is available:")+" " + self.latest_version), 0,0,1,3)

        ignore_version = QPushButton(_("Ignore this version"))
        ignore_version.clicked.connect(self.ignore_this_version)

        ignore_all_versions = QPushButton(_("Ignore all versions"))
        ignore_all_versions.clicked.connect(self.ignore_all_version)

        open_website = QPushButton(_("Goto download page"))
        open_website.clicked.connect(self.open_website)

        main_layout.addWidget(ignore_version, 1, 0)
        main_layout.addWidget(ignore_all_versions, 1, 1)
        main_layout.addWidget(open_website, 1, 2)

        dialog.setLayout(main_layout)

        self.dialog = dialog

        if not dialog.exec_(): return
