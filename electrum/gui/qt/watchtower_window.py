#!/usr/bin/env python
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

import socket

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import PyQt5.QtCore as QtCore

from electrum.i18n import _
from .util import *

help_wt = _("""A watchtower is a process that monitors your channels while you are offline, and prevents the other party from stealing funds in the channel.""")
help_local = _("""Electrum runs a watchtower on your computer. This process will persist after you close your wallet. It will not persist if you exit Electrum from the tray menu""")
help_remote = _("""To run a remote watchtower, start an electrum daemon on a computer that is always connected to the Internet, and set 'watchtower_host' and 'watchtower_port' in its config""")

class WatchTowerWindow(QDialog):

    def __init__(self, gui_object):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.lnwatcher = gui_object.daemon.network.lnwatcher
        self.wallet = self.lnwatcher
        self.config = gui_object.config
        self.setWindowTitle(_('Watchtower'))
        self.setMinimumSize(600, 20)
        vbox = QVBoxLayout(self)
        watchtower_url = self.config.get('watchtower_url')
        self.watchtower_e = QLineEdit(watchtower_url)
        self.channel_list = QTreeWidget(self)
        self.channel_list.setHeaderLabels([_('Node ID'), _('Amount')])

        vbox.addWidget(WWLabel(help_wt))
        vbox.addStretch(1)
        vbox.addWidget(HelpLabel(_('Local Watchtower') + ':', help_local))
        vbox.addWidget(self.channel_list)
        vbox.addStretch(1)        
        g = QGridLayout()
        g.addWidget(HelpLabel(_('Remote Watchtower') + ':', help_remote), 1, 0)
        g.addWidget(self.watchtower_e, 1, 1)
        vbox.addLayout(g)
        vbox.addStretch(1)
        b = QPushButton(_('Close'))
        b.clicked.connect(self.on_close)
        vbox.addLayout(Buttons(b))
        
    def update(self):
        pass

    def on_close(self):
        url = self.watchtower_e.text()
        if url:
            self.lnwatcher.set_remote_watchtower()
        self.hide()

    def is_hidden(self):
        return self.isMinimized() or self.isHidden()

    def show_or_hide(self):
        if self.is_hidden():
            self.bring_to_top()
        else:
            self.hide()

    def bring_to_top(self):
        self.show()
        self.raise_()

    def closeEvent(self, event):
        self.gui_object.watchtower_window = None
        event.accept()
