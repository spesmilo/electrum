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

help_about = _("""The local watchtower will persist on this computer after you close
your wallet, but it requires to be online regularly.""")

help_remote = _(""" To setup a remote watchtower, configure a remote electrum daemon
with 'watchtower_host' and 'watchtower_port' """)

class WatcherList(MyTreeView):
    def __init__(self, parent):
        super().__init__(parent, self.create_menu, stretch_column=0, editable_columns=[])
        self.setModel(QStandardItemModel(self))
        self.setSortingEnabled(True)
        self.update()

    def create_menu(self, x):
        pass

    def update(self):
        self.model().clear()
        self.update_headers({0:_('Outpoint'), 1:_('Tx'), 2:_('Status')})
        sweepstore = self.parent.lnwatcher.sweepstore
        for outpoint in sweepstore.list_sweep_tx():
            n = sweepstore.num_sweep_tx(outpoint)
            status = self.parent.lnwatcher.get_channel_status(outpoint)
            items = [QStandardItem(e) for e in [outpoint, "%d"%n, status]]
            self.model().insertRow(self.model().rowCount(), items)


class WatchTowerWindow(QDialog):

    def __init__(self, gui_object):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.config = gui_object.config
        self.lnwatcher = gui_object.daemon.network.lnwatcher
        self.setWindowTitle(_('Watchtower'))
        self.setMinimumSize(600, 20)
        watchtower_url = self.config.get('watchtower_url')
        self.watchtower_e = QLineEdit(watchtower_url)
        self.channel_list = WatcherList(self)
        # local
        local_w = QWidget()
        vbox_local = QVBoxLayout(local_w)
        vbox_local.addWidget(WWLabel(help_about))
        vbox_local.addWidget(self.channel_list)
        # remote
        remote_w = QWidget()
        vbox_remote = QVBoxLayout(remote_w)
        vbox_remote.addWidget(WWLabel(help_remote))
        g = QGridLayout(remote_w)
        g.addWidget(QLabel(_('URL') + ':'), 1, 0)
        g.addWidget(self.watchtower_e, 1, 1)
        vbox_remote.addLayout(g)
        vbox_remote.addStretch(1)
        # tabs
        tabs = QTabWidget()
        tabs.addTab(local_w, _('Local'))
        tabs.addTab(remote_w, _('Remote'))
        vbox = QVBoxLayout(self)
        vbox.addWidget(tabs)
        b = QPushButton(_('Close'))
        b.clicked.connect(self.on_close)
        vbox.addLayout(Buttons(b))
        self.channel_list.update()

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
