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

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QWidget, QLabel, QVBoxLayout, QCheckBox,
                             QGridLayout, QPushButton, QLineEdit, QTabWidget)

from electrum_ltc.i18n import _
from .util import HelpLabel, MyTreeView, Buttons


class WatcherList(MyTreeView):
    def __init__(self, parent):
        super().__init__(parent, self.create_menu, stretch_column=0, editable_columns=[])
        self.setModel(QStandardItemModel(self))
        self.setSortingEnabled(True)
        self.update()

    def create_menu(self, x):
        pass

    def update(self):
        if self.parent.lnwatcher is None:
            return
        self.model().clear()
        self.update_headers({0:_('Outpoint'), 1:_('Tx'), 2:_('Status')})
        lnwatcher = self.parent.lnwatcher
        l = lnwatcher.list_sweep_tx()
        for outpoint in l:
            n = lnwatcher.get_num_tx(outpoint)
            status = lnwatcher.get_channel_status(outpoint)
            items = [QStandardItem(e) for e in [outpoint, "%d"%n, status]]
            self.model().insertRow(self.model().rowCount(), items)


class LightningDialog(QDialog):

    def __init__(self, gui_object):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.config = gui_object.config
        self.network = gui_object.daemon.network
        self.lnwatcher = self.network.local_watchtower
        self.setWindowTitle(_('Lightning'))
        self.setMinimumSize(600, 20)
        self.watcher_list = WatcherList(self)
        # channel_db
        network_w = QWidget()
        network_vbox = QVBoxLayout(network_w)
        self.num_peers = QLabel('')
        network_vbox.addWidget(self.num_peers)
        self.num_nodes = QLabel('')
        network_vbox.addWidget(self.num_nodes)
        self.num_channels = QLabel('')
        network_vbox.addWidget(self.num_channels)
        self.status = QLabel('')
        network_vbox.addWidget(self.status)
        network_vbox.addStretch(1)
        # watchtower
        watcher_w = QWidget()
        watcher_vbox = QVBoxLayout(watcher_w)
        watcher_vbox.addWidget(self.watcher_list)

        # tabs
        tabs = QTabWidget()
        tabs.addTab(network_w, _('Network'))
        tabs.addTab(watcher_w, _('Watchtower'))
        vbox = QVBoxLayout(self)
        vbox.addWidget(tabs)
        b = QPushButton(_('Close'))
        b.clicked.connect(self.close)
        vbox.addLayout(Buttons(b))
        self.watcher_list.update()
        self.network.register_callback(self.update_status, ['ln_status'])

    def update_status(self, event, num_peers, num_nodes, known, unknown):
        self.num_peers.setText(_(f'Connected to {num_peers} peers'))
        self.num_nodes.setText(_(f'{num_nodes} nodes'))
        self.num_channels.setText(_(f'{known} channels'))
        self.status.setText(_(f'Requesting {unknown} channels...') if unknown else '')

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
