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
from .util import HelpLabel, MyTreeView, Buttons

help_local = _("""If this option is checked, Electrum will persist as a daemon after
you close all your wallet windows. Your local watchtower will keep
running, and it will protect your channels even if your wallet is not
open. For this to work, your computer needs to be online regularly.""")

help_remote = _("""To setup a remote watchtower, you must run an Electrum daemon on a
computer that is always connected to the internet. Configure
'watchtower_host' and 'watchtower_port' in the remote daemon, and
enter the corresponding URL here""")

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
        sweepstore = self.parent.lnwatcher.sweepstore
        for outpoint in sweepstore.list_sweep_tx():
            n = sweepstore.get_num_tx(outpoint)
            status = self.parent.lnwatcher.get_channel_status(outpoint)
            items = [QStandardItem(e) for e in [outpoint, "%d"%n, status]]
            self.model().insertRow(self.model().rowCount(), items)


class LightningDialog(QDialog):

    def __init__(self, gui_object):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.config = gui_object.config
        self.network = gui_object.daemon.network
        self.lnwatcher = self.network.lnwatcher
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
        # settings
        settings_w = QWidget()
        settings_vbox = QVBoxLayout(settings_w)
        persist_cb = QCheckBox(_("Persist as daemon after GUI is closed"))
        persist_cb.setToolTip(help_local)
        persist_cb.setChecked(bool(self.config.get('persist_daemon', False)))
        def on_persist_checked(v):
            self.config.set_key('persist_daemon', v == Qt.Checked, save=True)
        persist_cb.stateChanged.connect(on_persist_checked)

        remote_cb = QCheckBox(_("Use a remote watchtower"))
        remote_cb.setToolTip(help_remote)
        remote_cb.setChecked(bool(self.config.get('use_watchtower', False)))
        def on_remote_checked(v):
            self.config.set_key('use_watchtower', v == Qt.Checked, save=True)
            self.watchtower_url_e.setEnabled(v == Qt.Checked)
        remote_cb.stateChanged.connect(on_remote_checked)

        watchtower_url = self.config.get('watchtower_url')
        self.watchtower_url_e = QLineEdit(watchtower_url)
        self.watchtower_url_e.setEnabled(self.config.get('use_watchtower', False))
        def on_url():
            url = self.watchtower_url_e.text() or None
            watchtower_url = self.config.set_key('watchtower_url', url)
            if url:
                self.lnwatcher.set_remote_watchtower()
        self.watchtower_url_e.editingFinished.connect(on_url)

        g = QGridLayout(settings_w)
        g.addWidget(persist_cb, 0, 0, 1, 3)
        g.addWidget(remote_cb, 1, 0, 1, 3)
        g.addWidget(QLabel(_('URL')), 2, 1)
        g.addWidget(self.watchtower_url_e, 2, 2)
        settings_vbox.addLayout(g)
        settings_vbox.addStretch(1)
        # tabs
        tabs = QTabWidget()
        tabs.addTab(network_w, _('Network'))
        tabs.addTab(watcher_w, _('Watchtower'))
        tabs.addTab(settings_w, _('Settings'))
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
