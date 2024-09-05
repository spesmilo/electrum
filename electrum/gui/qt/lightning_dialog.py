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

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (QDialog, QLabel, QVBoxLayout, QPushButton)

from electrum.i18n import _

from .util import Buttons
from .util import QtEventListener, qt_event_listener

if TYPE_CHECKING:
    from . import ElectrumGui


class LightningDialog(QDialog, QtEventListener):

    def __init__(self, gui_object: 'ElectrumGui'):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.config = gui_object.config
        self.network = gui_object.daemon.network
        assert self.network
        self.setWindowTitle(_('Lightning Network'))
        self.setMinimumWidth(600)
        vbox = QVBoxLayout(self)
        self.num_peers = QLabel('')
        vbox.addWidget(self.num_peers)
        self.num_nodes = QLabel('')
        vbox.addWidget(self.num_nodes)
        self.num_channels = QLabel('')
        vbox.addWidget(self.num_channels)
        self.status = QLabel('')
        vbox.addWidget(self.status)
        vbox.addStretch(1)
        b = QPushButton(_('Close'))
        b.clicked.connect(self.close)
        vbox.addLayout(Buttons(b))
        self.register_callbacks()
        self.network.channel_db.update_counts() # trigger callback
        if self.network.lngossip:
            self.on_event_gossip_peers(self.network.lngossip.num_peers())
            self.on_event_unknown_channels(len(self.network.lngossip.unknown_ids))
        else:
            self.num_peers.setText(_('Lightning gossip not active.'))

    @qt_event_listener
    def on_event_channel_db(self, num_nodes, num_channels, num_policies):
        self.num_nodes.setText(_('{} nodes').format(num_nodes))
        self.num_channels.setText(_('{} channels').format(num_channels))

    @qt_event_listener
    def on_event_gossip_peers(self, num_peers):
        self.num_peers.setText(_('Connected to {} peers').format(num_peers))

    @qt_event_listener
    def on_event_unknown_channels(self, unknown):
        self.status.setText(_('Requesting {} channels...').format(unknown) if unknown else '')

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
        self.unregister_callbacks()
        self.gui_object.lightning_dialog = None
        event.accept()
