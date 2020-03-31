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

from PyQt5.QtWidgets import (QDialog, QLabel, QVBoxLayout, QPushButton)

from electrum.i18n import _

from .util import Buttons

if TYPE_CHECKING:
    from . import ElectrumGui


class LightningDialog(QDialog):

    def __init__(self, gui_object: 'ElectrumGui'):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.config = gui_object.config
        self.network = gui_object.daemon.network
        assert self.network
        self.setWindowTitle(_('Lightning Network'))
        self.setMinimumSize(600, 20)
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
        self.network.register_callback(self.on_channel_db, ['channel_db'])
        self.network.register_callback(self.set_num_peers, ['gossip_peers'])
        self.network.register_callback(self.set_unknown_channels, ['unknown_channels'])
        self.network.channel_db.update_counts() # trigger callback
        self.set_num_peers('', self.network.lngossip.num_peers())
        self.set_unknown_channels('', len(self.network.lngossip.unknown_ids))

    def on_channel_db(self, event, num_nodes, num_channels, num_policies):
        self.num_nodes.setText(_(f'{num_nodes} nodes'))
        self.num_channels.setText(_(f'{num_channels} channels'))

    def set_num_peers(self, event, num_peers):
        self.num_peers.setText(_(f'Connected to {num_peers} peers'))

    def set_unknown_channels(self, event, unknown):
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
        self.gui_object.lightning_dialog = None
        event.accept()
