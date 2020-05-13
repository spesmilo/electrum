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
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QPushButton, QLabel)

from electrum.i18n import _
from .util import MyTreeView, Buttons


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
        size = lnwatcher.sweepstore.filesize()
        self.parent.size_label.setText('Database size: %.2f Mb'%(size/1024/1024.))


class WatchtowerDialog(QDialog):

    def __init__(self, gui_object):
        QDialog.__init__(self)
        self.gui_object = gui_object
        self.config = gui_object.config
        self.network = gui_object.daemon.network
        assert self.network
        self.lnwatcher = self.network.local_watchtower
        self.setWindowTitle(_('Watchtower'))
        self.setMinimumSize(600, 20)
        self.size_label = QLabel()
        self.watcher_list = WatcherList(self)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self.size_label)
        vbox.addWidget(self.watcher_list)
        b = QPushButton(_('Close'))
        b.clicked.connect(self.close)
        vbox.addLayout(Buttons(b))
        self.watcher_list.update()

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
        self.gui_object.watchtower_dialog = None
        event.accept()
