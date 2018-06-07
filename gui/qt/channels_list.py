# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtWidgets
from electrum.util import inv_dict, bh2u
from electrum.i18n import _
from electrum.lnbase import OpenChannel
from .util import MyTreeWidget, SortableTreeWidgetItem

class ChannelsList(MyTreeWidget):
    update_rows = QtCore.pyqtSignal()
    update_single_row = QtCore.pyqtSignal(OpenChannel)

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Node ID'), _('Balance'), _('Remote'), _('Status')], 0)
        self.main_window = parent
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)

    def format_fields(self, chan):
        status = self.parent.wallet.lnworker.channel_state[chan.channel_id]
        return [
            bh2u(chan.node_id),
            self.parent.format_amount(chan.local_state.amount_msat//1000),
            self.parent.format_amount(chan.remote_state.amount_msat//1000),
            status
        ]

    def create_menu(self, position):
        menu = QtWidgets.QMenu()
        cur = self.currentItem()
        print('ID', bh2u(cur.data(0, QtCore.Qt.UserRole)))
        def close():
            print("closechannel result", self.parent.wallet.lnworker.close_channel_from_other_thread(cur.di))
        menu.addAction(_("Close channel"), close)
        menu.exec_(self.viewport().mapToGlobal(position))

    @QtCore.pyqtSlot(OpenChannel)
    def do_update_single_row(self, chan):
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item.data(0, QtCore.Qt.UserRole) == chan.channel_id:
                for i, v in enumerate(self.format_fields(chan)):
                    item.setData(i, QtCore.Qt.DisplayRole, v)

    @QtCore.pyqtSlot()
    def do_update_rows(self):
        self.clear()
        for chan in self.parent.wallet.lnworker.channels.values():
            item = SortableTreeWidgetItem(self.format_fields(chan))
            item.setData(0, QtCore.Qt.UserRole, chan.channel_id)
            self.insertTopLevelItem(0, item)

    def get_toolbar(self):
        nodeid_inp = QtWidgets.QLineEdit(self)
        local_amt_inp = QtWidgets.QLineEdit(self, text='200000')
        push_amt_inp = QtWidgets.QLineEdit(self, text='0')
        button = QtWidgets.QPushButton(_('Open channel'), self)
        button.clicked.connect(lambda: self.main_window.protect(self.open_channel, (nodeid_inp, local_amt_inp, push_amt_inp)))
        h = QtWidgets.QGridLayout()
        nodeid_label = QtWidgets.QLabel(self)
        nodeid_label.setText(_("Node ID"))
        local_amt_label = QtWidgets.QLabel(self)
        local_amt_label.setText("Local amount (sat)")
        push_amt_label = QtWidgets.QLabel(self)
        push_amt_label.setText("Push amount (sat)")
        h.addWidget(nodeid_label, 0, 0)
        h.addWidget(local_amt_label, 0, 1)
        h.addWidget(push_amt_label, 0, 2)
        h.addWidget(nodeid_inp, 1, 0)
        h.addWidget(local_amt_inp, 1, 1)
        h.addWidget(push_amt_inp, 1, 2)
        h.addWidget(button, 1, 3)
        h.setColumnStretch(0, 3)
        h.setColumnStretch(1, 1)
        h.setColumnStretch(2, 1)
        h.setColumnStretch(3, 1)
        return h

    def open_channel(self, nodeIdInput, local_amt_inp, push_amt_inp, password):
        node_id = str(nodeIdInput.text())
        local_amt = int(local_amt_inp.text())
        push_amt = int(push_amt_inp.text())
        assert local_amt >= 200000
        assert local_amt >= push_amt
        obj = self.parent.wallet.lnworker.open_channel(node_id, local_amt, push_amt, password)
