# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import *

from electrum.util import inv_dict, bh2u, bfh
from electrum.i18n import _
from electrum.lnbase import OpenChannel
from .util import MyTreeWidget, SortableTreeWidgetItem, WindowModalDialog, Buttons, OkButton, CancelButton
from .amountedit import BTCAmountEdit

class ChannelsList(MyTreeWidget):
    update_rows = QtCore.pyqtSignal()
    update_single_row = QtCore.pyqtSignal(OpenChannel)

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Node ID'), _('Balance'), _('Remote'), _('Status')], 0)
        self.main_window = parent
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.status = QLabel('')

    def format_fields(self, chan):
        status = self.parent.wallet.lnworker.channel_state[chan.channel_id]
        return [
            bh2u(chan.node_id),
            self.parent.format_amount(chan.local_state.amount_msat//1000),
            self.parent.format_amount(chan.remote_state.amount_msat//1000),
            status
        ]

    def create_menu(self, position):
        menu = QMenu()
        channel_id = self.currentItem().data(0, QtCore.Qt.UserRole)
        print('ID', bh2u(channel_id))
        def close():
            suc, msg = self.parent.wallet.lnworker.close_channel(channel_id)
            assert suc # TODO show error message in dialog
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
            item = SortableTreeWidgetItem(self.format_fields(chan.state))
            item.setData(0, QtCore.Qt.UserRole, chan.state.channel_id)
            self.insertTopLevelItem(0, item)

    def get_toolbar(self):
        b = QPushButton(_('Open Channel'))
        b.clicked.connect(self.new_channel_dialog)
        h = QHBoxLayout()
        h.addWidget(self.status)
        h.addStretch()
        h.addWidget(b)
        return h

    def on_update(self):
        n = len(self.parent.network.lightning_nodes)
        np = len(self.parent.wallet.lnworker.peers)
        self.status.setText(_('{} peers, {} nodes').format(np, n))

    def new_channel_dialog(self):
        d = WindowModalDialog(self.parent, _('Open Channel'))
        d.setFixedWidth(700)
        vbox = QVBoxLayout(d)
        h = QGridLayout()
        local_nodeid = QLineEdit()
        local_nodeid.setText(bh2u(self.parent.wallet.lnworker.pubkey))
        local_nodeid.setReadOnly(True)
        local_nodeid.setCursorPosition(0)
        remote_nodeid = QLineEdit()
        local_amt_inp = BTCAmountEdit(self.parent.get_decimal_point)
        local_amt_inp.setAmount(200000)
        push_amt_inp = BTCAmountEdit(self.parent.get_decimal_point)
        push_amt_inp.setAmount(0)
        h.addWidget(QLabel(_('Your Node ID')), 0, 0)
        h.addWidget(local_nodeid, 0, 1)
        h.addWidget(QLabel(_('Remote Node ID')), 1, 0)
        h.addWidget(remote_nodeid, 1, 1)
        h.addWidget(QLabel('Local amount'), 2, 0)
        h.addWidget(local_amt_inp, 2, 1)
        h.addWidget(QLabel('Push amount'), 3, 0)
        h.addWidget(push_amt_inp, 3, 1)
        vbox.addLayout(h)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec_():
            return
        nodeid_hex = str(remote_nodeid.text())
        local_amt = local_amt_inp.get_amount()
        push_amt = push_amt_inp.get_amount()
        try:
            node_id = bfh(nodeid_hex)
        except:
            self.parent.show_error(_('Invalid node ID'))
            return
        if node_id not in self.parent.wallet.lnworker.peers and node_id not in self.parent.network.lightning_nodes:
            self.parent.show_error(_('Unknown node:') + ' ' + nodeid_hex)
            return
        assert local_amt >= 200000
        assert local_amt >= push_amt
        self.main_window.protect(self.open_channel, (node_id, local_amt, push_amt))

    def open_channel(self, *args, **kwargs):
        self.parent.wallet.lnworker.open_channel(*args, **kwargs)
