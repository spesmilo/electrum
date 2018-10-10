# -*- coding: utf-8 -*-
import asyncio
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import *

from electrum.util import inv_dict, bh2u, bfh
from electrum.i18n import _
from electrum.lnhtlc import HTLCStateMachine
from electrum.lnutil import LOCAL, REMOTE, ConnStringFormatError

from .util import MyTreeWidget, SortableTreeWidgetItem, WindowModalDialog, Buttons, OkButton, CancelButton
from .amountedit import BTCAmountEdit

class ChannelsList(MyTreeWidget):
    update_rows = QtCore.pyqtSignal()
    update_single_row = QtCore.pyqtSignal(HTLCStateMachine)

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Node ID'), _('Balance'), _('Remote'), _('Status')], 0)
        self.main_window = parent
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.status = QLabel('')

    def format_fields(self, chan):
        return [
            bh2u(chan.node_id),
            self.parent.format_amount(chan.balance(LOCAL)//1000),
            self.parent.format_amount(chan.balance(REMOTE)//1000),
            chan.get_state()
        ]

    def create_menu(self, position):
        menu = QMenu()
        channel_id = self.currentItem().data(0, QtCore.Qt.UserRole)
        print('ID', bh2u(channel_id))
        def close():
            netw = self.parent.network
            coro = self.parent.wallet.lnworker.close_channel(channel_id)
            suc, msg = netw.run_from_another_thread(coro)
            if not suc:
                self.main_window.show_error('Force-close failed:\n{}'.format(msg))
        menu.addAction(_("Force-close channel"), close)
        menu.exec_(self.viewport().mapToGlobal(position))

    @QtCore.pyqtSlot(HTLCStateMachine)
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
        b = QPushButton(_('Open Channel'))
        b.clicked.connect(self.new_channel_dialog)
        h = QHBoxLayout()
        h.addWidget(self.status)
        h.addStretch()
        h.addWidget(b)
        return h

    def update_status(self):
        channel_db = self.parent.network.channel_db
        num_nodes = len(channel_db.nodes)
        num_channels = len(channel_db)
        num_peers = len(self.parent.wallet.lnworker.peers)
        self.status.setText(_('{} peers, {} nodes, {} channels')
                            .format(num_peers, num_nodes, num_channels))

    def new_channel_dialog(self):
        lnworker = self.parent.wallet.lnworker
        d = WindowModalDialog(self.parent, _('Open Channel'))
        d.setMinimumWidth(700)
        vbox = QVBoxLayout(d)
        h = QGridLayout()
        local_nodeid = QLineEdit()
        local_nodeid.setText(bh2u(lnworker.node_keypair.pubkey))
        local_nodeid.setReadOnly(True)
        local_nodeid.setCursorPosition(0)
        remote_nodeid = QLineEdit()
        local_amt_inp = BTCAmountEdit(self.parent.get_decimal_point)
        local_amt_inp.setAmount(200000)
        push_amt_inp = BTCAmountEdit(self.parent.get_decimal_point)
        push_amt_inp.setAmount(0)
        h.addWidget(QLabel(_('Your Node ID')), 0, 0)
        h.addWidget(local_nodeid, 0, 1)
        h.addWidget(QLabel(_('Remote Node ID or connection string or invoice')), 1, 0)
        h.addWidget(remote_nodeid, 1, 1)
        h.addWidget(QLabel('Local amount'), 2, 0)
        h.addWidget(local_amt_inp, 2, 1)
        h.addWidget(QLabel('Push amount'), 3, 0)
        h.addWidget(push_amt_inp, 3, 1)
        vbox.addLayout(h)
        ok_button = OkButton(d)
        ok_button.setDefault(True)
        vbox.addLayout(Buttons(CancelButton(d), ok_button))
        suggestion = lnworker.suggest_peer() or b''
        remote_nodeid.setText(bh2u(suggestion))
        remote_nodeid.setCursorPosition(0)
        if not d.exec_():
            return
        local_amt = local_amt_inp.get_amount()
        push_amt = push_amt_inp.get_amount()
        connect_contents = str(remote_nodeid.text()).strip()
        self.main_window.protect(self.open_channel, (connect_contents, local_amt, push_amt))

    def open_channel(self, *args, **kwargs):
        try:
            self.parent.wallet.lnworker.open_channel(*args, **kwargs)
        except Exception as e:
            # don't use str(e) because str(asyncio.TimeoutError()) (and many others) is ''
            self.parent.show_error('Cannot open channel: %s' % repr(e))
