# -*- coding: utf-8 -*-
import traceback
import asyncio
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtWidgets import *

from electrum.util import inv_dict, bh2u, bfh
from electrum.i18n import _
from electrum.lnchannel import Channel
from electrum.lnutil import LOCAL, REMOTE, ConnStringFormatError

from .util import MyTreeView, WindowModalDialog, Buttons, OkButton, CancelButton, EnterButton, WWLabel
from .amountedit import BTCAmountEdit
from .channel_details import ChannelDetailsDialog

class ChannelsList(MyTreeView):
    update_rows = QtCore.pyqtSignal()
    update_single_row = QtCore.pyqtSignal(Channel)

    def __init__(self, parent):
        super().__init__(parent, self.create_menu, 0)
        self.setModel(QtGui.QStandardItemModel(self))
        self.main_window = parent
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.network = self.parent.network
        self.lnworker = self.parent.wallet.lnworker

    def format_fields(self, chan):
        labels = {}
        for subject in (REMOTE, LOCAL):
            bal_minus_htlcs = chan.balance_minus_outgoing_htlcs(subject)//1000
            label = self.parent.format_amount(bal_minus_htlcs)
            other = subject.inverted()
            bal_other = chan.balance(other)//1000
            bal_minus_htlcs_other = chan.balance_minus_outgoing_htlcs(other)//1000
            if bal_other != bal_minus_htlcs_other:
                label += ' (+' + self.parent.format_amount(bal_other - bal_minus_htlcs_other) + ')'
            labels[subject] = label
        return [
            bh2u(chan.node_id),
            labels[LOCAL],
            labels[REMOTE],
            chan.get_state()
        ]

    def on_success(txid):
        self.main_window.show_error('Channel closed' + '\n' + txid)

    def on_failure(exc_info):
        type_, e, tb = exc_info
        traceback.print_tb(tb)
        self.main_window.show_error('Failed to close channel:\n{}'.format(repr(e)))

    def close(self, channel_id):
        def task():
            coro = self.lnworker.close_channel(channel_id)
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, 'please wait..', task, self.on_success, self.on_failure)

    def force_close(self, channel_id):
        def task():
            coro = self.lnworker.force_close_channel(channel_id)
            return self.network.run_from_another_thread(coro)
        if self.parent.question('Force-close channel?\nReclaimed funds will not be immediately available.'):
            WaitingDialog(self, 'please wait..', task, self.on_success, self.on_failure)

    def remove_channel(self, channel_id):
        if self.main_window.question(_('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.')):
            self.lnworker.remove_channel(channel_id)

    def create_menu(self, position):
        from .util import WaitingDialog
        menu = QMenu()
        idx = self.selectionModel().currentIndex()
        item = self.model().itemFromIndex(idx)
        if not item:
            return
        channel_id = idx.sibling(idx.row(), 0).data(QtCore.Qt.UserRole)
        chan = self.lnworker.channels[channel_id]
        menu.addAction(_("Details..."), lambda: self.details(channel_id))
        if not chan.is_closed():
            menu.addAction(_("Close channel"), lambda: self.close_channel(channel_id))
            menu.addAction(_("Force-close channel"), lambda: self.force_close(channel_id))
        else:
            menu.addAction(_("Remove"), lambda: self.remove_channel(channel_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    def details(self, channel_id):
        assert self.parent.wallet
        ChannelDetailsDialog(self.parent, channel_id).show()

    @QtCore.pyqtSlot(Channel)
    def do_update_single_row(self, chan):
        for row in range(self.model().rowCount()):
            item = self.model().item(row,0)
            if item.data(QtCore.Qt.UserRole) == chan.channel_id:
                for column, v in enumerate(self.format_fields(chan)):
                    self.model().item(row, column).setData(v, QtCore.Qt.DisplayRole)

    @QtCore.pyqtSlot()
    def do_update_rows(self):
        self.model().clear()
        self.update_headers([_('Node ID'), _('Local'), _('Remote'), _('Status')])
        for chan in self.parent.wallet.lnworker.channels.values():
            items = [QtGui.QStandardItem(x) for x in self.format_fields(chan)]
            items[0].setData(chan.channel_id, QtCore.Qt.UserRole)
            self.model().insertRow(0, items)

    def get_toolbar(self):
        h = QHBoxLayout()
        h.addStretch()
        h.addWidget(EnterButton(_('Open Channel'), self.new_channel_dialog))
        return h


    def statistics_dialog(self):
        channel_db = self.parent.network.channel_db
        capacity = self.parent.format_amount(channel_db.capacity()) + ' '+ self.parent.base_unit()
        d = WindowModalDialog(self.parent, _('Lightning Network Statistics'))
        d.setMinimumWidth(400)
        vbox = QVBoxLayout(d)
        h = QGridLayout()
        h.addWidget(QLabel(_('Nodes') + ':'), 0, 0)
        h.addWidget(QLabel('{}'.format(channel_db.num_nodes)), 0, 1)
        h.addWidget(QLabel(_('Channels') + ':'), 1, 0)
        h.addWidget(QLabel('{}'.format(channel_db.num_channels)), 1, 1)
        h.addWidget(QLabel(_('Capacity') + ':'), 2, 0)
        h.addWidget(QLabel(capacity), 2, 1)
        vbox.addLayout(h)
        vbox.addLayout(Buttons(OkButton(d)))
        d.exec_()

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
        self.parent.open_channel(connect_contents, local_amt, push_amt)
