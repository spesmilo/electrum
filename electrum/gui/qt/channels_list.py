# -*- coding: utf-8 -*-
import traceback
from enum import IntEnum

from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMenu, QHBoxLayout, QLabel, QVBoxLayout, QGridLayout, QLineEdit, QPushButton
from PyQt5.QtGui import QFont

from electrum.util import bh2u, NotEnoughFunds, NoDynamicFeeEstimates
from electrum.i18n import _
from electrum.lnchannel import Channel, peer_states
from electrum.wallet import Abstract_Wallet
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id, LN_MAX_FUNDING_SAT

from .util import (MyTreeView, WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, WaitingDialog, MONOSPACE_FONT)
from .amountedit import BTCAmountEdit, FreezableLineEdit


ROLE_CHANNEL_ID = Qt.UserRole


class ChannelsList(MyTreeView):
    update_rows = QtCore.pyqtSignal(Abstract_Wallet)
    update_single_row = QtCore.pyqtSignal(Channel)

    class Columns(IntEnum):
        SHORT_CHANID = 0
        NODE_ID = 1
        NODE_ALIAS = 2
        LOCAL_BALANCE = 3
        REMOTE_BALANCE = 4
        CHANNEL_STATUS = 5

    headers = {
        Columns.SHORT_CHANID: _('Short Channel ID'),
        Columns.NODE_ID: _('Node ID'),
        Columns.NODE_ALIAS: _('Node alias'),
        Columns.LOCAL_BALANCE: _('Local'),
        Columns.REMOTE_BALANCE: _('Remote'),
        Columns.CHANNEL_STATUS: _('Status'),
    }

    def __init__(self, parent):
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.NODE_ID,
                         editable_columns=[])
        self.setModel(QtGui.QStandardItemModel(self))
        self.main_window = parent
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.network = self.parent.network
        self.lnworker = self.parent.wallet.lnworker
        self.setSortingEnabled(True)

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
        status = self.lnworker.get_channel_status(chan)
        closed = chan.is_closed()
        if self.parent.network.is_lightning_running():
            node_info = self.lnworker.channel_db.get_node_info_for_node_id(chan.node_id)
            node_alias = (node_info.alias if node_info else '') or ''
        else:
            node_alias = ''
        return [
            format_short_channel_id(chan.short_channel_id),
            bh2u(chan.node_id),
            node_alias,
            '' if closed else labels[LOCAL],
            '' if closed else labels[REMOTE],
            status
        ]

    def on_success(self, txid):
        self.main_window.show_error('Channel closed' + '\n' + txid)

    def on_failure(self, exc_info):
        type_, e, tb = exc_info
        traceback.print_tb(tb)
        self.main_window.show_error('Failed to close channel:\n{}'.format(repr(e)))

    def close_channel(self, channel_id):
        msg = _('Close channel?')
        if not self.parent.question(msg):
            return
        def task():
            coro = self.lnworker.close_channel(channel_id)
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, 'please wait..', task, self.on_success, self.on_failure)

    def force_close(self, channel_id):
        chan = self.lnworker.channels[channel_id]
        to_self_delay = chan.config[REMOTE].to_self_delay
        if self.lnworker.wallet.is_lightning_backup():
            msg = _('WARNING: force-closing from an old state might result in fund loss.\nAre you sure?')
        else:
            msg = _('Force-close channel?') + '\n\n'\
                  + _(f'Funds retrieved from this channel will not be available before {to_self_delay} blocks after forced closure.') + ' '\
                  + _('After that delay, funds will be sent to an address derived from your wallet seed.') + '\n\n'\
                  + _('In the meantime, channel funds will not be recoverable from your seed, and will be lost if you lose your wallet.') + ' '\
                  + _('To prevent that, you should backup your wallet if you have not already done so.')
        if self.parent.question(msg):
            def task():
                coro = self.lnworker.force_close_channel(channel_id)
                return self.network.run_from_another_thread(coro)
            WaitingDialog(self, 'please wait..', task, self.on_success, self.on_failure)

    def remove_channel(self, channel_id):
        if self.main_window.question(_('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.')):
            self.lnworker.remove_channel(channel_id)

    def create_menu(self, position):
        menu = QMenu()
        idx = self.selectionModel().currentIndex()
        item = self.model().itemFromIndex(idx)
        if not item:
            return
        channel_id = idx.sibling(idx.row(), self.Columns.NODE_ID).data(ROLE_CHANNEL_ID)
        chan = self.lnworker.channels[channel_id]
        menu.addAction(_("Details..."), lambda: self.parent.show_channel(channel_id))
        self.add_copy_menu(menu, idx)
        funding_tx = self.parent.wallet.db.get_transaction(chan.funding_outpoint.txid)
        if funding_tx:
            menu.addAction(_("View funding transaction"), lambda: self.parent.show_transaction(funding_tx))
        if not chan.is_closed():
            if chan.peer_state == peer_states.GOOD:
                menu.addAction(_("Close channel"), lambda: self.close_channel(channel_id))
            menu.addAction(_("Force-close channel"), lambda: self.force_close(channel_id))
        else:
            item = chan.get_closing_height()
            if item:
                txid, height, timestamp = item
                closing_tx = self.lnworker.lnwatcher.db.get_transaction(txid)
                if closing_tx:
                    menu.addAction(_("View closing transaction"), lambda: self.parent.show_transaction(closing_tx))
        if chan.is_redeemed():
            menu.addAction(_("Delete"), lambda: self.remove_channel(channel_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    @QtCore.pyqtSlot(Channel)
    def do_update_single_row(self, chan):
        lnworker = self.parent.wallet.lnworker
        if not lnworker:
            return
        for row in range(self.model().rowCount()):
            item = self.model().item(row, self.Columns.NODE_ID)
            if item.data(ROLE_CHANNEL_ID) == chan.channel_id:
                for column, v in enumerate(self.format_fields(chan)):
                    self.model().item(row, column).setData(v, QtCore.Qt.DisplayRole)
        self.update_can_send(lnworker)

    @QtCore.pyqtSlot(Abstract_Wallet)
    def do_update_rows(self, wallet):
        if wallet != self.parent.wallet:
            return
        lnworker = self.parent.wallet.lnworker
        if not lnworker:
            return
        self.update_can_send(lnworker)
        self.model().clear()
        self.update_headers(self.headers)
        for chan in lnworker.channels.values():
            items = [QtGui.QStandardItem(x) for x in self.format_fields(chan)]
            self.set_editability(items)
            items[self.Columns.NODE_ID].setData(chan.channel_id, ROLE_CHANNEL_ID)
            items[self.Columns.NODE_ID].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.LOCAL_BALANCE].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.REMOTE_BALANCE].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(0, items)

    def update_can_send(self, lnworker):
        msg = _('Can send') + ' ' + self.parent.format_amount(lnworker.can_send())\
              + ' ' + self.parent.base_unit() + '; '\
              + _('can receive') + ' ' + self.parent.format_amount(lnworker.can_receive())\
              + ' ' + self.parent.base_unit()
        self.can_send_label.setText(msg)

    def get_toolbar(self):
        h = QHBoxLayout()
        self.can_send_label = QLabel('')
        h.addWidget(self.can_send_label)
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
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Enter Remote Node ID or connection string or invoice')))
        local_nodeid = FreezableLineEdit()
        local_nodeid.setMinimumWidth(700)
        local_nodeid.setText(bh2u(lnworker.node_keypair.pubkey))
        local_nodeid.setFrozen(True)
        local_nodeid.setCursorPosition(0)
        remote_nodeid = QLineEdit()
        remote_nodeid.setMinimumWidth(700)
        amount_e = BTCAmountEdit(self.parent.get_decimal_point)
        # max button
        def spend_max():
            amount_e.setFrozen(max_button.isChecked())
            if not max_button.isChecked():
                return
            make_tx = self.parent.mktx_for_open_channel('!')
            try:
                tx = make_tx(None)
            except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
                max_button.setChecked(False)
                amount_e.setFrozen(False)
                self.main_window.show_error(str(e))
                return
            amount = tx.output_value()
            amount = min(amount, LN_MAX_FUNDING_SAT)
            amount_e.setAmount(amount)
        max_button = EnterButton(_("Max"), spend_max)
        max_button.setFixedWidth(100)
        max_button.setCheckable(True)
        suggest_button = QPushButton(d, text=_('Suggest'))
        suggest_button.clicked.connect(lambda: remote_nodeid.setText(bh2u(lnworker.suggest_peer() or b'')))
        clear_button = QPushButton(d, text=_('Clear'))
        def on_clear():
            amount_e.setText('')
            remote_nodeid.setText('')
            max_button.setChecked(False)
        clear_button.clicked.connect(on_clear)
        h = QGridLayout()
        h.addWidget(QLabel(_('Your Node ID')), 0, 0)
        h.addWidget(local_nodeid, 0, 1, 1, 3)
        h.addWidget(QLabel(_('Remote Node ID')), 1, 0)
        h.addWidget(remote_nodeid, 1, 1, 1, 3)
        h.addWidget(suggest_button, 2, 1)
        h.addWidget(clear_button, 2, 2)
        h.addWidget(QLabel('Amount'), 3, 0)
        h.addWidget(amount_e, 3, 1)
        h.addWidget(max_button, 3, 2)
        vbox.addLayout(h)
        ok_button = OkButton(d)
        ok_button.setDefault(True)
        vbox.addLayout(Buttons(CancelButton(d), ok_button))
        if not d.exec_():
            return
        if max_button.isChecked() and amount_e.get_amount() < LN_MAX_FUNDING_SAT:
            # if 'max' enabled and amount is strictly less than max allowed,
            # that means we have fewer coins than max allowed, and hence we can
            # spend all coins
            funding_sat = '!'
        else:
            funding_sat = amount_e.get_amount()
        connect_str = str(remote_nodeid.text()).strip()
        if not connect_str or not funding_sat:
            return
        self.parent.open_channel(connect_str, funding_sat, 0)
