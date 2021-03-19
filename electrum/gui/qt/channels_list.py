# -*- coding: utf-8 -*-
import traceback
from enum import IntEnum
from typing import Sequence, Optional, Dict

from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QMenu, QHBoxLayout, QLabel, QVBoxLayout, QGridLayout, QLineEdit,
                             QPushButton, QAbstractItemView, QComboBox, QCheckBox)
from PyQt5.QtGui import QFont, QStandardItem, QBrush

from electrum.util import bh2u, NotEnoughFunds, NoDynamicFeeEstimates
from electrum.i18n import _
from electrum.lnchannel import AbstractChannel, PeerState, ChannelBackup, Channel, ChannelState
from electrum.wallet import Abstract_Wallet
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id, LN_MAX_FUNDING_SAT
from electrum.lnworker import LNWallet

from .util import (MyTreeView, WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, WaitingDialog, MONOSPACE_FONT, ColorScheme)
from .amountedit import BTCAmountEdit, FreezableLineEdit


ROLE_CHANNEL_ID = Qt.UserRole


class ChannelsList(MyTreeView):
    update_rows = QtCore.pyqtSignal(Abstract_Wallet)
    update_single_row = QtCore.pyqtSignal(Abstract_Wallet, AbstractChannel)
    gossip_db_loaded = QtCore.pyqtSignal()

    class Columns(IntEnum):
        SHORT_CHANID = 0
        NODE_ALIAS = 1
        CAPACITY = 2
        LOCAL_BALANCE = 3
        REMOTE_BALANCE = 4
        CHANNEL_STATUS = 5

    headers = {
        Columns.SHORT_CHANID: _('Short Channel ID'),
        Columns.NODE_ALIAS: _('Node alias'),
        Columns.CAPACITY: _('Capacity'),
        Columns.LOCAL_BALANCE: _('Can send'),
        Columns.REMOTE_BALANCE: _('Can receive'),
        Columns.CHANNEL_STATUS: _('Status'),
    }

    filter_columns = [
        Columns.SHORT_CHANID,
        Columns.NODE_ALIAS,
        Columns.CHANNEL_STATUS,
    ]

    _default_item_bg_brush = None  # type: Optional[QBrush]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.NODE_ALIAS,
                         editable_columns=[])
        self.setModel(QtGui.QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.main_window = parent
        self.gossip_db_loaded.connect(self.on_gossip_db)
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.network = self.parent.network
        self.lnworker = self.parent.wallet.lnworker
        self.setSortingEnabled(True)

    def format_fields(self, chan: AbstractChannel) -> Dict['ChannelsList.Columns', str]:
        labels = {}
        for subject in (REMOTE, LOCAL):
            if isinstance(chan, Channel):
                can_send = chan.available_to_spend(subject) / 1000
                label = self.parent.format_amount(can_send)
                other = subject.inverted()
                bal_other = chan.balance(other)//1000
                bal_minus_htlcs_other = chan.balance_minus_outgoing_htlcs(other)//1000
                if bal_other != bal_minus_htlcs_other:
                    label += ' (+' + self.parent.format_amount(bal_other - bal_minus_htlcs_other) + ')'
            else:
                assert isinstance(chan, ChannelBackup)
                label = ''
            labels[subject] = label
        status = chan.get_state_for_GUI()
        closed = chan.is_closed()
        node_alias = self.lnworker.get_node_alias(chan.node_id) or chan.node_id.hex()
        capacity_str = self.parent.format_amount(chan.get_capacity(), whitespaces=True)
        return {
            self.Columns.SHORT_CHANID: chan.short_id_for_GUI(),
            self.Columns.NODE_ALIAS: node_alias,
            self.Columns.CAPACITY: capacity_str,
            self.Columns.LOCAL_BALANCE: '' if closed else labels[LOCAL],
            self.Columns.REMOTE_BALANCE: '' if closed else labels[REMOTE],
            self.Columns.CHANNEL_STATUS: status,
        }

    def on_channel_closed(self, txid):
        self.main_window.show_error('Channel closed' + '\n' + txid)

    def on_request_sent(self, b):
        self.main_window.show_message(_('Request sent'))

    def on_failure(self, exc_info):
        type_, e, tb = exc_info
        traceback.print_tb(tb)
        self.main_window.show_error('Failed to close channel:\n{}'.format(repr(e)))

    def close_channel(self, channel_id):
        self.is_force_close = False
        msg = _('Close channel?')
        force_cb = QCheckBox('Request force close from remote peer')
        tooltip = _(
            'If you check this option, your node will pretend that it has lost its data and ask the remote node to broadcast their latest state. '
            'Doing so from time to time helps make sure that nodes are honest, because your node can punish them if they broadcast a revoked state.')
        tooltip = '<qt>' + tooltip + '</qt>' # rich text is word wrapped
        def on_checked(b):
            self.is_force_close = bool(b)
        force_cb.stateChanged.connect(on_checked)
        force_cb.setToolTip(tooltip)
        if not self.parent.question(msg, checkbox=force_cb):
            return
        if self.is_force_close:
            coro = self.lnworker.request_force_close(channel_id)
            on_success = self.on_request_sent
        else:
            coro = self.lnworker.close_channel(channel_id)
            on_success = self.on_channel_closed
        def task():
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, 'please wait..', task, on_success, self.on_failure)

    def force_close(self, channel_id):
        self.save_backup = True
        backup_cb = QCheckBox('Create a backup now', checked=True)
        def on_checked(b):
            self.save_backup = bool(b)
        backup_cb.stateChanged.connect(on_checked)
        chan = self.lnworker.channels[channel_id]
        to_self_delay = chan.config[REMOTE].to_self_delay
        msg = '<b>' + _('Force-close channel?') + '</b><br/>'\
            + '<p>' + _('If you force-close this channel, the funds you have in it will not be available for {} blocks.').format(to_self_delay) + ' '\
            + _('After that delay, funds will be swept to an address derived from your wallet seed.') + '</p>'\
            + '<u>' + _('Please create a backup of your wallet file!') + '</u> '\
            + '<p>' + _('Funds in this channel will not be recoverable from seed until they are swept back into your wallet, and might be lost if you lose your wallet file.') + ' '\
            + _('To prevent that, you should save a backup of your wallet on another device.') + '</p>'
        if not self.parent.question(msg, title=_('Force-close channel'), rich_text=True, checkbox=backup_cb):
            return
        if self.save_backup:
            if not self.parent.backup_wallet():
                return
        def task():
            coro = self.lnworker.force_close_channel(channel_id)
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, 'please wait..', task, self.on_channel_closed, self.on_failure)

    def remove_channel(self, channel_id):
        if self.main_window.question(_('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.')):
            self.lnworker.remove_channel(channel_id)

    def remove_channel_backup(self, channel_id):
        if self.main_window.question(_('Remove channel backup?')):
            self.lnworker.remove_channel_backup(channel_id)

    def export_channel_backup(self, channel_id):
        msg = ' '.join([
            _("Channel backups can be imported in another instance of the same wallet, by scanning this QR code."),
            _("Please note that channel backups cannot be used to restore your channels."),
            _("If you lose your wallet file, the only thing you can do with a backup is to request your channel to be closed, so that your funds will be sent on-chain."),
        ])
        data = self.lnworker.export_channel_backup(channel_id)
        self.main_window.show_qrcode(data, 'channel backup', help_text=msg,
                                     show_copy_text_btn=True)

    def request_force_close(self, channel_id):
        def task():
            coro = self.lnworker.request_force_close_from_backup(channel_id)
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, 'please wait..', task, self.on_request_sent, self.on_failure)

    def freeze_channel_for_sending(self, chan, b):
        if self.lnworker.channel_db or self.lnworker.is_trampoline_peer(chan.node_id):
            chan.set_frozen_for_sending(b)
        else:
            msg = ' '.join([
                _("Trampoline routing is enabled, but this channel is with a non-trampoline node."),
                _("This channel may still be used for receiving, but it is frozen for sending."),
                _("If you want to keep using this channel, you need to disable trampoline routing in your preferences."),
            ])
            self.main_window.show_warning(msg, title=_('Channel is frozen for sending'))

    def create_menu(self, position):
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)  # consecutive separators are merged together
        selected = self.selected_in_column(self.Columns.NODE_ALIAS)
        if not selected:
            menu.addAction(_("Import channel backup"), lambda: self.parent.do_process_from_text_channel_backup())
            menu.exec_(self.viewport().mapToGlobal(position))
            return
        multi_select = len(selected) > 1
        if multi_select:
            return
        idx = self.indexAt(position)
        if not idx.isValid():
            return
        item = self.model().itemFromIndex(idx)
        if not item:
            return
        channel_id = idx.sibling(idx.row(), self.Columns.NODE_ALIAS).data(ROLE_CHANNEL_ID)
        chan = self.lnworker.channel_backups.get(channel_id)
        if chan:
            funding_tx = self.parent.wallet.db.get_transaction(chan.funding_outpoint.txid)
            menu.addAction(_("View funding transaction"), lambda: self.parent.show_transaction(funding_tx))
            if chan.get_state() == ChannelState.FUNDED:
                menu.addAction(_("Request force-close"), lambda: self.request_force_close(channel_id))
            if chan.is_imported:
                menu.addAction(_("Delete"), lambda: self.remove_channel_backup(channel_id))
            menu.exec_(self.viewport().mapToGlobal(position))
            return
        chan = self.lnworker.channels[channel_id]
        menu.addAction(_("Details..."), lambda: self.parent.show_channel(channel_id))
        cc = self.add_copy_menu(menu, idx)
        cc.addAction(_("Node ID"), lambda: self.place_text_on_clipboard(
            chan.node_id.hex(), title=_("Node ID")))
        cc.addAction(_("Long Channel ID"), lambda: self.place_text_on_clipboard(
            channel_id.hex(), title=_("Long Channel ID")))
        if not chan.is_closed():
            if not chan.is_frozen_for_sending():
                menu.addAction(_("Freeze (for sending)"), lambda: self.freeze_channel_for_sending(chan, True))
            else:
                menu.addAction(_("Unfreeze (for sending)"), lambda: self.freeze_channel_for_sending(chan, False))
            if not chan.is_frozen_for_receiving():
                menu.addAction(_("Freeze (for receiving)"), lambda: chan.set_frozen_for_receiving(True))
            else:
                menu.addAction(_("Unfreeze (for receiving)"), lambda: chan.set_frozen_for_receiving(False))

        funding_tx = self.parent.wallet.db.get_transaction(chan.funding_outpoint.txid)
        if funding_tx:
            menu.addAction(_("View funding transaction"), lambda: self.parent.show_transaction(funding_tx))
        if not chan.is_closed():
            menu.addSeparator()
            if chan.peer_state == PeerState.GOOD:
                menu.addAction(_("Close channel"), lambda: self.close_channel(channel_id))
            menu.addAction(_("Force-close channel"), lambda: self.force_close(channel_id))
        else:
            item = chan.get_closing_height()
            if item:
                txid, height, timestamp = item
                closing_tx = self.lnworker.lnwatcher.db.get_transaction(txid)
                if closing_tx:
                    menu.addAction(_("View closing transaction"), lambda: self.parent.show_transaction(closing_tx))
        menu.addSeparator()
        menu.addAction(_("Export backup"), lambda: self.export_channel_backup(channel_id))
        if chan.is_redeemed():
            menu.addSeparator()
            menu.addAction(_("Delete"), lambda: self.remove_channel(channel_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    @QtCore.pyqtSlot(Abstract_Wallet, AbstractChannel)
    def do_update_single_row(self, wallet: Abstract_Wallet, chan: AbstractChannel):
        if wallet != self.parent.wallet:
            return
        for row in range(self.model().rowCount()):
            item = self.model().item(row, self.Columns.NODE_ALIAS)
            if item.data(ROLE_CHANNEL_ID) != chan.channel_id:
                continue
            for column, v in self.format_fields(chan).items():
                self.model().item(row, column).setData(v, QtCore.Qt.DisplayRole)
            items = [self.model().item(row, column) for column in self.Columns]
            self._update_chan_frozen_bg(chan=chan, items=items)
        if wallet.lnworker:
            self.update_can_send(wallet.lnworker)

    @QtCore.pyqtSlot()
    def on_gossip_db(self):
        self.do_update_rows(self.parent.wallet)

    @QtCore.pyqtSlot(Abstract_Wallet)
    def do_update_rows(self, wallet):
        if wallet != self.parent.wallet:
            return
        channels = list(wallet.lnworker.channels.values()) if wallet.lnworker else []
        backups = list(wallet.lnworker.channel_backups.values()) if wallet.lnworker else []
        if wallet.lnworker:
            self.update_can_send(wallet.lnworker)
        self.model().clear()
        self.update_headers(self.headers)
        for chan in channels + backups:
            field_map = self.format_fields(chan)
            items = [QtGui.QStandardItem(field_map[col]) for col in sorted(field_map)]
            self.set_editability(items)
            if self._default_item_bg_brush is None:
                self._default_item_bg_brush = items[self.Columns.NODE_ALIAS].background()
            items[self.Columns.NODE_ALIAS].setData(chan.channel_id, ROLE_CHANNEL_ID)
            items[self.Columns.NODE_ALIAS].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.LOCAL_BALANCE].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.REMOTE_BALANCE].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.CAPACITY].setFont(QFont(MONOSPACE_FONT))
            self._update_chan_frozen_bg(chan=chan, items=items)
            self.model().insertRow(0, items)

        self.sortByColumn(self.Columns.SHORT_CHANID, Qt.DescendingOrder)

    def _update_chan_frozen_bg(self, *, chan: AbstractChannel, items: Sequence[QStandardItem]):
        assert self._default_item_bg_brush is not None
        # frozen for sending
        item = items[self.Columns.LOCAL_BALANCE]
        if chan.is_frozen_for_sending():
            item.setBackground(ColorScheme.BLUE.as_color(True))
            item.setToolTip(_("This channel is frozen for sending. It will not be used for outgoing payments."))
        else:
            item.setBackground(self._default_item_bg_brush)
            item.setToolTip("")
        # frozen for receiving
        item = items[self.Columns.REMOTE_BALANCE]
        if chan.is_frozen_for_receiving():
            item.setBackground(ColorScheme.BLUE.as_color(True))
            item.setToolTip(_("This channel is frozen for receiving. It will not be included in invoices."))
        else:
            item.setBackground(self._default_item_bg_brush)
            item.setToolTip("")

    def update_can_send(self, lnworker: LNWallet):
        msg = _('Can send') + ' ' + self.parent.format_amount(lnworker.num_sats_can_send())\
              + ' ' + self.parent.base_unit() + '; '\
              + _('can receive') + ' ' + self.parent.format_amount(lnworker.num_sats_can_receive())\
              + ' ' + self.parent.base_unit()
        self.can_send_label.setText(msg)
        self.update_swap_button(lnworker)

    def update_swap_button(self, lnworker: LNWallet):
        if lnworker.num_sats_can_send() or lnworker.num_sats_can_receive():
            self.swap_button.setEnabled(True)
        else:
            self.swap_button.setEnabled(False)

    def get_toolbar(self):
        h = QHBoxLayout()
        self.can_send_label = QLabel('')
        h.addWidget(self.can_send_label)
        h.addStretch()
        self.swap_button = EnterButton(_('Swap'), self.swap_dialog)
        self.swap_button.setToolTip("Have at least one channel to do swaps.")
        self.swap_button.setDisabled(True)
        self.new_channel_button = EnterButton(_('Open Channel'), self.new_channel_with_warning)
        self.new_channel_button.setEnabled(self.parent.wallet.has_lightning())
        h.addWidget(self.new_channel_button)
        h.addWidget(self.swap_button)
        return h

    def new_channel_with_warning(self):
        if not self.parent.wallet.lnworker.channels:
            warning = _("Lightning support in Electrum is experimental. "
                         "Do not put large amounts in lightning channels.")
            if not self.parent.wallet.lnworker.has_recoverable_channels():
                warning += _("Funds stored in lightning channels are not recoverable from your seed. "
                             "You must backup your wallet file everytime you create a new channel.")
            answer = self.parent.question(
                _('Do you want to create your first channel?') + '\n\n' +
                _('WARNING') + ': ' + '\n\n' + warning)
            if answer:
                self.new_channel_dialog()
        else:
            self.new_channel_dialog()

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
        if self.parent.network.channel_db:
            vbox.addWidget(QLabel(_('Enter Remote Node ID or connection string or invoice')))
            remote_nodeid = QLineEdit()
            remote_nodeid.setMinimumWidth(700)
            suggest_button = QPushButton(d, text=_('Suggest Peer'))
            def on_suggest():
                self.parent.wallet.network.start_gossip()
                nodeid = bh2u(lnworker.suggest_peer() or b'')
                if not nodeid:
                    remote_nodeid.setText("")
                    remote_nodeid.setPlaceholderText(
                        "Please wait until the graph is synchronized to 30%, and then try again.")
                else:
                    remote_nodeid.setText(nodeid)
                remote_nodeid.repaint()  # macOS hack for #6269
            suggest_button.clicked.connect(on_suggest)
        else:
            from electrum.lnworker import hardcoded_trampoline_nodes
            trampolines = hardcoded_trampoline_nodes()
            trampoline_names = list(trampolines.keys())
            trampoline_combo = QComboBox()
            trampoline_combo.addItems(trampoline_names)
            trampoline_combo.setCurrentIndex(1)

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

        clear_button = QPushButton(d, text=_('Clear'))
        def on_clear():
            amount_e.setText('')
            amount_e.setFrozen(False)
            amount_e.repaint()  # macOS hack for #6269
            if self.parent.network.channel_db:
                remote_nodeid.setText('')
                remote_nodeid.repaint()  # macOS hack for #6269
            max_button.setChecked(False)
            max_button.repaint()  # macOS hack for #6269
        clear_button.clicked.connect(on_clear)
        clear_button.setFixedWidth(100)
        h = QGridLayout()
        if self.parent.network.channel_db:
            h.addWidget(QLabel(_('Remote Node ID')), 0, 0)
            h.addWidget(remote_nodeid, 0, 1, 1, 4)
            h.addWidget(suggest_button, 0, 5)
        else:
            h.addWidget(QLabel(_('Trampoline Node')), 0, 0)
            h.addWidget(trampoline_combo, 0, 1, 1, 3)

        h.addWidget(QLabel('Amount'), 2, 0)
        h.addWidget(amount_e, 2, 1)
        h.addWidget(max_button, 2, 2)
        h.addWidget(clear_button, 2, 3)
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
        if self.parent.network.channel_db:
            connect_str = str(remote_nodeid.text()).strip()
        else:
            name = trampoline_names[trampoline_combo.currentIndex()]
            connect_str = str(trampolines[name])
        if not connect_str or not funding_sat:
            return
        self.parent.open_channel(connect_str, funding_sat, 0)

    def swap_dialog(self):
        from .swap_dialog import SwapDialog
        d = SwapDialog(self.parent)
        d.run()
