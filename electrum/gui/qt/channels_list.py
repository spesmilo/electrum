# -*- coding: utf-8 -*-
import traceback
from enum import IntEnum
from typing import Sequence, Optional, Dict
from abc import abstractmethod, ABC

from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt, QRect, QSize
from PyQt5.QtWidgets import (QMenu, QHBoxLayout, QLabel, QVBoxLayout, QGridLayout, QLineEdit,
                             QPushButton, QAbstractItemView, QComboBox, QCheckBox,
                             QToolTip)
from PyQt5.QtGui import QFont, QStandardItem, QBrush, QPainter, QIcon, QHelpEvent

from electrum.util import bh2u, NotEnoughFunds, NoDynamicFeeEstimates
from electrum.i18n import _
from electrum.lnchannel import AbstractChannel, PeerState, ChannelBackup, Channel, ChannelState, ChanCloseOption
from electrum.wallet import Abstract_Wallet
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id
from electrum.lnworker import LNWallet
from electrum.gui import messages

from .util import (MyTreeView, WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, WaitingDialog, MONOSPACE_FONT, ColorScheme)
from .amountedit import BTCAmountEdit, FreezableLineEdit
from .util import read_QIcon, font_height


ROLE_CHANNEL_ID = Qt.UserRole


class ChannelsList(MyTreeView):
    update_rows = QtCore.pyqtSignal(Abstract_Wallet)
    update_single_row = QtCore.pyqtSignal(Abstract_Wallet, AbstractChannel)
    gossip_db_loaded = QtCore.pyqtSignal()

    class Columns(IntEnum):
        FEATURES = 0
        SHORT_CHANID = 1
        NODE_ALIAS = 2
        CAPACITY = 3
        LOCAL_BALANCE = 4
        REMOTE_BALANCE = 5
        CHANNEL_STATUS = 6

    headers = {
        Columns.SHORT_CHANID: _('Short Channel ID'),
        Columns.NODE_ALIAS: _('Node alias'),
        Columns.FEATURES: "",
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
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.NODE_ALIAS)
        self.setModel(QtGui.QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.main_window = parent
        self.gossip_db_loaded.connect(self.on_gossip_db)
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.network = self.parent.network
        self.wallet = self.parent.wallet
        self.setSortingEnabled(True)
        self.selectionModel().selectionChanged.connect(self.on_selection_changed)

    @property
    # property because lnworker might be initialized at runtime
    def lnworker(self):
        return self.wallet.lnworker

    def format_fields(self, chan: AbstractChannel) -> Dict['ChannelsList.Columns', str]:
        labels = {}
        for subject in (REMOTE, LOCAL):
            if isinstance(chan, Channel):
                can_send = chan.available_to_spend(subject) / 1000
                label = self.parent.format_amount(can_send, whitespaces=True)
                other = subject.inverted()
                bal_other = chan.balance(other)//1000
                bal_minus_htlcs_other = chan.balance_minus_outgoing_htlcs(other)//1000
                if bal_other != bal_minus_htlcs_other:
                    label += ' (+' + self.parent.format_amount(bal_other - bal_minus_htlcs_other, whitespaces=False) + ')'
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
            self.Columns.FEATURES: '',
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
        msg = _('Cooperative close?')
        msg += '\n' + _(messages.MSG_COOPERATIVE_CLOSE)
        if not self.parent.question(msg):
            return
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
        msg = _('Request force-close from remote peer?')
        msg += '\n' + _(messages.MSG_REQUEST_FORCE_CLOSE)
        if not self.parent.question(msg):
            return
        def task():
            coro = self.lnworker.request_force_close(channel_id)
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, 'please wait..', task, self.on_request_sent, self.on_failure)

    def freeze_channel_for_sending(self, chan, b):
        if not self.lnworker.uses_trampoline() or self.lnworker.is_trampoline_peer(chan.node_id):
            chan.set_frozen_for_sending(b)
        else:
            msg = messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP
            self.main_window.show_warning(msg, title=_('Channel is frozen for sending'))

    def get_rebalance_pair(self):
        selected = self.selected_in_column(self.Columns.NODE_ALIAS)
        if len(selected) == 2:
            idx1 = selected[0]
            idx2 = selected[1]
            channel_id1 = idx1.sibling(idx1.row(), self.Columns.NODE_ALIAS).data(ROLE_CHANNEL_ID)
            channel_id2 = idx2.sibling(idx2.row(), self.Columns.NODE_ALIAS).data(ROLE_CHANNEL_ID)
            chan1 = self.lnworker.channels.get(channel_id1)
            chan2 = self.lnworker.channels.get(channel_id2)
            if chan1 and chan2 and (not self.lnworker.uses_trampoline() or chan1.node_id != chan2.node_id):
                return chan1, chan2
        return None, None

    def on_rebalance(self):
        chan1, chan2 = self.get_rebalance_pair()
        self.parent.rebalance_dialog(chan1, chan2)

    def on_selection_changed(self):
        chan1, chan2 = self.get_rebalance_pair()
        self.rebalance_button.setEnabled(chan1 is not None)

    def create_menu(self, position):
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)  # consecutive separators are merged together
        selected = self.selected_in_column(self.Columns.NODE_ALIAS)
        if not selected:
            menu.addAction(_("Import channel backup"), lambda: self.parent.do_process_from_text_channel_backup())
            menu.exec_(self.viewport().mapToGlobal(position))
            return
        if len(selected) == 2:
            chan1, chan2 = self.get_rebalance_pair()
            if chan1 and chan2:
                menu.addAction(_("Rebalance"), lambda: self.parent.rebalance_dialog(chan1, chan2))
                menu.exec_(self.viewport().mapToGlobal(position))
            return
        elif len(selected) > 2:
            return
        idx = self.indexAt(position)
        if not idx.isValid():
            return
        item = self.model().itemFromIndex(idx)
        if not item:
            return
        channel_id = idx.sibling(idx.row(), self.Columns.NODE_ALIAS).data(ROLE_CHANNEL_ID)
        chan = self.lnworker.get_channel_by_id(channel_id) or self.lnworker.channel_backups[channel_id]
        menu.addAction(_("Details..."), lambda: self.parent.show_channel_details(chan))
        menu.addSeparator()
        cc = self.add_copy_menu(menu, idx)
        cc.addAction(_("Node ID"), lambda: self.place_text_on_clipboard(
            chan.node_id.hex(), title=_("Node ID")))
        cc.addAction(_("Long Channel ID"), lambda: self.place_text_on_clipboard(
            channel_id.hex(), title=_("Long Channel ID")))
        if not chan.is_backup() and not chan.is_closed():
            fm = menu.addMenu(_("Freeze"))
            if not chan.is_frozen_for_sending():
                fm.addAction(_("Freeze for sending"), lambda: self.freeze_channel_for_sending(chan, True))
            else:
                fm.addAction(_("Unfreeze for sending"), lambda: self.freeze_channel_for_sending(chan, False))
            if not chan.is_frozen_for_receiving():
                fm.addAction(_("Freeze for receiving"), lambda: chan.set_frozen_for_receiving(True))
            else:
                fm.addAction(_("Unfreeze for receiving"), lambda: chan.set_frozen_for_receiving(False))
        if close_opts := chan.get_close_options():
            cm = menu.addMenu(_("Close"))
            if ChanCloseOption.COOP_CLOSE in close_opts:
                cm.addAction(_("Cooperative close"), lambda: self.close_channel(channel_id))
            if ChanCloseOption.LOCAL_FCLOSE in close_opts:
                cm.addAction(_("Force-close"), lambda: self.force_close(channel_id))
            if ChanCloseOption.REQUEST_REMOTE_FCLOSE in close_opts:
                cm.addAction(_("Request force-close"), lambda: self.request_force_close(channel_id))
        if not chan.is_backup():
            menu.addAction(_("Export backup"), lambda: self.export_channel_backup(channel_id))
        if chan.can_be_deleted():
            menu.addSeparator()
            if chan.is_backup():
                menu.addAction(_("Delete"), lambda: self.remove_channel_backup(channel_id))
            else:
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
        self.model().clear()
        self.update_headers(self.headers)
        if not wallet.lnworker:
            return
        self.update_can_send(wallet.lnworker)
        channels = wallet.lnworker.get_channel_objects()
        for chan in channels.values():
            field_map = self.format_fields(chan)
            items = [QtGui.QStandardItem(field_map[col]) for col in sorted(field_map)]
            self.set_editability(items)
            if self._default_item_bg_brush is None:
                self._default_item_bg_brush = items[self.Columns.NODE_ALIAS].background()
            items[self.Columns.NODE_ALIAS].setData(chan.channel_id, ROLE_CHANNEL_ID)
            items[self.Columns.NODE_ALIAS].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.LOCAL_BALANCE].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.REMOTE_BALANCE].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.FEATURES].setData(ChannelFeatureIcons.from_channel(chan), self.ROLE_CUSTOM_PAINT)
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
        self.rebalance_button = EnterButton(_('Rebalance'), lambda x: self.on_rebalance())
        self.rebalance_button.setToolTip("Select two active channels to rebalance.")
        self.rebalance_button.setDisabled(True)
        self.swap_button = EnterButton(_('Swap'), lambda x: self.parent.run_swap_dialog())
        self.swap_button.setToolTip("Have at least one channel to do swaps.")
        self.swap_button.setDisabled(True)
        self.new_channel_button = EnterButton(_('Open Channel'), self.new_channel_with_warning)
        self.new_channel_button.setEnabled(self.parent.wallet.has_lightning())
        h.addWidget(self.new_channel_button)
        h.addWidget(self.rebalance_button)
        h.addWidget(self.swap_button)
        return h

    def new_channel_with_warning(self):
        lnworker = self.parent.wallet.lnworker
        if not lnworker.channels and not lnworker.channel_backups:
            warning = _(messages.MSG_LIGHTNING_WARNING)
            answer = self.parent.question(
                _('Do you want to create your first channel?') + '\n\n' + warning)
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

    def new_channel_dialog(self, *, amount_sat=None, min_amount_sat=None):
        from .new_channel_dialog import NewChannelDialog
        d = NewChannelDialog(self.parent, amount_sat, min_amount_sat)
        return d.run()


class ChannelFeature(ABC):
    def __init__(self):
        self.rect = QRect()

    @abstractmethod
    def tooltip(self) -> str:
        pass

    @abstractmethod
    def icon(self) -> QIcon:
        pass


class ChanFeatChannel(ChannelFeature):
    def tooltip(self) -> str:
        return _("This is a channel")
    def icon(self) -> QIcon:
        return read_QIcon("lightning")


class ChanFeatBackup(ChannelFeature):
    def tooltip(self) -> str:
        return _("This is a static channel backup")
    def icon(self) -> QIcon:
        return read_QIcon("lightning_disconnected")


class ChanFeatTrampoline(ChannelFeature):
    def tooltip(self) -> str:
        return _("The channel peer can route Trampoline payments.")
    def icon(self) -> QIcon:
        return read_QIcon("kangaroo")


class ChanFeatNoOnchainBackup(ChannelFeature):
    def tooltip(self) -> str:
        return _("This channel cannot be recovered from your seed. You must back it up manually.")
    def icon(self) -> QIcon:
        return read_QIcon("nocloud")


class ChanFeatAnchors(ChannelFeature):
    def tooltip(self) -> str:
        return _("This channel uses anchor outputs.")
    def icon(self) -> QIcon:
        return read_QIcon("anchor")


class ChannelFeatureIcons:

    def __init__(self, features: Sequence['ChannelFeature']):
        size = max(16, font_height())
        self.icon_size = QSize(size, size)
        self.features = features

    @classmethod
    def from_channel(cls, chan: AbstractChannel) -> 'ChannelFeatureIcons':
        feats = []
        if chan.is_backup():
            feats.append(ChanFeatBackup())
            if chan.is_imported:
                feats.append(ChanFeatNoOnchainBackup())
        else:
            feats.append(ChanFeatChannel())
            if chan.lnworker.is_trampoline_peer(chan.node_id):
                feats.append(ChanFeatTrampoline())
            if not chan.has_onchain_backup():
                feats.append(ChanFeatNoOnchainBackup())
            if chan.has_anchors():
                feats.append(ChanFeatAnchors())
        return ChannelFeatureIcons(feats)

    def paint(self, painter: QPainter, rect: QRect) -> None:
        painter.save()
        cur_x = rect.x()
        for feat in self.features:
            icon_rect = QRect(cur_x, rect.y(), self.icon_size.width(), self.icon_size.height())
            feat.rect = icon_rect
            if rect.contains(icon_rect):  # stay inside parent
                painter.drawPixmap(icon_rect, feat.icon().pixmap(self.icon_size))
            cur_x += self.icon_size.width() + 1
        painter.restore()

    def sizeHint(self, default_size: QSize) -> QSize:
        if not self.features:
            return default_size
        width = len(self.features) * (self.icon_size.width() + 1)
        return QSize(width, default_size.height())

    def show_tooltip(self, evt: QHelpEvent) -> bool:
        assert isinstance(evt, QHelpEvent)
        for feat in self.features:
            if feat.rect.contains(evt.pos()):
                QToolTip.showText(evt.globalPos(), feat.tooltip())
                break
        else:
            QToolTip.hideText()
            evt.ignore()
        return True
