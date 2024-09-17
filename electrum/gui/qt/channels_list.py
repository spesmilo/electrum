# -*- coding: utf-8 -*-
import traceback
import enum
from typing import Sequence, Optional, Dict, TYPE_CHECKING
from abc import abstractmethod, ABC

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import Qt, QRect, QSize
from PyQt6.QtWidgets import (QMenu, QHBoxLayout, QLabel, QVBoxLayout, QGridLayout, QLineEdit,
                             QPushButton, QAbstractItemView, QComboBox, QCheckBox,
                             QToolTip)
from PyQt6.QtGui import QFont, QStandardItem, QBrush, QPainter, QIcon, QHelpEvent

from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.i18n import _
from electrum.lnchannel import AbstractChannel, PeerState, ChannelBackup, Channel, ChannelState, ChanCloseOption
from electrum.wallet import Abstract_Wallet
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id
from electrum.lnworker import LNWallet
from electrum.gui import messages

from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   EnterButton, WaitingDialog, MONOSPACE_FONT, ColorScheme)
from .amountedit import BTCAmountEdit, FreezableLineEdit
from .util import read_QIcon, font_height
from .my_treeview import MyTreeView

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


ROLE_CHANNEL_ID = Qt.ItemDataRole.UserRole


class ChannelsList(MyTreeView):
    update_rows = QtCore.pyqtSignal(Abstract_Wallet)
    update_single_row = QtCore.pyqtSignal(Abstract_Wallet, AbstractChannel)
    gossip_db_loaded = QtCore.pyqtSignal()

    class Columns(MyTreeView.BaseColumnsEnum):
        FEATURES = enum.auto()
        SHORT_CHANID = enum.auto()
        NODE_ALIAS = enum.auto()
        CAPACITY = enum.auto()
        LOCAL_BALANCE = enum.auto()
        REMOTE_BALANCE = enum.auto()
        CHANNEL_STATUS = enum.auto()
        LONG_CHANID = enum.auto()

    headers = {
        Columns.SHORT_CHANID: _('Short Channel ID'),
        Columns.LONG_CHANID: _('Channel ID'),
        Columns.NODE_ALIAS: _('Node alias'),
        Columns.FEATURES: "",
        Columns.CAPACITY: _('Capacity'),
        Columns.LOCAL_BALANCE: _('Can send'),
        Columns.REMOTE_BALANCE: _('Can receive'),
        Columns.CHANNEL_STATUS: _('Status'),
    }

    filter_columns = [
        Columns.SHORT_CHANID,
        Columns.LONG_CHANID,
        Columns.NODE_ALIAS,
        Columns.CHANNEL_STATUS,
    ]

    _default_item_bg_brush = None  # type: Optional[QBrush]

    def __init__(self, main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_column=self.Columns.NODE_ALIAS,
        )
        self.setModel(QtGui.QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.gossip_db_loaded.connect(self.on_gossip_db)
        self.update_rows.connect(self.do_update_rows)
        self.update_single_row.connect(self.do_update_single_row)
        self.network = self.main_window.network
        self.wallet = self.main_window.wallet
        self.setSortingEnabled(True)

    @property
    # property because lnworker might be initialized at runtime
    def lnworker(self):
        return self.wallet.lnworker

    def format_fields(self, chan: AbstractChannel) -> Dict['ChannelsList.Columns', str]:
        labels = {}
        for subject in (REMOTE, LOCAL):
            if isinstance(chan, Channel):
                can_send = chan.available_to_spend(subject) / 1000
                label = self.main_window.format_amount(can_send, whitespaces=True)
                other = subject.inverted()
                bal_other = chan.balance(other)//1000
                bal_minus_htlcs_other = chan.balance_minus_outgoing_htlcs(other)//1000
                if bal_other != bal_minus_htlcs_other:
                    label += ' (+' + self.main_window.format_amount(bal_other - bal_minus_htlcs_other, whitespaces=False) + ')'
            else:
                assert isinstance(chan, ChannelBackup)
                label = ''
            labels[subject] = label
        status = chan.get_state_for_GUI()
        closed = chan.is_closed()
        node_alias = self.lnworker.get_node_alias(chan.node_id) or chan.node_id.hex()
        capacity_str = self.main_window.format_amount(chan.get_capacity(), whitespaces=True)
        return {
            self.Columns.SHORT_CHANID: chan.short_id_for_GUI(),
            self.Columns.LONG_CHANID: chan.channel_id.hex(),
            self.Columns.NODE_ALIAS: node_alias,
            self.Columns.FEATURES: '',
            self.Columns.CAPACITY: capacity_str,
            self.Columns.LOCAL_BALANCE: '' if closed else labels[LOCAL],
            self.Columns.REMOTE_BALANCE: '' if closed else labels[REMOTE],
            self.Columns.CHANNEL_STATUS: status,
        }

    def on_channel_closed(self, txid):
        self.main_window.show_error('Channel closed' + '\n' + txid)

    def on_failure(self, exc_info):
        type_, e, tb = exc_info
        traceback.print_tb(tb)
        self.main_window.show_error('Failed to close channel:\n{}'.format(repr(e)))

    def close_channel(self, channel_id):
        self.is_force_close = False
        msg = _('Cooperative close?')
        msg += '\n\n' + messages.MSG_COOPERATIVE_CLOSE
        if not self.main_window.question(msg):
            return
        coro = self.lnworker.close_channel(channel_id)
        on_success = self.on_channel_closed
        def task():
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, _('Please wait...'), task, on_success, self.on_failure)

    def force_close(self, channel_id):
        self.save_backup = True
        backup_cb = QCheckBox('Create a backup now', checked=True)
        def on_checked(_x):
            self.save_backup = backup_cb.isChecked()
        backup_cb.stateChanged.connect(on_checked)
        chan = self.lnworker.channels[channel_id]
        to_self_delay = chan.config[REMOTE].to_self_delay
        msg = '<b>' + _('Force-close channel?') + '</b><br/>'\
            + '<p>' + _('If you force-close this channel, the funds you have in it will not be available for {} blocks.').format(to_self_delay) + ' '\
            + _('After that delay, funds will be swept to an address derived from your wallet seed.') + '</p>'\
            + '<u>' + _('Please create a backup of your wallet file!') + '</u> '\
            + '<p>' + _('Funds in this channel will not be recoverable from seed until they are swept back into your wallet, and might be lost if you lose your wallet file.') + ' '\
            + _('To prevent that, you should save a backup of your wallet on another device.') + '</p>'
        if not self.main_window.question(msg, title=_('Force-close channel'), rich_text=True, checkbox=backup_cb):
            return
        if self.save_backup:
            if not self.main_window.backup_wallet():
                return
        def task():
            coro = self.lnworker.force_close_channel(channel_id)
            return self.network.run_from_another_thread(coro)
        WaitingDialog(self, _('Please wait...'), task, self.on_channel_closed, self.on_failure)

    def remove_channel(self, channel_id):
        if self.main_window.question(_('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.')):
            self.lnworker.remove_channel(channel_id)

    def remove_channel_backup(self, channel_id):
        if self.main_window.question(_('Remove channel backup?')):
            self.lnworker.remove_channel_backup(channel_id)

    def export_channel_backup(self, channel_id):
        msg = ' '.join([
            _("Channel backups can be imported in another instance of the same wallet."),
            _("In the Electrum mobile app, use the 'Send' button to scan this QR code."),
            '\n\n',
            _("Please note that channel backups cannot be used to restore your channels."),
            _("If you lose your wallet file, the only thing you can do with a backup is to request your channel to be closed, so that your funds will be sent on-chain."),
        ])
        data = self.lnworker.export_channel_backup(channel_id)
        self.main_window.show_qrcode(data, 'channel backup', help_text=msg,
                                     show_copy_text_btn=True)

    def request_force_close(self, channel_id):
        msg = _('Request force-close from remote peer?')
        msg += '\n\n' + messages.MSG_REQUEST_FORCE_CLOSE
        if not self.main_window.question(msg):
            return
        def task():
            coro = self.lnworker.request_force_close(channel_id)
            return self.network.run_from_another_thread(coro)
        def on_done(b):
            self.main_window.show_message(_('Request scheduled'))
        WaitingDialog(self, _('Please wait...'), task, on_done, self.on_failure)

    def set_frozen(self, chan, *, for_sending, value):
        if not self.lnworker.uses_trampoline() or self.lnworker.is_trampoline_peer(chan.node_id):
            if for_sending:
                chan.set_frozen_for_sending(value)
            else:
                chan.set_frozen_for_receiving(value)
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
        if chan1 is None:
            self.main_window.show_error("Select two active channels to rebalance.")
            return
        self.main_window.rebalance_dialog(chan1, chan2)

    def on_double_click(self, idx):
        channel_id = idx.sibling(idx.row(), self.Columns.NODE_ALIAS).data(ROLE_CHANNEL_ID)
        chan = self.lnworker.get_channel_by_id(channel_id) or self.lnworker.channel_backups[channel_id]
        self.main_window.show_channel_details(chan)

    def create_menu(self, position):
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)  # consecutive separators are merged together
        selected = self.selected_in_column(self.Columns.NODE_ALIAS)
        if not selected:
            menu.exec(self.viewport().mapToGlobal(position))
            return
        if len(selected) == 2:
            chan1, chan2 = self.get_rebalance_pair()
            if chan1 and chan2:
                menu.addAction(_("Rebalance channels"), lambda: self.main_window.rebalance_dialog(chan1, chan2))
                menu.exec(self.viewport().mapToGlobal(position))
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
        menu.addAction(_("Details"), lambda: self.main_window.show_channel_details(chan))
        menu.addSeparator()
        cc = self.add_copy_menu(menu, idx)
        cc.addAction(_("Node ID"), lambda: self.place_text_on_clipboard(
            chan.node_id.hex(), title=_("Node ID")))
        cc.addAction(_("Long Channel ID"), lambda: self.place_text_on_clipboard(
            channel_id.hex(), title=_("Long Channel ID")))
        if not chan.is_backup() and not chan.is_closed():
            fm = menu.addMenu(_("Freeze"))
            if not chan.is_frozen_for_sending():
                fm.addAction(_("Freeze for sending"), lambda: self.set_frozen(chan, for_sending=True, value=True))
            else:
                fm.addAction(_("Unfreeze for sending"), lambda: self.set_frozen(chan, for_sending=True, value=False))
            if not chan.is_frozen_for_receiving():
                fm.addAction(_("Freeze for receiving"), lambda: self.set_frozen(chan, for_sending=False, value=True))
            else:
                fm.addAction(_("Unfreeze for receiving"), lambda: self.set_frozen(chan, for_sending=False, value=False))
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
        menu.exec(self.viewport().mapToGlobal(position))

    @QtCore.pyqtSlot(Abstract_Wallet, AbstractChannel)
    def do_update_single_row(self, wallet: Abstract_Wallet, chan: AbstractChannel):
        if wallet != self.wallet:
            return
        for row in range(self.model().rowCount()):
            item = self.model().item(row, self.Columns.NODE_ALIAS)
            if item.data(ROLE_CHANNEL_ID) != chan.channel_id:
                continue
            for column, v in self.format_fields(chan).items():
                self.model().item(row, column).setData(v, QtCore.Qt.ItemDataRole.DisplayRole)
            items = [self.model().item(row, column) for column in self.Columns]
            self._update_chan_frozen_bg(chan=chan, items=items)
        if wallet.lnworker:
            self.update_can_send(wallet.lnworker)

    @QtCore.pyqtSlot()
    def on_gossip_db(self):
        self.do_update_rows(self.wallet)

    @QtCore.pyqtSlot(Abstract_Wallet)
    def do_update_rows(self, wallet):
        if wallet != self.wallet:
            return
        self.model().clear()
        self.update_headers(self.headers)
        self.set_visibility_of_columns()
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

        # FIXME sorting by SHORT_CHANID should treat values as tuple, not as string ( 50x1x1 > 8x1x1 )
        self.sortByColumn(self.Columns.SHORT_CHANID, Qt.SortOrder.DescendingOrder)

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
        msg = _('Can send') + ' ' + self.main_window.format_amount(lnworker.num_sats_can_send())\
              + ' ' + self.main_window.base_unit() + '; '\
              + _('can receive') + ' ' + self.main_window.format_amount(lnworker.num_sats_can_receive())\
              + ' ' + self.main_window.base_unit()
        self.can_send_label.setText(msg)

    def create_toolbar(self, config):
        toolbar, menu = self.create_toolbar_with_menu('')
        self.can_send_label = toolbar.itemAt(0).widget()
        menu.addAction(_('Rebalance channels'), lambda: self.on_rebalance())
        menu.addAction(read_QIcon('update.png'), _('Submarine swap'), lambda: self.main_window.run_swap_dialog())
        menu.addSeparator()
        menu.addAction(_("Import channel backup"), lambda: self.main_window.do_process_from_text_channel_backup())
        # only enable menu if has LN. Or we could selectively enable menu items?
        #     and maybe add item "main_window.init_lightning_dialog()" when applicable
        menu.setEnabled(self.wallet.has_lightning())
        self.new_channel_button = EnterButton(_('New Channel'), self.main_window.new_channel_dialog)
        self.new_channel_button.setEnabled(self.wallet.has_lightning())
        toolbar.insertWidget(2, self.new_channel_button)
        return toolbar

    def statistics_dialog(self):
        channel_db = self.network.channel_db
        capacity = self.main_window.format_amount(channel_db.capacity()) + ' '+ self.main_window.base_unit()
        d = WindowModalDialog(self.main_window, _('Lightning Network Statistics'))
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
        d.exec()

    def set_visibility_of_columns(self):
        def set_visible(col: int, b: bool):
            self.showColumn(col) if b else self.hideColumn(col)
        set_visible(self.Columns.LONG_CHANID, False)


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
        return read_QIcon("cloud_no")


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
