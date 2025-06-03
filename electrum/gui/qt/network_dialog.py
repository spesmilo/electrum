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

from enum import IntEnum

from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QTreeWidget, QTreeWidgetItem, QMenu, QGridLayout, QComboBox, QLineEdit, QDialog, QVBoxLayout, QHeaderView,
    QCheckBox, QTabWidget, QWidget, QLabel, QPushButton, QHBoxLayout,
    QListWidget, QListWidgetItem,
)
from PyQt6.QtGui import QIntValidator

from electrum.i18n import _
from electrum import blockchain
from electrum.interface import ServerAddr, PREFERRED_NETWORK_PROTOCOL
from electrum.network import Network, ProxySettings, is_valid_host, is_valid_port
from electrum.logging import get_logger
from electrum.util import is_valid_websocket_url
from electrum.gui import messages

from .util import (
    Buttons, CloseButton, HelpButton, read_QIcon, char_width_in_lineedit, PasswordLineEdit, QtEventListener,
    qt_event_listener, Spinner, HelpLabel
)


_logger = get_logger(__name__)

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'


class NetworkDialog(QDialog, QtEventListener):
    def __init__(self, *, network: Network):
        QDialog.__init__(self)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 500)
        self.tabs = tabs = QTabWidget()
        self._blockchain_tab = ServerWidget(network)
        self._proxy_tab = ProxyWidget(network)
        self._nostr_tab = NostrWidget(network)
        tabs.addTab(self._blockchain_tab, _('Server'))
        tabs.addTab(self._nostr_tab, _('Nostr'))
        tabs.addTab(self._proxy_tab, _('Proxy'))
        vbox = QVBoxLayout(self)
        vbox.addWidget(self.tabs)
        vbox.addLayout(Buttons(CloseButton(self)))

    def show(self, *, proxy_tab: bool = False):
        super().show()
        self.tabs.setCurrentWidget(self._proxy_tab if proxy_tab else self._blockchain_tab)


class NodesListWidget(QTreeWidget):
    """List of connected servers."""

    SERVER_ADDR_ROLE = Qt.ItemDataRole.UserRole + 100
    CHAIN_ID_ROLE = Qt.ItemDataRole.UserRole + 101
    ITEMTYPE_ROLE = Qt.ItemDataRole.UserRole + 102

    class ItemType(IntEnum):
        CHAIN = 0
        CONNECTED_SERVER = 1
        DISCONNECTED_SERVER = 2
        TOPLEVEL = 3

    followServer = pyqtSignal([ServerAddr], arguments=['server'])
    followChain = pyqtSignal([str], arguments=['chain_id'])
    setServer = pyqtSignal([str], arguments=['server'])

    def __init__(self, *, network: Network):
        QTreeWidget.__init__(self)
        self.setHeaderLabels([_('Server'), _('Height')])
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)
        self.network = network

    def create_menu(self, position):
        item = self.currentItem()
        if not item:
            return
        item_type = item.data(0, self.ITEMTYPE_ROLE)
        menu = QMenu()
        if item_type in [self.ItemType.CONNECTED_SERVER, self.ItemType.DISCONNECTED_SERVER]:
            server = item.data(0, self.SERVER_ADDR_ROLE)  # type: ServerAddr
            if item_type == self.ItemType.CONNECTED_SERVER:
                def do_follow_server():
                    self.followServer.emit(server)
                menu.addAction(read_QIcon("chevron-right.png"), _("Use as server"), do_follow_server)
            elif item_type == self.ItemType.DISCONNECTED_SERVER:
                def do_set_server():
                    self.setServer.emit(str(server))
                menu.addAction(read_QIcon("chevron-right.png"), _("Use as server"), do_set_server)

            def set_bookmark(*, add: bool):
                self.network.set_server_bookmark(server, add=add)
                self.update()

            if self.network.is_server_bookmarked(server):
                menu.addAction(read_QIcon("bookmark_remove.png"), _("Remove from bookmarks"), lambda: set_bookmark(add=False))
            else:
                menu.addAction(read_QIcon("bookmark_add.png"), _("Bookmark this server"), lambda: set_bookmark(add=True))
        elif item_type == self.ItemType.CHAIN:
            chain_id = item.data(0, self.CHAIN_ID_ROLE)

            def do_follow_chain():
                self.followChain.emit(chain_id)

            menu.addAction(_("Follow this branch"), do_follow_chain)
        else:
            return
        menu.exec(self.viewport().mapToGlobal(position))

    def keyPressEvent(self, event):
        if event.key() in [Qt.Key.Key_F2, Qt.Key.Key_Return, Qt.Key.Key_Enter]:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def update(self):
        self.clear()
        network = self.network
        servers = self.network.get_servers()

        use_tor = bool(network.is_proxy_tor)

        # connected servers
        connected_servers_item = QTreeWidgetItem([_("Connected nodes"), ''])
        connected_servers_item.setData(0, self.ITEMTYPE_ROLE, self.ItemType.TOPLEVEL)
        chains = network.get_blockchains()
        n_chains = len(chains)
        for chain_id, interfaces in chains.items():
            b = blockchain.blockchains.get(chain_id)
            if b is None:
                continue
            name = b.get_name()
            if n_chains > 1:
                x = QTreeWidgetItem([name + '@%d'%b.get_max_forkpoint(), '%d'%b.height()])
                x.setData(0, self.ITEMTYPE_ROLE, self.ItemType.CHAIN)
                x.setData(0, self.CHAIN_ID_ROLE, b.get_id())
            else:
                x = connected_servers_item
            for i in interfaces:
                item = QTreeWidgetItem([f"{i.server.to_friendly_name()}", '%d'%i.tip])
                item.setData(0, self.ITEMTYPE_ROLE, self.ItemType.CONNECTED_SERVER)
                item.setData(0, self.SERVER_ADDR_ROLE, i.server)
                item.setToolTip(0, str(i.server))
                if i == network.interface:
                    item.setIcon(0, read_QIcon("chevron-right.png"))
                elif network.is_server_bookmarked(i.server):
                    item.setIcon(0, read_QIcon("bookmark.png"))
                x.addChild(item)
            if n_chains > 1:
                connected_servers_item.addChild(x)

        # disconnected servers
        disconnected_servers_item = QTreeWidgetItem([_("Other known servers"), ""])
        disconnected_servers_item.setData(0, self.ITEMTYPE_ROLE, self.ItemType.TOPLEVEL)
        connected_hosts = set([iface.host for ifaces in chains.values() for iface in ifaces])
        protocol = PREFERRED_NETWORK_PROTOCOL
        server_addrs = [
            ServerAddr(_host, port, protocol=protocol)
            for _host, d in servers.items()
            if (port := d.get(protocol))]
        server_addrs.sort(key=lambda x: (-network.is_server_bookmarked(x), str(x)))
        for server in server_addrs:
            if server.host in connected_hosts:
                continue
            if server.host.endswith('.onion') and not use_tor:
                continue
            item = QTreeWidgetItem([server.net_addr_str(), ""])
            item.setData(0, self.ITEMTYPE_ROLE, self.ItemType.DISCONNECTED_SERVER)
            item.setData(0, self.SERVER_ADDR_ROLE, server)
            if network.is_server_bookmarked(server):
                item.setIcon(0, read_QIcon("bookmark.png"))
            disconnected_servers_item.addChild(item)

        self.addTopLevelItem(connected_servers_item)
        self.addTopLevelItem(disconnected_servers_item)

        connected_servers_item.setExpanded(True)
        for i in range(connected_servers_item.childCount()):
            connected_servers_item.child(i).setExpanded(True)
        disconnected_servers_item.setExpanded(True)

        # headers
        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

        super().update()


class ProxyWidget(QWidget):
    PROXY_MODES = {
        'socks4': 'SOCKS4',
        'socks5': 'SOCKS5/TOR'
    }

    torProbeFinished = pyqtSignal([str, int], arguments=['host', 'port'])

    def __init__(self, network: Network, parent=None):
        super().__init__(parent)
        self.network = network
        self.config = network.config

        fixed_width_port = 6 * char_width_in_lineedit()

        # proxy setting.
        self.proxy_cb = QCheckBox(_('Use proxy'))
        self.proxy_mode = QComboBox()
        for k, v in self.PROXY_MODES.items():
            self.proxy_mode.addItem(v, k)
        self.proxy_mode.setCurrentIndex(1)
        self.proxy_host = QLineEdit()
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(fixed_width_port)
        self.proxy_port_validator = QIntValidator(1, 65535)
        self.proxy_port.setValidator(self.proxy_port_validator)

        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText(_("Proxy username"))
        self.proxy_password = PasswordLineEdit()
        self.proxy_password.setPlaceholderText(_("Proxy password"))

        grid = QGridLayout(self)
        grid.setSpacing(8)

        grid.addWidget(self.proxy_cb, 0, 0, 1, 4)
        proxy_helpbutton = HelpButton(
            _('Proxy settings apply to all connections: with Electrum servers, but also with third-party services.'))
        grid.addWidget(proxy_helpbutton, 0, 4, alignment=Qt.AlignmentFlag.AlignRight)
        grid.addWidget(self.proxy_mode, 1, 0, 1, 1)
        grid.addWidget(self.proxy_host, 1, 1, 1, 3)
        grid.addWidget(self.proxy_port, 1, 4, 1, 1)
        grid.addWidget(self.proxy_user, 2, 1, 1, 2)
        grid.addWidget(self.proxy_password, 2, 3, 1, 2)

        detect_l = QHBoxLayout()
        self.detect_button = QPushButton(_('Detect Tor proxy'))
        self.spinner = Spinner()
        self.spinner.setMargin(5)
        detect_l.addWidget(self.detect_button)
        detect_l.addWidget(self.spinner)

        grid.addLayout(detect_l, 3, 0, 1, 5, alignment=Qt.AlignmentFlag.AlignLeft)

        spacer = QVBoxLayout()
        spacer.addStretch(1)
        grid.addLayout(spacer, 4, 0, 1, 5)

        self.update_from_config()
        self.update()

        # connect signal handlers after init from config
        self.proxy_cb.stateChanged.connect(self.on_proxy_enable_toggle)
        self.proxy_mode.currentIndexChanged.connect(self.on_proxy_settings_changed)
        self.proxy_host.editingFinished.connect(self.on_proxy_settings_changed)
        self.proxy_port.editingFinished.connect(self.on_proxy_settings_changed)
        self.proxy_user.editingFinished.connect(self.on_proxy_settings_changed)
        self.proxy_password.editingFinished.connect(self.on_proxy_settings_changed)
        self.detect_button.clicked.connect(self.detect_tor)

        self.torProbeFinished.connect(self.on_tor_probe_finished)

    def update(self):
        enabled = self.proxy_cb.isChecked() and self.config.cv.NETWORK_PROXY.is_modifiable()
        for item in [
                self.proxy_mode, self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password,
                self.detect_button
        ]:
            item.setEnabled(enabled)

        if not self.proxy_port.hasAcceptableInput() and not is_valid_port(self.proxy_port.text()):
            return

        if not is_valid_host(self.proxy_host.text()):
            return

        net_params = self.network.get_parameters()
        proxy = self.get_proxy_settings()
        net_params = net_params._replace(proxy=proxy)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def update_from_config(self):
        proxy = ProxySettings.from_config(self.config)
        self.proxy_cb.setChecked(proxy.enabled)
        self.proxy_mode.setCurrentText(self.PROXY_MODES.get(proxy.mode))
        self.proxy_host.setText(proxy.host)
        self.proxy_port.setText(proxy.port)
        self.proxy_user.setText(proxy.user)
        self.proxy_password.setText(proxy.password)

        if not self.config.cv.NETWORK_PROXY.is_modifiable():
            for w in [
                    self.proxy_cb, self.proxy_mode, self.proxy_host, self.proxy_port,
                    self.proxy_user, self.proxy_password, self.detect_button
            ]:
                w.setEnabled(False)

    def on_proxy_enable_toggle(self):
        # probe if enabled and no pre-existing settings
        # if self.proxy_cb.isChecked() and (not self.proxy_host.text() or not self.proxy_port.text()):
        #     self.detect_tor()
        self.update()

    def on_proxy_settings_changed(self):
        self.update()

    def get_proxy_settings(self) -> ProxySettings:
        proxy = ProxySettings()
        proxy.enabled = self.proxy_cb.isChecked()
        proxy.mode = self.proxy_mode.currentData()
        proxy.host = self.proxy_host.text()
        proxy.port = self.proxy_port.text()
        proxy.user = self.proxy_user.text()
        proxy.password = self.proxy_password.text()
        return proxy

    def detect_tor(self):
        self.detect_button.setEnabled(False)
        self.spinner.setVisible(True)
        ProxySettings.probe_tor(self.torProbeFinished.emit)  # via signal

    @pyqtSlot(str, int)
    def on_tor_probe_finished(self, host: str, port: int):
        self.detect_button.setEnabled(True)
        self.spinner.setVisible(False)
        if host:
            self.proxy_mode.setCurrentIndex(1)
            self.proxy_host.setText(host)
            self.proxy_port.setText(str(port))
            self.update()


class ConnectMode(IntEnum):
    AUTOCONNECT = 0
    MANUAL      = 1
    ONESERVER   = 2

class ServerWidget(QWidget, QtEventListener):
    CONNECT_MODES = {
        ConnectMode.AUTOCONNECT: messages.MSG_CONNECTMODE_AUTOCONNECT,
        ConnectMode.MANUAL: messages.MSG_CONNECTMODE_MANUAL,
        ConnectMode.ONESERVER: messages.MSG_CONNECTMODE_ONESERVER,
    }

    def __init__(self, network: Network, parent=None):
        super().__init__(parent)
        self.network = network
        self.config = network.config

        self.setLayout(QVBoxLayout())

        grid = QGridLayout()

        self.connect_combo = QComboBox()
        for i, v in sorted(self.CONNECT_MODES.items()):
            self.connect_combo.addItem(v, i)
        self.connect_combo.currentIndexChanged.connect(self.on_server_settings_changed)
        grid.addWidget(QLabel(_('Connection mode') + ':'), 0, 0)
        msg = (
            f"""
            {messages.MSG_CONNECTMODE_SERVER_HELP}<br/><br/>
            {messages.MSG_CONNECTMODE_NODES_HELP}
            <ul>
            <li><b>{messages.MSG_CONNECTMODE_AUTOCONNECT}</b>: {messages.MSG_CONNECTMODE_AUTOCONNECT_HELP}</li>
            <li><b>{messages.MSG_CONNECTMODE_MANUAL}</b>: {messages.MSG_CONNECTMODE_MANUAL_HELP}</li>
            <li><b>{messages.MSG_CONNECTMODE_ONESERVER}</b>: {messages.MSG_CONNECTMODE_ONESERVER_HELP}</li>
            </ul>
            """
        )
        grid.addWidget(HelpButton(msg), 0, 4)
        grid.addWidget(self.connect_combo, 0, 1, 1, 3)

        self.server_e = QLineEdit()
        self.server_e.editingFinished.connect(self.on_server_settings_changed)
        grid.addWidget(QLabel(_('Server') + ':'), 1, 0)
        grid.addWidget(self.server_e, 1, 1, 1, 3)
        grid.addWidget(HelpButton(messages.MSG_CONNECTMODE_SERVER_HELP), 1, 4)

        self.status_label_header = QLabel(_('Status') + ':')
        self.status_label = QLabel('')
        self.status_label_helpbutton = HelpButton(messages.MSG_CONNECTMODE_NODES_HELP)
        grid.addWidget(self.status_label_header, 2, 0)
        grid.addWidget(self.status_label, 2, 1, 1, 3)
        grid.addWidget(self.status_label_helpbutton, 2, 4)

        msg = _('This is the height of your local copy of the blockchain.')
        self.height_label_header = QLabel(_('Blockchain') + ':')
        self.height_label = QLabel('')
        self.height_label_helpbutton = HelpButton(msg)
        grid.addWidget(self.height_label_header, 3, 0)
        grid.addWidget(self.height_label, 3, 1)
        grid.addWidget(self.height_label_helpbutton, 3, 4)

        self.split_label = QLabel('')
        grid.addWidget(self.split_label, 4, 1, 1, 3)

        self.layout().addLayout(grid)

        self.nodes_list_widget = NodesListWidget(network=self.network)
        self.nodes_list_widget.followServer.connect(self.follow_server)
        self.nodes_list_widget.followChain.connect(self.follow_branch)

        def do_set_server(server):
            self.server_e.setText(server)
            self.set_server()
        self.nodes_list_widget.setServer.connect(do_set_server)

        self.layout().addWidget(self.nodes_list_widget)
        self.nodes_list_widget.update()

        self.register_callbacks()
        self.destroyed.connect(lambda: self.unregister_callbacks())

        self.update_from_config()
        self.update()

    @qt_event_listener
    def on_event_network_updated(self):
        self.nodes_list_widget.update()  # NOTE: move event handling to widget itself?
        self.update()

    def is_auto_connect(self):
        return self.connect_combo.currentIndex() == ConnectMode.AUTOCONNECT

    def is_one_server(self):
        return self.connect_combo.currentIndex() == ConnectMode.ONESERVER

    def on_server_settings_changed(self):
        if not self.network._was_started:
            self.update()
            return
        server = self.server_e.text().strip()
        net_params = self.network.get_parameters()
        if server != net_params.server or self.is_auto_connect() != net_params.auto_connect or self.is_one_server() != net_params.oneserver:
            self.set_server()

    def update(self):
        self.server_e.setEnabled(self.config.cv.NETWORK_SERVER.is_modifiable() and not self.is_auto_connect())
        for item in [
                self.status_label_header, self.status_label, self.status_label_helpbutton,
                self.height_label_header, self.height_label, self.height_label_helpbutton]:
            item.setVisible(self.network._was_started)
        msg = _('Fork detection disabled') if self.is_one_server() else ''
        if self.network._was_started:
            # Network was started, so we don't run in initial setup wizard.
            # behavior in this case is to apply changes immediately.
            # Also, we show block height and potential chain tips
            height_str = _('{} blocks').format(self.network.get_local_height())
            self.height_label.setText(height_str)
            self.status_label.setText(self.network.get_status())
            chains = self.network.get_blockchains()
            if len(chains) > 1:
                chain = self.network.blockchain()
                forkpoint = chain.get_max_forkpoint()
                name = chain.get_name()
                msg = _('Fork detected at block {0}').format(forkpoint) + '\n'
                if self.is_auto_connect():
                    msg += _('You are following branch {}').format(name)
                else:
                    msg += _('Your server is on branch {0} ({1} blocks)').format(name, chain.get_branch_size())
        self.split_label.setText(msg)

    def update_from_config(self):
        auto_connect = self.config.NETWORK_AUTO_CONNECT
        one_server = self.config.NETWORK_ONESERVER
        v = ConnectMode.AUTOCONNECT if auto_connect else ConnectMode.ONESERVER if one_server else ConnectMode.MANUAL
        self.connect_combo.setCurrentIndex(v)

        server = self.config.NETWORK_SERVER
        self.server_e.setText(server)

        self.server_e.setEnabled(self.config.cv.NETWORK_SERVER.is_modifiable() and not auto_connect)
        self.nodes_list_widget.setEnabled(self.config.cv.NETWORK_SERVER.is_modifiable())

    def follow_branch(self, chain_id):
        self.network.run_from_another_thread(self.network.follow_chain_given_id(chain_id))
        self.update()

    def follow_server(self, server: ServerAddr):
        self.server_e.setText(str(server))
        self.network.run_from_another_thread(self.network.follow_chain_given_server(server))
        self.update()

    def set_server(self):
        net_params = self.network.get_parameters()
        try:
            server = ServerAddr.from_str_with_inference(str(self.server_e.text()))
            if not server:
                raise Exception("failed to parse server")
        except Exception:
            return
        net_params = net_params._replace(
            server=server,
            auto_connect=self.is_auto_connect(),
            oneserver=self.is_one_server(),
        )
        self.network.run_from_another_thread(self.network.set_parameters(net_params))


class NostrWidget(QWidget, QtEventListener):

    def __init__(self, network: Network, parent=None):
        super().__init__(parent)
        self.network = network
        self.config = network.config
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        grid = QGridLayout()
        nostr_relays_label = QLabel(self.config.cv.NOSTR_RELAYS.get_short_desc())
        nostr_helpbutton = HelpButton(self.config.cv.NOSTR_RELAYS.get_long_desc())
        grid.addWidget(nostr_relays_label, 0, 0)
        grid.addWidget(nostr_helpbutton, 0, 1)
        vbox.addLayout(grid)

        self.relays_list = QListWidget()
        self.relay_edit = QLineEdit()
        self.relay_edit.textChanged.connect(self.on_relay_edited)
        vbox.addWidget(self.relays_list)
        vbox.addStretch()
        self.add_button = QPushButton(_('Add'))
        self.add_button.clicked.connect(self.add_relay)
        self.add_button.setEnabled(False)
        remove_button = QPushButton(_('Remove'))
        remove_button.clicked.connect(self.remove_relay)
        reset_button = QPushButton(_('Reset'))
        reset_button.clicked.connect(self.reset_relays)
        buttons = Buttons(self.relay_edit, self.add_button, remove_button, reset_button)
        vbox.addLayout(buttons)
        self.update_list()

    def on_relay_edited(self, text):
        self.add_button.setEnabled(is_valid_websocket_url(text))

    def update_list(self):
        self.relays_list.clear()
        for relay in self.config.get_nostr_relays():
            item = QListWidgetItem(relay)
            self.relays_list.addItem(item)

    def add_relay(self):
        relay = self.relay_edit.text()
        self.config.add_nostr_relay(relay)
        self.update_list()

    def remove_relay(self):
        item = self.relays_list.currentItem()
        if item is None:
            return
        self.config.remove_nostr_relay(item.text())
        self.update_list()

    def reset_relays(self):
        self.config.NOSTR_RELAYS = None
        self.update_list()
