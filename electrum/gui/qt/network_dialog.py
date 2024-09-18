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

import socket
import time
from enum import IntEnum
from typing import Tuple, TYPE_CHECKING
import threading

from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtWidgets import (QTreeWidget, QTreeWidgetItem, QMenu, QGridLayout, QComboBox,
                             QLineEdit, QDialog, QVBoxLayout, QHeaderView, QCheckBox,
                             QTabWidget, QWidget, QLabel)
from PyQt6.QtGui import QIntValidator

from electrum.i18n import _
from electrum import constants, blockchain, util
from electrum.interface import ServerAddr, PREFERRED_NETWORK_PROTOCOL
from electrum.network import Network
from electrum.logging import get_logger
from electrum.util import detect_tor_socks_proxy
from electrum.simple_config import SimpleConfig

from .util import (Buttons, CloseButton, HelpButton, read_QIcon, char_width_in_lineedit,
                   PasswordLineEdit)
from .util import QtEventListener, qt_event_listener


_logger = get_logger(__name__)

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'


class NetworkDialog(QDialog, QtEventListener):
    def __init__(self, *, network: Network, config: 'SimpleConfig'):
        QDialog.__init__(self)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 500)
        self.nlayout = NetworkChoiceLayout(network, config)
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.nlayout.layout())
        vbox.addLayout(Buttons(CloseButton(self)))
        self.register_callbacks()
        self._cleaned_up = False

    def show(self):
        super().show()
        if td := self.nlayout.td:
            td.trigger_rescan()

    @qt_event_listener
    def on_event_network_updated(self):
        self.nlayout.update()

    def clean_up(self):
        if self._cleaned_up:
            return
        self._cleaned_up = True
        self.nlayout.clean_up()
        self.unregister_callbacks()


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


class NetworkChoiceLayout(object):
    # TODO consolidate to ProxyWidget+ServerWidget
    # TODO TorDetector is unnecessary, Network tests socks5 peer and detects Tor
    # TODO apply on editingFinished is not ideal, separate Apply button and on Close?
    def __init__(self, network: Network, config: 'SimpleConfig', wizard=False):
        self.network = network
        self.config = config
        self.tor_proxy = None

        self.tabs = tabs = QTabWidget()
        self._proxy_tab = proxy_tab = QWidget()
        blockchain_tab = QWidget()
        tabs.addTab(blockchain_tab, _('Overview'))
        tabs.addTab(proxy_tab, _('Proxy'))
        tabs.currentChanged.connect(self._on_tab_changed)

        fixed_width_hostname = 24 * char_width_in_lineedit()
        fixed_width_port = 6 * char_width_in_lineedit()

        # Proxy tab
        grid = QGridLayout(proxy_tab)
        grid.setSpacing(8)

        # proxy setting
        self.proxy_cb = QCheckBox(_('Use proxy'))
        self.proxy_cb.clicked.connect(self.check_disable_proxy)
        self.proxy_cb.clicked.connect(self.set_proxy)

        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(['SOCKS4', 'SOCKS5'])
        self.proxy_host = QLineEdit()
        self.proxy_host.setFixedWidth(fixed_width_hostname)
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(fixed_width_port)
        self.proxy_port_validator = QIntValidator(1, 65535)
        self.proxy_port.setValidator(self.proxy_port_validator)

        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText(_("Proxy user"))
        self.proxy_password = PasswordLineEdit()
        self.proxy_password.setPlaceholderText(_("Password"))
        self.proxy_password.setFixedWidth(fixed_width_port)

        self.proxy_mode.currentIndexChanged.connect(self.set_proxy)
        self.proxy_host.editingFinished.connect(self.set_proxy)
        self.proxy_port.editingFinished.connect(self.set_proxy)
        self.proxy_user.editingFinished.connect(self.set_proxy)
        self.proxy_password.editingFinished.connect(self.set_proxy)

        self.proxy_mode.currentIndexChanged.connect(self.proxy_settings_changed)
        self.proxy_host.textEdited.connect(self.proxy_settings_changed)
        self.proxy_port.textEdited.connect(self.proxy_settings_changed)
        self.proxy_user.textEdited.connect(self.proxy_settings_changed)
        self.proxy_password.textEdited.connect(self.proxy_settings_changed)

        self.tor_cb = QCheckBox(_("Use Tor Proxy"))
        self.tor_cb.setIcon(read_QIcon("tor_logo.png"))
        self.tor_cb.hide()
        self.tor_cb.clicked.connect(self.use_tor_proxy)

        grid.addWidget(self.tor_cb, 1, 0, 1, 3)
        grid.addWidget(self.proxy_cb, 2, 0, 1, 3)
        grid.addWidget(HelpButton(_('Proxy settings apply to all connections: with Electrum servers, but also with third-party services.')), 2, 4)
        grid.addWidget(self.proxy_mode, 4, 1)
        grid.addWidget(self.proxy_host, 4, 2)
        grid.addWidget(self.proxy_port, 4, 3)
        grid.addWidget(self.proxy_user, 5, 2)
        grid.addWidget(self.proxy_password, 5, 3)
        grid.setRowStretch(7, 1)

        # Blockchain Tab
        grid = QGridLayout(blockchain_tab)
        msg =  ' '.join([
            _("Electrum connects to several nodes in order to download block headers and find out the longest blockchain."),
            _("This blockchain is used to verify the transactions sent by your transaction server.")
        ])
        self.status_label = QLabel('')
        grid.addWidget(QLabel(_('Status') + ':'), 0, 0)
        grid.addWidget(self.status_label, 0, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)

        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setEnabled(self.config.cv.NETWORK_AUTO_CONNECT.is_modifiable())
        self.autoconnect_cb.clicked.connect(self.set_server)
        self.autoconnect_cb.clicked.connect(self.update)
        msg = ' '.join([
            _("If auto-connect is enabled, Electrum will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electrum will warn you if your server is lagging.")
        ])
        grid.addWidget(self.autoconnect_cb, 1, 0, 1, 3)
        grid.addWidget(HelpButton(msg), 1, 4)

        self.server_e = QLineEdit()
        self.server_e.setFixedWidth(fixed_width_hostname + fixed_width_port)
        self.server_e.editingFinished.connect(self.set_server)
        msg = _("Electrum sends your wallet addresses to a single server, in order to receive your transaction history.")
        grid.addWidget(QLabel(_('Server') + ':'), 2, 0)
        grid.addWidget(self.server_e, 2, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 2, 4)

        self.height_label = QLabel('')
        msg = _('This is the height of your local copy of the blockchain.')
        grid.addWidget(QLabel(_('Blockchain') + ':'), 3, 0)
        grid.addWidget(self.height_label, 3, 1)
        grid.addWidget(HelpButton(msg), 3, 4)

        self.split_label = QLabel('')
        grid.addWidget(self.split_label, 4, 0, 1, 3)

        self.nodes_list_widget = NodesListWidget(network=self.network)
        self.nodes_list_widget.followServer.connect(self.follow_server)
        self.nodes_list_widget.followChain.connect(self.follow_branch)

        def do_set_server(server):
            self.server_e.setText(server)
            self.set_server()
        self.nodes_list_widget.setServer.connect(do_set_server)
        grid.addWidget(self.nodes_list_widget, 6, 0, 1, 5)

        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        self.layout_ = vbox
        # tor detector
        self.td = td = TorDetector()
        td.found_proxy.connect(self.suggest_proxy)
        td.start()

        self.fill_in_proxy_settings()
        self.update()

    def clean_up(self):
        if self.td:
            self.td.found_proxy.disconnect()
            self.td.stop()
            self.td = None

    def check_disable_proxy(self, b):
        if not self.config.cv.NETWORK_PROXY.is_modifiable():
            b = False
        for w in [self.proxy_mode, self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password]:
            w.setEnabled(b)

    def enable_set_server(self):
        if self.config.cv.NETWORK_SERVER.is_modifiable():
            enabled = not self.autoconnect_cb.isChecked()
            self.server_e.setEnabled(enabled)
        else:
            for w in [self.autoconnect_cb, self.server_e, self.nodes_list_widget]:
                w.setEnabled(False)

    def update(self):
        net_params = self.network.get_parameters()
        server = net_params.server
        auto_connect = net_params.auto_connect
        if not self.server_e.hasFocus():
            self.server_e.setText(server.to_friendly_name())
        self.autoconnect_cb.setChecked(auto_connect)

        height_str = "%d "%(self.network.get_local_height()) + _('blocks')
        self.height_label.setText(height_str)
        self.status_label.setText(self.network.get_status())
        chains = self.network.get_blockchains()
        if len(chains) > 1:
            chain = self.network.blockchain()
            forkpoint = chain.get_max_forkpoint()
            name = chain.get_name()
            msg = _('Chain split detected at block {0}').format(forkpoint) + '\n'
            msg += (_('You are following branch') if auto_connect else _('Your server is on branch'))+ ' ' + name
            msg += ' (%d %s)' % (chain.get_branch_size(), _('blocks'))
        else:
            msg = ''
        self.split_label.setText(msg)
        self.nodes_list_widget.update()
        self.enable_set_server()

    def fill_in_proxy_settings(self):
        proxy_config = self.network.get_parameters().proxy
        if not proxy_config:
            proxy_config = {"mode": "none", "host": "localhost", "port": "9050"}

        b = proxy_config.get('mode') != "none"
        self.check_disable_proxy(b)
        if b:
            self.proxy_cb.setChecked(True)
            self.proxy_mode.setCurrentIndex(
                self.proxy_mode.findText(str(proxy_config.get("mode").upper())))

        self.proxy_host.setText(proxy_config.get("host"))
        self.proxy_port.setText(proxy_config.get("port"))
        self.proxy_user.setText(proxy_config.get("user", ""))
        self.proxy_password.setText(proxy_config.get("password", ""))

    def layout(self):
        return self.layout_

    def follow_branch(self, chain_id):
        self.network.run_from_another_thread(self.network.follow_chain_given_id(chain_id))
        self.update()

    def follow_server(self, server: ServerAddr):
        self.network.run_from_another_thread(self.network.follow_chain_given_server(server))
        self.update()

    def accept(self):
        pass

    def set_server(self):
        net_params = self.network.get_parameters()
        try:
            server = ServerAddr.from_str_with_inference(str(self.server_e.text()))
            if not server: raise Exception("failed to parse")
        except Exception:
            return
        net_params = net_params._replace(server=server,
                                         auto_connect=self.autoconnect_cb.isChecked())
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def set_proxy(self):
        net_params = self.network.get_parameters()
        if self.proxy_cb.isChecked():
            if not self.proxy_port.hasAcceptableInput():
                return
            proxy = {'mode':str(self.proxy_mode.currentText()).lower(),
                     'host':str(self.proxy_host.text()),
                     'port':str(self.proxy_port.text()),
                     'user':str(self.proxy_user.text()),
                     'password':str(self.proxy_password.text())}
        else:
            proxy = None
            self.tor_cb.setChecked(False)
        net_params = net_params._replace(proxy=proxy)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def _on_tab_changed(self):
        if self.tabs.currentWidget() is self._proxy_tab:
            self.td.trigger_rescan()

    def suggest_proxy(self, found_proxy):
        if found_proxy is None:
            self.tor_cb.hide()
            return
        self.tor_proxy = found_proxy
        self.tor_cb.setText(_("Use Tor proxy at port {}").format(str(found_proxy[1])))
        if (self.proxy_cb.isChecked()
                and self.proxy_mode.currentIndex() == self.proxy_mode.findText('SOCKS5')
                and self.proxy_host.text() == "127.0.0.1"
                and self.proxy_port.text() == str(found_proxy[1])):
            self.tor_cb.setChecked(True)
        self.tor_cb.show()

    def use_tor_proxy(self, use_it):
        if not use_it:
            self.proxy_cb.setChecked(False)
        else:
            socks5_mode_index = self.proxy_mode.findText('SOCKS5')
            if socks5_mode_index == -1:
                _logger.info("can't find proxy_mode 'SOCKS5'")
                return
            self.proxy_mode.setCurrentIndex(socks5_mode_index)
            self.proxy_host.setText("127.0.0.1")
            self.proxy_port.setText(str(self.tor_proxy[1]))
            self.proxy_user.setText("")
            self.proxy_password.setText("")
            self.tor_cb.setChecked(True)
            self.proxy_cb.setChecked(True)
        self.check_disable_proxy(use_it)
        self.set_proxy()

    def proxy_settings_changed(self):
        self.tor_cb.setChecked(False)


class TorDetector(QThread):
    found_proxy = pyqtSignal(object)

    def __init__(self):
        QThread.__init__(self)
        self._work_to_do_evt = threading.Event()
        self._stopping = False

    def run(self):
        while True:
            # do rescan
            net_addr = detect_tor_socks_proxy()
            self.found_proxy.emit(net_addr)
            # wait until triggered
            self._work_to_do_evt.wait()
            self._work_to_do_evt.clear()
            if self._stopping:
                return

    def trigger_rescan(self) -> None:
        self._work_to_do_evt.set()

    def stop(self):
        self._stopping = True
        self._work_to_do_evt.set()
        self.exit()
        self.wait()


class ProxyWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        fixed_width_hostname = 24 * char_width_in_lineedit()
        fixed_width_port = 6 * char_width_in_lineedit()

        grid = QGridLayout(self)
        grid.setSpacing(8)

        # proxy setting.
        self.proxy_cb = QCheckBox(_('Use proxy'))
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(['SOCKS4', 'SOCKS5'])
        self.proxy_mode.setCurrentIndex(1)
        self.proxy_host = QLineEdit()
        self.proxy_host.setFixedWidth(fixed_width_hostname)
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(fixed_width_port)
        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText(_("Proxy user"))
        self.proxy_password = PasswordLineEdit()
        self.proxy_password.setPlaceholderText(_("Password"))
        self.proxy_password.setFixedWidth(fixed_width_port)

        grid.addWidget(self.proxy_cb, 0, 0, 1, 3)
        grid.addWidget(HelpButton(_('Proxy settings apply to all connections: with Electrum servers, but also with third-party services.')), 0, 4)
        grid.addWidget(self.proxy_mode, 1, 1)
        grid.addWidget(self.proxy_host, 1, 2)
        grid.addWidget(self.proxy_port, 1, 3)
        grid.addWidget(self.proxy_user, 2, 2)
        grid.addWidget(self.proxy_password, 2, 3)

    def get_proxy_settings(self):
        return {
            'enabled': self.proxy_cb.isChecked(),
            'mode': ['socks4', 'socks5'][self.proxy_mode.currentIndex()],
            'host': self.proxy_host.text(),
            'port': self.proxy_port.text(),
            'user': self.proxy_user.text(),
            'password': self.proxy_password.text()
        }


class ServerWidget(QWidget, QtEventListener):
    def __init__(self, network, parent=None):
        super().__init__(parent)
        self.network = network
        self.config = network.config

        fixed_width_hostname = 24 * char_width_in_lineedit()
        fixed_width_port = 6 * char_width_in_lineedit()

        self.setLayout(QVBoxLayout())

        grid = QGridLayout(self)

        msg = ' '.join([
            _("Electrum connects to several nodes in order to download block headers and find out the longest blockchain."),
            _("This blockchain is used to verify the transactions sent by your transaction server.")
        ])
        self.status_label = QLabel('')
        grid.addWidget(QLabel(_('Status') + ':'), 0, 0)
        grid.addWidget(self.status_label, 0, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)

        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setEnabled(self.config.cv.NETWORK_AUTO_CONNECT.is_modifiable())
        msg = ' '.join([
            _("If auto-connect is enabled, Electrum will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electrum will warn you if your server is lagging.")
        ])
        grid.addWidget(self.autoconnect_cb, 1, 0, 1, 3)
        grid.addWidget(HelpButton(msg), 1, 4)

        self.server_e = QLineEdit()
        self.server_e.setFixedWidth(fixed_width_hostname + fixed_width_port)
        msg = _("Electrum sends your wallet addresses to a single server, in order to receive your transaction history.")
        grid.addWidget(QLabel(_('Server') + ':'), 2, 0)
        grid.addWidget(self.server_e, 2, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 2, 4)

        self.height_label = QLabel('')
        msg = _('This is the height of your local copy of the blockchain.')
        grid.addWidget(QLabel(_('Blockchain') + ':'), 3, 0)
        grid.addWidget(self.height_label, 3, 1)
        grid.addWidget(HelpButton(msg), 3, 4)

        self.split_label = QLabel('')
        grid.addWidget(self.split_label, 4, 0, 1, 3)

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

    @qt_event_listener
    def on_event_network_updated(self):
        self.nodes_list_widget.update()

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
        net_params = net_params._replace(server=server,
                                         auto_connect=self.autoconnect_cb.isChecked())
        self.network.run_from_another_thread(self.network.set_parameters(net_params))
