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
from typing import Tuple

from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtWidgets import (QTreeWidget, QTreeWidgetItem, QMenu, QGridLayout, QComboBox,
                             QLineEdit, QDialog, QVBoxLayout, QHeaderView, QCheckBox,
                             QTabWidget, QWidget, QLabel)
from PyQt5.QtGui import QFontMetrics

from electrum.i18n import _
from electrum import constants, blockchain
from electrum.interface import serialize_server, deserialize_server
from electrum.network import Network
from electrum.logging import get_logger

from .util import Buttons, CloseButton, HelpButton, read_QIcon, char_width_in_lineedit


_logger = get_logger(__name__)

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'

class NetworkDialog(QDialog):
    def __init__(self, network, config, network_updated_signal_obj):
        QDialog.__init__(self)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 300)
        self.nlayout = NetworkChoiceLayout(network, config)
        self.network_updated_signal_obj = network_updated_signal_obj
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.nlayout.layout())
        vbox.addLayout(Buttons(CloseButton(self)))
        self.network_updated_signal_obj.network_updated_signal.connect(
            self.on_update)
        network.register_callback(self.on_network, ['network_updated'])

    def on_network(self, event, *args):
        self.network_updated_signal_obj.network_updated_signal.emit(event, args)

    def on_update(self):
        self.nlayout.update()



class NodesListWidget(QTreeWidget):

    def __init__(self, parent):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels([_('Connected node'), _('Height')])
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)

    def create_menu(self, position):
        item = self.currentItem()
        if not item:
            return
        is_server = not bool(item.data(0, Qt.UserRole))
        menu = QMenu()
        if is_server:
            server = item.data(1, Qt.UserRole)
            menu.addAction(_("Use as server"), lambda: self.parent.follow_server(server))
        else:
            chain_id = item.data(1, Qt.UserRole)
            menu.addAction(_("Follow this branch"), lambda: self.parent.follow_branch(chain_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    def keyPressEvent(self, event):
        if event.key() in [ Qt.Key_F2, Qt.Key_Return ]:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def update(self, network: Network):
        self.clear()
        self.addChild = self.addTopLevelItem
        chains = network.get_blockchains()
        n_chains = len(chains)
        for chain_id, interfaces in chains.items():
            b = blockchain.blockchains.get(chain_id)
            if b is None: continue
            name = b.get_name()
            if n_chains > 1:
                x = QTreeWidgetItem([name + '@%d'%b.get_max_forkpoint(), '%d'%b.height()])
                x.setData(0, Qt.UserRole, 1)
                x.setData(1, Qt.UserRole, b.get_id())
            else:
                x = self
            for i in interfaces:
                star = ' *' if i == network.interface else ''
                item = QTreeWidgetItem([i.host + star, '%d'%i.tip])
                item.setData(0, Qt.UserRole, 0)
                item.setData(1, Qt.UserRole, i.server)
                x.addChild(item)
            if n_chains > 1:
                self.addTopLevelItem(x)
                x.setExpanded(True)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)

        super().update()


class ServerListWidget(QTreeWidget):
    class Columns(IntEnum):
        HOST = 0
        PORT = 1

    SERVER_STR_ROLE = Qt.UserRole + 100

    def __init__(self, parent):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels([_('Host'), _('Port')])
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)

    def create_menu(self, position):
        item = self.currentItem()
        if not item:
            return
        menu = QMenu()
        server = item.data(self.Columns.HOST, self.SERVER_STR_ROLE)
        menu.addAction(_("Use as server"), lambda: self.set_server(server))
        menu.exec_(self.viewport().mapToGlobal(position))

    def set_server(self, s):
        host, port, protocol = deserialize_server(s)
        self.parent.server_host.setText(host)
        self.parent.server_port.setText(port)
        self.parent.set_server()

    def keyPressEvent(self, event):
        if event.key() in [ Qt.Key_F2, Qt.Key_Return ]:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def update(self, servers, protocol, use_tor):
        self.clear()
        for _host, d in sorted(servers.items()):
            if _host.endswith('.onion') and not use_tor:
                continue
            port = d.get(protocol)
            if port:
                x = QTreeWidgetItem([_host, port])
                server = serialize_server(_host, port, protocol)
                x.setData(self.Columns.HOST, self.SERVER_STR_ROLE, server)
                self.addTopLevelItem(x)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(self.Columns.HOST, QHeaderView.Stretch)
        h.setSectionResizeMode(self.Columns.PORT, QHeaderView.ResizeToContents)

        super().update()


class NetworkChoiceLayout(object):

    def __init__(self, network: Network, config, wizard=False):
        self.network = network
        self.config = config
        self.protocol = None
        self.tor_proxy = None

        self.tabs = tabs = QTabWidget()
        server_tab = QWidget()
        proxy_tab = QWidget()
        blockchain_tab = QWidget()
        tabs.addTab(blockchain_tab, _('Overview'))
        tabs.addTab(server_tab, _('Server'))
        tabs.addTab(proxy_tab, _('Proxy'))

        fixed_width_hostname = 24 * char_width_in_lineedit()
        fixed_width_port = 6 * char_width_in_lineedit()

        # server tab
        grid = QGridLayout(server_tab)
        grid.setSpacing(8)

        self.server_host = QLineEdit()
        self.server_host.setFixedWidth(fixed_width_hostname)
        self.server_port = QLineEdit()
        self.server_port.setFixedWidth(fixed_width_port)
        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setEnabled(self.config.is_modifiable('auto_connect'))

        self.server_host.editingFinished.connect(self.set_server)
        self.server_port.editingFinished.connect(self.set_server)
        self.autoconnect_cb.clicked.connect(self.set_server)
        self.autoconnect_cb.clicked.connect(self.update)

        msg = ' '.join([
            _("If auto-connect is enabled, Electrum will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electrum will warn you if your server is lagging.")
        ])
        grid.addWidget(self.autoconnect_cb, 0, 0, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)

        grid.addWidget(QLabel(_('Server') + ':'), 1, 0)
        grid.addWidget(self.server_host, 1, 1, 1, 2)
        grid.addWidget(self.server_port, 1, 3)

        label = _('Server peers') if network.is_connected() else _('Default Servers')
        grid.addWidget(QLabel(label), 2, 0, 1, 5)
        self.servers_list = ServerListWidget(self)
        grid.addWidget(self.servers_list, 3, 0, 1, 5)

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
        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText(_("Proxy user"))
        self.proxy_password = QLineEdit()
        self.proxy_password.setPlaceholderText(_("Password"))
        self.proxy_password.setEchoMode(QLineEdit.Password)
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

        self.server_label = QLabel('')
        msg = _("Electrum sends your wallet addresses to a single server, in order to receive your transaction history.")
        grid.addWidget(QLabel(_('Server') + ':'), 1, 0)
        grid.addWidget(self.server_label, 1, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 1, 4)

        self.height_label = QLabel('')
        msg = _('This is the height of your local copy of the blockchain.')
        grid.addWidget(QLabel(_('Blockchain') + ':'), 2, 0)
        grid.addWidget(self.height_label, 2, 1)
        grid.addWidget(HelpButton(msg), 2, 4)

        self.split_label = QLabel('')
        grid.addWidget(self.split_label, 3, 0, 1, 3)

        self.nodes_list_widget = NodesListWidget(self)
        grid.addWidget(self.nodes_list_widget, 5, 0, 1, 5)

        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        self.layout_ = vbox
        # tor detector
        self.td = td = TorDetector()
        td.found_proxy.connect(self.suggest_proxy)
        td.start()

        self.fill_in_proxy_settings()
        self.update()

    def check_disable_proxy(self, b):
        if not self.config.is_modifiable('proxy'):
            b = False
        for w in [self.proxy_mode, self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password]:
            w.setEnabled(b)

    def enable_set_server(self):
        if self.config.is_modifiable('server'):
            enabled = not self.autoconnect_cb.isChecked()
            self.server_host.setEnabled(enabled)
            self.server_port.setEnabled(enabled)
            self.servers_list.setEnabled(enabled)
        else:
            for w in [self.autoconnect_cb, self.server_host, self.server_port, self.servers_list]:
                w.setEnabled(False)

    def update(self):
        net_params = self.network.get_parameters()
        host, port, protocol = net_params.host, net_params.port, net_params.protocol
        proxy_config, auto_connect = net_params.proxy, net_params.auto_connect
        if not self.server_host.hasFocus() and not self.server_port.hasFocus():
            self.server_host.setText(host)
            self.server_port.setText(str(port))
        self.autoconnect_cb.setChecked(auto_connect)

        interface = self.network.interface
        host = interface.host if interface else _('None')
        self.server_label.setText(host)

        self.set_protocol(protocol)
        self.servers = self.network.get_servers()
        self.servers_list.update(self.servers, self.protocol, self.tor_cb.isChecked())
        self.enable_set_server()

        height_str = "%d "%(self.network.get_local_height()) + _('blocks')
        self.height_label.setText(height_str)
        n = len(self.network.get_interfaces())
        status = _("Connected to {0} nodes.").format(n) if n else _("Not connected")
        self.status_label.setText(status)
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
        self.nodes_list_widget.update(self.network)

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

    def set_protocol(self, protocol):
        if protocol != self.protocol:
            self.protocol = protocol

    def change_protocol(self, use_ssl):
        p = 's' if use_ssl else 't'
        host = self.server_host.text()
        pp = self.servers.get(host, constants.net.DEFAULT_PORTS)
        if p not in pp.keys():
            p = list(pp.keys())[0]
        port = pp[p]
        self.server_host.setText(host)
        self.server_port.setText(port)
        self.set_protocol(p)
        self.set_server()

    def follow_branch(self, chain_id):
        self.network.run_from_another_thread(self.network.follow_chain_given_id(chain_id))
        self.update()

    def follow_server(self, server):
        self.network.run_from_another_thread(self.network.follow_chain_given_server(server))
        self.update()

    def server_changed(self, x):
        if x:
            self.change_server(str(x.text(0)), self.protocol)

    def change_server(self, host, protocol):
        pp = self.servers.get(host, constants.net.DEFAULT_PORTS)
        if protocol and protocol not in protocol_letters:
            protocol = None
        if protocol:
            port = pp.get(protocol)
            if port is None:
                protocol = None
        if not protocol:
            if 's' in pp.keys():
                protocol = 's'
                port = pp.get(protocol)
            else:
                protocol = list(pp.keys())[0]
                port = pp.get(protocol)
        self.server_host.setText(host)
        self.server_port.setText(port)

    def accept(self):
        pass

    def set_server(self):
        net_params = self.network.get_parameters()
        net_params = net_params._replace(host=str(self.server_host.text()),
                                         port=str(self.server_port.text()),
                                         auto_connect=self.autoconnect_cb.isChecked())
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def set_proxy(self):
        net_params = self.network.get_parameters()
        if self.proxy_cb.isChecked():
            proxy = { 'mode':str(self.proxy_mode.currentText()).lower(),
                      'host':str(self.proxy_host.text()),
                      'port':str(self.proxy_port.text()),
                      'user':str(self.proxy_user.text()),
                      'password':str(self.proxy_password.text())}
        else:
            proxy = None
            self.tor_cb.setChecked(False)
        net_params = net_params._replace(proxy=proxy)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def suggest_proxy(self, found_proxy):
        if found_proxy is None:
            self.tor_cb.hide()
            return
        self.tor_proxy = found_proxy
        self.tor_cb.setText("Use Tor proxy at port " + str(found_proxy[1]))
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

    def run(self):
        # Probable ports for Tor to listen at
        ports = [9050, 9150]
        while True:
            for p in ports:
                net_addr = ("127.0.0.1", p)
                if TorDetector.is_tor_port(net_addr):
                    self.found_proxy.emit(net_addr)
                    break
            else:
                self.found_proxy.emit(None)
            time.sleep(10)

    @staticmethod
    def is_tor_port(net_addr: Tuple[str, int]) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect(net_addr)
            # Tor responds uniquely to HTTP-like requests
            s.send(b"GET\n")
            if b"Tor is not an HTTP Proxy" in s.recv(1024):
                return True
        except socket.error:
            pass
        return False
