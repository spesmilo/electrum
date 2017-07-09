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

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum.i18n import _
from electrum.network import DEFAULT_PORTS
from electrum.network import serialize_server, deserialize_server

from util import *

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'

class NetworkDialog(QDialog):
    def __init__(self, network, config):
        QDialog.__init__(self)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(400, 20)
        self.nlayout = NetworkChoiceLayout(network, config)
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.nlayout.layout())
        vbox.addLayout(Buttons(CloseButton(self)))

        self.connect(self, QtCore.SIGNAL('updated'), self.on_update)
        network.register_callback(self.on_network, ['updated'])

    def on_network(self, event, *args):
        self.emit(QtCore.SIGNAL('updated'), event, *args)

    def on_update(self):
        self.nlayout.update()


class NodesListWidget(QTreeWidget):

    def __init__(self, parent):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels([_('Node'), _('Height')])
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)

    def create_menu(self, position):
        item = self.currentItem()
        if not item:
            return
        is_server = not bool(item.data(0, Qt.UserRole).toInt()[0])
        menu = QMenu()
        if is_server:
            server = unicode(item.data(1, Qt.UserRole).toString())
            menu.addAction(_("Use as server"), lambda: self.parent.follow_server(server))
        else:
            index = item.data(1, Qt.UserRole).toInt()[0]
            menu.addAction(_("Follow this branch"), lambda: self.parent.follow_branch(index))
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
        self.emit(SIGNAL('customContextMenuRequested(const QPoint&)'), pt)

    def update(self, network):
        self.clear()
        checkpoint = network.get_checkpoint()
        n_chains = len(network.blockchains)
        if n_chains > 1:
            for b in network.blockchains.values():
                name = network.get_blockchain_name(b)
                x = QTreeWidgetItem([name + '@%d'%checkpoint, '%d'%b.height()])
                x.setData(0, Qt.UserRole, 1)
                x.setData(1, Qt.UserRole, b.checkpoint)
                for i in network.interfaces.values():
                    if i.blockchain == b:
                        item = QTreeWidgetItem([i.host, '%d'%i.tip])
                        item.setData(0, Qt.UserRole, 0)
                        item.setData(1, Qt.UserRole, i.server)
                        x.addChild(item)
                self.addTopLevelItem(x)
                x.setExpanded(True)
        else:
            for i in network.interfaces.values():
                item = QTreeWidgetItem([i.host, '%d'%i.tip])
                item.setData(0, Qt.UserRole, 0)
                item.setData(1, Qt.UserRole, i.server)
                self.addTopLevelItem(item)

        h = self.header()
        h.setStretchLastSection(False)
        h.setResizeMode(0, QHeaderView.Stretch)
        h.setResizeMode(1, QHeaderView.ResizeToContents)




class NetworkChoiceLayout(object):

    def __init__(self, network, config, wizard=False):
        self.network = network
        self.config = config
        self.protocol = None
        self.tor_proxy = None

        tabs = QTabWidget()
        server_tab = QWidget()
        proxy_tab = QWidget()
        blockchain_tab = QWidget()
        tabs.addTab(server_tab, _('Server'))
        tabs.addTab(proxy_tab, _('Proxy'))
        tabs.addTab(blockchain_tab, _('Blockchain'))

        # server tab
        grid = QGridLayout(server_tab)
        grid.setSpacing(8)

        self.server_host = QLineEdit()
        self.server_host.setFixedWidth(200)
        self.server_port = QLineEdit()
        self.server_port.setFixedWidth(60)
        self.ssl_cb = QCheckBox(_('Use SSL'))
        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setEnabled(self.config.is_modifiable('auto_connect'))

        self.server_host.editingFinished.connect(self.set_server)
        self.server_port.editingFinished.connect(self.set_server)
        self.ssl_cb.clicked.connect(self.change_protocol)
        self.autoconnect_cb.clicked.connect(self.set_server)
        self.autoconnect_cb.clicked.connect(self.enable_set_server)

        msg = ' '.join([
            _("If auto-connect is enabled, Electrum will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electrum will warn you if your server is lagging.")
        ])
        grid.addWidget(self.autoconnect_cb, 0, 0, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)

        msg = _("Electrum sends your wallet addresses to a single server, in order to receive your transaction history.")
        grid.addWidget(QLabel(_('Server') + ':'), 1, 0)
        grid.addWidget(self.server_host, 1, 1, 1, 2)
        grid.addWidget(self.server_port, 1, 3)
        grid.addWidget(HelpButton(msg), 1, 4)

        label = _('Active Servers') if network.is_connected() else _('Default Servers')
        self.servers_list_widget = QTreeWidget()
        self.servers_list_widget.setHeaderLabels( [ label, _('Limit') ] )
        self.servers_list_widget.setColumnWidth(0, 240)
        grid.addWidget(self.servers_list_widget, 3, 0, 1, 5)


        # Proxy tab
        grid = QGridLayout(proxy_tab)
        grid.setSpacing(8)

        # proxy setting
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(['NONE', 'SOCKS4', 'SOCKS5', 'HTTP'])
        self.proxy_host = QLineEdit()
        self.proxy_host.setFixedWidth(200)
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(60)
        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText(_("Proxy user"))
        self.proxy_password = QLineEdit()
        self.proxy_password.setPlaceholderText(_("Password"))
        self.proxy_password.setEchoMode(QLineEdit.Password)
        self.proxy_password.setFixedWidth(60)

        self.proxy_mode.currentIndexChanged.connect(self.set_proxy)
        self.proxy_host.editingFinished.connect(self.set_proxy)
        self.proxy_port.editingFinished.connect(self.set_proxy)
        self.proxy_user.editingFinished.connect(self.set_proxy)
        self.proxy_password.editingFinished.connect(self.set_proxy)

        self.check_disable_proxy()
        self.proxy_mode.connect(self.proxy_mode, SIGNAL('currentIndexChanged(int)'), self.check_disable_proxy)

        self.proxy_mode.connect(self.proxy_mode, SIGNAL('currentIndexChanged(int)'), self.proxy_settings_changed)
        self.proxy_host.connect(self.proxy_host, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)
        self.proxy_port.connect(self.proxy_port, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)
        self.proxy_user.connect(self.proxy_user, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)
        self.proxy_password.connect(self.proxy_password, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)

        self.tor_cb = QCheckBox(_("Use Tor Proxy"))
        self.tor_cb.setIcon(QIcon(":icons/tor_logo.png"))
        self.tor_cb.hide()
        self.tor_cb.clicked.connect(self.use_tor_proxy)

        grid.addWidget(self.ssl_cb, 0, 0, 1, 3)
        grid.addWidget(self.tor_cb, 1, 0, 1, 3)
        grid.addWidget(self.proxy_mode, 4, 1)
        grid.addWidget(self.proxy_host, 4, 2)
        grid.addWidget(self.proxy_port, 4, 3)
        grid.addWidget(self.proxy_user, 5, 2)
        grid.addWidget(self.proxy_password, 5, 3)
        grid.setRowStretch(6, 1)

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
        self.height_label = QLabel('')
        msg = _('This is the height of your local copy of the blockchain.')
        grid.addWidget(QLabel(_("Height") + ':'), 1, 0)
        grid.addWidget(self.height_label, 1, 1)
        grid.addWidget(HelpButton(msg), 1, 4)

        self.split_label = QLabel('')
        grid.addWidget(self.split_label, 2, 0, 1, 3)
        self.nodes_list_widget = NodesListWidget(self)
        grid.addWidget(self.nodes_list_widget, 5, 0, 1, 5)
        grid.setRowStretch(7, 1)
        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        self.layout_ = vbox
        # tor detector
        self.td = td = TorDetector()
        td.found_proxy.connect(self.suggest_proxy)
        td.start()
        self.servers_list_widget.connect(
            self.servers_list_widget,
            SIGNAL('currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)'),
            lambda x,y: self.server_changed(x))
        # update
        self.update()

    def check_disable_proxy(self, index = False):
        if self.config.is_modifiable('proxy'):
            for w in [self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password]:
                w.setEnabled(self.proxy_mode.currentText() != 'NONE')
        else:
            for w in [self.proxy_host, self.proxy_port, self.proxy_mode]: w.setEnabled(False)

    def enable_set_server(self):
        if self.config.is_modifiable('server'):
            enabled = not self.autoconnect_cb.isChecked()
            self.server_host.setEnabled(enabled)
            self.server_port.setEnabled(enabled)
            self.servers_list_widget.setEnabled(enabled)
        else:
            for w in [self.autoconnect_cb, self.server_host, self.server_port, self.ssl_cb, self.servers_list_widget]:
                w.setEnabled(False)

    def update(self):
        host, port, protocol, proxy_config, auto_connect = self.network.get_parameters()
        if not proxy_config:
            proxy_config = { "mode":"none", "host":"localhost", "port":"9050"}
        self.server_host.setText(host)
        self.server_port.setText(port)
        self.ssl_cb.setChecked(protocol=='s')
        self.autoconnect_cb.setChecked(auto_connect)

        self.set_protocol(protocol)
        self.update_servers_list()
        self.enable_set_server()

        # proxy tab
        self.proxy_mode.setCurrentIndex(self.proxy_mode.findText(str(proxy_config.get("mode").upper())))
        self.proxy_host.setText(proxy_config.get("host"))
        self.proxy_port.setText(proxy_config.get("port"))
        self.proxy_user.setText(proxy_config.get("user", ""))
        self.proxy_password.setText(proxy_config.get("password", ""))

        height_str = "%d "%(self.network.get_local_height())
        self.height_label.setText(height_str)
        n = len(self.network.get_interfaces())
        status = _("Connected to %d nodes.")%n if n else _("Not connected")
        self.status_label.setText(status)
        if len(self.network.blockchains)>1:
            checkpoint = self.network.get_checkpoint()
            name = self.network.get_blockchain_name(self.network.blockchain())
            msg = _('Chain split detected at block %d')%checkpoint + '\n'
            msg += (_('You are following branch') if auto_connect else _('Your server is on branch'))+ ' ' + name
        else:
            msg = ''
        self.split_label.setText(msg)
        self.nodes_list_widget.update(self.network)

    def layout(self):
        return self.layout_

    def update_servers_list(self):
        self.servers = self.network.get_servers()
        use_tor = self.tor_cb.isChecked()
        self.servers_list_widget.clear()
        for _host, d in sorted(self.servers.items()):
            if _host.endswith('.onion') and not use_tor:
                continue
            if d.get(self.protocol):
                pruning_level = d.get('pruning','')
                self.servers_list_widget.addTopLevelItem(QTreeWidgetItem( [ _host, pruning_level ] ))

    def set_protocol(self, protocol):
        if protocol != self.protocol:
            self.protocol = protocol

    def change_protocol(self, use_ssl):
        p = 's' if use_ssl else 't'
        host = unicode(self.server_host.text())
        pp = self.servers.get(host, DEFAULT_PORTS)
        if p not in pp.keys():
            p = pp.keys()[0]
        port = pp[p]
        self.server_host.setText( host )
        self.server_port.setText( port )
        self.set_protocol(p)
        self.set_server()

    def follow_branch(self, index):
        self.network.follow_chain(index)
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        auto_connect = True
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)
        self.update()

    def follow_server(self, server):
        self.network.switch_to_interface(server)
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        host, port, protocol = server.split(':')
        auto_connect = False
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)
        self.update()

    def server_changed(self, x):
        if x:
            self.change_server(str(x.text(0)), self.protocol)

    def change_server(self, host, protocol):
        pp = self.servers.get(host, DEFAULT_PORTS)
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
                protocol = pp.keys()[0]
                port = pp.get(protocol)
        self.server_host.setText( host )
        self.server_port.setText( port )
        self.ssl_cb.setChecked(protocol=='s')
        self.set_server()

    def accept(self):
        pass

    def set_server(self):
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        host = str(self.server_host.text())
        port = str(self.server_port.text())
        protocol = 's' if self.ssl_cb.isChecked() else 't'
        auto_connect = self.autoconnect_cb.isChecked()
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)

    def set_proxy(self):
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        if self.proxy_mode.currentText() != 'NONE':
            proxy = { 'mode':str(self.proxy_mode.currentText()).lower(),
                      'host':str(self.proxy_host.text()),
                      'port':str(self.proxy_port.text()),
                      'user':str(self.proxy_user.text()),
                      'password':str(self.proxy_password.text())}
        else:
            proxy = None
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)

    def suggest_proxy(self, found_proxy):
        self.tor_proxy = found_proxy
        self.tor_cb.setText("Use Tor proxy at port " + str(found_proxy[1]))
        if self.proxy_mode.currentIndex() == 2 \
            and self.proxy_host.text() == "127.0.0.1" \
                and self.proxy_port.text() == str(found_proxy[1]):
            self.tor_cb.setChecked(True)
        self.tor_cb.show()

    def use_tor_proxy(self, use_it):
        # 2 = SOCKS5
        if not use_it:
            self.proxy_mode.setCurrentIndex(0)
            self.tor_cb.setChecked(False)
        else:
            self.proxy_mode.setCurrentIndex(2)
            self.proxy_host.setText("127.0.0.1")
            self.proxy_port.setText(str(self.tor_proxy[1]))
            self.proxy_user.setText("")
            self.proxy_password.setText("")
            self.tor_cb.setChecked(True)

    def proxy_settings_changed(self):
        self.tor_cb.setChecked(False)


class TorDetector(QThread):
    found_proxy = pyqtSignal(object)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        # Probable ports for Tor to listen at
        ports = [9050, 9150]
        for p in ports:
            if TorDetector.is_tor_port(p):
                self.found_proxy.emit(("127.0.0.1", p))
                return

    @staticmethod
    def is_tor_port(port):
        try:
            s = socket._socketobject(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect(("127.0.0.1", port))
            # Tor responds uniquely to HTTP-like requests
            s.send("GET\n")
            if "Tor is not an HTTP Proxy" in s.recv(1024):
                return True
        except socket.error:
            pass
        return False
