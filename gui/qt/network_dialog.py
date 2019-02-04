#!/usr/bin/env python3
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

import socket, queue

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import PyQt5.QtCore as QtCore

from electroncash.i18n import _
from electroncash import networks
from electroncash.util import print_error, Weak
from electroncash.network import serialize_server, deserialize_server, get_eligible_servers

from .util import *

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'

class NetworkDialog(QDialog, MessageBoxMixin):
    network_updated_signal = pyqtSignal()

    def __init__(self, network, config):
        QDialog.__init__(self)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 20)
        self.nlayout = NetworkChoiceLayout(self, network, config)
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.nlayout.layout())
        vbox.addLayout(Buttons(CloseButton(self)))
        self.network_updated_signal.connect(self.on_update)
        network.register_callback(self.on_network, ['updated', 'interfaces'])

    def on_network(self, event, *args):
        ''' This may run in network thread '''
        self.network_updated_signal.emit() # this enqueues call to on_update in GUI thread

    @rate_limited(0.333) # limit network window updates to max 3 per second. More frequent isn't that useful anyway -- and on large wallets/big synchs the network spams us with events which we would rather collapse into 1
    def on_update(self):
        ''' This always runs in main GUI thread '''
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
            index = item.data(1, Qt.UserRole)
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
        self.customContextMenuRequested.emit(pt)

    def update(self, network):
        self.clear()
        self.addChild = self.addTopLevelItem
        chains = network.get_blockchains()
        n_chains = len(chains)
        for k, items in chains.items():
            b = network.blockchains[k]
            name = b.get_name()
            if n_chains >1:
                x = QTreeWidgetItem([name + '@%d'%b.get_base_height(), '%d'%b.height()])
                x.setData(0, Qt.UserRole, 1)
                x.setData(1, Qt.UserRole, b.base_height)
            else:
                x = self
            for i in items:
                star = ' ◀' if i == network.interface else ''
                item = QTreeWidgetItem([i.host + star, '%d'%i.tip])
                item.setData(0, Qt.UserRole, 0)
                item.setData(1, Qt.UserRole, i.server)
                x.addChild(item)
            if n_chains>1:
                self.addTopLevelItem(x)
                x.setExpanded(True)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)

class ServerFlag:
    ''' Used by ServerListWidget for Server flags & Symbols '''
    Banned = 2 # Blacklisting/banning was a hidden mechanism inherited from Electrum. We would blacklist misbehaving servers under the hood. Now that facility is exposed (editable by the user). We never connect to blacklisted servers.
    Preferred = 1 # Preferred servers (white-listed) start off as the servers in servers.json and are "more trusted" and optionally the user can elect to connect to only these servers
    NoFlag = 0
    Symbol = ("", "★", "⛔") # indexed using pseudo-enum above
    UnSymbol = ("", "✖", "⚬") # used for "disable X" context menu

class ServerListWidget(QTreeWidget):

    def __init__(self, parent):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels(['', _('Host'), _('Port')])
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)

    def create_menu(self, position):
        item = self.currentItem()
        if not item:
            return
        menu = QMenu()
        server = item.data(2, Qt.UserRole)
        if self.parent.can_set_server(server):
            useAction = menu.addAction(_("Use as server"), lambda: self.set_server(server))
        else:
            useAction = menu.addAction(server.split(':',1)[0], lambda: None)
            useAction.setDisabled(True)
        menu.addSeparator()
        flagval = item.data(0, Qt.UserRole)
        iswl = flagval & ServerFlag.Preferred
        if flagval & ServerFlag.Banned:
            optxt = ServerFlag.UnSymbol[ServerFlag.Banned] + " " + _("Unban server")
            isbl = True
            useAction.setDisabled(True)
            useAction.setText(_("Server banned"))
        else:
            optxt = ServerFlag.Symbol[ServerFlag.Banned] + " " + _("Ban server")
            isbl = False
            if not isbl:
                if flagval & ServerFlag.Preferred:
                    optxt_fav = ServerFlag.UnSymbol[ServerFlag.Preferred] + " " + _("Remove from preferred")
                else:
                    optxt_fav = ServerFlag.Symbol[ServerFlag.Preferred] + " " + _("Add to preferred")
                menu.addAction(optxt_fav, lambda: self.parent.set_whitelisted(server, not iswl))
        menu.addAction(optxt, lambda: self.parent.set_blacklisted(server, not isbl))
        menu.exec_(self.viewport().mapToGlobal(position))

    def set_server(self, s):
        host, port, protocol = deserialize_server(s)
        self.parent.server_host.setText(host)
        self.parent.server_port.setText(port)
        self.parent.autoconnect_cb.setChecked(False) # force auto-connect off if they did "Use as server"
        self.parent.set_server()
        self.parent.update()

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

    @staticmethod
    def lightenItemText(item, rang=None):
        if rang is None: rang = range(0, item.columnCount())
        for i in rang:
            brush = item.foreground(i); color = brush.color(); color.setHsvF(color.hueF(), color.saturationF(), 0.5); brush.setColor(color)
            item.setForeground(i, brush)

    def update(self, network, servers, protocol, use_tor):
        self.clear()
        self.setIndentation(0)
        wl_only = network.is_whitelist_only()
        for _host, d in sorted(servers.items()):
            if _host.endswith('.onion') and not use_tor:
                continue
            port = d.get(protocol)
            if port:
                server = serialize_server(_host, port, protocol)
                flag, flagval, tt = (ServerFlag.Symbol[ServerFlag.Banned], ServerFlag.Banned, _("This server is banned")) if network.server_is_blacklisted(server) else ("", 0, "")
                flag2, flagval2, tt2 = (ServerFlag.Symbol[ServerFlag.Preferred], ServerFlag.Preferred, _("This is a preferred server")) if network.server_is_whitelisted(server) else ("", 0, "")
                flag = flag or flag2; del flag2
                tt = tt or tt2; del tt2
                flagval |= flagval2; del flagval2
                x = QTreeWidgetItem([flag, _host, port])
                if tt: x.setToolTip(0, tt)
                if (wl_only and flagval != ServerFlag.Preferred) or flagval & ServerFlag.Banned:
                    # lighten the text of servers we can't/won't connect to for the given mode
                    self.lightenItemText(x, range(1,3))
                x.setData(2, Qt.UserRole, server)
                x.setData(0, Qt.UserRole, flagval)
                self.addTopLevelItem(x)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)


class NetworkChoiceLayout(QObject):

    def __init__(self, parent, network, config, wizard=False):
        super().__init__(parent)
        self.network = network
        self.config = config
        self.protocol = None
        self.tor_proxy = None

        # tor detector
        self.td = TorDetector(self)
        self.td.found_proxy.connect(self.suggest_proxy)

        self.tabs = tabs = QTabWidget()
        server_tab = QWidget()
        weakTd = Weak.ref(self.td)
        class ProxyTab(QWidget):
            def showEvent(slf, e):
                super().showEvent(e)
                td = weakTd()
                if e.isAccepted() and td:
                    td.start() # starts the tor detector when proxy_tab appears
            def hideEvent(slf, e):
                super().hideEvent(e)
                td = weakTd()
                if e.isAccepted() and td:
                    td.stop() # stops the tor detector when proxy_tab disappears
        proxy_tab = ProxyTab()
        blockchain_tab = QWidget()
        tabs.addTab(blockchain_tab, _('Overview'))
        tabs.addTab(server_tab, _('Server'))
        tabs.addTab(proxy_tab, _('Proxy'))

        if wizard:
            tabs.setCurrentIndex(1)

        # server tab
        grid = QGridLayout(server_tab)
        grid.setSpacing(8)

        self.server_host = QLineEdit()
        self.server_host.setFixedWidth(200)
        self.server_port = QLineEdit()
        self.server_port.setFixedWidth(60)
        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setEnabled(self.config.is_modifiable('auto_connect'))

        self.server_host.editingFinished.connect(self.set_server)
        self.server_port.editingFinished.connect(self.set_server)
        self.autoconnect_cb.clicked.connect(self.set_server)
        self.autoconnect_cb.clicked.connect(self.update)

        msg = ' '.join([
            _("If auto-connect is enabled, Electron Cash will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electron Cash will warn you if your server is lagging.")
        ])
        grid.addWidget(self.autoconnect_cb, 0, 0, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)

        self.preferred_only_cb = QCheckBox(_("Connect only to preferred servers"))
        self.preferred_only_cb.setEnabled(self.config.is_modifiable('whitelist_servers_only'))
        self.preferred_only_cb.setToolTip(_("If enabled, restricts Electron Cash to connecting to servers only marked as 'preferred'."))

        self.preferred_only_cb.clicked.connect(self.set_whitelisted_only) # re-set the config key and notify network.py

        msg = '\n\n'.join([
            _("If 'Connect only to preferred servers' is enabled, Electron Cash will only connect to servers marked as 'preferred' servers ({}).").format(ServerFlag.Symbol[ServerFlag.Preferred]),
            _("This feature was added in response to the potential for a malicious actor to deny service via launching many servers (aka a sybil attack)."),
            _("If unsure, most of the time it's safe to leave this option disabled. However leaving it enabled is safer (if a little bit discouraging to new server operators wanting to populate their servers).")
        ])
        grid.addWidget(self.preferred_only_cb, 1, 0, 1, 3)
        grid.addWidget(HelpButton(msg), 1, 4)


        grid.addWidget(QLabel(_('Server') + ':'), 2, 0)
        grid.addWidget(self.server_host, 2, 1, 1, 2)
        grid.addWidget(self.server_port, 2, 3)

        self.server_list_label = label = QLabel('') # will get set by self.update()
        grid.addWidget(label, 3, 0, 1, 5)
        self.servers_list = ServerListWidget(self)
        grid.addWidget(self.servers_list, 4, 0, 1, 5)
        self.legend_label = label = WWLabel('') # will get populated with the legend by self.update()
        self.legend_label.linkActivated.connect(self.on_view_blacklist)
        grid.addWidget(label, 5, 0, 1, 4)
        msg = ' '.join([
            _("Preferred servers ({}) are servers you have designated as reliable and/or trustworthy.").format(ServerFlag.Symbol[ServerFlag.Preferred]),
            _("Initially, the preferred list is the hard-coded list of known-good servers vetted by the Electron Cash developers."),
            _("You can add or remove any server from this list and optionally elect to only connect to preferred servers."),
            "\n\n"+_("Banned servers ({}) are servers deemed unreliable and/or untrustworthy, and so they will never be connected-to by Electron Cash.").format(ServerFlag.Symbol[ServerFlag.Banned])
        ])
        grid.addWidget(HelpButton(msg), 5, 4)

        # Proxy tab
        grid = QGridLayout(proxy_tab)
        grid.setSpacing(8)

        # proxy setting
        self.proxy_cb = QCheckBox(_('Use proxy'))
        self.proxy_cb.clicked.connect(self.check_disable_proxy)
        self.proxy_cb.clicked.connect(self.set_proxy)

        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(['SOCKS4', 'SOCKS5', 'HTTP'])
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

        self.proxy_mode.currentIndexChanged.connect(self.proxy_settings_changed)
        self.proxy_host.textEdited.connect(self.proxy_settings_changed)
        self.proxy_port.textEdited.connect(self.proxy_settings_changed)
        self.proxy_user.textEdited.connect(self.proxy_settings_changed)
        self.proxy_password.textEdited.connect(self.proxy_settings_changed)

        self.tor_cb = QCheckBox(_("Use Tor Proxy"))
        self.tor_cb.setIcon(QIcon(":icons/tor_logo.png"))
        self.tor_cb.hide()
        self.tor_cb.clicked.connect(self.use_tor_proxy)

        grid.addWidget(self.tor_cb, 1, 0, 1, 3)
        grid.addWidget(self.proxy_cb, 2, 0, 1, 3)
        grid.addWidget(HelpButton(_('Proxy settings apply to all connections: with Electron Cash servers, but also with third-party services.')), 2, 4)
        grid.addWidget(self.proxy_mode, 4, 1)
        grid.addWidget(self.proxy_host, 4, 2)
        grid.addWidget(self.proxy_port, 4, 3)
        grid.addWidget(self.proxy_user, 5, 2)
        grid.addWidget(self.proxy_password, 5, 3)
        grid.setRowStretch(7, 1)

        # Blockchain Tab
        grid = QGridLayout(blockchain_tab)
        msg =  ' '.join([
            _("Electron Cash connects to several nodes in order to download block headers and find out the longest blockchain."),
            _("This blockchain is used to verify the transactions sent by your transaction server.")
        ])
        self.status_label = QLabel('')
        grid.addWidget(QLabel(_('Status') + ':'), 0, 0)
        grid.addWidget(self.status_label, 0, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)

        self.server_label = QLabel('')
        msg = _("Electron Cash sends your wallet addresses to a single server, in order to receive your transaction history.")
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

        self.fill_in_proxy_settings()
        self.update()

    def check_disable_proxy(self, b):
        if not self.config.is_modifiable('proxy'):
            b = False
        for w in [self.proxy_mode, self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password]:
            w.setEnabled(b)

    def get_set_server_flags(self):
        return (self.config.is_modifiable('server'),
                (not self.autoconnect_cb.isChecked()
                 and not self.preferred_only_cb.isChecked())
               )

    def can_set_server(self, server):
        return bool(self.get_set_server_flags()[0]
                    and not self.network.server_is_blacklisted(server)
                    and (not self.network.is_whitelist_only()
                         or self.network.server_is_whitelisted(server))
                    )

    def enable_set_server(self):
        modifiable, notauto = self.get_set_server_flags()
        if modifiable:
            self.server_host.setEnabled(notauto)
            self.server_port.setEnabled(notauto)
        else:
            for w in [self.autoconnect_cb, self.server_host, self.server_port]:
                w.setEnabled(False)

    def update(self):
        host, port, protocol, proxy_config, auto_connect = self.network.get_parameters()
        preferred_only = self.network.is_whitelist_only()
        self.server_host.setText(host)
        self.server_port.setText(port)
        self.autoconnect_cb.setChecked(auto_connect)
        self.preferred_only_cb.setChecked(preferred_only)

        host = self.network.interface.host if self.network.interface else _('None')
        self.server_label.setText(host)

        self.set_protocol(protocol)
        self.servers = self.network.get_servers()
        self.server_list_label.setText((_('Server peers') if self.network.is_connected() else _('Servers')) + " ({})".format(len(self.servers)))
        if self.network.blacklisted_servers:
            bl_srv_ct_str = ' ({}) <a href="ViewBanList">{}</a>'.format(len(self.network.blacklisted_servers), _("View ban list..."))
        else:
            bl_srv_ct_str = " (0)<i> </i>" # ensure rich text
        servers_whitelisted = set(get_eligible_servers(self.servers, protocol)).intersection(self.network.whitelisted_servers) - self.network.blacklisted_servers
        self.legend_label.setText(ServerFlag.Symbol[ServerFlag.Preferred] + "=" + _("Preferred") + " ({})".format(len(servers_whitelisted)) + "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                                  + ServerFlag.Symbol[ServerFlag.Banned] + "=" + _("Banned") + bl_srv_ct_str)
        self.servers_list.update(self.network, self.servers, self.protocol, self.tor_cb.isChecked())
        self.enable_set_server()

        height_str = "%d "%(self.network.get_local_height()) + _('blocks')
        self.height_label.setText(height_str)
        n = len(self.network.get_interfaces())
        status = _("Connected to %d nodes.")%n if n else _("Not connected")
        self.status_label.setText(status)
        chains = self.network.get_blockchains()
        if len(chains)>1:
            chain = self.network.blockchain()
            checkpoint = chain.get_base_height()
            name = chain.get_name()
            msg = _('Chain split detected at block %d')%checkpoint + '\n'
            msg += (_('You are following branch') if auto_connect else _('Your server is on branch'))+ ' ' + name
            msg += ' (%d %s)' % (chain.get_branch_size(), _('blocks'))
        else:
            msg = ''
        self.split_label.setText(msg)
        self.nodes_list_widget.update(self.network)

    def fill_in_proxy_settings(self):
        host, port, protocol, proxy_config, auto_connect = self.network.get_parameters()
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
        pp = self.servers.get(host, networks.net.DEFAULT_PORTS)
        if p not in pp.keys():
            p = list(pp.keys())[0]
        port = pp[p]
        self.server_host.setText(host)
        self.server_port.setText(port)
        self.set_protocol(p)
        self.set_server()

    def follow_branch(self, index):
        self.network.follow_chain(index)
        self.update()

    def follow_server(self, server):
        self.network.switch_to_interface(server)
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        host, port, protocol = deserialize_server(server)
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)
        self.update()

    def server_changed(self, x):
        if x:
            self.change_server(str(x.text(0)), self.protocol)

    def change_server(self, host, protocol):
        pp = self.servers.get(host, networks.net.DEFAULT_PORTS)
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
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        host = str(self.server_host.text())
        port = str(self.server_port.text())
        auto_connect = self.autoconnect_cb.isChecked()
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)

    def set_proxy(self):
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        if self.proxy_cb.isChecked():
            proxy = { 'mode':str(self.proxy_mode.currentText()).lower(),
                      'host':str(self.proxy_host.text()),
                      'port':str(self.proxy_port.text()),
                      'user':str(self.proxy_user.text()),
                      'password':str(self.proxy_password.text())}
        else:
            proxy = None
            self.tor_cb.setChecked(False)
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)

    def suggest_proxy(self, found_proxy):
        if not found_proxy:
            self.tor_cb.hide()
            self.tor_cb.setChecked(False) # It's not clear to me that if the tor service goes away and comes back later, and in the meantime they unchecked proxy_cb, that this should remain checked. I can see it being confusing for that to be the case. Better to uncheck. It gets auto-re-checked anyway if it comes back and it's the same due to code below. -Calin
            return
        self.tor_proxy = found_proxy
        self.tor_cb.setText("Use Tor proxy at port " + str(found_proxy[1]))
        if (self.proxy_mode.currentIndex() == self.proxy_mode.findText('SOCKS5')
            and self.proxy_host.text() == found_proxy[0]
            and self.proxy_port.text() == str(found_proxy[1])
            and self.proxy_cb.isChecked()):
            self.tor_cb.setChecked(True)
        self.tor_cb.show()

    def use_tor_proxy(self, use_it):
        if not use_it:
            self.proxy_cb.setChecked(False)
        else:
            socks5_mode_index = self.proxy_mode.findText('SOCKS5')
            if socks5_mode_index == -1:
                print_error("[network_dialog] can't find proxy_mode 'SOCKS5'")
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

    def set_blacklisted(self, server, bl):
        self.network.server_set_blacklisted(server, bl, True)
        self.set_server() # if the blacklisted server is the active server, this will force a reconnect to another server
        self.update()

    def set_whitelisted(self, server, flag):
        self.network.server_set_whitelisted(server, flag, True)
        self.set_server()
        self.update()

    def set_whitelisted_only(self, b):
        self.network.set_whitelist_only(b)
        self.set_server() # forces us to send a set-server to network.py which recomputes eligible servers, etc
        self.update()

    def on_view_blacklist(self, ignored):
        ''' The 'view ban list...' link leads to a modal dialog box where the
        user has the option to clear the entire blacklist. Build that dialog here. '''
        bl = sorted(self.network.blacklisted_servers)
        parent = self.parent()
        if not bl:
            parent.show_error(_("Server ban list is empty!"))
            return
        d = WindowModalDialog(parent.top_level_window(), _("Banned Servers"))
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_("Banned Servers") + " ({})".format(len(bl))))
        tree = QTreeWidget()
        tree.setHeaderLabels([_('Host'), _('Port')])
        for s in bl:
            host, port, protocol = deserialize_server(s)
            item = QTreeWidgetItem([host, str(port)])
            item.setFlags(Qt.ItemIsEnabled)
            tree.addTopLevelItem(item)
        tree.setIndentation(3)
        h = tree.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        vbox.addWidget(tree)

        clear_but = QPushButton(_("Clear ban list"))
        weakSelf = Weak.ref(self)
        weakD = Weak.ref(d)
        clear_but.clicked.connect(lambda: weakSelf() and weakSelf().on_clear_blacklist() and weakD().reject())
        vbox.addLayout(Buttons(clear_but, CloseButton(d)))
        d.exec_()

    def on_clear_blacklist(self):
        bl = list(self.network.blacklisted_servers)
        blen = len(bl)
        if self.parent().question(_("Clear all {} servers from the ban list?").format(blen)):
            for i,s in enumerate(bl):
                self.network.server_set_blacklisted(s, False, save=bool(i+1 == blen)) # save on last iter
            self.update()
            return True
        return False


class TorDetector(QThread):
    found_proxy = pyqtSignal(object)

    def start(self):
        self.stopQ = queue.Queue() # create a new stopQ blowing away the old one just in case it has old data in it (this prevents races with stop/start arriving too quickly for the thread)
        super().start()

    def stop(self):
        if self.isRunning():
            self.stopQ.put(None)

    def run(self):
        ports = [9050, 9150] # Probable ports for Tor to listen at
        while True:
            for p in ports:
                if TorDetector.is_tor_port(p):
                    self.found_proxy.emit(("127.0.0.1", p))
                    break
            else:
                self.found_proxy.emit(None) # no proxy found, will hide the Tor checkbox
            try:
                self.stopQ.get(timeout=10.0) # keep trying every 10 seconds
                return # we must have gotten a stop signal if we get here, break out of function, ending thread
            except queue.Empty:
                continue # timeout, keep looping

    @staticmethod
    def is_tor_port(port):
        try:
            s = (socket._socketobject if hasattr(socket, "_socketobject") else socket.socket)(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect(("127.0.0.1", port))
            # Tor responds uniquely to HTTP-like requests
            s.send(b"GET\n")
            if b"Tor is not an HTTP Proxy" in s.recv(1024):
                return True
        except socket.error:
            pass
        return False
