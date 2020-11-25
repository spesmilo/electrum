#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2020 The Electron Cash Developers
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

import queue
import socket
from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import PyQt5.QtCore as QtCore

from electroncash import networks
from electroncash.i18n import _, pgettext
from electroncash.interface import Interface
from electroncash.network import serialize_server, deserialize_server, get_eligible_servers
from electroncash.plugins import run_hook
from electroncash.tor import TorController
from electroncash.util import print_error, Weak, PrintError, in_main_thread

from .util import *
from .utils import UserPortValidator

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'

class NetworkDialog(MessageBoxMixin, QDialog):
    network_updated_signal = pyqtSignal()

    def __init__(self, network, config):
        QDialog.__init__(self)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 350)
        self.nlayout = NetworkChoiceLayout(self, network, config)
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.nlayout.layout())
        # We don't want the close button's behavior to have the enter key close
        # the window because user may edit text fields, etc, so we do the below:
        close_but = CloseButton(self); close_but.setDefault(False); close_but.setAutoDefault(False)
        vbox.addLayout(Buttons(close_but))
        self.network_updated_signal.connect(self.on_update)
        # below timer is to work around Qt on Linux display glitches when
        # showing this window.
        self.workaround_timer = QTimer()
        self.workaround_timer.timeout.connect(self._workaround_update)
        self.workaround_timer.setSingleShot(True)
        network.register_callback(self.on_network, ['blockchain_updated', 'interfaces', 'status'])
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.network_updated_signal.emit)
        self.refresh_timer.setInterval(500)

    def jumpto(self, location : str):
        self.nlayout.jumpto(location)

    def on_network(self, event, *args):
        ''' This may run in network thread '''
        #print_error("[NetworkDialog] on_network:",event,*args)
        self.network_updated_signal.emit() # this enqueues call to on_update in GUI thread

    @rate_limited(0.333) # limit network window updates to max 3 per second. More frequent isn't that useful anyway -- and on large wallets/big synchs the network spams us with events which we would rather collapse into 1
    def on_update(self):
        ''' This always runs in main GUI thread '''
        self.nlayout.update()

    def closeEvent(self, e):
        # Warn if non-SSL mode when closing dialog
        if (not self.nlayout.ssl_cb.isChecked()
                and not self.nlayout.tor_cb.isChecked()
                and not self.nlayout.server_host.text().lower().endswith('.onion')
                and not self.nlayout.config.get('non_ssl_noprompt', False)):
            ok, chk = self.question(''.join([_("You have selected non-SSL mode for your server settings."), ' ',
                                             _("Using this mode presents a potential security risk."), '\n\n',
                                             _("Are you sure you wish to proceed?")]),
                                    detail_text=''.join([
                                             _("All of your traffic to the blockchain servers will be sent unencrypted."), ' ',
                                             _("Additionally, you may also be vulnerable to man-in-the-middle attacks."), ' ',
                                             _("It is strongly recommended that you go back and enable SSL mode."),
                                             ]),
                                    rich_text=False,
                                    title=_('Security Warning'),
                                    icon=QMessageBox.Critical,
                                    checkbox_text=("Don't ask me again"))
            if chk: self.nlayout.config.set_key('non_ssl_noprompt', True)
            if not ok:
                e.ignore()
                return
        super().closeEvent(e)

    def hideEvent(self, e):
        super().hideEvent(e)
        if not self.isVisible():
            self.workaround_timer.stop()
            self.refresh_timer.stop()

    def showEvent(self, e):
        super().showEvent(e)
        if e.isAccepted():
            # Single-shot. Works around Linux/Qt bugs
            # -- see _workaround_update below for description.
            self.workaround_timer.start(500)
            self.refresh_timer.start()

    def _workaround_update(self):
        # Hack to work around strange behavior on some Linux:
        # On some Linux systems (Debian based), the dialog sometimes is empty
        # and glitchy if we don't do this. Note this .update() call is a Qt
        # C++ QWidget::update() call and has nothing to do with our own
        # same-named `update` methods.
        QDialog.update(self)



class NodesListWidget(QTreeWidget):

    def __init__(self, parent):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels([_('Connected node'), '', _('Height')])
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
            item, col = self.currentItem(), self.currentColumn()
            if item and col > -1:
                self.on_activated(item, col)
        else:
            super().keyPressEvent(event)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def update(self, network, servers):
        item = self.currentItem()
        sel = None
        if item:
            sel = item.data(1, Qt.UserRole)
        self.clear()
        self.addChild = self.addTopLevelItem
        chains = network.get_blockchains()
        n_chains = len(chains)
        restore_sel = None
        for k, items in chains.items():
            b = network.blockchains[k]
            name = b.get_name()
            if n_chains > 1:
                x = QTreeWidgetItem([name + '@%d'%b.get_base_height(), '', '%d'%b.height()])
                x.setData(0, Qt.UserRole, 1)
                x.setData(1, Qt.UserRole, b.base_height)
            else:
                x = self.invisibleRootItem()
            for i in items:
                star = ' ◀' if i == network.interface else ''

                display_text = i.host
                is_onion = i.host.lower().endswith('.onion')
                if is_onion and i.host in servers and 'display' in servers[i.host]:
                    display_text = servers[i.host]['display'] + ' (.onion)'

                item = QTreeWidgetItem([display_text + star, '', '%d'%i.tip])
                item.setData(0, Qt.UserRole, 0)
                item.setData(1, Qt.UserRole, i.server)
                if i.server == sel:
                    restore_sel = item
                if is_onion:
                    item.setIcon(1, QIcon(":icons/tor_logo.svg"))
                x.addChild(item)
            if n_chains > 1:
                self.addTopLevelItem(x)
                x.setExpanded(True)

        # restore selection, if there was any
        if restore_sel:
            val = self.hasAutoScroll()
            self.setAutoScroll(False)  # prevent automatic scrolling when we do this which may annoy user / appear glitchy
            self.setCurrentItem(restore_sel)
            self.setAutoScroll(val)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)


class ServerFlag:
    ''' Used by ServerListWidget for Server flags & Symbols '''
    BadCertificate = 4 # Servers with a bad certificate.
    Banned = 2 # Blacklisting/banning was a hidden mechanism inherited from Electrum. We would blacklist misbehaving servers under the hood. Now that facility is exposed (editable by the user). We never connect to blacklisted servers.
    Preferred = 1 # Preferred servers (white-listed) start off as the servers in servers.json and are "more trusted" and optionally the user can elect to connect to only these servers
    NoFlag = 0
    Symbol = {
        NoFlag: "",
        Preferred: "⭐",
        Banned: "⛔",
        BadCertificate: "❗️"
    }
    UnSymbol = { # used for "disable X" context menu
        NoFlag: "",
        Preferred: "❌",
        Banned: "✅",
        BadCertificate: ""
    }

class ServerListWidget(QTreeWidget):

    def __init__(self, parent):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels(['', _('Host'), '', _('Port')])
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
        if flagval & ServerFlag.BadCertificate:
            optxt = ServerFlag.UnSymbol[ServerFlag.BadCertificate] + " " + _("Remove pinned certificate")
            menu.addAction(optxt, partial(self.on_remove_pinned_certificate, server))
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_remove_pinned_certificate(self, server):
        if not self.parent.remove_pinned_certificate(server):
            QMessageBox.critical(None, _("Remove pinned certificate"),
                                 _("Failed to remove the pinned certificate. Check the log for errors."))

    def set_server(self, s):
        host, port, protocol = deserialize_server(s)
        self.parent.server_host.setText(host)
        self.parent.server_port.setText(port)
        self.parent.autoconnect_cb.setChecked(False) # force auto-connect off if they did "Use as server"
        self.parent.set_server()
        self.parent.update()

    def keyPressEvent(self, event):
        if event.key() in [ Qt.Key_F2, Qt.Key_Return ]:
            item, col = self.currentItem(), self.currentColumn()
            if item and col > -1:
                self.on_activated(item, col)
        else:
            super().keyPressEvent(event)

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
        sel_item = self.currentItem()
        sel = sel_item.data(2, Qt.UserRole) if sel_item else None
        restore_sel = None
        self.clear()
        self.setIndentation(0)
        wl_only = network.is_whitelist_only()
        for _host, d in sorted(servers.items()):
            is_onion = _host.lower().endswith('.onion')
            if is_onion and not use_tor:
                continue
            port = d.get(protocol)
            if port:
                server = serialize_server(_host, port, protocol)

                flag = ""
                flagval = 0
                tt = ""

                if network.server_is_blacklisted(server):
                    flagval |= ServerFlag.Banned
                if network.server_is_whitelisted(server):
                    flagval |= ServerFlag.Preferred
                if network.server_is_bad_certificate(server):
                    flagval |= ServerFlag.BadCertificate

                if flagval & ServerFlag.Banned:
                    flag = ServerFlag.Symbol[ServerFlag.Banned]
                    tt = _("This server is banned")
                elif flagval & ServerFlag.BadCertificate:
                    flag = ServerFlag.Symbol[ServerFlag.BadCertificate]
                    tt = _("This server's pinned certificate mismatches its current certificate")
                elif flagval & ServerFlag.Preferred:
                    flag = ServerFlag.Symbol[ServerFlag.Preferred]
                    tt = _("This is a preferred server")

                display_text = _host
                if is_onion and 'display' in d:
                    display_text = d['display'] + ' (.onion)'

                x = QTreeWidgetItem([flag, display_text, '', port])
                if is_onion:
                    x.setIcon(2, QIcon(":icons/tor_logo.svg"))
                if tt: x.setToolTip(0, tt)
                if (wl_only and not flagval & ServerFlag.Preferred) or flagval & ServerFlag.Banned:
                    # lighten the text of servers we can't/won't connect to for the given mode
                    self.lightenItemText(x, range(1,4))
                x.setData(2, Qt.UserRole, server)
                x.setData(0, Qt.UserRole, flagval)
                x.setTextAlignment(0, Qt.AlignHCenter)
                self.addTopLevelItem(x)
                if server == sel:
                    restore_sel = x

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        # restore selection
        if restore_sel:
            val = self.hasAutoScroll()
            self.setAutoScroll(False)  # prevent automatic scrolling when we do this which may annoy user / appear glitchy
            self.setCurrentItem(restore_sel)
            self.setAutoScroll(val)


class NetworkChoiceLayout(QObject, PrintError):

    def __init__(self, parent, network, config, wizard=False):
        super().__init__(parent)
        self.network = network
        self.config = config
        self.protocol = None
        self.tor_proxy = None

        # tor detector
        self.td = TorDetector(self, self.network)
        self.td.found_proxy.connect(self.suggest_proxy)

        self.tabs = tabs = QTabWidget()
        self.server_tab = server_tab = QWidget()
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
        self.proxy_tab = proxy_tab = ProxyTab()
        self.blockchain_tab = blockchain_tab = QWidget()
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
        self.ssl_cb = QCheckBox(_('Use SSL'))
        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setEnabled(self.config.is_modifiable('auto_connect'))

        weakSelf = Weak.ref(self)  # Qt/Python GC hygeine: avoid strong references to self in lambda slots.
        self.server_host.editingFinished.connect(lambda: weakSelf() and weakSelf().set_server(onion_hack=True))
        self.server_port.editingFinished.connect(lambda: weakSelf() and weakSelf().set_server(onion_hack=True))
        self.ssl_cb.clicked.connect(self.change_protocol)
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


        grid.addWidget(self.ssl_cb, 2, 0, 1, 3)
        self.ssl_help = HelpButton(_('SSL is used to authenticate and encrypt your connections with the blockchain servers.') + "\n\n"
                                   + _('Due to potential security risks, you may only disable SSL when using a Tor Proxy.'))
        grid.addWidget(self.ssl_help, 2, 4)

        grid.addWidget(QLabel(_('Server') + ':'), 3, 0)
        grid.addWidget(self.server_host, 3, 1, 1, 2)
        grid.addWidget(self.server_port, 3, 3)

        self.server_list_label = label = QLabel('') # will get set by self.update()
        grid.addWidget(label, 4, 0, 1, 5)
        self.servers_list = ServerListWidget(self)
        grid.addWidget(self.servers_list, 5, 0, 1, 5)
        self.legend_label = label = WWLabel('') # will get populated with the legend by self.update()
        label.setTextInteractionFlags(label.textInteractionFlags() & (~Qt.TextSelectableByMouse))  # disable text selection by mouse here
        self.legend_label.linkActivated.connect(self.on_view_blacklist)
        grid.addWidget(label, 6, 0, 1, 4)
        msg = ' '.join([
            _("Preferred servers ({}) are servers you have designated as reliable and/or trustworthy.").format(ServerFlag.Symbol[ServerFlag.Preferred]),
            _("Initially, the preferred list is the hard-coded list of known-good servers vetted by the Electron Cash developers."),
            _("You can add or remove any server from this list and optionally elect to only connect to preferred servers."),
            "\n\n"+_("Banned servers ({}) are servers deemed unreliable and/or untrustworthy, and so they will never be connected-to by Electron Cash.").format(ServerFlag.Symbol[ServerFlag.Banned])
        ])
        grid.addWidget(HelpButton(msg), 6, 4)

        # Proxy tab
        grid = QGridLayout(proxy_tab)
        grid.setSpacing(8)

        # proxy setting
        self.proxy_cb = QCheckBox(_('Use proxy'))
        self.proxy_cb.setToolTip(_("If enabled, all connections application-wide will be routed through this proxy."))
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

        self.tor_cb = QCheckBox(_("Use Tor Proxy"))
        self.tor_cb.setIcon(QIcon(":icons/tor_logo.svg"))
        self.tor_cb.setEnabled(False)
        self.tor_cb.clicked.connect(self.use_tor_proxy)
        tor_proxy_tooltip = _("If enabled, all connections application-wide will be routed through Tor.")
        tor_proxy_help = (
            tor_proxy_tooltip + "\n\n" +
            _("Depending on your configuration and preferences as a user, this may or may not be ideal.  "
              "In general, connections routed through Tor hide your IP address from servers, at the expense of "
              "performance and network throughput.") + "\n\n" +
            _("For the average user, it's recommended that you leave this option "
              "disabled and only leave the 'Start Tor client' option enabled.") )
        self.tor_cb.setToolTip(tor_proxy_tooltip)

        self.tor_enabled = QCheckBox()
        self.tor_enabled.setIcon(QIcon(":icons/tor_logo.svg"))
        self.tor_enabled.clicked.connect(self.set_tor_enabled)
        self.tor_enabled.setChecked(self.network.tor_controller.is_enabled())
        self.tor_enabled_help = HelpButton('')

        self.tor_custom_port_cb = QCheckBox(_("Custom port"))
        self.tor_enabled.clicked.connect(self.tor_custom_port_cb.setEnabled)
        self.tor_custom_port_cb.setChecked(bool(self.network.tor_controller.get_socks_port()))
        self.tor_custom_port_cb.clicked.connect(self.on_custom_port_cb_click)
        custom_port_tooltip = _("Leave unspecified to automatically allocate a port.")
        self.tor_custom_port_cb.setToolTip(custom_port_tooltip)
        self.network.tor_controller.status_changed.append_weak(self.on_tor_status_changed)

        self.tor_socks_port = QLineEdit()
        self.tor_socks_port.setFixedWidth(60)
        self.tor_socks_port.editingFinished.connect(self.set_tor_socks_port)
        self.tor_socks_port.setText(str(self.network.tor_controller.get_socks_port()))
        self.tor_socks_port.setToolTip(custom_port_tooltip)
        self.tor_socks_port.setValidator(UserPortValidator(self.tor_socks_port, accept_zero=True))

        self.update_tor_enabled()

        # Start Tor
        grid.addWidget(self.tor_enabled, 1, 0, 1, 2)
        grid.addWidget(self.tor_enabled_help, 1, 4)
        # Custom Tor port
        hbox = QHBoxLayout()
        hbox.addSpacing(20)  # indentation
        hbox.addWidget(self.tor_custom_port_cb, 0, Qt.AlignLeft|Qt.AlignVCenter)
        hbox.addWidget(self.tor_socks_port, 0, Qt.AlignLeft|Qt.AlignVCenter)
        hbox.addStretch(2)
        hbox.setContentsMargins(0,0,0,6)  # a bit of a "paragraph break" here
        grid.addLayout(hbox, 2, 0, 1, 3)
        grid.addWidget(HelpButton(custom_port_tooltip), 2, 4)
        # Use Tor Proxy
        grid.addWidget(self.tor_cb, 3, 0, 1, 3)
        grid.addWidget(HelpButton(tor_proxy_help), 3, 4)
        # Proxy settings
        grid.addWidget(self.proxy_cb, 4, 0, 1, 3)
        grid.addWidget(HelpButton(_('Proxy settings apply to all connections: with Electron Cash servers, but also with third-party services.')), 4, 4)
        grid.addWidget(self.proxy_mode, 6, 1)
        grid.addWidget(self.proxy_host, 6, 2)
        grid.addWidget(self.proxy_port, 6, 3)
        grid.addWidget(self.proxy_user, 7, 2)
        grid.addWidget(self.proxy_password, 7, 3)
        grid.setRowStretch(8, 1)

        # Blockchain Tab
        grid = QGridLayout(blockchain_tab)
        msg = ' '.join([
            _("Electron Cash connects to several nodes in order to download block headers and find out the longest blockchain."),
            _("This blockchain is used to verify the transactions sent by your transaction server.")
        ])
        row = 0
        self.status_label = QLabel('')
        self.status_label.setTextInteractionFlags(self.status_label.textInteractionFlags() | Qt.TextSelectableByMouse)
        grid.addWidget(QLabel(_('Status') + ':'), row, 0)
        grid.addWidget(self.status_label, row, 1, 1, 3)
        grid.addWidget(HelpButton(msg), row, 4)
        row += 1

        self.server_label = QLabel('')
        self.server_label.setTextInteractionFlags(self.server_label.textInteractionFlags() | Qt.TextSelectableByMouse)
        msg = _("Electron Cash sends your wallet addresses to a single server, in order to receive your transaction history.")
        grid.addWidget(QLabel(_('Server') + ':'), row, 0)
        grid.addWidget(self.server_label, row, 1, 1, 3)
        grid.addWidget(HelpButton(msg), row, 4)
        row += 1

        self.height_label = QLabel('')
        self.height_label.setTextInteractionFlags(self.height_label.textInteractionFlags() | Qt.TextSelectableByMouse)
        msg = _('This is the height of your local copy of the blockchain.')
        grid.addWidget(QLabel(_('Blockchain') + ':'), row, 0)
        grid.addWidget(self.height_label, row, 1)
        grid.addWidget(HelpButton(msg), row, 4)
        row += 1

        self.reqs_label = QLabel('')
        self.reqs_label.setTextInteractionFlags(self.height_label.textInteractionFlags() | Qt.TextSelectableByMouse)
        msg = _('The number of unanswered network requests.\n\n'
                "You can configure:\n\n"
                "    - Limit: maximum request backlog size\n"
                "    - ChunkSize: requests to enqueue every 100ms\n\n"
                "If the connection drops when synchronizing, you may wish "
                "to reduce these values to throttle requests to the server.")
        grid.addWidget(QLabel(_('Pending requests') + ':'), row, 0)
        hbox = QHBoxLayout()
        hbox.addWidget(self.reqs_label)
        hbox.setContentsMargins(0, 0, 12, 0)
        hbox.addWidget(QLabel(_("Limit:")))
        self.req_max_sb = sb = QSpinBox()
        sb.setRange(1, 2000)
        sb.setFocusPolicy(Qt.TabFocus|Qt.ClickFocus|Qt.WheelFocus)
        hbox.addWidget(sb)
        hbox.addWidget(QLabel(_("ChunkSize:")))
        self.req_chunk_sb = sb = QSpinBox()
        sb.setRange(1, 100)
        sb.setFocusPolicy(Qt.TabFocus|Qt.ClickFocus|Qt.WheelFocus)
        hbox.addWidget(sb)
        but = QPushButton(_("Reset"))
        f = but.font()
        f.setPointSize(f.pointSize()-2)
        but.setFont(f)
        but.setDefault(False); but.setAutoDefault(False)
        hbox.addWidget(but)
        grid.addLayout(hbox, row, 1, 1, 3)
        grid.setAlignment(hbox, Qt.AlignLeft|Qt.AlignVCenter)
        grid.setColumnStretch(3, 1)
        grid.addWidget(HelpButton(msg), row, 4)
        row += 1
        def req_max_changed(val):
            Interface.set_req_throttle_params(self.config, max=val)
        def req_chunk_changed(val):
            Interface.set_req_throttle_params(self.config, chunkSize=val)
        def req_defaults():
            p = Interface.req_throttle_default
            Interface.set_req_throttle_params(self.config, max=p.max, chunkSize=p.chunkSize)
            self.update()
        but.clicked.connect(req_defaults)
        self.req_max_sb.valueChanged.connect(req_max_changed)
        self.req_chunk_sb.valueChanged.connect(req_chunk_changed)

        self.split_label = QLabel('')
        self.split_label.setTextInteractionFlags(self.split_label.textInteractionFlags() | Qt.TextSelectableByMouse)
        grid.addWidget(self.split_label, row, 0, 1, 3)
        row += 2

        self.nodes_list_widget = NodesListWidget(self)
        grid.addWidget(self.nodes_list_widget, row, 0, 1, 5)
        row += 1

        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        self.layout_ = vbox

        self.network.tor_controller.active_port_changed.append_weak(self.on_tor_port_changed)

        self.network.server_list_updated.append_weak(self.on_server_list_updated)

        self.fill_in_proxy_settings()
        self.update()

    _tor_client_names = {
        TorController.BinaryType.MISSING: _('Tor'),
        TorController.BinaryType.SYSTEM: _('system Tor'),
        TorController.BinaryType.INTEGRATED: _('integrated Tor')
    }

    def update_tor_enabled(self, *args):
        tbt = self.network.tor_controller.tor_binary_type
        tbname = self._tor_client_names[tbt]

        self.tor_enabled.setText(_("Start {tor_binary_name} client").format(
            tor_binary_name=tbname,
            tor_binary_name_capitalized=tbname[:1].upper() + tbname[1:]
        ))
        avalable = tbt != TorController.BinaryType.MISSING
        self.tor_enabled.setEnabled(avalable)
        self.tor_custom_port_cb.setEnabled(avalable and self.tor_enabled.isChecked())
        self.tor_socks_port.setEnabled(avalable and self.tor_custom_port_cb.isChecked())

        tor_enabled_tooltip = [_("This will start a private instance of the Tor proxy controlled by Electron Cash.")]
        if not avalable:
            tor_enabled_tooltip.insert(0, _("This feature is unavailable because no Tor binary was found."))
        tor_enabled_tooltip_text = ' '.join(tor_enabled_tooltip)
        self.tor_enabled.setToolTip(tor_enabled_tooltip_text)
        self.tor_enabled_help.help_text = (
            tor_enabled_tooltip_text + "\n\n"
            + _("If unsure, it's safe to enable this feature, and leave 'Use Tor Proxy' disabled.  "
                "In that situation, only certain plugins (such as CashFusion) will use Tor, but your "
                "regular SPV server connections will remain unaffected.") )

    def jumpto(self, location : str):
        if not isinstance(location, str):
            return
        location = location.strip().lower()
        if location in ('proxy', 'tor'):
            self.tabs.setCurrentWidget(self.proxy_tab)
        elif location in ('servers', 'server'):
            self.tabs.setCurrentWidget(self.server_tab)
        elif location in ('blockchain', 'overview', 'main'):
            self.tabs.setCurrentWidget(self.blockchain_tab)
        elif not run_hook('on_network_dialog_jumpto', self, location):
            self.print_error(f"jumpto: unknown location '{location}'")

    @in_main_thread
    def on_tor_port_changed(self, controller: TorController):
        if not controller.active_socks_port or not controller.is_enabled() or not self.tor_use:
            return

        # The Network class handles actually changing the port, we just
        # set the value in the text box here.
        self.proxy_port.setText(str(controller.active_socks_port))

    @in_main_thread
    def on_server_list_updated(self):
        self.update()

    def check_disable_proxy(self, b):
        if not self.config.is_modifiable('proxy'):
            b = False
        if self.tor_use:
            # Disallow changing the proxy settings when Tor is in use
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
        if not self.server_host.hasFocus() and not self.server_port.hasFocus():
            self.server_host.setText(host)
            self.server_port.setText(port)
        self.ssl_cb.setChecked(protocol=='s')
        ssl_disable = self.ssl_cb.isChecked() and not self.tor_cb.isChecked() and not host.lower().endswith('.onion')
        for w in [self.ssl_cb]:#, self.ssl_help]:
            w.setDisabled(ssl_disable)
        self.autoconnect_cb.setChecked(auto_connect)
        self.preferred_only_cb.setChecked(preferred_only)

        self.servers = self.network.get_servers()

        host = self.network.interface.host if self.network.interface else pgettext('Referencing server', 'None')
        is_onion = host.lower().endswith('.onion')
        if is_onion and host in self.servers and 'display' in self.servers[host]:
            host = self.servers[host]['display'] + ' (.onion)'
        self.server_label.setText(host)

        self.set_protocol(protocol)
        def protocol_suffix():
            if protocol == 't':
                return '  (non-SSL)'
            elif protocol == 's':
                return '  [SSL]'
            return ''
        server_list_txt = (_('Server peers') if self.network.is_connected() else _('Servers')) + " ({})".format(len(self.servers))
        server_list_txt += protocol_suffix()
        self.server_list_label.setText(server_list_txt)
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
        if n: status += protocol_suffix()
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

        self.reqs_label.setText(str((self.network.interface and len(self.network.interface.unanswered_requests)) or 0))
        params = Interface.get_req_throttle_params(self.config)
        self.req_max_sb.setValue(params.max)
        self.req_chunk_sb.setValue(params.chunkSize)

        self.nodes_list_widget.update(self.network, self.servers)

    def fill_in_proxy_settings(self):
        host, port, protocol, proxy_config, auto_connect = self.network.get_parameters()
        if not proxy_config:
            proxy_config = {"mode": "none", "host": "localhost", "port": "9050"}

        # We need to restore the "Use tor" checkbox as its value is needed in the server
        # list, to determine whether to show .onion servers, before the TorDetector
        # has been started.
        self._set_tor_use(self.config.get('tor_use', False))

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
        self.ssl_cb.setChecked(protocol=='s')

    def accept(self):
        pass

    def set_server(self, onion_hack=False):
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        host = str(self.server_host.text())
        port = str(self.server_port.text())
        protocol = 's' if self.ssl_cb.isChecked() else 't'
        if onion_hack:
            # Fix #1174 -- bring back from the dead non-SSL support for .onion only in a safe way
            if host.lower().endswith('.onion'):
                self.print_error("Onion/TCP hack: detected .onion, forcing TCP (non-SSL) mode")
                protocol = 't'
                self.ssl_cb.setChecked(False)
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
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)

    def suggest_proxy(self, found_proxy):
        if not found_proxy:
            self.tor_cb.setEnabled(False)
            self._set_tor_use(False) # It's not clear to me that if the tor service goes away and comes back later, and in the meantime they unchecked proxy_cb, that this should remain checked. I can see it being confusing for that to be the case. Better to uncheck. It gets auto-re-checked anyway if it comes back and it's the same due to code below. -Calin
            return
        self.tor_proxy = found_proxy
        self.tor_cb.setText(_("Use Tor proxy at port {tor_port}").format(tor_port = found_proxy[1]))
        same_proxy = (self.proxy_mode.currentIndex() == self.proxy_mode.findText('SOCKS5')
            and self.proxy_host.text() == found_proxy[0]
            and self.proxy_port.text() == str(found_proxy[1])
            and self.proxy_cb.isChecked())
        self._set_tor_use(same_proxy)
        self.tor_cb.setEnabled(True)

    def _set_tor_use(self, use_it):
        self.tor_use = use_it
        self.config.set_key('tor_use', self.tor_use)
        self.tor_cb.setChecked(self.tor_use)
        self.proxy_cb.setEnabled(not self.tor_use)
        self.check_disable_proxy(not self.tor_use)

    def use_tor_proxy(self, use_it):
        self._set_tor_use(use_it)

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
            self.proxy_cb.setChecked(True)
        self.set_proxy()

    def set_tor_enabled(self, enabled: bool):
        self.network.tor_controller.set_enabled(enabled)

    @in_main_thread
    def on_tor_status_changed(self, controller):
        if controller.status == TorController.Status.ERRORED and self.tabs.isVisible():
            tbname = self._tor_client_names[self.network.tor_controller.tor_binary_type]
            msg = _("The {tor_binary_name} client experienced an error or could not be started.").format(tor_binary_name=tbname)
            QMessageBox.critical(None, _("Tor Client Error"), msg)

    def set_tor_socks_port(self):
        socks_port = int(self.tor_socks_port.text())
        self.network.tor_controller.set_socks_port(socks_port)

    def on_custom_port_cb_click(self, b):
        self.tor_socks_port.setEnabled(b)
        if not b:
            self.tor_socks_port.setText("0")
            self.set_tor_socks_port()

    def proxy_settings_changed(self):
        self.tor_cb.setChecked(False)

    def remove_pinned_certificate(self, server):
        return self.network.remove_pinned_certificate(server)

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

    def __init__(self, parent, network):
        super().__init__(parent)
        self.network = network
        self.network.tor_controller.active_port_changed.append_weak(self.on_tor_port_changed)

    def on_tor_port_changed(self, controller: TorController):
        if controller.active_socks_port and self.isRunning():
            self.stopQ.put('kick')

    def start(self):
        self.stopQ = queue.Queue() # create a new stopQ blowing away the old one just in case it has old data in it (this prevents races with stop/start arriving too quickly for the thread)
        super().start()

    def stop(self):
        if self.isRunning():
            self.stopQ.put(None)
            self.wait()

    def run(self):
        while True:
            ports = [9050, 9150] # Probable ports for Tor to listen at

            if self.network.tor_controller and self.network.tor_controller.is_enabled() and self.network.tor_controller.active_socks_port:
                ports.insert(0, self.network.tor_controller.active_socks_port)

            for p in ports:
                if TorDetector.is_tor_port(p):
                    self.found_proxy.emit(("127.0.0.1", p))
                    break
            else:
                self.found_proxy.emit(None) # no proxy found, will hide the Tor checkbox
            try:
                stopq = self.stopQ.get(timeout=10.0) # keep trying every 10 seconds
                if stopq is None:
                    return # we must have gotten a stop signal if we get here, break out of function, ending thread
                # We were kicked, which means the tor port changed.
                # Run the detection after a slight delay which increases the reliability.
                QThread.msleep(250)
                continue
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
