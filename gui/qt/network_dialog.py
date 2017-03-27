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

from electrum_ltc.i18n import _
from electrum_ltc.network import DEFAULT_PORTS
from electrum_ltc.network import serialize_server, deserialize_server

from util import *

protocol_names = ['TCP', 'SSL']
protocol_letters = 'ts'

class NetworkDialog(WindowModalDialog):
    def __init__(self, network, config, parent):
        WindowModalDialog.__init__(self, parent, _('Network'))
        self.setMinimumSize(400, 20)
        self.nlayout = NetworkChoiceLayout(network, config)
        vbox = QVBoxLayout(self)
        vbox.addLayout(self.nlayout.layout())
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self)))

    def do_exec(self):
        result = self.exec_()
        if result:
            self.nlayout.accept()
        return result


class NetworkChoiceLayout(object):
    def __init__(self, network, config, wizard=False):
        self.network = network
        self.config = config
        self.protocol = None
        self.tor_proxy = None

        self.servers = network.get_servers()
        host, port, protocol, proxy_config, auto_connect = network.get_parameters()
        if not proxy_config:
            proxy_config = { "mode":"none", "host":"localhost", "port":"9050"}

        if not wizard:
            if network.is_connected():
                status = _("Server") + ": %s"%(host)
            else:
                status = _("Disconnected from server")
        else:
            status = _("Please choose a server.") + "\n" + _("Press 'Next' if you are offline.")

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

        # server
        self.server_host = QLineEdit()
        self.server_host.setFixedWidth(200)
        self.server_port = QLineEdit()
        self.server_port.setFixedWidth(60)

        # use SSL
        self.ssl_cb = QCheckBox(_('Use SSL'))
        self.ssl_cb.setChecked(auto_connect)
        self.ssl_cb.stateChanged.connect(self.change_protocol)

        # auto connect
        self.autoconnect_cb = QCheckBox(_('Select server automatically'))
        self.autoconnect_cb.setChecked(auto_connect)
        self.autoconnect_cb.setEnabled(self.config.is_modifiable('auto_connect'))

        msg = _("Electrum sends your wallet addresses to a single server, in order to receive your transaction history.")
        grid.addWidget(QLabel(_('Server') + ':'), 0, 0)
        grid.addWidget(self.server_host, 0, 1, 1, 2)
        grid.addWidget(self.server_port, 0, 3)
        grid.addWidget(HelpButton(msg), 0, 4)
        msg = ' '.join([
            _("If auto-connect is enabled, Electrum will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electrum will warn you if your server is lagging.")
        ])
        grid.addWidget(self.ssl_cb, 1, 1, 1, 3)
        grid.addWidget(self.autoconnect_cb, 2, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 2, 4)
        label = _('Active Servers') if network.is_connected() else _('Default Servers')
        self.servers_list_widget = QTreeWidget()
        self.servers_list_widget.setHeaderLabels( [ label, _('Limit') ] )
        self.servers_list_widget.setMaximumHeight(150)
        self.servers_list_widget.setColumnWidth(0, 240)
        grid.addWidget(self.servers_list_widget, 3, 0, 1, 5)

        def enable_set_server():
            if config.is_modifiable('server'):
                enabled = not self.autoconnect_cb.isChecked()
                self.server_host.setEnabled(enabled)
                self.server_port.setEnabled(enabled)
                self.servers_list_widget.setEnabled(enabled)
            else:
                for w in [self.autoconnect_cb, self.server_host, self.server_port, self.ssl_cb, self.servers_list_widget]:
                    w.setEnabled(False)

        self.autoconnect_cb.clicked.connect(enable_set_server)
        enable_set_server()

        # Proxy tab
        grid = QGridLayout(proxy_tab)
        grid.setSpacing(8)

        # proxy setting
        self.proxy_mode = QComboBox()
        self.proxy_host = QLineEdit()
        self.proxy_host.setFixedWidth(200)
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(60)
        self.proxy_mode.addItems(['NONE', 'SOCKS4', 'SOCKS5', 'HTTP'])
        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText(_("Proxy user"))
        self.proxy_password = QLineEdit()
        self.proxy_password.setPlaceholderText(_("Password"))
        self.proxy_password.setEchoMode(QLineEdit.Password)
        self.proxy_password.setFixedWidth(60)

        def check_for_disable(index = False):
            if self.config.is_modifiable('proxy'):
                for w in [self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password]:
                    w.setEnabled(self.proxy_mode.currentText() != 'NONE')
            else:
                for w in [self.proxy_host, self.proxy_port, self.proxy_mode]: w.setEnabled(False)

        check_for_disable()
        self.proxy_mode.connect(self.proxy_mode, SIGNAL('currentIndexChanged(int)'), check_for_disable)

        self.proxy_mode.setCurrentIndex(self.proxy_mode.findText(str(proxy_config.get("mode").upper())))
        self.proxy_host.setText(proxy_config.get("host"))
        self.proxy_port.setText(proxy_config.get("port"))
        self.proxy_user.setText(proxy_config.get("user", ""))
        self.proxy_password.setText(proxy_config.get("password", ""))

        self.proxy_mode.connect(self.proxy_mode, SIGNAL('currentIndexChanged(int)'), self.proxy_settings_changed)
        self.proxy_host.connect(self.proxy_host, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)
        self.proxy_port.connect(self.proxy_port, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)
        self.proxy_user.connect(self.proxy_user, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)
        self.proxy_password.connect(self.proxy_password, SIGNAL('textEdited(QString)'), self.proxy_settings_changed)

        self.tor_cb = QCheckBox(_("Use Tor Proxy"))
        self.tor_cb.setIcon(QIcon(":icons/tor_logo.png"))
        self.tor_cb.hide()
        self.tor_cb.clicked.connect(self.use_tor_proxy)

        grid.addWidget(self.tor_cb, 1, 0, 1, 3)
        grid.addWidget(self.proxy_mode, 4, 1)
        grid.addWidget(self.proxy_host, 4, 2)
        grid.addWidget(self.proxy_port, 4, 3)
        grid.addWidget(self.proxy_user, 5, 2)
        grid.addWidget(self.proxy_password, 5, 3)
        grid.setRowStretch(6, 1)

        # Blockchain Tab
        from electrum_ltc import bitcoin
        from amountedit import AmountEdit
        grid = QGridLayout(blockchain_tab)
        n = len(network.get_interfaces())
        status = _("Connected to %d nodes.")%n if n else _("Not connected")
        height_str = "%d "%(network.get_local_height()) + _("blocks")
        self.checkpoint_height, self.checkpoint_value = network.blockchain.get_checkpoint()
        self.cph_label = QLabel(_('Height'))
        self.cph = QLineEdit("%d"%self.checkpoint_height)
        self.cph.setFixedWidth(80)
        self.cpv_label = QLabel(_('Hash'))
        self.cpv = QLineEdit(self.checkpoint_value)
        self.cpv.setCursorPosition(0)
        self.cpv.setFocusPolicy(Qt.NoFocus)
        self.cpv.setReadOnly(True)
        def on_cph():
            try:
                height = int(self.cph.text())
            except:
                height = 0
            self.cph.setText('%d'%height)
            if height == self.checkpoint_height:
                return
            try:
                self.network.print_error("fetching header")
                header = self.network.synchronous_get(('blockchain.block.get_header', [height]), 5)
                _hash = self.network.blockchain.hash_header(header)
            except BaseException as e:
                self.network.print_error(str(e))
                _hash = ''
            self.cpv.setText(_hash)
            self.cpv.setCursorPosition(0)
            if _hash:
                self.checkpoint_height = height
                self.checkpoint_value = _hash
        self.cph.editingFinished.connect(on_cph)

        msg =  ' '.join([
            _("Electrum connects to several nodes in order to download block headers and find out the longest blockchain."),
            _("This blockchain is used to verify the transactions sent by your transaction server.")
        ])
        grid.addWidget(QLabel(_('Status') + ':'), 0, 0)
        grid.addWidget(QLabel(status), 0, 1, 1, 3)
        grid.addWidget(HelpButton(msg), 0, 4)
        msg = _('This is the height of your local copy of the blockchain.')
        grid.addWidget(QLabel(_("Height") + ':'), 1, 0)
        grid.addWidget(QLabel(height_str), 1, 1)
        grid.addWidget(HelpButton(msg), 1, 4)
        msg = ''.join([
            _('A checkpoint can be used to verify that you are on the correct blockchain.'), ' ',
            _('By default, your checkpoint is the genesis block.'), '\n\n',
            _('If you edit the height field, the corresponding block hash will be fetched from your current server.'), ' ',
            _('If you press OK, the checkpoint will be saved, and Electrum will only accept headers from nodes that pass this checkpoint.'), '\n\n',
            _('If there is a hard fork, you will have to check the block hash from an independent source, in order to be sure that you are on the desired side of the fork.'),
        ])
        grid.addWidget(QLabel(_('Checkpoint') +':'), 3, 0, 1, 2)
        grid.addWidget(HelpButton(msg), 3, 4)
        grid.addWidget(self.cph_label, 4, 0)
        grid.addWidget(self.cph, 4, 1)
        grid.addWidget(self.cpv_label, 5, 0)
        grid.addWidget(self.cpv, 5, 1, 1, 4)
        grid.setRowStretch(7, 1)
        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        self.layout_ = vbox
        # tor detector
        self.td = td = TorDetector()
        td.found_proxy.connect(self.suggest_proxy)
        td.start()
        self.change_server(host, protocol)
        self.set_protocol(protocol)
        self.servers_list_widget.connect(
            self.servers_list_widget,
            SIGNAL('currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)'),
            lambda x,y: self.server_changed(x))

    def layout(self):
        return self.layout_

    def init_servers_list(self):
        self.servers_list_widget.clear()
        for _host, d in sorted(self.servers.items()):
            if d.get(self.protocol):
                pruning_level = d.get('pruning','')
                self.servers_list_widget.addTopLevelItem(QTreeWidgetItem( [ _host, pruning_level ] ))

    def set_protocol(self, protocol):
        if protocol != self.protocol:
            self.protocol = protocol
            self.init_servers_list()

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

    def accept(self):
        host = str(self.server_host.text())
        port = str(self.server_port.text())
        protocol = 's' if self.ssl_cb.isChecked() else 't'
        if self.proxy_mode.currentText() != 'NONE':
            proxy = { 'mode':str(self.proxy_mode.currentText()).lower(),
                      'host':str(self.proxy_host.text()),
                      'port':str(self.proxy_port.text()),
                      'user':str(self.proxy_user.text()),
                      'password':str(self.proxy_password.text())}
        else:
            proxy = None
        auto_connect = self.autoconnect_cb.isChecked()
        self.network.set_parameters(host, port, protocol, proxy, auto_connect)
        self.network.blockchain.set_checkpoint(self.checkpoint_height, self.checkpoint_value)

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
