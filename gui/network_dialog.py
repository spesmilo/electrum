#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys, time, datetime, re, threading
from i18n import _
from electrum.util import print_error, print_msg
import os.path, json, ast, traceback

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from electrum.interface import DEFAULT_SERVERS, DEFAULT_PORTS

from qt_util import *

protocol_names = ['TCP', 'HTTP', 'SSL', 'HTTPS']
protocol_letters = 'thsg'

class NetworkDialog(QDialog):
    def __init__(self, interface, config, parent):

        QDialog.__init__(self,parent)
        self.setModal(1)
        self.setWindowTitle(_('Server'))
        self.setMinimumSize(375, 20)

        self.interface = interface
        self.config = config
        self.protocol = None

        if parent:
            if interface.is_connected:
                status = _("Connected to")+" %s"%(interface.host) + "\n%d "%(parent.wallet.verifier.height)+_("blocks")
            else:
                status = _("Not connected")
            server = interface.server
        else:
            import random
            status = _("Please choose a server.") + "\n" + _("Select 'Cancel' if you are offline.")
            server = interface.server

        self.servers = interface.get_servers()

        vbox = QVBoxLayout()
        vbox.setSpacing(30)

        hbox = QHBoxLayout()
        l = QLabel()
        l.setPixmap(QPixmap(":icons/network.png"))
        hbox.addStretch(10)
        hbox.addWidget(l)
        hbox.addWidget(QLabel(status))
        hbox.addStretch(50)
        vbox.addLayout(hbox)

        # grid layout
        grid = QGridLayout()
        grid.setSpacing(8)
        vbox.addLayout(grid)

        # server
        self.server_protocol = QComboBox()
        self.server_host = QLineEdit()
        self.server_host.setFixedWidth(200)
        self.server_port = QLineEdit()
        self.server_port.setFixedWidth(60)

        self.server_protocol.addItems(protocol_names)

        grid.addWidget(QLabel(_('Server') + ':'), 0, 0)
        grid.addWidget(self.server_protocol, 0, 1)
        grid.addWidget(self.server_host, 0, 2)
        grid.addWidget(self.server_port, 0, 3)

        self.server_protocol.connect(self.server_protocol, SIGNAL('currentIndexChanged(int)'), self.change_protocol)

        label = _('Active Servers') if interface.servers else _('Default Servers')
        self.servers_list_widget = QTreeWidget(parent)
        self.servers_list_widget.setHeaderLabels( [ label, _('Limit') ] )
        self.servers_list_widget.setMaximumHeight(150)
        self.servers_list_widget.setColumnWidth(0, 240)

        if server:
            host, port, protocol = server.split(':')
            self.set_protocol(protocol)
            self.change_server(host, protocol)
        else:
            self.set_protocol('s')

        self.servers_list_widget.connect(self.servers_list_widget, 
                                         SIGNAL('currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)'), 
                                         lambda x,y: self.server_changed(x))
        grid.addWidget(self.servers_list_widget, 1, 1, 1, 3)

        if not config.is_modifiable('server'):
            for w in [self.server_host, self.server_port, self.server_protocol, self.servers_list_widget]: w.setEnabled(False)

        # auto cycle
        self.autocycle_cb = QCheckBox(_('Try random servers if disconnected'))
        self.autocycle_cb.setChecked(self.config.get('auto_cycle', True))
        grid.addWidget(self.autocycle_cb, 3, 1, 3, 2)
        if not self.config.is_modifiable('auto_cycle'): self.autocycle_cb.setEnabled(False)

        # proxy setting
        self.proxy_mode = QComboBox()
        self.proxy_host = QLineEdit()
        self.proxy_host.setFixedWidth(200)
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(60)
        self.proxy_mode.addItems(['NONE', 'SOCKS4', 'SOCKS5', 'HTTP'])

        def check_for_disable(index = False):
            if self.proxy_mode.currentText() != 'NONE':
                self.proxy_host.setEnabled(True)
                self.proxy_port.setEnabled(True)
            else:
                self.proxy_host.setEnabled(False)
                self.proxy_port.setEnabled(False)

        check_for_disable()
        self.proxy_mode.connect(self.proxy_mode, SIGNAL('currentIndexChanged(int)'), check_for_disable)

        if not self.config.is_modifiable('proxy'):
            for w in [self.proxy_host, self.proxy_port, self.proxy_mode]: w.setEnabled(False)

        proxy_config = interface.proxy if interface.proxy else { "mode":"none", "host":"localhost", "port":"8080"}
        self.proxy_mode.setCurrentIndex(self.proxy_mode.findText(str(proxy_config.get("mode").upper())))
        self.proxy_host.setText(proxy_config.get("host"))
        self.proxy_port.setText(proxy_config.get("port"))

        grid.addWidget(QLabel(_('Proxy') + ':'), 2, 0)
        grid.addWidget(self.proxy_mode, 2, 1)
        grid.addWidget(self.proxy_host, 2, 2)
        grid.addWidget(self.proxy_port, 2, 3)

        # buttons
        vbox.addLayout(ok_cancel_buttons(self))
        self.setLayout(vbox) 


    def init_servers_list(self):
        self.servers_list_widget.clear()
        for _host, d in self.servers.items():
            if d.get(self.protocol):
                pruning_level = d.get('pruning','')
                self.servers_list_widget.addTopLevelItem(QTreeWidgetItem( [ _host, pruning_level ] ))


    def set_protocol(self, protocol):
        if protocol != self.protocol:
            self.protocol = protocol
            self.init_servers_list()
        
    def change_protocol(self, index):
        p = protocol_letters[index]
        host = unicode(self.server_host.text())
        pp = self.servers.get(host)
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
        if protocol:
            port = pp.get(protocol)
            if not port: protocol = None
                    
        if not protocol:
            if 's' in pp.keys():
                protocol = 's'
                port = pp.get(protocol)
            else:
                protocol = pp.keys()[0]
                port = pp.get(protocol)
            
        self.server_host.setText( host )
        self.server_port.setText( port )
        self.server_protocol.setCurrentIndex(protocol_letters.index(protocol))

        if not self.servers: return
        for p in protocol_letters:
            i = protocol_letters.index(p)
            j = self.server_protocol.model().index(i,0)
            #if p not in pp.keys(): # and self.interface.is_connected:
            #    self.server_protocol.model().setData(j, QVariant(0), Qt.UserRole-1)
            #else:
            #    self.server_protocol.model().setData(j, QVariant(33), Qt.UserRole-1)


    def do_exec(self):

        if not self.exec_(): return

        server = ':'.join([str( self.server_host.text() ),
                           str( self.server_port.text() ),
                           (protocol_letters[self.server_protocol.currentIndex()]) ])

        if self.proxy_mode.currentText() != 'NONE':
            proxy = { 'mode':str(self.proxy_mode.currentText()).lower(), 
                      'host':str(self.proxy_host.text()), 
                      'port':str(self.proxy_port.text()) }
        else:
            proxy = None

        self.config.set_key("proxy", proxy, True)
        self.config.set_key("server", server, True)
        self.interface.set_server(server, proxy)
        self.config.set_key('auto_cycle', self.autocycle_cb.isChecked(), True)
        return True
