#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
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

from __future__ import absolute_import

import socket
import time
import threading
import base64
from decimal import Decimal
from Queue import Queue

import smtplib
import imaplib
import email
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email import Encoders

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum_ltc.paymentrequest import PR_UNPAID, PR_PAID, PR_EXPIRED
from electrum_ltc.plugins import BasePlugin, hook
from electrum_ltc import util
from electrum_ltc.paymentrequest import PaymentRequest
from electrum_ltc.i18n import _
from electrum_ltc_gui.qt.util import EnterButton



class Processor(threading.Thread):
    polling_interval = 5*60

    def __init__(self, imap_server, username, password, callback):
        threading.Thread.__init__(self)
        self.daemon = True
        self.username = username
        self.password = password
        self.imap_server = imap_server
        self.on_receive = callback

    def poll(self):
        try:
            self.M.select()
        except:
            return
        typ, data = self.M.search(None, 'ALL')
        for num in data[0].split():
            typ, msg_data = self.M.fetch(num, '(RFC822)')
            msg = email.message_from_string(msg_data[0][1])
            p = msg.get_payload()
            if not msg.is_multipart():
                p = [p]
                continue
            for item in p:
                if item.get_content_type() == "application/litecoin-paymentrequest":
                    pr_str = item.get_payload()
                    pr_str = base64.b64decode(pr_str)
                    self.on_receive(pr_str)

    def run(self):
        self.M = imaplib.IMAP4_SSL(self.imap_server)
        self.M.login(self.username, self.password)
        while True:
            self.poll()
            time.sleep(self.polling_interval)
        self.M.close()
        self.M.logout()

    def send(self, recipient, message, payment_request):
        msg = MIMEMultipart()
        msg['Subject'] = message
        msg['To'] = recipient
        msg['From'] = self.username
        part = MIMEBase('application', "litecoin-paymentrequest")
        part.set_payload(payment_request)
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="payreq.ltc"')
        msg.attach(part)
        s = smtplib.SMTP_SSL(self.imap_server, timeout=2)
        s.login(self.username, self.password)
        s.sendmail(self.username, [recipient], msg.as_string())
        s.quit()


class Plugin(BasePlugin):

    def fullname(self):
        return 'Email'

    def description(self):
        return _("Send and receive payment requests via email")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.imap_server = self.config.get('email_server', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        if self.imap_server and self.username and self.password:
            self.processor = Processor(self.imap_server, self.username, self.password, self.on_receive)
            self.processor.start()
        self.obj = QObject()
        self.obj.connect(self.obj, SIGNAL('email:new_invoice'), self.new_invoice)

    def on_receive(self, pr_str):
        self.print_error('received payment request')
        self.pr = PaymentRequest(pr_str)
        self.obj.emit(SIGNAL('email:new_invoice'))

    def new_invoice(self):
        self.parent.invoices.add(self.pr)
        #window.update_invoices_list()

    @hook
    def receive_list_menu(self, menu, addr):
        window = menu.parentWidget()
        menu.addAction(_("Send via e-mail"), lambda: self.send(window, addr))

    def send(self, window, addr):
        from electrum_ltc import paymentrequest
        r = window.wallet.receive_requests.get(addr)
        message = r.get('memo', '')
        if r.get('signature'):
            pr = paymentrequest.serialize_request(r)
        else:
            pr = paymentrequest.make_request(self.config, r)
        if not pr:
            return
        recipient, ok = QtGui.QInputDialog.getText(window, 'Send request', 'Email invoice to:')
        if not ok:
            return
        recipient = str(recipient)
        payload = pr.SerializeToString()
        self.print_error('sending mail to', recipient)
        try:
            self.processor.send(recipient, message, payload)
        except BaseException as e:
            window.show_message(str(e))
            return

        window.show_message(_('Request sent.'))


    def requires_settings(self):
        return True

    def settings_widget(self, window):
        self.settings_window = window
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self, x):
        from electrum_ltc_gui.qt.util import Buttons, CloseButton, OkButton

        d = QDialog(self.settings_window)
        d.setWindowTitle("Email settings")
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Server hosting your email acount')))
        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel('Server (IMAP)'), 0, 0)
        server_e = QLineEdit()
        server_e.setText(self.imap_server)
        grid.addWidget(server_e, 0, 1)

        grid.addWidget(QLabel('Username'), 1, 0)
        username_e = QLineEdit()
        username_e.setText(self.username)
        grid.addWidget(username_e, 1, 1)

        grid.addWidget(QLabel('Password'), 2, 0)
        password_e = QLineEdit()
        password_e.setText(self.password)
        grid.addWidget(password_e, 2, 1)

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        if not d.exec_():
            return

        server = str(server_e.text())
        self.config.set_key('email_server', server)

        username = str(username_e.text())
        self.config.set_key('email_username', username)

        password = str(password_e.text())
        self.config.set_key('email_password', password)
