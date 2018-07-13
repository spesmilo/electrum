#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
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
import random
import time
import threading
import base64
from functools import partial
import traceback
import sys

import smtplib
import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.encoders import encode_base64

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QLineEdit,
                             QInputDialog)

from electrum_ltc.plugin import BasePlugin, hook
from electrum_ltc.paymentrequest import PaymentRequest
from electrum_ltc.i18n import _
from electrum_ltc.util import PrintError
from ...gui.qt.util import (EnterButton, Buttons, CloseButton, OkButton,
                            WindowModalDialog, get_parent_main_window)


class Processor(threading.Thread, PrintError):
    polling_interval = 5*60

    def __init__(self, imap_server, username, password, callback):
        threading.Thread.__init__(self)
        self.daemon = True
        self.username = username
        self.password = password
        self.imap_server = imap_server
        self.on_receive = callback
        self.M = None
        self.reset_connect_wait()

    def reset_connect_wait(self):
        self.connect_wait = 100  # ms, between failed connection attempts

    def poll(self):
        try:
            self.M.select()
        except:
            return
        typ, data = self.M.search(None, 'ALL')
        for num in str(data[0], 'utf8').split():
            typ, msg_data = self.M.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
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
        while True:
            try:
                self.M = imaplib.IMAP4_SSL(self.imap_server)
                self.M.login(self.username, self.password)
            except BaseException as e:
                self.print_error('connecting failed: {}'.format(e))
                self.connect_wait *= 2
            else:
                self.reset_connect_wait()
            # Reconnect when host changes
            while self.M and self.M.host == self.imap_server:
                try:
                    self.poll()
                except BaseException as e:
                    self.print_error('polling failed: {}'.format(e))
                    break
                time.sleep(self.polling_interval)
            time.sleep(random.randint(0, self.connect_wait))

    def send(self, recipient, message, payment_request):
        msg = MIMEMultipart()
        msg['Subject'] = message
        msg['To'] = recipient
        msg['From'] = self.username
        part = MIMEBase('application', "litecoin-paymentrequest")
        part.set_payload(payment_request)
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="payreq.ltc"')
        msg.attach(part)
        try:
            s = smtplib.SMTP_SSL(self.imap_server, timeout=2)
            s.login(self.username, self.password)
            s.sendmail(self.username, [recipient], msg.as_string())
            s.quit()
        except BaseException as e:
            self.print_error(e)


class QEmailSignalObject(QObject):
    email_new_invoice_signal = pyqtSignal()


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
        self.obj = QEmailSignalObject()
        self.obj.email_new_invoice_signal.connect(self.new_invoice)
        self.wallets = set()

    def on_receive(self, pr_str):
        self.print_error('received payment request')
        self.pr = PaymentRequest(pr_str)
        self.obj.email_new_invoice_signal.emit()

    @hook
    def load_wallet(self, wallet, main_window):
        self.wallets |= {wallet}

    @hook
    def close_wallet(self, wallet):
        self.wallets -= {wallet}

    def new_invoice(self):
        for wallet in self.wallets:
            wallet.invoices.add(self.pr)
        #main_window.invoice_list.update()

    @hook
    def receive_list_menu(self, menu, addr):
        window = get_parent_main_window(menu)
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
        recipient, ok = QInputDialog.getText(window, 'Send request', 'Email invoice to:')
        if not ok:
            return
        recipient = str(recipient)
        payload = pr.SerializeToString()
        self.print_error('sending mail to', recipient)
        try:
            # FIXME this runs in the GUI thread and blocks it...
            self.processor.send(recipient, message, payload)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            window.show_message(str(e))
        else:
            window.show_message(_('Request sent.'))

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Email settings"))
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Server hosting your email account')))
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
        self.imap_server = server

        username = str(username_e.text())
        self.config.set_key('email_username', username)
        self.username = username

        password = str(password_e.text())
        self.config.set_key('email_password', password)
        self.password = password

        check_connection = CheckConnectionThread(server, username, password)
        check_connection.connection_error_signal.connect(lambda e: window.show_message(
            _("Unable to connect to mail server:\n {}").format(e) + "\n" +
            _("Please check your connection and credentials.")
        ))
        check_connection.start()


class CheckConnectionThread(QThread):
    connection_error_signal = pyqtSignal(str)

    def __init__(self, server, username, password):
        super().__init__()
        self.server = server
        self.username = username
        self.password = password

    def run(self):
        try:
            conn = imaplib.IMAP4_SSL(self.server)
            conn.login(self.username, self.password)
        except BaseException as e:
            self.connection_error_signal.emit(str(e))
